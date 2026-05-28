package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sestypes "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/pkg/awsclient"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

type EmailHandler struct {
	dbs          domain.DatabaseRepository
	orgs         domain.OrganizationRepository
	projects     domain.ProjectRepository
	emailLogRepo domain.EmailLogRepository
	aws          *awsclient.Clients
	secretKey    string
	logger       *slog.Logger
}

func NewEmailHandler(
	dbs domain.DatabaseRepository,
	orgs domain.OrganizationRepository,
	projects domain.ProjectRepository,
	emailLogRepo domain.EmailLogRepository,
	awsClients *awsclient.Clients,
	secretKey string,
	logger *slog.Logger,
) *EmailHandler {
	return &EmailHandler{
		dbs:          dbs,
		orgs:         orgs,
		projects:     projects,
		emailLogRepo: emailLogRepo,
		aws:          awsClients,
		secretKey:    secretKey,
		logger:       logger,
	}
}

func (h *EmailHandler) Setup(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && project.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get project")
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.Domain == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "domain is required")
		return
	}

	// Store email config as engine 'ses' in databases table
	// Generate random SMTP details
	smtpUser := fmt.Sprintf("AKIA%s", randomString(16))
	smtpPass := randomString(32)

	creds := map[string]string{
		"smtp_host":      "email-smtp.us-east-1.amazonaws.com",
		"smtp_port":      "587",
		"smtp_user":      smtpUser,
		"smtp_pass":      smtpPass,
		"verified_from":  fmt.Sprintf("hello@%s", req.Domain),
	}
	credsJSON, _ := json.Marshal(creds)
	enc, err := crypto.Encrypt(credsJSON, h.secretKey)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to encrypt credentials")
		return
	}

	db, err := h.dbs.Create(r.Context(), &domain.Database{
		OrgID:           orgID,
		ProjectID:       &projectID,
		Name:            "email-" + req.Domain,
		Engine:          "ses",
		Version:         "latest",
		Host:            "email-smtp.us-east-1.amazonaws.com",
		Port:            587,
		DBName:          req.Domain,
		CredentialsEnc:  enc,
		Status:          "pending",
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create email record")
		return
	}

	// In the background, trigger AWS SES CreateEmailIdentity
	if h.aws != nil {
		go func() {
			ctx := context.Background()
			_, err := h.aws.SES.CreateEmailIdentity(ctx, &sesv2.CreateEmailIdentityInput{
				EmailIdentity: aws.String(req.Domain),
			})
			if err != nil {
				h.logger.Error("failed to create SES email identity", "domain", req.Domain, "error", err)
			}
		}()
	}

	respondJSON(w, http.StatusCreated, db)
}

func (h *EmailHandler) Status(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	allDBs, err := h.dbs.ListByProject(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list database configurations")
		return
	}

	var emailDB *domain.Database
	for _, db := range allDBs {
		if db.Engine == "ses" {
			emailDB = db
			break
		}
	}

	if emailDB == nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "email not configured for this project")
		return
	}

	status := emailDB.Status // default: reflect persisted status (pending/verified/etc.)
	if h.aws != nil {
		resp, err := h.aws.SES.GetEmailIdentity(r.Context(), &sesv2.GetEmailIdentityInput{
			EmailIdentity: aws.String(emailDB.DBName),
		})
		if err == nil && resp.VerifiedForSendingStatus {
			status = "verified"
			_ = h.dbs.UpdateStatus(r.Context(), emailDB.ID, "verified", emailDB.Host, emailDB.Port)
			emailDB.Status = "verified"
		}
	}

	type emailStatusResponse struct {
		Domain         string `json:"domain"`
		Status         string `json:"status"`
		SMTPOperations any    `json:"smtp_operations"`
	}

	var smtpOpts map[string]string
	if len(emailDB.CredentialsEnc) > 0 {
		plain, err := crypto.Decrypt(emailDB.CredentialsEnc, h.secretKey)
		if err == nil {
			_ = json.Unmarshal(plain, &smtpOpts)
		}
	}

	respondJSON(w, http.StatusOK, emailStatusResponse{
		Domain:         emailDB.DBName,
		Status:         status,
		SMTPOperations: smtpOpts,
	})
}

func (h *EmailHandler) Test(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	var req struct {
		To string `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.To == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "recipient is required")
		return
	}

	allDBs, err := h.dbs.ListByProject(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	var emailDB *domain.Database
	for _, db := range allDBs {
		if db.Engine == "ses" {
			emailDB = db
			break
		}
	}

	if emailDB == nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "email not configured for this project")
		return
	}

	var smtpOpts map[string]string
	if len(emailDB.CredentialsEnc) > 0 {
		plain, err := crypto.Decrypt(emailDB.CredentialsEnc, h.secretKey)
		if err == nil {
			_ = json.Unmarshal(plain, &smtpOpts)
		}
	}

	fromEmail := fmt.Sprintf("hello@%s", emailDB.DBName)
	if smtpOpts != nil && smtpOpts["verified_from"] != "" {
		fromEmail = smtpOpts["verified_from"]
	}

	if h.aws != nil {
		_, err := h.aws.SES.SendEmail(r.Context(), &sesv2.SendEmailInput{
			FromEmailAddress: aws.String(fromEmail),
			Destination: &sestypes.Destination{
				ToAddresses: []string{req.To},
			},
			Content: &sestypes.EmailContent{
				Simple: &sestypes.Message{
					Subject: &sestypes.Content{
						Data: aws.String("Capsule Email Service Test"),
					},
					Body: &sestypes.Body{
						Text: &sestypes.Content{
							Data: aws.String("Hi there!\n\nThis is a successful test email from your verified Capsule domain: " + emailDB.DBName + ".\n\nCheers,\nThe Capsule Team"),
						},
					},
				},
			},
		})
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to send email: "+err.Error())
			return
		}
	}

	respondJSON(w, http.StatusOK, map[string]string{"message": "Test email sent successfully to " + req.To})
}

func (h *EmailHandler) Stats(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}
	_ = projectID

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	type emailStats struct {
		SentLast24H    float64 `json:"sent_last_24h"`
		Quota24H       float64 `json:"quota_24h"`
		SendingEnabled bool    `json:"sending_enabled"`
	}

	// No AWS client — return zeroes
	if h.aws == nil || h.aws.SES == nil {
		respondJSON(w, http.StatusOK, emailStats{})
		return
	}

	out, err := h.aws.SES.GetAccount(r.Context(), &sesv2.GetAccountInput{})
	if err != nil {
		h.logger.Warn("failed to get SES account stats", "error", err)
		respondJSON(w, http.StatusOK, emailStats{})
		return
	}

	var sent, quota float64
	if out.SendQuota != nil {
		sent = out.SendQuota.SentLast24Hours
		quota = out.SendQuota.Max24HourSend
	}

	respondJSON(w, http.StatusOK, emailStats{
		SentLast24H:    sent,
		Quota24H:       quota,
		SendingEnabled: out.SendingEnabled,
	})
}

func (h *EmailHandler) DNSRecords(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	allDBs, err := h.dbs.ListByProject(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list databases")
		return
	}

	var emailDB *domain.Database
	for _, db := range allDBs {
		if db.Engine == "ses" {
			emailDB = db
			break
		}
	}

	if emailDB == nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "email not configured for this project")
		return
	}

	domainName := emailDB.DBName

	type dnsRecord struct {
		Type   string `json:"type"`
		Host   string `json:"host"`
		Value  string `json:"value"`
		Status string `json:"status"`
	}
	type dnsResponse struct {
		Domain             string      `json:"domain"`
		Records            []dnsRecord `json:"records"`
		DKIMStatus         string      `json:"dkim_status"`
		VerificationStatus string      `json:"verification_status"`
	}

	if h.aws == nil {
		respondError(w, http.StatusServiceUnavailable, "AWS_UNAVAILABLE", "email features require AWS SES configuration")
		return
	}

	awsResp, err := h.aws.SES.GetEmailIdentity(r.Context(), &sesv2.GetEmailIdentityInput{
		EmailIdentity: aws.String(domainName),
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get email identity: "+err.Error())
		return
	}

	var records []dnsRecord
	if awsResp.DkimAttributes != nil {
		for _, token := range awsResp.DkimAttributes.Tokens {
			status := "pending"
			if awsResp.DkimAttributes.Status == sestypes.DkimStatusSuccess {
				status = "verified"
			}
			records = append(records, dnsRecord{
				Type:   "CNAME",
				Host:   token + "._domainkey." + domainName,
				Value:  token + ".dkim.amazonses.com",
				Status: status,
			})
		}
	}
	records = append(records,
		dnsRecord{Type: "TXT", Host: "_dmarc." + domainName, Value: "v=DMARC1; p=none; rua=mailto:dmarc@" + domainName, Status: "recommended"},
		dnsRecord{Type: "TXT", Host: domainName, Value: "v=spf1 include:amazonses.com ~all", Status: "recommended"},
	)

	dkimStatus := "PENDING"
	if awsResp.DkimAttributes != nil {
		dkimStatus = string(awsResp.DkimAttributes.Status)
	}
	verificationStatus := "PENDING"
	if awsResp.VerifiedForSendingStatus {
		verificationStatus = "SUCCESS"
	}

	respondJSON(w, http.StatusOK, dnsResponse{
		Domain:             domainName,
		Records:            records,
		DKIMStatus:         dkimStatus,
		VerificationStatus: verificationStatus,
	})
}

func (h *EmailHandler) Send(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && project.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get project")
		return
	}

	var req struct {
		From    string `json:"from"`
		To      string `json:"to"`
		Subject string `json:"subject"`
		HTML    string `json:"html"`
		Text    string `json:"text"`
		ReplyTo string `json:"reply_to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.From == "" || req.To == "" || req.Subject == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "from, to, and subject are required")
		return
	}

	// Determine domain from from address
	emailDomain := ""
	if atIdx := indexOf(req.From, '@'); atIdx >= 0 {
		emailDomain = req.From[atIdx+1:]
	}

	messageID := ""

	if h.aws != nil {
		input := &sesv2.SendEmailInput{
			FromEmailAddress: aws.String(req.From),
			Destination: &sestypes.Destination{
				ToAddresses: []string{req.To},
			},
			Content: &sestypes.EmailContent{
				Simple: &sestypes.Message{
					Subject: &sestypes.Content{
						Data: aws.String(req.Subject),
					},
					Body: &sestypes.Body{},
				},
			},
		}
		if req.HTML != "" {
			input.Content.Simple.Body.Html = &sestypes.Content{Data: aws.String(req.HTML)}
		}
		if req.Text != "" {
			input.Content.Simple.Body.Text = &sestypes.Content{Data: aws.String(req.Text)}
		}
		if req.ReplyTo != "" {
			input.ReplyToAddresses = []string{req.ReplyTo}
		}

		out, err := h.aws.SES.SendEmail(r.Context(), input)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to send email: "+err.Error())
			return
		}
		if out.MessageId != nil {
			messageID = *out.MessageId
		}
	}

	// Save to email_logs
	if h.emailLogRepo != nil {
		logEntry := &domain.EmailLog{
			ProjectID: projectID,
			Domain:    emailDomain,
			FromAddr:  req.From,
			ToAddr:    req.To,
			Subject:   req.Subject,
			Status:    "sent",
			MessageID: messageID,
		}
		if _, err := h.emailLogRepo.Create(r.Context(), logEntry); err != nil {
			h.logger.Warn("failed to save email log", "error", err)
		}
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message_id": messageID,
		"status":     "sent",
	})
}

func (h *EmailHandler) Logs(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	limit := 50
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}

	logs, err := h.emailLogRepo.ListByProject(r.Context(), projectID, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list email logs")
		return
	}
	if logs == nil {
		logs = []*domain.EmailLog{}
	}

	respondJSON(w, http.StatusOK, map[string]any{"data": logs})
}

func (h *EmailHandler) Suppressions(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}
	_ = projectID

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	type suppressionEntry struct {
		Email     string    `json:"email"`
		Reason    string    `json:"reason"`
		CreatedAt time.Time `json:"created_at"`
	}

	if h.aws == nil {
		respondJSON(w, http.StatusOK, map[string]any{"data": []suppressionEntry{}})
		return
	}

	out, err := h.aws.SES.ListSuppressedDestinations(r.Context(), &sesv2.ListSuppressedDestinationsInput{
		PageSize: aws.Int32(100),
	})
	if err != nil {
		h.logger.Warn("failed to list SES suppressed destinations", "error", err)
		respondJSON(w, http.StatusOK, map[string]any{"data": []suppressionEntry{}})
		return
	}

	entries := make([]suppressionEntry, 0, len(out.SuppressedDestinationSummaries))
	for _, s := range out.SuppressedDestinationSummaries {
		email := ""
		if s.EmailAddress != nil {
			email = *s.EmailAddress
		}
		createdAt := time.Time{}
		if s.LastUpdateTime != nil {
			createdAt = *s.LastUpdateTime
		}
		entries = append(entries, suppressionEntry{
			Email:     email,
			Reason:    string(s.Reason),
			CreatedAt: createdAt,
		})
	}

	respondJSON(w, http.StatusOK, map[string]any{"data": entries})
}

func (h *EmailHandler) DeleteSuppression(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	_, err = uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	emailAddr, err := url.PathUnescape(chi.URLParam(r, "emailAddr"))
	if err != nil || emailAddr == "" {
		respondError(w, http.StatusBadRequest, "INVALID_PARAM", "invalid email address")
		return
	}

	if h.aws != nil {
		_, err := h.aws.SES.DeleteSuppressedDestination(r.Context(), &sesv2.DeleteSuppressedDestinationInput{
			EmailAddress: aws.String(emailAddr),
		})
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete suppression: "+err.Error())
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// indexOf returns the index of char c in s, or -1 if not found.
func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, n)
	rand.Seed(time.Now().UnixNano())
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
