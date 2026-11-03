package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/security"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// SecurityHandler serves Git Capsule package B7: security overview, alerts, SARIF upload,
// policy, suppressions, scans (this file) and Renovate (renovate.go).
type SecurityHandler struct {
	authzHolder
	svc      *security.Service
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
}

const securityBase = "/orgs/{orgID}/projects/{projectID}/security"

// maxSarifBody is a 10 MiB (compressed) SARIF as base64 inside JSON, plus room for the envelope.
const maxSarifBody = (security.MaxCompressedBytes/3+1)*4 + 64<<10

// MountSecurity registers the B7 routes on the authenticated /api/v1 router. It uses the Service
// published by security.WireSecurity (looked up per request); without it every route answers 501.
//
// sarifUpload is authenticated like every other route: a user or a project API token. A CI token
// restricted to the "security:write" scope additionally needs middleware.TokenAllows to accept
// POST .../security/sarif (see the package B7 notes).
func MountSecurity(r chi.Router, az *authz.Service, orgs domain.OrganizationRepository, projects domain.ProjectRepository) {
	h := &SecurityHandler{orgs: orgs, projects: projects}
	h.SetAuthz(az)
	r.Get(securityBase+"/overview", h.Overview)
	r.Get(securityBase+"/alerts", h.AlertsList)
	r.Get(securityBase+"/alerts/{alertID}", h.AlertGet)
	r.Post(securityBase+"/alerts/{alertID}/dismiss", h.AlertDismiss)
	r.Post(securityBase+"/alerts/{alertID}/reopen", h.AlertReopen)
	r.Post(securityBase+"/sarif", h.SarifUpload)
	r.Get(securityBase+"/sarif/{uploadID}", h.SarifStatus)
	r.Get(securityBase+"/policy", h.PolicyGet)
	r.Put(securityBase+"/policy", h.PolicyPut)
	r.Get(securityBase+"/suppressions", h.SuppressionsList)
	r.Post(securityBase+"/suppressions", h.SuppressionCreate)
	r.Delete(securityBase+"/suppressions/{suppressionID}", h.SuppressionDelete)
	r.Post(securityBase+"/scans", h.ScanTrigger)
	r.Get(securityBase+"/renovate", h.RenovateGet)
	r.Put(securityBase+"/renovate", h.RenovatePut)
	r.Post(securityBase+"/renovate/run", h.RenovateRun)
}

// NewSecurityHandler builds the handler directly (tests).
func NewSecurityHandler(svc *security.Service, az *authz.Service, orgs domain.OrganizationRepository, projects domain.ProjectRepository) *SecurityHandler {
	h := &SecurityHandler{svc: svc, orgs: orgs, projects: projects}
	h.SetAuthz(az)
	return h
}

func (h *SecurityHandler) service() *security.Service {
	if h.svc != nil {
		return h.svc
	}
	return security.Shared()
}

type secErrorBody struct {
	Code    string                `json:"code"`
	Message string                `json:"message"`
	Fields  []security.FieldError `json:"fields,omitempty"`
}

func secError(w http.ResponseWriter, status int, code, msg string, fields []security.FieldError) {
	respondJSON(w, status, struct {
		Error secErrorBody `json:"error"`
	}{secErrorBody{Code: code, Message: msg, Fields: fields}})
}

// secCtx is the authorized request context.
type secCtx struct {
	t security.Target
	a security.Actor
}

// begin authorizes act and resolves target and actor (errors are written).
func (h *SecurityHandler) begin(w http.ResponseWriter, r *http.Request, act authz.Action) (secCtx, bool) {
	var c secCtx
	if h.service() == nil {
		respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "security is not configured")
		return c, false
	}
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return c, false
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return c, false
	}
	if !h.authorize(w, r, h.orgs, orgID, projectID, act) {
		return c, false
	}
	p, err := h.projects.GetByID(r.Context(), projectID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && p.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return c, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load project")
		return c, false
	}
	org, err := h.orgs.GetByID(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load organization")
		return c, false
	}
	c.t = security.Target{ProjectID: projectID, OrgID: orgID, OrgSlug: org.Slug, ProjectSlug: p.Slug}
	c.a = security.Actor{IP: middleware.ClientIP(r)}
	if u := middleware.GetUser(r.Context()); u != nil {
		c.a.UserID, c.a.Login = u.ID, u.Name
	}
	c.a.Admin = act == authz.SecurityAdmin || h.can(r, c, authz.SecurityAdmin)
	return c, true
}

// can asks authz whether the caller also holds another action on the project.
func (h *SecurityHandler) can(r *http.Request, c secCtx, act authz.Action) bool {
	if c.a.UserID == uuid.Nil {
		return false
	}
	ok, err := h.service2().Can(r.Context(), c.a.UserID, c.t.OrgID, c.t.ProjectID, act)
	return err == nil && ok
}

func (h *SecurityHandler) service2() *authz.Service { return h.authzHolder.service(h.orgs) }

// fail maps service errors to the HTTP contract.
func (h *SecurityHandler) fail(w http.ResponseWriter, err error) {
	var (
		ve *security.ValidationError
		se *security.SarifError
		fe *security.ForbiddenError
		ce *security.ConflictError
		be *security.BusinessError
		ge *gitcore.Error
	)
	switch {
	case errors.As(err, &ve):
		secError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", ve.Error(), ve.Fields)
	case errors.As(err, &se):
		status := http.StatusUnprocessableEntity
		if se.Code == "SARIF_TOO_LARGE" {
			status = http.StatusRequestEntityTooLarge
		}
		secError(w, status, se.Code, se.Message, nil)
	case errors.As(err, &fe):
		secError(w, http.StatusForbidden, fe.Code, fe.Message, nil)
	case errors.As(err, &ce):
		secError(w, http.StatusConflict, ce.Code, ce.Message, nil)
	case errors.As(err, &be):
		secError(w, http.StatusUnprocessableEntity, be.Code, be.Message, nil)
	case errors.Is(err, security.ErrNotFound):
		secError(w, http.StatusNotFound, "NOT_FOUND", "not found", nil)
	case errors.Is(err, security.ErrRateLimit):
		w.Header().Set("Retry-After", "60")
		secError(w, http.StatusTooManyRequests, "RATE_LIMITED", "demasiadas subidas SARIF para este proyecto: espera un minuto", nil)
	case errors.Is(err, security.ErrNotReady):
		secError(w, http.StatusServiceUnavailable, "NOT_CONFIGURED", "esta funcion no esta configurada en el servidor", nil)
	case errors.As(err, &ge):
		secError(w, ge.HTTPStatus(), string(ge.Code), ge.Message, nil)
	default:
		slog.Error("security: unexpected error", "err", err)
		secError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "unexpected error", nil)
	}
}

func secDecode(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			secError(w, http.StatusRequestEntityTooLarge, "SARIF_TOO_LARGE", "el cuerpo supera el limite permitido", nil)
		default:
			secError(w, http.StatusBadRequest, "INVALID_BODY", "invalid JSON body: "+gpJSONErr(err), nil)
		}
		return false
	}
	return true
}

func secTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// ---- JSON views ------------------------------------------------------------------------------

func secPerson(p security.Person) map[string]any {
	m := map[string]any{"user_id": nil, "login": p.Login, "name": p.Name, "email": p.Email, "avatar_url": p.AvatarURL}
	if p.UserID != nil {
		m["user_id"] = p.UserID.String()
	}
	return m
}

// alertView is the contract Alert. Evidence is empty for secrets and the value of a secret does
// not exist anywhere, so nothing needs hiding here.
func alertView(a security.Alert) map[string]any {
	loc := map[string]any{"path": a.Path, "start_line": a.StartLine, "end_line": a.EndLine}
	if a.Package != "" {
		loc["package"], loc["version"], loc["fixed_version"] = a.Package, a.Version, a.FixedVersion
	}
	if a.Advisory != "" {
		loc["advisory"] = a.Advisory
	}
	var dismissal any
	if a.Dismissal != nil {
		dismissal = map[string]any{
			"reason": a.Dismissal.Reason, "justification": a.Dismissal.Justification, "by": secPerson(a.Dismissal.By),
			"expires_at": a.Dismissal.ExpiresAt.UTC().Format(time.RFC3339),
		}
	}
	trace := a.Trace
	if trace == nil {
		trace = []security.TraceStep{}
	}
	m := map[string]any{
		"id": a.ID.String(), "kind": string(a.Kind), "tool": a.Tool, "rule_id": a.RuleID, "severity": string(a.Severity),
		"state": string(a.State), "title": a.Title, "description": a.Description, "fingerprint": a.Fingerprint,
		"location": loc, "first_seen_sha": a.FirstSeenSHA, "last_seen_sha": a.LastSeenSHA, "branch": a.Branch,
		"dismissal": dismissal, "trace": trace, "fixed_at": secTime(a.FixedAt),
		"created_at": a.CreatedAt.UTC().Format(time.RFC3339), "updated_at": a.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if a.Evidence != "" {
		m["evidence"] = a.Evidence
	}
	return m
}

func suppressionView(s security.Suppression, now time.Time) map[string]any {
	state := s.State
	if state == security.SuppActive && !s.ExpiresAt.After(now) {
		state = security.SuppExpired
	}
	match := map[string]any{}
	if s.Match.RuleID != "" {
		match["rule_id"] = s.Match.RuleID
	}
	if s.Match.Fingerprint != "" {
		match["fingerprint"] = s.Match.Fingerprint
	}
	if s.Match.PathGlob != "" {
		match["path_glob"] = s.Match.PathGlob
	}
	return map[string]any{
		"id": s.ID.String(), "match": match, "reason": s.Reason, "justification": s.Justification,
		"expires_at": s.ExpiresAt.UTC().Format(time.RFC3339), "created_by": secPerson(s.CreatedByPerson),
		"state": state, "source": s.Source, "created_at": s.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func uploadView(u *security.Upload) map[string]any {
	m := map[string]any{
		"id": u.ID.String(), "status": u.Status, "alerts_created": u.AlertsCreated, "alerts_fixed": u.AlertsFixed,
	}
	if u.Error != "" {
		m["error"] = u.Error
	}
	if u.Superseded {
		m["superseded"] = true
	}
	return m
}

func jobView(j *security.Job) map[string]any {
	return map[string]any{"id": j.ID.String(), "status": j.Status, "detail": j.Detail}
}

// ---- handlers --------------------------------------------------------------------------------

// GET .../security/overview
func (h *SecurityHandler) Overview(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityRead)
	if !ok {
		return
	}
	o, err := h.service().Overview(r.Context(), c.t.ProjectID)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"by_severity": o.BySeverity, "by_kind": o.ByKind, "open": o.Open, "dismissed": o.Dismissed,
		"last_scan_at": secTime(o.LastScanAt), "policy_blocking": o.PolicyBlocking,
	})
}

// GET .../security/alerts
func (h *SecurityHandler) AlertsList(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityRead)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit := 0
	if v := q.Get("limit"); v != "" {
		n, err := atoiStrict(v)
		if err != nil || n < 1 || n > 100 {
			secError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "limit debe estar entre 1 y 100", []security.FieldError{{Field: "limit", Message: "1..100"}})
			return
		}
		limit = n
	}
	aq := security.AlertQuery{
		Kind: q.Get("kind"), Severity: q.Get("severity"), State: q.Get("state"), Branch: q.Get("branch"), Tool: q.Get("tool"),
		Cursor: q.Get("cursor"), Limit: limit,
		// viewers see counters of secret alerts, not the alerts (rule and path are for triage and above)
		IncludeSecrets: h.can(r, c, authz.SecurityTriage),
	}
	items, next, err := h.service().ListAlerts(r.Context(), c.t.ProjectID, aq)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, a := range items {
		out = append(out, alertView(a))
	}
	var nc any
	if next != "" {
		nc = next
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": out, "next_cursor": nc})
}

func atoiStrict(s string) (int, error) {
	n := 0
	if s == "" || len(s) > 9 {
		return 0, errors.New("bad int")
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, errors.New("bad int")
		}
		n = n*10 + int(ch-'0')
	}
	return n, nil
}

func (h *SecurityHandler) alertID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "alertID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid alert id")
		return uuid.Nil, false
	}
	return id, true
}

// GET .../security/alerts/{alertID}
func (h *SecurityHandler) AlertGet(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityRead)
	if !ok {
		return
	}
	id, ok := h.alertID(w, r)
	if !ok {
		return
	}
	a, err := h.service().GetAlert(r.Context(), c.t.ProjectID, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	if a.Kind == security.KindSecret && !h.can(r, c, authz.SecurityTriage) {
		secError(w, http.StatusForbidden, "FORBIDDEN", "los detalles de las alertas de secretos son para deployer y admin", nil)
		return
	}
	respondJSON(w, http.StatusOK, alertView(*a))
}

type dismissBody struct {
	Reason        string    `json:"reason"`
	Justification string    `json:"justification"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// POST .../security/alerts/{alertID}/dismiss
func (h *SecurityHandler) AlertDismiss(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityTriage)
	if !ok {
		return
	}
	id, ok := h.alertID(w, r)
	if !ok {
		return
	}
	var body dismissBody
	if !secDecode(w, r, 64<<10, &body) {
		return
	}
	a, err := h.service().Dismiss(r.Context(), c.t, c.a, id, security.DismissInput{
		Reason: body.Reason, Justification: body.Justification, ExpiresAt: body.ExpiresAt,
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, alertView(*a))
}

// POST .../security/alerts/{alertID}/reopen
func (h *SecurityHandler) AlertReopen(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityTriage)
	if !ok {
		return
	}
	id, ok := h.alertID(w, r)
	if !ok {
		return
	}
	a, err := h.service().Reopen(r.Context(), c.t, c.a, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, alertView(*a))
}

type sarifBody struct {
	CommitSHA string `json:"commit_sha"`
	Ref       string `json:"ref"`
	ToolName  string `json:"tool_name"`
	Sarif     string `json:"sarif"`
	PR        *int   `json:"pr"`
}

// POST .../security/sarif
func (h *SecurityHandler) SarifUpload(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityTriage)
	if !ok {
		return
	}
	var body sarifBody
	if !secDecode(w, r, maxSarifBody, &body) {
		return
	}
	pr := 0
	if body.PR != nil {
		pr = *body.PR
	}
	u, err := h.service().Upload(r.Context(), c.t, c.a, security.UploadInput{
		CommitSHA: body.CommitSHA, Ref: body.Ref, ToolName: body.ToolName, Sarif: body.Sarif, PR: pr,
		IdempotencyKey: strings.TrimSpace(r.Header.Get("Idempotency-Key")),
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, uploadView(u))
}

// GET .../security/sarif/{uploadID}
func (h *SecurityHandler) SarifStatus(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityRead)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "uploadID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid upload id")
		return
	}
	u, err := h.service().UploadStatus(r.Context(), c.t.ProjectID, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, uploadView(u))
}

// GET .../security/policy
func (h *SecurityHandler) PolicyGet(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityRead)
	if !ok {
		return
	}
	p, err := h.service().GetPolicy(r.Context(), c.t.ProjectID)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, p)
}

// PUT .../security/policy
func (h *SecurityHandler) PolicyPut(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityAdmin)
	if !ok {
		return
	}
	var body security.Policy
	if !secDecode(w, r, 64<<10, &body) {
		return
	}
	p, err := h.service().PutPolicy(r.Context(), c.t, c.a, body)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, p)
}

// GET .../security/suppressions
func (h *SecurityHandler) SuppressionsList(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityRead)
	if !ok {
		return
	}
	items, err := h.service().ListSuppressions(r.Context(), c.t.ProjectID)
	if err != nil {
		h.fail(w, err)
		return
	}
	now := time.Now()
	out := make([]map[string]any, 0, len(items))
	for _, s := range items {
		out = append(out, suppressionView(s, now))
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": out})
}

type suppressionBody struct {
	Match         security.SuppressionMatch `json:"match"`
	Reason        string                    `json:"reason"`
	Justification string                    `json:"justification"`
	ExpiresAt     time.Time                 `json:"expires_at"`
}

// POST .../security/suppressions
func (h *SecurityHandler) SuppressionCreate(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityTriage)
	if !ok {
		return
	}
	var body suppressionBody
	if !secDecode(w, r, 64<<10, &body) {
		return
	}
	s, _, err := h.service().CreateSuppression(r.Context(), c.t, c.a, security.SuppressionInput{
		Match: body.Match, Reason: body.Reason, Justification: body.Justification, ExpiresAt: body.ExpiresAt,
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	s.CreatedByPerson = security.Person{UserID: &c.a.UserID, Name: c.a.Login}
	respondJSON(w, http.StatusCreated, suppressionView(*s, time.Now()))
}

// DELETE .../security/suppressions/{suppressionID}
func (h *SecurityHandler) SuppressionDelete(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityTriage)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "suppressionID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid suppression id")
		return
	}
	if err := h.service().RevokeSuppression(r.Context(), c.t, c.a, id); err != nil {
		h.fail(w, err)
		return
	}
	respondNoContent(w)
}

type scanBody struct {
	Tools []string `json:"tools"`
	Ref   string   `json:"ref"`
}

// POST .../security/scans
func (h *SecurityHandler) ScanTrigger(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityTriage)
	if !ok {
		return
	}
	var body scanBody
	if r.ContentLength != 0 && !secDecode(w, r, 64<<10, &body) {
		return
	}
	j, err := h.service().TriggerScan(r.Context(), c.t, c.a, body.Tools, body.Ref, strings.TrimSpace(r.Header.Get("Idempotency-Key")))
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, jobView(j))
}
