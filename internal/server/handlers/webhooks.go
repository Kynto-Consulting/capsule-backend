package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/internal/webhookout"
)

// WebhookAuditor records webhook changes in audit_logs (authz.MemberStore satisfies it). nil = no audit.
type WebhookAuditor interface {
	Audit(ctx context.Context, e authz.AuditEntry) error
}

// WebhooksHandler serves the outbound webhook API of Git Capsule (package A5):
//
//	/orgs/{orgID}/projects/{projectID}/webhooks...   permission webhooks.manage
//	/orgs/{orgID}/webhooks...                        permission org.admin (owner or admin of the org)
type WebhooksHandler struct {
	authzHolder
	orgs  domain.OrganizationRepository
	svc   *webhookout.Service
	audit WebhookAuditor
	log   *slog.Logger
}

// NewWebhooksHandler builds the handler. audit and logger may be nil.
func NewWebhooksHandler(orgs domain.OrganizationRepository, svc *webhookout.Service, audit WebhookAuditor, logger *slog.Logger) *WebhooksHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &WebhooksHandler{orgs: orgs, svc: svc, audit: audit, log: logger}
}

// Mount registers the routes on r (an authenticated router).
func (h *WebhooksHandler) Mount(r chi.Router) {
	const p = "/orgs/{orgID}/projects/{projectID}/webhooks"
	r.Get(p, h.list)
	r.Post(p, h.create)
	r.Patch(p+"/{webhookID}", h.update)
	r.Delete(p+"/{webhookID}", h.remove)
	r.Post(p+"/{webhookID}/test", h.test)
	r.Post(p+"/{webhookID}/rotate-secret", h.rotate)
	r.Get(p+"/{webhookID}/deliveries", h.deliveries)
	r.Post(p+"/{webhookID}/deliveries/{deliveryID}/redeliver", h.redeliver)

	const o = "/orgs/{orgID}/webhooks"
	r.Get(o, h.list)
	r.Post(o, h.create)
	r.Patch(o+"/{webhookID}", h.update)
	r.Delete(o+"/{webhookID}", h.remove)
	r.Post(o+"/{webhookID}/test", h.test)
	r.Post(o+"/{webhookID}/rotate-secret", h.rotate)
	r.Get(o+"/{webhookID}/deliveries", h.deliveries)
	r.Post(o+"/{webhookID}/deliveries/{deliveryID}/redeliver", h.redeliver)
}

// scope authorizes the request and returns where the webhook lives.
func (h *WebhooksHandler) scope(w http.ResponseWriter, r *http.Request) (webhookout.Scope, bool) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return webhookout.Scope{}, false
	}
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return webhookout.Scope{}, false
	}
	if raw := chi.URLParam(r, "projectID"); raw != "" {
		projectID, err := uuid.Parse(raw)
		if err != nil {
			respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
			return webhookout.Scope{}, false
		}
		if !h.authorize(w, r, h.orgs, orgID, projectID, authz.WebhooksManage) {
			return webhookout.Scope{}, false
		}
		return webhookout.Scope{OrgID: orgID, ProjectID: &projectID}, true
	}
	role, err := h.orgs.GetMemberRole(r.Context(), orgID, user.ID)
	if errors.Is(err, domain.ErrNotFound) {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return webhookout.Scope{}, false
	}
	if err != nil {
		h.log.Error("webhooks: checking org role failed", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check permissions")
		return webhookout.Scope{}, false
	}
	if role != "owner" && role != "admin" {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "organization admin required")
		return webhookout.Scope{}, false
	}
	return webhookout.Scope{OrgID: orgID}, true
}

func (h *WebhooksHandler) fail(w http.ResponseWriter, err error) {
	var ve *webhookout.ValidationError
	switch {
	case errors.As(err, &ve):
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", ve.Error())
	case errors.Is(err, domain.ErrNotFound):
		respondError(w, http.StatusNotFound, "NOT_FOUND", "webhook not found")
	case errors.Is(err, webhookout.ErrNotRotatable):
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
	case errors.Is(err, webhookout.ErrDisabled):
		respondError(w, http.StatusConflict, "WEBHOOK_DISABLED", "the webhook is disabled; enable it first")
	case err != nil && err.Error() == "invalid cursor":
		respondError(w, http.StatusBadRequest, "INVALID_CURSOR", "invalid cursor")
	default:
		h.log.Error("webhooks: request failed", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
	}
}

func webhookID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, name))
	if err != nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "webhook not found")
		return uuid.Nil, false
	}
	return id, true
}

func (h *WebhooksHandler) record(r *http.Request, sc webhookout.Scope, action string, id uuid.UUID, vals map[string]any) {
	if h.audit == nil {
		return
	}
	u := middleware.GetUser(r.Context())
	if u == nil {
		return
	}
	// Never put URLs or secrets in the audit trail.
	if err := h.audit.Audit(r.Context(), authz.AuditEntry{
		OrgID: sc.OrgID, UserID: u.ID, Action: action, ResourceType: "webhook", ResourceID: id,
		IP: middleware.ClientIP(r), NewValues: vals,
	}); err != nil {
		h.log.Warn("webhooks: audit failed", "action", action, "error", err)
	}
}

// ---- JSON --------------------------------------------------------------------------------------

type webhookJSON struct {
	ID                 uuid.UUID  `json:"id"`
	Kind               string     `json:"kind"`
	URL                string     `json:"url,omitempty"`
	EmailTo            []string   `json:"email_to,omitempty"`
	Events             []string   `json:"events"`
	Active             bool       `json:"active"`
	BranchFilter       string     `json:"branch_filter,omitempty"`
	ProjectID          *uuid.UUID `json:"project_id,omitempty"`
	Secret             string     `json:"secret,omitempty"` // only at create and rotate
	HasSecret          bool       `json:"has_secret"`
	PreviousSecretTill *time.Time `json:"previous_secret_expires_at,omitempty"`
	DisabledReason     string     `json:"disabled_reason,omitempty"`
	LastDeliveryStatus int        `json:"last_delivery_status"`
	LastDeliveryAt     *time.Time `json:"last_delivery_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
}

// maskURL hides the secret part of a Slack or Discord incoming webhook URL.
func maskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	seg := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 3)
	if len(seg) >= 2 {
		return u.Scheme + "://" + u.Host + "/" + seg[0] + "/" + seg[1] + "/..."
	}
	return u.Scheme + "://" + u.Host + "/..."
}

func toWebhookJSON(w *webhookout.Webhook, showSecret bool) webhookJSON {
	j := webhookJSON{
		ID: w.ID, Kind: w.Kind, EmailTo: w.EmailTo, Events: w.Events, Active: w.Active,
		BranchFilter: w.BranchFilter, ProjectID: w.ProjectID, HasSecret: w.Secret != "",
		DisabledReason: w.DisabledReason, LastDeliveryStatus: w.LastDeliveryStatus,
		LastDeliveryAt: w.LastDeliveryAt, CreatedAt: w.CreatedAt,
	}
	if j.Events == nil {
		j.Events = []string{}
	}
	switch w.Kind {
	case webhookout.KindHTTP:
		j.URL = w.URL
	case webhookout.KindSlack, webhookout.KindDiscord:
		j.URL = maskURL(w.URL)
	}
	if showSecret {
		j.Secret = w.Secret
	}
	if w.PrevSecret != "" && w.PrevSecretExpiresAt != nil && w.PrevSecretExpiresAt.After(time.Now()) {
		j.PreviousSecretTill = w.PrevSecretExpiresAt
	}
	return j
}

type deliveryJSON struct {
	ID              uuid.UUID         `json:"id"`
	Event           string            `json:"event"`
	Status          string            `json:"status"`
	StatusCode      int               `json:"status_code"`
	DurationMS      int               `json:"duration_ms"`
	Attempt         int               `json:"attempt"`
	Error           string            `json:"error,omitempty"`
	DeliveredAt     *time.Time        `json:"delivered_at,omitempty"`
	NextAttemptAt   *time.Time        `json:"next_attempt_at,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	RedeliveryOf    *uuid.UUID        `json:"redelivery_of,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseExcerpt string            `json:"response_excerpt,omitempty"`
}

func toDeliveryJSON(d *webhookout.Delivery) deliveryJSON {
	j := deliveryJSON{
		ID: d.ID, Event: d.Event, Status: d.Status, StatusCode: d.StatusCode, DurationMS: d.DurationMS,
		Attempt: d.Attempt, Error: d.Error, DeliveredAt: d.DeliveredAt, CreatedAt: d.CreatedAt,
		RedeliveryOf: d.RedeliveryOf, RequestHeaders: d.RequestHeaders, ResponseExcerpt: d.ResponseExcerpt,
	}
	if j.RequestHeaders == nil {
		j.RequestHeaders = map[string]string{}
	}
	if d.Status == webhookout.StatusPending {
		t := d.NextAttemptAt
		j.NextAttemptAt = &t
	}
	return j
}

const maxWebhookJSON = 64 << 10

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWebhookJSON))
	if err := dec.Decode(v); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid JSON body")
		return false
	}
	return true
}

// ---- handlers ----------------------------------------------------------------------------------

func (h *WebhooksHandler) list(w http.ResponseWriter, r *http.Request) {
	sc, ok := h.scope(w, r)
	if !ok {
		return
	}
	whs, err := h.svc.List(r.Context(), sc)
	if err != nil {
		h.fail(w, err)
		return
	}
	items := make([]webhookJSON, 0, len(whs))
	for i := range whs {
		items = append(items, toWebhookJSON(&whs[i], false))
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items})
}

type webhookInputJSON struct {
	Kind         string   `json:"kind"`
	URL          string   `json:"url"`
	EmailTo      []string `json:"email_to"`
	Events       []string `json:"events"`
	Active       *bool    `json:"active"`
	BranchFilter string   `json:"branch_filter"`
}

func (h *WebhooksHandler) create(w http.ResponseWriter, r *http.Request) {
	sc, ok := h.scope(w, r)
	if !ok {
		return
	}
	var in webhookInputJSON
	if !decodeBody(w, r, &in) {
		return
	}
	var by uuid.UUID
	if u := middleware.GetUser(r.Context()); u != nil {
		by = u.ID
	}
	wh, err := h.svc.Create(r.Context(), sc, webhookout.CreateInput{
		Kind: in.Kind, URL: in.URL, EmailTo: in.EmailTo, Events: in.Events, Active: in.Active, BranchFilter: in.BranchFilter,
	}, by)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.record(r, sc, "webhook.create", wh.ID, map[string]any{"kind": wh.Kind, "events": wh.Events, "active": wh.Active})
	respondJSON(w, http.StatusCreated, toWebhookJSON(wh, true))
}

func (h *WebhooksHandler) update(w http.ResponseWriter, r *http.Request) {
	sc, ok := h.scope(w, r)
	if !ok {
		return
	}
	id, ok := webhookID(w, r, "webhookID")
	if !ok {
		return
	}
	var in struct {
		Kind         *string   `json:"kind"`
		URL          *string   `json:"url"`
		EmailTo      *[]string `json:"email_to"`
		Events       *[]string `json:"events"`
		Active       *bool     `json:"active"`
		BranchFilter *string   `json:"branch_filter"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	wh, err := h.svc.Update(r.Context(), sc, id, webhookout.PatchInput{
		Kind: in.Kind, URL: in.URL, EmailTo: in.EmailTo, Events: in.Events, Active: in.Active, BranchFilter: in.BranchFilter,
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	h.record(r, sc, "webhook.update", wh.ID, map[string]any{"kind": wh.Kind, "events": wh.Events, "active": wh.Active})
	respondJSON(w, http.StatusOK, toWebhookJSON(wh, false))
}

func (h *WebhooksHandler) remove(w http.ResponseWriter, r *http.Request) {
	sc, ok := h.scope(w, r)
	if !ok {
		return
	}
	id, ok := webhookID(w, r, "webhookID")
	if !ok {
		return
	}
	if err := h.svc.Delete(r.Context(), sc, id); err != nil {
		h.fail(w, err)
		return
	}
	h.record(r, sc, "webhook.delete", id, nil)
	respondNoContent(w)
}

func (h *WebhooksHandler) test(w http.ResponseWriter, r *http.Request) {
	sc, ok := h.scope(w, r)
	if !ok {
		return
	}
	id, ok := webhookID(w, r, "webhookID")
	if !ok {
		return
	}
	d, err := h.svc.SendTest(r.Context(), sc, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.record(r, sc, "webhook.test", id, map[string]any{"status": d.Status})
	respondJSON(w, http.StatusOK, toDeliveryJSON(d))
}

func (h *WebhooksHandler) rotate(w http.ResponseWriter, r *http.Request) {
	sc, ok := h.scope(w, r)
	if !ok {
		return
	}
	id, ok := webhookID(w, r, "webhookID")
	if !ok {
		return
	}
	wh, err := h.svc.RotateSecret(r.Context(), sc, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.record(r, sc, "webhook.rotate", id, nil)
	respondJSON(w, http.StatusOK, toWebhookJSON(wh, true))
}

func (h *WebhooksHandler) deliveries(w http.ResponseWriter, r *http.Request) {
	sc, ok := h.scope(w, r)
	if !ok {
		return
	}
	id, ok := webhookID(w, r, "webhookID")
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, next, err := h.svc.Deliveries(r.Context(), sc, id, r.URL.Query().Get("cursor"), limit)
	if err != nil {
		h.fail(w, err)
		return
	}
	items := make([]deliveryJSON, 0, len(rows))
	for i := range rows {
		items = append(items, toDeliveryJSON(&rows[i]))
	}
	var nc *string
	if next != "" {
		nc = &next
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nc})
}

func (h *WebhooksHandler) redeliver(w http.ResponseWriter, r *http.Request) {
	sc, ok := h.scope(w, r)
	if !ok {
		return
	}
	id, ok := webhookID(w, r, "webhookID")
	if !ok {
		return
	}
	did, ok := webhookID(w, r, "deliveryID")
	if !ok {
		return
	}
	d, err := h.svc.Redeliver(r.Context(), sc, id, did)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.record(r, sc, "webhook.redeliver", id, map[string]any{"delivery_id": d.ID.String()})
	respondJSON(w, http.StatusAccepted, toDeliveryJSON(d))
}
