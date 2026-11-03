package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/connaudit"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// connAttach is embedded by DeploymentHandler: it fills connection_warnings
// (with suppressions applied at read time) on the deployments it serves.
type connAttach struct{ connStore connaudit.Store }

// SetConnAudit wires the connection audit store (nil: the field is omitted).
func (c *connAttach) SetConnAudit(s connaudit.Store) { c.connStore = s }

func (c *connAttach) attachConn(ctx context.Context, projectID uuid.UUID, ds ...*domain.Deployment) {
	if c.connStore == nil || len(ds) == 0 {
		return
	}
	ids := make([]uuid.UUID, 0, len(ds))
	for _, d := range ds {
		ids = append(ids, d.ID)
	}
	got, err := c.connStore.FindingsFor(ctx, ids)
	if err != nil {
		return // the deployment itself must still be served
	}
	sups, _ := c.connStore.Suppressions(ctx, projectID)
	now := time.Now()
	for _, d := range ds {
		if f := got[d.ID]; len(f) > 0 {
			d.ConnectionWarnings = connaudit.Apply(f, sups, now)
		}
	}
}

// ConnAuditHandler manages the per-project connection audit policy and suppressions.
type ConnAuditHandler struct {
	authzHolder
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
	store    connaudit.Store
}

func NewConnAuditHandler(orgs domain.OrganizationRepository, projects domain.ProjectRepository, store connaudit.Store) *ConnAuditHandler {
	return &ConnAuditHandler{orgs: orgs, projects: projects, store: store}
}

func (h *ConnAuditHandler) load(w http.ResponseWriter, r *http.Request, act authz.Action) (uuid.UUID, bool) {
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return uuid.Nil, false
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return uuid.Nil, false
	}
	if h.store == nil {
		respondError(w, http.StatusNotImplemented, "NOT_CONFIGURED", "connection audit is not configured on this server")
		return uuid.Nil, false
	}
	if !h.authorize(w, r, h.orgs, orgID, projectID, act) {
		return uuid.Nil, false
	}
	p, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && p.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return uuid.Nil, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load project")
		return uuid.Nil, false
	}
	return projectID, true
}

// Get: GET .../connection-audit -> {mode, suppressions}.
func (h *ConnAuditHandler) Get(w http.ResponseWriter, r *http.Request) {
	pid, ok := h.load(w, r, authz.ProjectRead)
	if !ok {
		return
	}
	mode, err := h.store.Mode(r.Context(), pid)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to read policy")
		return
	}
	sups, err := h.store.Suppressions(r.Context(), pid)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to read suppressions")
		return
	}
	if sups == nil {
		sups = []connaudit.Suppression{}
	}
	respondJSON(w, http.StatusOK, map[string]any{"connection_audit_mode": mode, "suppressions": sups})
}

// SetMode: PUT .../connection-audit/mode {"connection_audit_mode":"warn|strict|off"}.
func (h *ConnAuditHandler) SetMode(w http.ResponseWriter, r *http.Request) {
	pid, ok := h.load(w, r, authz.ProjectOps)
	if !ok {
		return
	}
	var req struct {
		Mode string `json:"connection_audit_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	m, valid := connaudit.ParseMode(req.Mode)
	if !valid || strings.TrimSpace(req.Mode) == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "connection_audit_mode must be warn, strict or off")
		return
	}
	if err := h.store.SetMode(r.Context(), pid, m); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save policy")
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"connection_audit_mode": m})
}

// PutSuppression: PUT .../connection-audit/suppressions {"finding_id","reason","expires_at"?}.
func (h *ConnAuditHandler) PutSuppression(w http.ResponseWriter, r *http.Request) {
	pid, ok := h.load(w, r, authz.ProjectOps)
	if !ok {
		return
	}
	var s connaudit.Suppression
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	s.FindingID = strings.ToLower(strings.TrimSpace(s.FindingID))
	s.Reason = strings.TrimSpace(s.Reason)
	if msg := s.Validate(time.Now()); msg != "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", msg)
		return
	}
	if u := middleware.GetUser(r.Context()); u != nil {
		s.CreatedBy = u.Email
	}
	if err := h.store.PutSuppression(r.Context(), pid, s); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save suppression")
		return
	}
	s.CreatedAt = time.Now().UTC()
	respondJSON(w, http.StatusOK, s)
}

// DeleteSuppression: DELETE .../connection-audit/suppressions?finding_id=ID.
func (h *ConnAuditHandler) DeleteSuppression(w http.ResponseWriter, r *http.Request) {
	pid, ok := h.load(w, r, authz.ProjectOps)
	if !ok {
		return
	}
	id := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("finding_id")))
	if id == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "finding_id query parameter is required")
		return
	}
	if err := h.store.DeleteSuppression(r.Context(), pid, id); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete suppression")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
