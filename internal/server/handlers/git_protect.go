package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitprotect"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// GitProtectHandler serves Git Capsule package A4: branch protection rules (list, create, put,
// delete, evaluate).
type GitProtectHandler struct {
	authzHolder
	svc      *gitprotect.Service
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
}

const gitProtectBase = "/orgs/{orgID}/projects/{projectID}/git"

// MountGitProtect registers the A4 routes on the authenticated /api/v1 router. It uses the
// Service published by gitprotect.WireGitProtect; without it every route answers 501.
// repoUpdate, tagCreate and tagDelete are B1's routes: they call the A4 hooks
// gitprotect.Service.CheckMergeStyles and GuardTag instead of being mounted here.
func MountGitProtect(r chi.Router, az *authz.Service, orgs domain.OrganizationRepository, projects domain.ProjectRepository) {
	h := &GitProtectHandler{svc: gitprotect.Shared(), orgs: orgs, projects: projects}
	h.SetAuthz(az)
	r.Get(gitProtectBase+"/protections", h.List)
	r.Post(gitProtectBase+"/protections", h.Create)
	r.Get(gitProtectBase+"/protections/evaluate", h.Evaluate)
	r.Put(gitProtectBase+"/protections/{ruleID}", h.Put)
	r.Delete(gitProtectBase+"/protections/{ruleID}", h.Delete)
}

// NewGitProtectHandler builds the handler directly (tests).
func NewGitProtectHandler(svc *gitprotect.Service, az *authz.Service, orgs domain.OrganizationRepository, projects domain.ProjectRepository) *GitProtectHandler {
	h := &GitProtectHandler{svc: svc, orgs: orgs, projects: projects}
	h.SetAuthz(az)
	return h
}

type gpErrorBody struct {
	Code    string                  `json:"code"`
	Message string                  `json:"message"`
	Fields  []gitprotect.FieldError `json:"fields,omitempty"`
}

func gpError(w http.ResponseWriter, status int, code, msg string, fields []gitprotect.FieldError) {
	respondJSON(w, status, struct {
		Error gpErrorBody `json:"error"`
	}{gpErrorBody{Code: code, Message: msg, Fields: fields}})
}

// target authorizes act and resolves the project and organization slugs (errors are written).
func (h *GitProtectHandler) target(w http.ResponseWriter, r *http.Request, act authz.Action) (gitprotect.Target, bool) {
	var t gitprotect.Target
	if h.svc == nil {
		respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "branch protection is not configured")
		return t, false
	}
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return t, false
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return t, false
	}
	if !h.authorize(w, r, h.orgs, orgID, projectID, act) {
		return t, false
	}
	p, err := h.projects.GetByID(r.Context(), projectID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && p.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return t, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load project")
		return t, false
	}
	org, err := h.orgs.GetByID(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load organization")
		return t, false
	}
	return gitprotect.Target{ProjectID: projectID, OrgID: orgID, OrgSlug: org.Slug, ProjectSlug: p.Slug}, true
}

func (h *GitProtectHandler) actor(r *http.Request) gitprotect.Actor {
	a := gitprotect.Actor{IP: middleware.ClientIP(r)}
	if u := middleware.GetUser(r.Context()); u != nil {
		a.UserID = u.ID
	}
	return a
}

// fail maps service errors to the HTTP contract.
func (h *GitProtectHandler) fail(w http.ResponseWriter, err error) {
	var (
		ve *gitprotect.ValidationError
		pe *gitprotect.PolicyError
		ce *gitprotect.ConflictError
		fe *gitprotect.ForbiddenError
		ge *gitcore.Error
	)
	switch {
	case errors.As(err, &ve):
		msg := ve.Error()
		gpError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", msg, ve.Fields)
	case errors.As(err, &pe):
		gpError(w, http.StatusUnprocessableEntity, pe.Code, pe.Message, nil)
	case errors.As(err, &ce):
		gpError(w, http.StatusConflict, ce.Code, ce.Message, nil)
	case errors.As(err, &fe):
		gpError(w, http.StatusForbidden, fe.Code, fe.Message, nil)
	case errors.Is(err, gitprotect.ErrNotFound):
		gpError(w, http.StatusNotFound, "NOT_FOUND", "protection rule not found", nil)
	case errors.As(err, &ge):
		gpError(w, ge.HTTPStatus(), string(ge.Code), ge.Message, nil)
	default:
		slog.Error("git protect: unexpected error", "err", err)
		gpError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "unexpected error", nil)
	}
}

// gpBody is Input plus the response-only fields a client may echo back on PUT.
type gpBody struct {
	gitprotect.Input
	ID            json.RawMessage `json:"id"`
	CreatedAt     json.RawMessage `json:"created_at"`
	UpdatedAt     json.RawMessage `json:"updated_at"`
	ForgejoSynced json.RawMessage `json:"forgejo_synced"`
	SyncError     json.RawMessage `json:"sync_error"`
	SyncStatus    json.RawMessage `json:"sync_status"`
	LastSyncedAt  json.RawMessage `json:"last_synced_at"`
	DriftCount    json.RawMessage `json:"drift_count"`
	Warnings      json.RawMessage `json:"warnings"`
}

// gpDecodeStrict reads a small JSON body rejecting unknown fields (a typo must not silently fall
// back to a default).
func gpDecodeStrict(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		gpError(w, http.StatusBadRequest, "INVALID_BODY", "invalid JSON body: "+gpJSONErr(err), nil)
		return false
	}
	return true
}

func gpJSONErr(err error) string {
	s := err.Error()
	if strings.HasPrefix(s, "json: unknown field") {
		return strings.TrimPrefix(s, "json: ")
	}
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se):
		return "syntax error"
	case errors.As(err, &te):
		return "field " + te.Field + " has the wrong type"
	}
	return "unreadable body"
}

// GET .../git/protections
func (h *GitProtectHandler) List(w http.ResponseWriter, r *http.Request) {
	t, ok := h.target(w, r, authz.GitRead)
	if !ok {
		return
	}
	items, err := h.svc.List(r.Context(), t)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

// POST .../git/protections
func (h *GitProtectHandler) Create(w http.ResponseWriter, r *http.Request) {
	t, ok := h.target(w, r, authz.GitAdmin)
	if !ok {
		return
	}
	var body gpBody
	if !gpDecodeStrict(w, r, &body) {
		return
	}
	p, err := h.svc.Create(r.Context(), t, h.actor(r), body.Input)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusCreated, p)
}

func gpRuleID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid rule id")
		return uuid.Nil, false
	}
	return id, true
}

// PUT .../git/protections/{ruleID}
func (h *GitProtectHandler) Put(w http.ResponseWriter, r *http.Request) {
	t, ok := h.target(w, r, authz.GitAdmin)
	if !ok {
		return
	}
	id, ok := gpRuleID(w, r)
	if !ok {
		return
	}
	var body gpBody
	if !gpDecodeStrict(w, r, &body) {
		return
	}
	p, err := h.svc.Replace(r.Context(), t, h.actor(r), id, body.Input)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, p)
}

// DELETE .../git/protections/{ruleID}
func (h *GitProtectHandler) Delete(w http.ResponseWriter, r *http.Request) {
	t, ok := h.target(w, r, authz.GitAdmin)
	if !ok {
		return
	}
	id, ok := gpRuleID(w, r)
	if !ok {
		return
	}
	warns, err := h.svc.Delete(r.Context(), t, h.actor(r), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	if len(warns) > 0 {
		w.Header().Set("X-Capsule-Warnings", strings.Join(warns, " | "))
	}
	respondNoContent(w)
}

// GET .../git/protections/evaluate?branch=
func (h *GitProtectHandler) Evaluate(w http.ResponseWriter, r *http.Request) {
	t, ok := h.target(w, r, authz.GitRead)
	if !ok {
		return
	}
	ev, err := h.svc.Evaluate(r.Context(), t, r.URL.Query().Get("branch"))
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, ev)
}
