package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/environments"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// EnvironmentsHandler serves Git Capsule package A6: environments, promotions and approvals.
type EnvironmentsHandler struct {
	authzHolder
	svc      *environments.Service
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
}

const envBase = "/orgs/{orgID}/projects/{projectID}"

// MountEnvironments registers the A6 routes on the authenticated /api/v1 router. It uses the
// Service published by environments.WireEnvironments; without it every route answers 501.
func MountEnvironments(r chi.Router, az *authz.Service, orgs domain.OrganizationRepository, projects domain.ProjectRepository) {
	h := NewEnvironmentsHandler(environments.Shared(), az, orgs, projects)
	r.Get(envBase+"/environments", h.EnvList)
	r.Post(envBase+"/environments", h.EnvCreate)
	r.Get(envBase+"/environments/{env}", h.EnvGet)
	r.Put(envBase+"/environments/{env}", h.EnvPut)
	r.Delete(envBase+"/environments/{env}", h.EnvDelete)
	r.Get(envBase+"/environments/{env}/deployments", h.EnvDeployments)
	r.Post(envBase+"/promotions", h.PromotionCreate)
	r.Get(envBase+"/promotions/{promotionID}", h.PromotionGet)
	r.Post(envBase+"/promotions/{promotionID}/approve", h.PromotionApprove)
	r.Post(envBase+"/promotions/{promotionID}/reject", h.PromotionReject)
	r.Post(envBase+"/promotions/{promotionID}/cancel", h.PromotionCancel)
	r.Get("/orgs/{orgID}/approvals", h.ApprovalsPending)
}

// NewEnvironmentsHandler builds the handler directly (tests).
func NewEnvironmentsHandler(svc *environments.Service, az *authz.Service, orgs domain.OrganizationRepository, projects domain.ProjectRepository) *EnvironmentsHandler {
	h := &EnvironmentsHandler{svc: svc, orgs: orgs, projects: projects}
	h.SetAuthz(az)
	return h
}

type envErrorBody struct {
	Code    string                    `json:"code"`
	Message string                    `json:"message"`
	Fields  []environments.FieldError `json:"fields,omitempty"`
}

func envError(w http.ResponseWriter, status int, code, msg string, fields []environments.FieldError) {
	respondJSON(w, status, struct {
		Error envErrorBody `json:"error"`
	}{envErrorBody{Code: code, Message: msg, Fields: fields}})
}

// target authorizes act and resolves the project and organization slugs (errors are written).
func (h *EnvironmentsHandler) target(w http.ResponseWriter, r *http.Request, act authz.Action) (environments.Target, environments.Actor, bool) {
	var t environments.Target
	var a environments.Actor
	if h.svc == nil {
		respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "environments are not configured")
		return t, a, false
	}
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return t, a, false
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return t, a, false
	}
	if !h.authorize(w, r, h.orgs, orgID, projectID, act) {
		return t, a, false
	}
	p, err := h.projects.GetByID(r.Context(), projectID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && p.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return t, a, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load project")
		return t, a, false
	}
	org, err := h.orgs.GetByID(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load organization")
		return t, a, false
	}
	u := middleware.GetUser(r.Context())
	acc, err := h.service(h.orgs).Access(r.Context(), u.ID, orgID, projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check permissions")
		return t, a, false
	}
	a = environments.Actor{UserID: u.ID, Role: acc.Role, IP: middleware.ClientIP(r)}
	return environments.Target{ProjectID: projectID, OrgID: orgID, OrgSlug: org.Slug, ProjectSlug: p.Slug}, a, true
}

// fail maps service errors to the HTTP contract.
func (h *EnvironmentsHandler) fail(w http.ResponseWriter, err error) {
	var (
		ve *environments.ValidationError
		pe *environments.PolicyError
		ce *environments.ConflictError
		fe *environments.ForbiddenError
		ge *gitcore.Error
	)
	switch {
	case errors.As(err, &ve):
		envError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", ve.Error(), ve.Fields)
	case errors.As(err, &pe):
		envError(w, http.StatusUnprocessableEntity, pe.Code, pe.Message, nil)
	case errors.As(err, &ce):
		envError(w, http.StatusConflict, ce.Code, ce.Message, nil)
	case errors.As(err, &fe):
		envError(w, http.StatusForbidden, fe.Code, fe.Message, nil)
	case errors.Is(err, environments.ErrNotFound):
		envError(w, http.StatusNotFound, "NOT_FOUND", "not found", nil)
	case errors.Is(err, environments.ErrDuplicate):
		envError(w, http.StatusConflict, "ENV_EXISTS", "an environment with that name already exists", nil)
	case errors.Is(err, environments.ErrInvalidState):
		envError(w, http.StatusConflict, "INVALID_STATE", "the promotion is not in a state that allows this", nil)
	case errors.As(err, &ge):
		envError(w, ge.HTTPStatus(), string(ge.Code), ge.Message, nil)
	default:
		slog.Error("environments: unexpected error", "err", err)
		envError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "unexpected error", nil)
	}
}

// envDecode reads a small JSON body rejecting unknown fields.
func envDecode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		msg := "unreadable body"
		var se *json.SyntaxError
		var te *json.UnmarshalTypeError
		switch {
		case strings.HasPrefix(err.Error(), "json: unknown field"):
			msg = strings.TrimPrefix(err.Error(), "json: ")
		case errors.As(err, &se):
			msg = "syntax error"
		case errors.As(err, &te):
			msg = "field " + te.Field + " has the wrong type"
		}
		envError(w, http.StatusBadRequest, "INVALID_BODY", "invalid JSON body: "+msg, nil)
		return false
	}
	return true
}

// envBody is Input plus the response-only fields a client may echo back on PUT.
type envBody struct {
	environments.Input
	ID        json.RawMessage `json:"id"`
	Current   json.RawMessage `json:"current"`
	CreatedAt json.RawMessage `json:"created_at"`
}

// GET .../environments
func (h *EnvironmentsHandler) EnvList(w http.ResponseWriter, r *http.Request) {
	t, _, ok := h.target(w, r, authz.EnvRead)
	if !ok {
		return
	}
	items, err := h.svc.ListEnvs(r.Context(), t)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items})
}

// POST .../environments
func (h *EnvironmentsHandler) EnvCreate(w http.ResponseWriter, r *http.Request) {
	t, a, ok := h.target(w, r, authz.EnvAdmin)
	if !ok {
		return
	}
	var b envBody
	if !envDecode(w, r, &b) {
		return
	}
	v, err := h.svc.CreateEnv(r.Context(), t, a, b.Input)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusCreated, v)
}

// GET .../environments/{env}
func (h *EnvironmentsHandler) EnvGet(w http.ResponseWriter, r *http.Request) {
	t, _, ok := h.target(w, r, authz.EnvRead)
	if !ok {
		return
	}
	v, err := h.svc.GetEnv(r.Context(), t, chi.URLParam(r, "env"))
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, v)
}

// PUT .../environments/{env}
func (h *EnvironmentsHandler) EnvPut(w http.ResponseWriter, r *http.Request) {
	t, a, ok := h.target(w, r, authz.EnvAdmin)
	if !ok {
		return
	}
	var b envBody
	if !envDecode(w, r, &b) {
		return
	}
	v, err := h.svc.PutEnv(r.Context(), t, a, chi.URLParam(r, "env"), b.Input)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, v)
}

// DELETE .../environments/{env}
func (h *EnvironmentsHandler) EnvDelete(w http.ResponseWriter, r *http.Request) {
	t, a, ok := h.target(w, r, authz.EnvAdmin)
	if !ok {
		return
	}
	if err := h.svc.DeleteEnv(r.Context(), t, a, chi.URLParam(r, "env")); err != nil {
		h.fail(w, err)
		return
	}
	respondNoContent(w)
}

// GET .../environments/{env}/deployments
func (h *EnvironmentsHandler) EnvDeployments(w http.ResponseWriter, r *http.Request) {
	t, _, ok := h.target(w, r, authz.EnvRead)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, next, err := h.svc.EnvDeployments(r.Context(), t, chi.URLParam(r, "env"), r.URL.Query().Get("cursor"), limit)
	if err != nil {
		if strings.Contains(err.Error(), "invalid cursor") {
			envError(w, http.StatusBadRequest, "INVALID_CURSOR", "invalid cursor", nil)
			return
		}
		h.fail(w, err)
		return
	}
	var nc any
	if next != "" {
		nc = next
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nc})
}
