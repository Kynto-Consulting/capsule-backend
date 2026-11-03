package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type EnvVarHandler struct {
	authzHolder
	envvars domain.EnvVarRepository
	orgs    domain.OrganizationRepository
	projects domain.ProjectRepository
}

func NewEnvVarHandler(envvars domain.EnvVarRepository, orgs domain.OrganizationRepository, projects domain.ProjectRepository) *EnvVarHandler {
	return &EnvVarHandler{envvars: envvars, orgs: orgs, projects: projects}
}

type envVarResponse struct {
	ID        uuid.UUID `json:"id"`
	ProjectID uuid.UUID `json:"project_id"`
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	IsSecret  bool      `json:"is_secret"`
	Scope     string    `json:"scope"`
	Masked    bool      `json:"masked,omitempty"`
}

// envMask replaces secret values for roles that cannot reveal them.
const envMask = "********"

func toEnvVarResponse(e *domain.EnvVar) envVarResponse {
	return envVarResponse{
		ID:        e.ID,
		ProjectID: e.ProjectID,
		Key:       e.Key,
		Value:     string(e.ValueEnc),
		IsSecret:  e.IsSecret,
		Scope:     e.Scope,
	}
}

func (h *EnvVarHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID, projectID, ok := h.parseIDs(w, r)
	if !ok {
		return
	}
	if !h.checkMember(w, r, orgID, projectID, authz.ProjectRead) {
		return
	}
	if !h.checkProject(w, r, projectID, orgID) {
		return
	}

	vars, err := h.envvars.ListByProject(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list env vars")
		return
	}

	// Secret values are only revealed to roles with ProjectEnvReveal.
	reveal := false
	if user := middleware.GetUser(r.Context()); user != nil {
		reveal, _ = h.service(h.orgs).Can(r.Context(), user.ID, orgID, projectID, authz.ProjectEnvReveal)
	}
	resp := make([]envVarResponse, len(vars))
	for i, v := range vars {
		resp[i] = toEnvVarResponse(v)
		if v.IsSecret && !reveal {
			resp[i].Value = envMask
			resp[i].Masked = true
		}
	}
	respondJSON(w, http.StatusOK, resp)
}

func (h *EnvVarHandler) Set(w http.ResponseWriter, r *http.Request) {
	orgID, projectID, ok := h.parseIDs(w, r)
	if !ok {
		return
	}
	if !h.checkMember(w, r, orgID, projectID, authz.ProjectEnvWrite) {
		return
	}
	if !h.checkProject(w, r, projectID, orgID) {
		return
	}

	var req struct {
		Key      string `json:"key"`
		Value    string `json:"value"`
		IsSecret bool   `json:"is_secret"`
		Scope    string `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	req.Key = strings.TrimSpace(strings.ToUpper(req.Key))
	if req.Key == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "key is required")
		return
	}
	if req.Scope == "" {
		req.Scope = "runtime"
	}

	ev, err := h.envvars.Upsert(r.Context(), &domain.EnvVar{
		ProjectID: projectID,
		Key:       req.Key,
		ValueEnc:  []byte(req.Value),
		IsSecret:  req.IsSecret,
		Scope:     req.Scope,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to set env var")
		return
	}

	respondJSON(w, http.StatusOK, toEnvVarResponse(ev))
}

func (h *EnvVarHandler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID, projectID, ok := h.parseIDs(w, r)
	if !ok {
		return
	}
	if !h.checkMember(w, r, orgID, projectID, authz.ProjectEnvWrite) {
		return
	}
	key := strings.ToUpper(chi.URLParam(r, "key"))

	if err := h.envvars.Delete(r.Context(), projectID, key); err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "env var not found")
		return
	}
	respondNoContent(w)
}

func (h *EnvVarHandler) parseIDs(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return uuid.Nil, uuid.Nil, false
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return uuid.Nil, uuid.Nil, false
	}
	return orgID, projectID, true
}

func (h *EnvVarHandler) checkMember(w http.ResponseWriter, r *http.Request, orgID, projectID uuid.UUID, act authz.Action) bool {
	return h.authorize(w, r, h.orgs, orgID, projectID, act)
}

func (h *EnvVarHandler) checkProject(w http.ResponseWriter, r *http.Request, projectID, orgID uuid.UUID) bool {
	p, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && p.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return false
	}
	return true
}
