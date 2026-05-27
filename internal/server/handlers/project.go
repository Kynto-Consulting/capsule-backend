package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type ProjectHandler struct {
	projects domain.ProjectRepository
	orgs     domain.OrganizationRepository
}

func NewProjectHandler(projects domain.ProjectRepository, orgs domain.OrganizationRepository) *ProjectHandler {
	return &ProjectHandler{projects: projects, orgs: orgs}
}

type createProjectRequest struct {
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	RepoURL       string `json:"repo_url"`
	Branch        string `json:"branch"`
	BuildStrategy string `json:"build_strategy"`
	Runtime       string `json:"runtime"`
	Serverless    bool   `json:"serverless"`
	Replicas      int    `json:"replicas"`
}

func (h *ProjectHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}

	ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID)
	if !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member of this organization")
		return
	}

	var req createProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	if req.Name == "" || req.Slug == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "name and slug required")
		return
	}
	if req.Branch == "" {
		req.Branch = "main"
	}
	if req.BuildStrategy == "" {
		req.BuildStrategy = "auto"
	}
	if req.Replicas == 0 {
		req.Replicas = 1
	}

	project, err := h.projects.Create(r.Context(), &domain.Project{
		OrgID:         orgID,
		Name:          req.Name,
		Slug:          req.Slug,
		RepoURL:       req.RepoURL,
		Branch:        req.Branch,
		BuildStrategy: req.BuildStrategy,
		Runtime:       req.Runtime,
		Serverless:    req.Serverless,
		Replicas:      req.Replicas,
	})
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			respondError(w, http.StatusConflict, "SLUG_TAKEN", "project slug already exists in this org")
			return
		}
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create project")
		return
	}

	respondJSON(w, http.StatusCreated, project)
}

func (h *ProjectHandler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}

	ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID)
	if !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	projects, total, err := h.projects.ListByOrg(r.Context(), orgID, 1, 100)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list projects")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"data": projects,
		"meta": domain.ListMeta{Page: 1, PerPage: 100, Total: total},
	})
}

func (h *ProjectHandler) Get(w http.ResponseWriter, r *http.Request) {
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

	ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID)
	if !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, project)
}

func (h *ProjectHandler) Update(w http.ResponseWriter, r *http.Request) {
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

	ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID)
	if !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	var req struct {
		Name          *string `json:"name"`
		RepoURL       *string `json:"repo_url"`
		Branch        *string `json:"branch"`
		BuildStrategy *string `json:"build_strategy"`
		DeployType    *string `json:"deploy_type"`
		Runtime       *string `json:"runtime"`
		Serverless    *bool   `json:"serverless"`
		Replicas      *int    `json:"replicas"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Name != nil {
		project.Name = strings.TrimSpace(*req.Name)
	}
	if req.RepoURL != nil {
		project.RepoURL = *req.RepoURL
	}
	if req.Branch != nil {
		project.Branch = *req.Branch
	}
	if req.BuildStrategy != nil {
		project.BuildStrategy = *req.BuildStrategy
	}
	if req.DeployType != nil {
		project.DeployType = *req.DeployType
	}
	if req.Runtime != nil {
		project.Runtime = *req.Runtime
	}
	if req.Serverless != nil {
		project.Serverless = *req.Serverless
	}
	if req.Replicas != nil {
		project.Replicas = *req.Replicas
	}

	updated, err := h.projects.Update(r.Context(), project)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update project")
		return
	}
	respondJSON(w, http.StatusOK, updated)
}

func (h *ProjectHandler) Delete(w http.ResponseWriter, r *http.Request) {
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

	ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID)
	if !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	if err := h.projects.Delete(r.Context(), projectID); err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	respondNoContent(w)
}
