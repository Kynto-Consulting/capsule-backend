package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type ProjectHandler struct {
	authzHolder
	projects domain.ProjectRepository
	orgs     domain.OrganizationRepository
	onDelete func(uuid.UUID) // optional cleanup hook run after a project is deleted (ports firewall rules)
	health   domain.ProjectHealthStore // optional: deploy health-check settings
}

func NewProjectHandler(projects domain.ProjectRepository, orgs domain.OrganizationRepository) *ProjectHandler {
	return &ProjectHandler{projects: projects, orgs: orgs}
}

type createProjectRequest struct {
	Name          string `json:"name"           validate:"required,min=1,max=100"`
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
	if !middleware.DecodeAndValidate(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	if req.Slug == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "slug required")
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

	notifyProjectCreated(project) // core Git: provision the repository in the background
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

	page, limit := parsePagination(r)
	var projects []*domain.Project
	var total int
	if lp, ok := h.projects.(interface {
		ListByOrgIncludingPreviews(context.Context, uuid.UUID, int, int) ([]*domain.Project, int, error)
	}); ok && r.URL.Query().Get("include_previews") == "true" {
		projects, total, err = lp.ListByOrgIncludingPreviews(r.Context(), orgID, page, limit)
	} else {
		projects, total, err = h.projects.ListByOrg(r.Context(), orgID, page, limit)
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list projects")
		return
	}
	filtered, err := h.service(h.orgs).FilterProjects(r.Context(), user.ID, orgID, projects)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check permissions")
		return
	}
	total -= len(projects) - len(filtered)
	projects = filtered

	respondJSON(w, http.StatusOK, map[string]any{
		"data": projects,
		"meta": domain.ListMeta{Page: page, PerPage: limit, Total: total},
	})
}

func (h *ProjectHandler) Get(w http.ResponseWriter, r *http.Request) {
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

	if !h.authorize(w, r, h.orgs, orgID, projectID, authz.ProjectRead) {
		return
	}

	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && project.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	h.attachHealth(r.Context(), project)
	respondJSON(w, http.StatusOK, project)
}

func (h *ProjectHandler) Update(w http.ResponseWriter, r *http.Request) {
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

	if !h.authorize(w, r, h.orgs, orgID, projectID, authz.ProjectOps) {
		return
	}

	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && project.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	var req struct {
		Name          *string `json:"name"`
		Slug          *string `json:"slug"`
		Description   *string `json:"description"`
		RepoURL       *string `json:"repo_url"`
		Branch        *string `json:"branch"`
		BuildStrategy *string `json:"build_strategy"`
		DeployType    *string `json:"deploy_type"`
		Runtime       *string `json:"runtime"`
		Serverless    *bool   `json:"serverless"`
		Replicas      *int    `json:"replicas"`
		// Deploy health check (see docs "Despliegues y salud").
		HealthPath            *string `json:"health_path"`
		HealthTimeoutSeconds  *int    `json:"health_timeout_seconds"`
		HealthIntervalSeconds *int    `json:"health_interval_seconds"`
		HealthExpectedStatus  *string `json:"health_expected_status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	// Validate the health fields before anything is persisted.
	hp := healthPatch{Path: req.HealthPath, Timeout: req.HealthTimeoutSeconds, Interval: req.HealthIntervalSeconds, Expected: req.HealthExpectedStatus}
	var newHealth *domain.ProjectHealthConfig
	if !hp.empty() {
		if h.health == nil {
			respondError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "health settings are not available")
			return
		}
		cur, herr := h.health.GetHealthConfig(r.Context(), projectID)
		if herr != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load health settings")
			return
		}
		merged, verr := mergeHealth(cur, hp)
		if verr != nil {
			respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", verr.Error())
			return
		}
		newHealth = &merged
	}

	if req.Name != nil {
		project.Name = strings.TrimSpace(*req.Name)
	}
	if req.Description != nil {
		project.Description = *req.Description
	}
	if req.Slug != nil {
		newSlug := strings.TrimSpace(strings.ToLower(*req.Slug))
		if newSlug != project.Slug {
			existing, _ := h.projects.GetBySlug(r.Context(), orgID, newSlug)
			if existing != nil {
				respondError(w, http.StatusConflict, "SLUG_TAKEN", "project slug already exists in this org")
				return
			}
			project.Slug = newSlug
		}
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
	if newHealth != nil {
		if err := h.health.SetHealthConfig(r.Context(), projectID, *newHealth); err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save health settings")
			return
		}
	}
	h.attachHealth(r.Context(), updated)
	respondJSON(w, http.StatusOK, updated)
}

func (h *ProjectHandler) Delete(w http.ResponseWriter, r *http.Request) {
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

	if !h.authorize(w, r, h.orgs, orgID, projectID, authz.ProjectDelete) {
		return
	}

	if p, err := h.projects.GetByID(r.Context(), projectID); err == domain.ErrNotFound || (err == nil && p.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}

	if err := h.projects.Delete(r.Context(), projectID); err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if h.onDelete != nil {
		go h.onDelete(projectID)
	}
	respondNoContent(w)
}

// SetOnDelete registers a hook run (in a goroutine) after a project is deleted.
func (h *ProjectHandler) SetOnDelete(fn func(uuid.UUID)) { h.onDelete = fn }
