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

type OrgHandler struct {
	repo domain.OrganizationRepository
}

func NewOrgHandler(repo domain.OrganizationRepository) *OrgHandler {
	return &OrgHandler{repo: repo}
}

type createOrgRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (h *OrgHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	var req createOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.TrimSpace(strings.ToLower(req.Slug))
	if req.Name == "" || req.Slug == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "name and slug are required")
		return
	}

	org, err := h.repo.Create(r.Context(), &domain.Organization{
		Name:    req.Name,
		Slug:    req.Slug,
		OwnerID: user.ID,
	})
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			respondError(w, http.StatusConflict, "SLUG_TAKEN", "slug already in use")
			return
		}
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create organization")
		return
	}

	respondJSON(w, http.StatusCreated, org)
}

func (h *OrgHandler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	orgs, total, err := h.repo.ListByUser(r.Context(), user.ID, 1, 100)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list organizations")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"data": orgs,
		"meta": domain.ListMeta{Page: 1, PerPage: 100, Total: total},
	})
}

func (h *OrgHandler) Get(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid organization id")
		return
	}

	org, err := h.repo.GetByID(r.Context(), orgID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "organization not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	ok, _ := h.repo.IsMember(r.Context(), org.ID, user.ID)
	if !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	respondJSON(w, http.StatusOK, org)
}

type updateOrgRequest struct {
	Name string `json:"name"`
}

func (h *OrgHandler) Update(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid organization id")
		return
	}

	org, err := h.repo.GetByID(r.Context(), orgID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "organization not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	if org.OwnerID != user.ID {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "only owner can update")
		return
	}

	var req updateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "name is required")
		return
	}

	org.Name = req.Name
	updated, err := h.repo.Update(r.Context(), org)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update organization")
		return
	}

	respondJSON(w, http.StatusOK, updated)
}

func (h *OrgHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid organization id")
		return
	}

	org, err := h.repo.GetByID(r.Context(), orgID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "organization not found")
		return
	}
	if org.OwnerID != user.ID {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "only owner can delete")
		return
	}

	if err := h.repo.Delete(r.Context(), orgID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete")
		return
	}
	respondNoContent(w)
}
