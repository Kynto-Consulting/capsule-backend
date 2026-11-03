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

type OrgHandler struct {
	repo  domain.OrganizationRepository
	modes authz.MemberStore // optional: project_access_mode storage + audit
}

// SetAccessModes enables reading/updating project_access_mode.
func (h *OrgHandler) SetAccessModes(s authz.MemberStore) { h.modes = s }

// orgResponse adds the project access mode to the organization JSON.
type orgResponse struct {
	*domain.Organization
	ProjectAccessMode string `json:"project_access_mode,omitempty"`
}

func (h *OrgHandler) orgJSON(r *http.Request, org *domain.Organization) orgResponse {
	resp := orgResponse{Organization: org}
	if h.modes != nil {
		if m, err := h.modes.GetOrgAccessMode(r.Context(), org.ID); err == nil {
			resp.ProjectAccessMode = m
		}
	}
	return resp
}

func NewOrgHandler(repo domain.OrganizationRepository) *OrgHandler {
	return &OrgHandler{repo: repo}
}

type createOrgRequest struct {
	Name string `json:"name" validate:"required,min=1,max=100"`
	Slug string `json:"slug" validate:"required,min=1,max=50,slug"`
}

func (h *OrgHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}

	var req createOrgRequest
	if !middleware.DecodeAndValidate(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.TrimSpace(strings.ToLower(req.Slug))

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

	page, limit := parsePagination(r)
	orgs, total, err := h.repo.ListByUser(r.Context(), user.ID, page, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list organizations")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"data": orgs,
		"meta": domain.ListMeta{Page: page, PerPage: limit, Total: total},
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

	respondJSON(w, http.StatusOK, h.orgJSON(r, org))
}

type updateOrgRequest struct {
	Name              string  `json:"name"`
	ProjectAccessMode *string `json:"project_access_mode"`
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

	// Owners may change everything; org admins may only change project_access_mode.
	isOwner := org.OwnerID == user.ID
	if !isOwner {
		if role, _ := h.repo.GetMemberRole(r.Context(), orgID, user.ID); role != "admin" {
			respondError(w, http.StatusForbidden, "FORBIDDEN", "only owner can update")
			return
		}
	}

	var req updateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" && req.ProjectAccessMode == nil {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "name is required")
		return
	}
	if req.Name != "" && !isOwner {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "only owner can update")
		return
	}
	if req.ProjectAccessMode != nil {
		if !authz.ValidMode(*req.ProjectAccessMode) {
			respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "project_access_mode must be one of: open, restricted")
			return
		}
		if h.modes == nil {
			respondError(w, http.StatusNotImplemented, "NOT_CONFIGURED", "project access mode is not configured on this server")
			return
		}
		oldMode, _ := h.modes.GetOrgAccessMode(r.Context(), orgID)
		if err := h.modes.SetOrgAccessMode(r.Context(), orgID, *req.ProjectAccessMode); err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update project access mode")
			return
		}
		_ = h.modes.Audit(r.Context(), authz.AuditEntry{
			OrgID: orgID, UserID: user.ID, Action: "org.project_access_mode.set", ResourceType: "organization", ResourceID: orgID,
			IP: middleware.ClientIP(r), OldValues: map[string]any{"project_access_mode": oldMode},
			NewValues: map[string]any{"project_access_mode": *req.ProjectAccessMode},
		})
		notifyOrgChanged(orgID) // core Git: re-sync the teams of every project
	}

	updated := org
	if req.Name != "" {
		org.Name = req.Name
		updated, err = h.repo.Update(r.Context(), org)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update organization")
			return
		}
	}

	respondJSON(w, http.StatusOK, h.orgJSON(r, updated))
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
