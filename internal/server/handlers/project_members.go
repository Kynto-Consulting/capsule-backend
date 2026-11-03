package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// ProjectMembersHandler manages per-project roles.
type ProjectMembersHandler struct {
	authzHolder
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
	store    authz.MemberStore
}

// NewProjectMembersHandler wires the handler. svc may be nil (org-only fallback is NOT
// used here: the store itself is the source of truth for explicit roles).
func NewProjectMembersHandler(orgs domain.OrganizationRepository, projects domain.ProjectRepository, store authz.MemberStore, svc *authz.Service) *ProjectMembersHandler {
	h := &ProjectMembersHandler{orgs: orgs, projects: projects, store: store}
	if svc == nil && store != nil {
		svc = authz.New(store)
	}
	h.SetAuthz(svc)
	return h
}

// projectMemberView is one row of the effective member list.
type projectMemberView struct {
	UserID  uuid.UUID    `json:"user_id"`
	Email   string       `json:"email"`
	Name    string       `json:"name"`
	OrgRole string       `json:"org_role"`
	Role    authz.Role   `json:"role"`
	Source  authz.Source `json:"source"`
}

// resolve parses ids, checks the project belongs to the org and that the caller
// has ProjectMembers on it. It writes the error response itself.
func (h *ProjectMembersHandler) resolve(w http.ResponseWriter, r *http.Request) (orgID, projectID uuid.UUID, user *domain.User, ok bool) {
	if h.store == nil {
		respondError(w, http.StatusNotImplemented, "NOT_CONFIGURED", "project members are not configured on this server")
		return
	}
	user = middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}
	var err error
	if orgID, err = uuid.Parse(chi.URLParam(r, "orgID")); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	if projectID, err = uuid.Parse(chi.URLParam(r, "projectID")); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}
	if !h.authorize(w, r, h.orgs, orgID, projectID, authz.ProjectMembers) {
		return
	}
	p, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && p.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load project")
		return
	}
	ok = true
	return
}

func (h *ProjectMembersHandler) audit(r *http.Request, orgID, projectID uuid.UUID, user *domain.User, action string, oldV, newV map[string]any) {
	err := h.store.Audit(r.Context(), authz.AuditEntry{
		OrgID: orgID, UserID: user.ID, Action: action, ResourceType: "project", ResourceID: projectID,
		IP: middleware.ClientIP(r), OldValues: oldV, NewValues: newV,
	})
	if err != nil {
		slog.Warn("audit log failed", "action", action, "error", err)
	}
}

// List handles GET /orgs/{orgID}/projects/{projectID}/members.
func (h *ProjectMembersHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID, projectID, _, ok := h.resolve(w, r)
	if !ok {
		return
	}
	mode, err := h.store.GetOrgAccessMode(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load access mode")
		return
	}
	explicit, err := h.store.ListExplicit(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list project members")
		return
	}
	byUser := make(map[uuid.UUID]string, len(explicit))
	for _, m := range explicit {
		byUser[m.UserID] = m.Role
	}
	orgMembers, err := h.orgs.GetMembers(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list organization members")
		return
	}
	out := make([]projectMemberView, 0, len(orgMembers))
	for _, om := range orgMembers {
		acc := authz.Resolve(om.Role, mode, byUser[om.UserID])
		if acc.Role == "" {
			continue // restricted mode and no explicit role: no access
		}
		out = append(out, projectMemberView{
			UserID: om.UserID, Email: om.Email, Name: om.Name, OrgRole: om.Role, Role: acc.Role, Source: acc.Source,
		})
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": out, "access_mode": mode})
}

type putProjectMemberRequest struct {
	Role string `json:"role"`
}

// Put handles PUT /orgs/{orgID}/projects/{projectID}/members/{userID} (upsert).
func (h *ProjectMembersHandler) Put(w http.ResponseWriter, r *http.Request) {
	orgID, projectID, caller, ok := h.resolve(w, r)
	if !ok {
		return
	}
	targetID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user id")
		return
	}
	var req putProjectMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if !authz.ValidProjectRole(req.Role) {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "role must be one of: admin, deployer, viewer")
		return
	}
	targetOrgRole, err := h.orgs.GetMemberRole(r.Context(), orgID, targetID)
	if err != nil {
		respondError(w, http.StatusNotFound, "USER_NOT_FOUND", "user is not a member of this organization")
		return
	}
	if targetOrgRole == "owner" || targetOrgRole == "admin" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "organization owners and admins are always project admins")
		return
	}
	mode, err := h.store.GetOrgAccessMode(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load access mode")
		return
	}
	explicit, err := h.store.ListExplicit(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list project members")
		return
	}
	oldRole := ""
	for _, m := range explicit {
		if m.UserID == targetID {
			oldRole = m.Role
		}
	}
	cur := authz.Resolve(targetOrgRole, mode, oldRole)
	next := authz.Resolve(targetOrgRole, mode, req.Role)
	if !h.keepsAdmin(w, r, orgID, projectID, cur, next) {
		return
	}
	if err := h.store.UpsertMember(r.Context(), projectID, targetID, req.Role, caller.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save project member")
		return
	}
	h.audit(r, orgID, projectID, caller, "project_member.set",
		map[string]any{"user_id": targetID, "role": oldRole},
		map[string]any{"user_id": targetID, "role": req.Role})
	notifyMembersChanged(orgID, projectID)
	respondJSON(w, http.StatusOK, map[string]any{
		"user_id": targetID, "org_role": targetOrgRole, "role": next.Role, "source": next.Source,
	})
}

// Delete handles DELETE /orgs/{orgID}/projects/{projectID}/members/{userID}.
func (h *ProjectMembersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID, projectID, caller, ok := h.resolve(w, r)
	if !ok {
		return
	}
	targetID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user id")
		return
	}
	explicit, err := h.store.ListExplicit(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list project members")
		return
	}
	oldRole, found := "", false
	for _, m := range explicit {
		if m.UserID == targetID {
			oldRole, found = m.Role, true
		}
	}
	if !found {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "no explicit project role for this user")
		return
	}
	// A stale row of someone who left the org can always be removed.
	if targetOrgRole, err := h.orgs.GetMemberRole(r.Context(), orgID, targetID); err == nil {
		mode, err := h.store.GetOrgAccessMode(r.Context(), orgID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load access mode")
			return
		}
		cur := authz.Resolve(targetOrgRole, mode, oldRole)
		next := authz.Resolve(targetOrgRole, mode, "")
		if !h.keepsAdmin(w, r, orgID, projectID, cur, next) {
			return
		}
	}
	if _, err := h.store.RemoveMember(r.Context(), projectID, targetID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to remove project member")
		return
	}
	h.audit(r, orgID, projectID, caller, "project_member.remove",
		map[string]any{"user_id": targetID, "role": oldRole}, nil)
	notifyMembersChanged(orgID, projectID)
	respondNoContent(w)
}

// keepsAdmin refuses (409) a change that would leave the project without any
// effective admin. Org owners/admins count as admins everywhere.
func (h *ProjectMembersHandler) keepsAdmin(w http.ResponseWriter, r *http.Request, orgID, projectID uuid.UUID, cur, next authz.Access) bool {
	if cur.Role != authz.RoleAdmin || next.Role == authz.RoleAdmin {
		return true
	}
	n, err := h.store.CountEffectiveAdmins(r.Context(), orgID, projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to count project admins")
		return false
	}
	if n <= 1 {
		respondError(w, http.StatusConflict, "LAST_ADMIN", "a project must keep at least one admin")
		return false
	}
	return true
}
