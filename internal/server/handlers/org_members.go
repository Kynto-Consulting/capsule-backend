package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// validMemberRoles contains the allowed role values for org members.
var validMemberRoles = map[string]bool{
	"admin":    true,
	"member":   true,
	"readonly": true,
}

// OrgMembersHandler handles HTTP requests for org membership management.
type OrgMembersHandler struct {
	orgs  domain.OrganizationRepository
	users domain.UserRepository
}

// NewOrgMembersHandler creates a new OrgMembersHandler.
func NewOrgMembersHandler(orgs domain.OrganizationRepository, users domain.UserRepository) *OrgMembersHandler {
	return &OrgMembersHandler{orgs: orgs, users: users}
}

// List handles GET /orgs/{orgID}/members
// Returns all members of an organization. Caller must be a member.
func (h *OrgMembersHandler) List(w http.ResponseWriter, r *http.Request) {
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

	ok, err := h.orgs.IsMember(r.Context(), orgID, user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check membership")
		return
	}
	if !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member of this organization")
		return
	}

	members, err := h.orgs.GetMembers(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list members")
		return
	}

	if members == nil {
		members = []*domain.OrgMember{}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"data": members,
	})
}

type inviteMemberRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// Invite handles POST /orgs/{orgID}/members
// Adds an existing user to the org by email. Caller must be owner or admin.
func (h *OrgMembersHandler) Invite(w http.ResponseWriter, r *http.Request) {
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

	// Caller must be a member with at least admin role.
	callerRole, err := h.orgs.GetMemberRole(r.Context(), orgID, user.ID)
	if err != nil {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member of this organization")
		return
	}
	if callerRole != "owner" && callerRole != "admin" {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "only owners and admins can invite members")
		return
	}

	var req inviteMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.Email == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "email is required")
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}
	if !validMemberRoles[req.Role] {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "role must be one of: admin, member, readonly")
		return
	}

	// Look up the target user by email.
	target, err := h.users.GetByEmail(r.Context(), req.Email)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "USER_NOT_FOUND", "user not registered, ask them to sign up first")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to look up user")
		return
	}

	if err := h.orgs.AddMember(r.Context(), orgID, target.ID, req.Role); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to add member")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]any{
		"user_id": target.ID,
		"email":   target.Email,
		"name":    target.Name,
		"role":    req.Role,
	})
}

type updateRoleRequest struct {
	Role string `json:"role"`
}

// UpdateRole handles PATCH /orgs/{orgID}/members/{userID}
// Updates a member's role. Caller must be owner or admin. Owner role cannot be changed.
func (h *OrgMembersHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
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

	targetUserID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user id")
		return
	}

	// Caller must be owner or admin.
	callerRole, err := h.orgs.GetMemberRole(r.Context(), orgID, user.ID)
	if err != nil {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member of this organization")
		return
	}
	if callerRole != "owner" && callerRole != "admin" {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "only owners and admins can change member roles")
		return
	}

	// Prevent changing the owner's role.
	targetRole, err := h.orgs.GetMemberRole(r.Context(), orgID, targetUserID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "member not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to look up member")
		return
	}
	if targetRole == "owner" {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "the owner's role cannot be changed")
		return
	}

	var req updateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if !validMemberRoles[req.Role] {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "role must be one of: admin, member, readonly")
		return
	}

	if err := h.orgs.UpdateMemberRole(r.Context(), orgID, targetUserID, req.Role); err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "member not found")
		return
	} else if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update member role")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"user_id": targetUserID,
		"role":    req.Role,
	})
}

// Remove handles DELETE /orgs/{orgID}/members/{userID}
// Removes a member from the org. Owner cannot be removed.
func (h *OrgMembersHandler) Remove(w http.ResponseWriter, r *http.Request) {
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

	targetUserID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user id")
		return
	}

	// Caller must be owner or admin, OR the member removing themselves.
	callerRole, err := h.orgs.GetMemberRole(r.Context(), orgID, user.ID)
	if err != nil {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member of this organization")
		return
	}

	isSelf := user.ID == targetUserID
	isPrivileged := callerRole == "owner" || callerRole == "admin"

	if !isSelf && !isPrivileged {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "only owners and admins can remove other members")
		return
	}

	// Prevent removing the owner (including owner removing themselves via this endpoint).
	targetRole, err := h.orgs.GetMemberRole(r.Context(), orgID, targetUserID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "member not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to look up member")
		return
	}
	if targetRole == "owner" {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "the owner cannot be removed from the organization")
		return
	}

	if err := h.orgs.RemoveMember(r.Context(), orgID, targetUserID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to remove member")
		return
	}

	respondNoContent(w)
}
