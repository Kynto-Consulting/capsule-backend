package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

const adminBcryptCost = 12

// AdminHandler exposes user-management endpoints for admin users.
type AdminHandler struct {
	users domain.UserRepository
}

func NewAdminHandler(users domain.UserRepository) *AdminHandler {
	return &AdminHandler{users: users}
}

// requireAdmin is an inline guard; call at the top of every handler.
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	u := middleware.GetUser(r.Context())
	if u == nil || u.Role != "admin" {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "admin access required")
		return false
	}
	return true
}

// ListUsers returns all platform users (paginated).
// GET /api/v1/admin/users
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	page, limit := parsePagination(r)
	users, total, err := h.users.ListAll(r.Context(), page, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list users")
		return
	}
	if users == nil {
		users = []*domain.User{}
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"data": users,
		"meta": domain.ListMeta{Page: page, PerPage: limit, Total: total},
	})
}

// CreateUser creates a user directly without TOTP.
// POST /api/v1/admin/users
func (h *AdminHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Name = strings.TrimSpace(req.Name)
	if req.Email == "" || req.Name == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name, email, and password are required")
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), adminBcryptCost)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to hash password")
		return
	}

	user, err := h.users.Create(r.Context(), &domain.User{
		Name:         req.Name,
		Email:        req.Email,
		PasswordHash: string(hash),
		Role:         req.Role,
	})
	if err != nil {
		respondError(w, http.StatusConflict, "EMAIL_TAKEN", "email already registered")
		return
	}
	respondJSON(w, http.StatusCreated, user)
}

// SuspendUser sets the user's role to "suspended".
// PATCH /api/v1/admin/users/{userID}/suspend
func (h *AdminHandler) SuspendUser(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user id")
		return
	}
	if err := h.users.SetRole(r.Context(), userID, "suspended"); err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	} else if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to suspend user")
		return
	}
	respondNoContent(w)
}

// UnsuspendUser restores the user's role to "member".
// PATCH /api/v1/admin/users/{userID}/unsuspend
func (h *AdminHandler) UnsuspendUser(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user id")
		return
	}
	if err := h.users.SetRole(r.Context(), userID, "member"); err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	} else if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to unsuspend user")
		return
	}
	respondNoContent(w)
}

// SetUserRole sets an arbitrary role on the user (promote to admin, demote, etc.).
// PATCH /api/v1/admin/users/{userID}/role
func (h *AdminHandler) SetUserRole(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user id")
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Role == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "role is required")
		return
	}
	if err := h.users.SetRole(r.Context(), userID, req.Role); err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	} else if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update role")
		return
	}
	respondNoContent(w)
}

// DeleteUser hard-deletes (soft) a user account.
// DELETE /api/v1/admin/users/{userID}
func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user id")
		return
	}
	if err := h.users.Delete(r.Context(), userID); err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	} else if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete user")
		return
	}
	respondNoContent(w)
}
