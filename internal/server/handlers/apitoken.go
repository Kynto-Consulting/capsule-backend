package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// APITokenHandler manages platform API tokens (cap_ prefix).
// These tokens authenticate to the full Capsule REST API as an alternative to JWT.
type APITokenHandler struct {
	tokens domain.APITokenRepository
}

func NewAPITokenHandler(tokens domain.APITokenRepository) *APITokenHandler {
	return &APITokenHandler{tokens: tokens}
}

// POST /user/tokens
func (h *APITokenHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())

	var req struct {
		Name         string  `json:"name"          validate:"required,min=1,max=100"`
		RateLimitRPM int     `json:"rate_limit_rpm"`
		IPAllowlist  string  `json:"ip_allowlist"`
	}
	if !middleware.DecodeAndValidate(w, r, &req) {
		return
	}
	if req.RateLimitRPM <= 0 {
		req.RateLimitRPM = 600
	}

	// Generate a 32-byte random token with cap_ prefix
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate token")
		return
	}
	plainToken := "cap_" + hex.EncodeToString(raw)
	hashed := hashToken(plainToken)

	token, err := h.tokens.Create(r.Context(), &domain.APIToken{
		UserID:       user.ID,
		Name:         req.Name,
		TokenHash:    hashed,
		Prefix:       plainToken[:12], // "cap_" + first 8 hex chars
		Scopes:       "*",
		RateLimitRPM: req.RateLimitRPM,
		IPAllowlist:  req.IPAllowlist,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create token")
		return
	}

	type createResponse struct {
		ID           uuid.UUID  `json:"id"`
		Name         string     `json:"name"`
		Token        string     `json:"token"` // only returned once
		Prefix       string     `json:"prefix"`
		RateLimitRPM int        `json:"rate_limit_rpm"`
		CreatedAt    time.Time  `json:"created_at"`
	}
	respondJSON(w, http.StatusCreated, createResponse{
		ID:           token.ID,
		Name:         token.Name,
		Token:        plainToken,
		Prefix:       token.Prefix,
		RateLimitRPM: token.RateLimitRPM,
		CreatedAt:    token.CreatedAt,
	})
}

// GET /user/tokens
func (h *APITokenHandler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())

	tokens, err := h.tokens.ListByUser(r.Context(), user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list tokens")
		return
	}
	if tokens == nil {
		tokens = []*domain.APIToken{}
	}

	// Strip TokenHash from response — it's tagged json:"-" on the model, safe to return directly
	respondJSON(w, http.StatusOK, tokens)
}

// DELETE /user/tokens/{tokenID}
func (h *APITokenHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())

	tokenID, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid token id")
		return
	}

	// Verify ownership before revoking
	tokens, err := h.tokens.ListByUser(r.Context(), user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to verify ownership")
		return
	}
	owned := false
	for _, t := range tokens {
		if t.ID == tokenID {
			owned = true
			break
		}
	}
	if !owned {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "token not found")
		return
	}

	if err := h.tokens.Revoke(r.Context(), tokenID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to revoke token")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PATCH /user/tokens/{tokenID}
func (h *APITokenHandler) Update(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())

	tokenID, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid token id")
		return
	}

	var req struct {
		RateLimitRPM int    `json:"rate_limit_rpm"`
		IPAllowlist  string `json:"ip_allowlist"`
	}
	if !middleware.DecodeAndValidate(w, r, &req) {
		return
	}

	// Verify ownership
	tokens, err := h.tokens.ListByUser(r.Context(), user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to verify ownership")
		return
	}
	owned := false
	for _, t := range tokens {
		if t.ID == tokenID {
			owned = true
			break
		}
	}
	if !owned {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "token not found")
		return
	}

	updated, err := h.tokens.Update(r.Context(), tokenID, req.RateLimitRPM, req.IPAllowlist)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update token")
		return
	}
	respondJSON(w, http.StatusOK, updated)
}
