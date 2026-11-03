package handlers

import (
	"encoding/json"
	"strings"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// APITokenHandler manages platform API tokens (cap_ prefix).
// These tokens authenticate to the full Capsule REST API as an alternative to JWT.
type APITokenHandler struct {
	authzHolder
	tokens   domain.APITokenRepository
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
}

// NewAPITokenHandler creates the handler. orgs/projects are needed only to
// validate project-scoped (deploy) tokens.
func NewAPITokenHandler(tokens domain.APITokenRepository, orgs domain.OrganizationRepository, projects domain.ProjectRepository) *APITokenHandler {
	return &APITokenHandler{tokens: tokens, orgs: orgs, projects: projects}
}

// POST /user/tokens
func (h *APITokenHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())

	var req struct {
		Name         string  `json:"name"          validate:"required,min=1,max=100"`
		RateLimitRPM int     `json:"rate_limit_rpm"`
		IPAllowlist  string  `json:"ip_allowlist"`
		// Scopes: ["*"] (default) or ["deploy"]; a plain string is also accepted.
		Scopes    json.RawMessage `json:"scopes"`
		ProjectID *uuid.UUID      `json:"project_id"`
	}
	if !middleware.DecodeAndValidate(w, r, &req) {
		return
	}
	if req.RateLimitRPM <= 0 {
		req.RateLimitRPM = 600
	}
	scopes, projectID, serr := h.resolveScopes(r, user.ID, req.Scopes, req.ProjectID)
	if serr != "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", serr)
		return
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
		Prefix:       plainToken[:10], // "cap_" + first 6 hex chars (varchar(10) limit)
		Scopes:       scopes,
		ProjectID:    projectID,
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
		Scopes       string     `json:"scopes"`
		ProjectID    *uuid.UUID `json:"project_id,omitempty"`
		CreatedAt    time.Time  `json:"created_at"`
	}
	respondJSON(w, http.StatusCreated, createResponse{
		ID:           token.ID,
		Name:         token.Name,
		Token:        plainToken,
		Prefix:       token.Prefix,
		RateLimitRPM: token.RateLimitRPM,
		Scopes:       token.Scopes,
		ProjectID:    token.ProjectID,
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

// resolveScopes validates the requested scopes/project and returns the value to store.
func (h *APITokenHandler) resolveScopes(r *http.Request, userID uuid.UUID, raw json.RawMessage, projectID *uuid.UUID) (string, *uuid.UUID, string) {
	var scopes []string
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &scopes); err != nil {
			var one string
			if err2 := json.Unmarshal(raw, &one); err2 != nil {
				return "", nil, "scopes must be an array of strings"
			}
			scopes = middleware.ParseScopes(one)
		}
	}
	if len(scopes) == 0 {
		scopes = []string{middleware.ScopeAll}
	}
	seen := map[string]bool{}
	var clean []string
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s != middleware.ScopeAll && s != middleware.ScopeDeploy && s != middleware.ScopeSecurityWrite {
			return "", nil, "unknown scope: " + s
		}
		if !seen[s] {
			seen[s] = true
			clean = append(clean, s)
		}
	}
	if seen[middleware.ScopeAll] && len(clean) > 1 {
		return "", nil, "scope * cannot be combined with other scopes"
	}
	if seen[middleware.ScopeAll] {
		if projectID != nil {
			return "", nil, "project_id is only valid with project-bound scopes (deploy, security:write)"
		}
		return middleware.ScopeAll, nil, ""
	}
	// deploy scope: must be bound to a project the caller belongs to.
	if projectID == nil {
		return "", nil, "project_id is required for project-bound scopes (deploy, security:write)"
	}
	if h.projects == nil || h.orgs == nil {
		return "", nil, "project-scoped tokens are not available"
	}
	p, err := h.projects.GetByID(r.Context(), *projectID)
	if err != nil {
		return "", nil, "project not found"
	}
	// A project-bound token can only be minted by someone who may do what it will do.
	for _, sc := range clean {
		action := authz.ProjectDeploy
		if sc == middleware.ScopeSecurityWrite {
			action = authz.SecurityTriage
		}
		if ok, _ := h.service(h.orgs).Can(r.Context(), userID, p.OrgID, p.ID, action); !ok {
			return "", nil, "project not found"
		}
	}
	return strings.Join(clean, ","), projectID, ""
}
