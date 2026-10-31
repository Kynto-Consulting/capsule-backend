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

// secretMask is returned instead of the value of secret variables unless the
// caller is an admin/owner who asked for ?reveal=true.
const secretMask = "********"

// OrgEnvHandler manages account-level (organization) variables that every
// project in the org inherits at deploy time.
type OrgEnvHandler struct {
	envvars domain.OrgEnvVarRepository
	orgs    domain.OrganizationRepository
}

func NewOrgEnvHandler(envvars domain.OrgEnvVarRepository, orgs domain.OrganizationRepository) *OrgEnvHandler {
	return &OrgEnvHandler{envvars: envvars, orgs: orgs}
}

type orgEnvVarResponse struct {
	ID       uuid.UUID `json:"id"`
	OrgID    uuid.UUID `json:"org_id"`
	Key      string    `json:"key"`
	Value    string    `json:"value"`
	IsSecret bool      `json:"is_secret"`
	Scope    string    `json:"scope"`
}

func toOrgEnvVarResponse(e *domain.OrgEnvVar, reveal bool) orgEnvVarResponse {
	val := string(e.ValueEnc)
	if e.IsSecret && !reveal {
		val = secretMask
	}
	return orgEnvVarResponse{ID: e.ID, OrgID: e.OrgID, Key: e.Key, Value: val, IsSecret: e.IsSecret, Scope: e.Scope}
}

// role returns the caller's org role; writes the 403 itself when not a member.
func (h *OrgEnvHandler) role(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return uuid.Nil, "", false
	}
	role, err := h.orgs.GetMemberRole(r.Context(), orgID, user.ID)
	if err != nil {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return uuid.Nil, "", false
	}
	return orgID, role, true
}

func isOrgAdmin(role string) bool { return role == "owner" || role == "admin" }

// GET /orgs/{orgID}/env[?reveal=true]
func (h *OrgEnvHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID, role, ok := h.role(w, r)
	if !ok {
		return
	}
	reveal := r.URL.Query().Get("reveal") == "true"
	if reveal && !isOrgAdmin(role) {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "only owners and admins can reveal secret values")
		return
	}
	vars, err := h.envvars.ListByOrg(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list env vars")
		return
	}
	resp := make([]orgEnvVarResponse, len(vars))
	for i, v := range vars {
		resp[i] = toOrgEnvVarResponse(v, reveal)
	}
	respondJSON(w, http.StatusOK, resp)
}

// PUT /orgs/{orgID}/env  {"key","value","is_secret","scope"}
func (h *OrgEnvHandler) Set(w http.ResponseWriter, r *http.Request) {
	orgID, role, ok := h.role(w, r)
	if !ok {
		return
	}
	if !isOrgAdmin(role) {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "only owners and admins can change account variables")
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
	if req.Scope != "build" && req.Scope != "runtime" && req.Scope != "both" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "scope must be build, runtime or both")
		return
	}
	ev, err := h.envvars.Upsert(r.Context(), &domain.OrgEnvVar{
		OrgID: orgID, Key: req.Key, ValueEnc: []byte(req.Value), IsSecret: req.IsSecret, Scope: req.Scope,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to set env var")
		return
	}
	// Same as project env: the PUT response echoes the value the caller just sent.
	respondJSON(w, http.StatusOK, toOrgEnvVarResponse(ev, true))
}

// DELETE /orgs/{orgID}/env/{key}
func (h *OrgEnvHandler) Delete(w http.ResponseWriter, r *http.Request) {
	orgID, role, ok := h.role(w, r)
	if !ok {
		return
	}
	if !isOrgAdmin(role) {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "only owners and admins can change account variables")
		return
	}
	key := strings.ToUpper(chi.URLParam(r, "key"))
	if err := h.envvars.Delete(r.Context(), orgID, key); err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "env var not found")
		return
	} else if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete env var")
		return
	}
	respondNoContent(w)
}
