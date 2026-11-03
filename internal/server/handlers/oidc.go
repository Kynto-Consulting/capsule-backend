package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/oidc"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// OIDCHandler serves the OpenID Connect provider endpoints.
type OIDCHandler struct {
	svc  *oidc.Service
	orgs domain.OrganizationRepository
}

func NewOIDCHandler(svc *oidc.Service, orgs domain.OrganizationRepository) *OIDCHandler {
	return &OIDCHandler{svc: svc, orgs: orgs}
}

// IsOIDCPath reports whether a request path belongs to the OIDC provider's
// root-level routes (they manage their own CORS, so the global CORS handler
// must stay out of the way).
func IsOIDCPath(p string) bool {
	return strings.HasPrefix(p, "/oauth/") || p == "/.well-known/openid-configuration"
}

// MountPublic registers the root-level protocol endpoints. authLimiter is
// applied to /oauth/authorize and /oauth/token.
func (h *OIDCHandler) MountPublic(r chi.Router, authLimiter func(http.Handler) http.Handler) {
	r.Get("/.well-known/openid-configuration", h.Discovery)
	r.Options("/.well-known/openid-configuration", h.Preflight)
	r.Get("/oauth/jwks", h.JWKS)
	r.Options("/oauth/jwks", h.Preflight)
	r.With(authLimiter).Get("/oauth/authorize", h.Authorize)
	r.With(authLimiter).Post("/oauth/token", h.Token)
	r.Options("/oauth/token", h.Preflight)
	r.Get("/oauth/userinfo", h.UserInfo)
	r.Post("/oauth/userinfo", h.UserInfo)
	r.Options("/oauth/userinfo", h.Preflight)
}

// MountAPIPublic registers /api/v1 routes that need no session.
func (h *OIDCHandler) MountAPIPublic(r chi.Router) {
	r.Post("/oauth/requests/{id}/deny", h.Deny)
}

// MountAPI registers authenticated /api/v1 routes.
func (h *OIDCHandler) MountAPI(r chi.Router) {
	r.Get("/oauth/requests/{id}", h.RequestInfo)
	r.Post("/oauth/requests/{id}/approve", h.Approve)

	r.Post("/oauth/clients", h.CreateClient)
	r.Get("/oauth/clients", h.ListClients)
	r.Delete("/oauth/clients/{clientRef}", h.DeleteClient)
	r.Patch("/oauth/clients/{clientRef}", h.UpdateClient)
}

func oidcCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

// Preflight answers CORS preflights for the browser-callable endpoints.
func (h *OIDCHandler) Preflight(w http.ResponseWriter, r *http.Request) {
	oidcCORS(w)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func (h *OIDCHandler) Discovery(w http.ResponseWriter, r *http.Request) {
	oidcCORS(w)
	w.Header().Set("Cache-Control", "public, max-age=300")
	respondJSON(w, http.StatusOK, h.svc.Discovery())
}

func (h *OIDCHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	oidcCORS(w)
	w.Header().Set("Cache-Control", "public, max-age=300")
	respondJSON(w, http.StatusOK, h.svc.JWKS())
}

func writeOAuthError(w http.ResponseWriter, e *oidc.OAuthError) {
	noStore(w)
	if e.Basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="capsule-oidc", charset="UTF-8"`)
	}
	respondJSON(w, e.Status, e)
}

func (h *OIDCHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	res := h.svc.Authorize(r.Context(), r.URL.Query())
	if res.Fatal != nil {
		// Never redirect on an unverified client/redirect_uri.
		respondJSON(w, res.Fatal.Status, res.Fatal)
		return
	}
	http.Redirect(w, r, res.RedirectURL, http.StatusFound)
}

func (h *OIDCHandler) Token(w http.ResponseWriter, r *http.Request) {
	oidcCORS(w)
	noStore(w)
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, &oidc.OAuthError{Code: "invalid_request", Desc: "malformed form body", Status: http.StatusBadRequest})
		return
	}
	// Only the body: ignore query-string parameters on the token endpoint.
	form := r.PostForm
	tr := oidc.TokenRequest{Form: form}
	if id, secret, ok := r.BasicAuth(); ok {
		// RFC 6749 2.3.1: credentials are form-urlencoded before Basic encoding.
		if v, err := url.QueryUnescape(id); err == nil {
			id = v
		}
		if v, err := url.QueryUnescape(secret); err == nil {
			secret = v
		}
		tr.BasicID, tr.BasicSecret, tr.HasBasic = id, secret, true
	}
	resp, e := h.svc.Token(r.Context(), tr)
	if e != nil {
		writeOAuthError(w, e)
		return
	}
	respondJSON(w, http.StatusOK, resp)
}

func (h *OIDCHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	oidcCORS(w)
	noStore(w)
	header := r.Header.Get("Authorization")
	if len(header) < 8 || !strings.EqualFold(header[:7], "Bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="capsule-oidc"`)
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_request", "error_description": "missing bearer token"})
		return
	}
	claims, e := h.svc.UserInfo(r.Context(), strings.TrimSpace(header[7:]))
	if e != nil {
		if e.Status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer realm="capsule-oidc", error="invalid_token"`)
		}
		respondJSON(w, e.Status, e)
		return
	}
	respondJSON(w, http.StatusOK, claims)
}

// ---- consent API (called by the dashboard) ---------------------------------

func (h *OIDCHandler) RequestInfo(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	info, err := h.svc.RequestInfo(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		h.requestError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, info)
}

func (h *OIDCHandler) Approve(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}
	redirect, err := h.svc.Approve(r.Context(), chi.URLParam(r, "id"), user)
	if err != nil {
		h.requestError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"redirect_url": redirect})
}

func (h *OIDCHandler) Deny(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	redirect, err := h.svc.Deny(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		h.requestError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"redirect_url": redirect})
}

func (h *OIDCHandler) requestError(w http.ResponseWriter, err error) {
	switch err {
	case oidc.ErrRequestNotFound:
		respondError(w, http.StatusNotFound, "NOT_FOUND", "authorization request not found or expired")
	case domain.ErrUnauthorized:
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
	default:
		respondError(w, http.StatusInternalServerError, "INTERNAL", "internal error")
	}
}

// ---- client administration -------------------------------------------------

func isPlatformAdmin(u *domain.User) bool { return u != nil && u.Role == "admin" }

// canManageOrg reports whether the user is platform admin or owner/admin of the org.
func (h *OIDCHandler) canManageClient(r *http.Request, user *domain.User, c *oidc.Client) bool {
	if isPlatformAdmin(user) {
		return true
	}
	if c.OrgID == nil {
		return false
	}
	role, err := h.orgs.GetMemberRole(r.Context(), *c.OrgID, user.ID)
	return err == nil && (role == "owner" || role == "admin")
}

type clientResponse struct {
	*oidc.Client
	Public       bool   `json:"public"`
	ClientSecret string `json:"client_secret,omitempty"`
}

func newClientResponse(c *oidc.Client, secret string) clientResponse {
	return clientResponse{Client: c, Public: c.Public(), ClientSecret: secret}
}

type createClientRequest struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	OrgID        *string  `json:"org_id"`
	FirstParty   bool     `json:"first_party"`
	Public       bool     `json:"public"`
}

func (h *OIDCHandler) CreateClient(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}
	var req createClientRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "name is required (max 100 chars)")
		return
	}
	params := oidc.NewClientParams{
		Name: req.Name, RedirectURIs: req.RedirectURIs, FirstParty: req.FirstParty,
		Public: req.Public, CreatedBy: user.ID,
	}
	if req.FirstParty && !isPlatformAdmin(user) {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "only platform admins can create first-party clients")
		return
	}
	if req.OrgID != nil {
		orgID, err := uuid.Parse(*req.OrgID)
		if err != nil {
			respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "invalid org_id")
			return
		}
		org, err := h.orgs.GetByID(r.Context(), orgID)
		if err != nil {
			respondError(w, http.StatusNotFound, "NOT_FOUND", "organization not found")
			return
		}
		params.OrgID = &org.ID
	}
	probe := &oidc.Client{OrgID: params.OrgID}
	if !h.canManageClient(r, user, probe) {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "requires platform admin or owner/admin of the organization")
		return
	}
	client, secret, err := h.svc.CreateClient(r.Context(), params)
	if err != nil {
		if oidc.IsRedirectError(err) {
			respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
			return
		}
		respondError(w, http.StatusInternalServerError, "INTERNAL", "could not create client")
		return
	}
	noStore(w)
	respondJSON(w, http.StatusCreated, newClientResponse(client, secret))
}

func (h *OIDCHandler) ListClients(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}
	store := h.svc.Store()
	var clients []*oidc.Client
	var err error
	if isPlatformAdmin(user) {
		clients, err = store.ListClients(r.Context(), true, nil)
	} else {
		memberships, mErr := store.UserOrgs(r.Context(), user.ID)
		if mErr != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "could not list clients")
			return
		}
		ids := make([]uuid.UUID, 0, len(memberships))
		for _, m := range memberships {
			if m.Role == "owner" || m.Role == "admin" {
				ids = append(ids, m.OrgID)
			}
		}
		if len(ids) == 0 {
			respondJSON(w, http.StatusOK, []clientResponse{})
			return
		}
		clients, err = store.ListClients(r.Context(), false, ids)
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL", "could not list clients")
		return
	}
	out := make([]clientResponse, 0, len(clients))
	for _, c := range clients {
		out = append(out, newClientResponse(c, ""))
	}
	respondJSON(w, http.StatusOK, out)
}

// loadManagedClient resolves {clientRef} and checks the caller may manage it.
// Responses never reveal clients the caller cannot manage (404).
func (h *OIDCHandler) loadManagedClient(w http.ResponseWriter, r *http.Request) (*oidc.Client, bool) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return nil, false
	}
	c, err := h.svc.Store().GetClient(r.Context(), chi.URLParam(r, "clientRef"))
	if err != nil || c.RevokedAt != nil || !h.canManageClient(r, user, c) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "client not found")
		return nil, false
	}
	return c, true
}

func (h *OIDCHandler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	c, ok := h.loadManagedClient(w, r)
	if !ok {
		return
	}
	if err := h.svc.Store().RevokeClient(r.Context(), c.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL", "could not revoke client")
		return
	}
	respondNoContent(w)
}

func (h *OIDCHandler) UpdateClient(w http.ResponseWriter, r *http.Request) {
	c, ok := h.loadManagedClient(w, r)
	if !ok {
		return
	}
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	uris, err := oidc.ValidateRedirectURIs(req.RedirectURIs)
	if err != nil {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
		return
	}
	if err := h.svc.Store().UpdateRedirectURIs(r.Context(), c.ID, uris); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL", "could not update client")
		return
	}
	c.RedirectURIs = uris
	respondJSON(w, http.StatusOK, newClientResponse(c, ""))
}
