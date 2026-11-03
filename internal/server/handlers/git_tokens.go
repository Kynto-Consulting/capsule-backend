package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gittokens"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// Git Capsule A7: tokens cgt_, credential helper endpoint, service tokens, SSH keys and the
// internal /internal/git-auth endpoint (git_auth_internal.go). Contract: docs/git-capsule/API.openapi.yaml
// (gitCredentialIssue, gitTokens*, gitTokenCreate/Revoke, gitSshKey*, serviceToken*).

// GitTokensHandler serves the A7 user-facing routes.
type GitTokensHandler struct {
	svc       *gittokens.Service
	apiTokens domain.APITokenRepository
	logger    *slog.Logger
}

// GitTokensWiring is what WireGitTokens needs from main.go.
type GitTokensWiring struct {
	Store         gittokens.Store
	Users         domain.UserRepository
	Orgs          domain.OrganizationRepository
	Projects      domain.ProjectRepository
	Authz         *authz.Service
	APITokens     domain.APITokenRepository
	UsernameTaken gittokens.UsernameTaker // e.g. repository.OIDCRepository (same naming rules as the OIDC provider)
	// Identity is optional: A2's Capsule->Forgejo resolver. nil = gittokens.NameRules.
	Identity gittokens.IdentityResolver
	// ServiceIdentity and Notifier are optional.
	ServiceIdentity gittokens.ServiceIdentityResolver
	Notifier        gittokens.Notifier
}

var (
	gitTokensMu     sync.RWMutex
	gitTokensShared *GitTokensHandler
)

func sharedGitTokens() *GitTokensHandler {
	gitTokensMu.RLock()
	defer gitTokensMu.RUnlock()
	return gitTokensShared
}

// WireGitTokens builds the Service, publishes it (gittokens.Shared) and starts its background
// loop (SSH key reconciliation, expiry warnings, purge). Called from the git-capsule:wiring block.
func WireGitTokens(ctx context.Context, logger *slog.Logger, w GitTokensWiring) *gittokens.Service {
	cfg := gittokens.ConfigFromEnv()
	az := w.Authz
	if az == nil {
		az = authz.New(authz.OrgOnlyStore{Orgs: w.Orgs})
	}
	ident := w.Identity
	if ident == nil {
		ident = gittokens.NameRules{Users: w.Users, Taken: w.UsernameTaken}
	}
	svc := gittokens.New(cfg, gittokens.Deps{
		Store:           w.Store,
		Access:          az,
		Directory:       gittokens.DomainDirectory{Orgs: w.Orgs, Projects: w.Projects},
		Identity:        ident,
		ServiceIdentity: w.ServiceIdentity,
		Sessions:        gittokens.APITokenSessions{Tokens: w.APITokens},
		Keys:            func() gitcore.Keys { return gitcore.Shared() },
		Notifier:        w.Notifier,
		Logger:          logger,
	})
	gittokens.SetShared(svc)
	gitTokensMu.Lock()
	gitTokensShared = &GitTokensHandler{svc: svc, apiTokens: w.APITokens, logger: logger}
	gitTokensMu.Unlock()
	if cfg.AuthSecret == "" && !cfg.AllowUnsecured && logger != nil {
		logger.Warn("git tokens: CAPSULE_GIT_AUTH_SECRET is not set; /internal/git-auth stays closed (fail closed) until Caddy and the backend share it")
	}
	go svc.Run(ctx)
	return svc
}

// MountGitTokens registers the user-facing routes inside the authenticated /api/v1 group.
// It does nothing until WireGitTokens ran.
func MountGitTokens(r chi.Router) {
	h := sharedGitTokens()
	if h == nil {
		return
	}
	r.Post("/user/git-credentials", h.Issue)
	r.Get("/user/git-tokens", h.List)
	r.Post("/user/git-tokens", h.Create)
	r.Delete("/user/git-tokens", h.RevokeSession)
	r.Delete("/user/git-tokens/{tokenID}", h.Revoke)
	r.Get("/user/git-ssh-keys", h.ListKeys)
	r.Post("/user/git-ssh-keys", h.AddKey)
	r.Delete("/user/git-ssh-keys/{keyID}", h.DeleteKey)
	r.Get("/orgs/{orgID}/projects/{projectID}/git/service-tokens", h.ListService)
	r.Post("/orgs/{orgID}/projects/{projectID}/git/service-tokens", h.CreateService)
	r.Delete("/orgs/{orgID}/projects/{projectID}/git/service-tokens/{tokenID}", h.RevokeService)
}

// MountGitAuthInternal registers GET /internal/git-auth on the ROOT router (not under /api/v1 and
// not behind the user authentication middleware: Caddy calls it with the Git client's Basic
// credentials). It does nothing until WireGitTokens ran.
func MountGitAuthInternal(root chi.Router) {
	h := sharedGitTokens()
	if h == nil {
		return
	}
	root.Handle("/internal/git-auth", &GitAuthInternalHandler{svc: h.svc, logger: h.logger})
}

// ---- helpers -------------------------------------------------------------------------------

func (h *GitTokensHandler) fail(w http.ResponseWriter, err error) {
	if ge, ok := gittokens.AsError(err); ok {
		respondError(w, ge.Status, ge.Code, ge.Message)
		return
	}
	if errors.Is(err, domain.ErrNotFound) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "not found")
		return
	}
	if h.logger != nil {
		h.logger.Error("git tokens: request failed", "error", err.Error())
	}
	respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
}

func decodeSmallJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		respondError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON")
		return false
	}
	return true
}

func gitNoStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

var reCLISession = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// sessionRef binds ephemeral tokens to the caller's session: a cap_ API token (revoking or
// expiring that token ends the Git credentials) or a CLI-chosen session id (cli_session_id,
// sent by capsule git credential). Browser sessions carry neither and are refused by Issue.
func (h *GitTokensHandler) sessionRef(r *http.Request, user *domain.User, cliSession string) string {
	if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && strings.HasPrefix(bearer, "cap_") {
		// api_tokens.token_hash is the hex SHA-256 of the token: the same function.
		rec, err := h.apiTokens.GetByHash(r.Context(), gittokens.Hash(bearer))
		if err == nil && rec.UserID == user.ID {
			return gittokens.CapSessionRef(rec.ID)
		}
		return ""
	}
	if cliSession == "" {
		cliSession = r.Header.Get("X-Capsule-CLI-Session")
	}
	if reCLISession.MatchString(cliSession) {
		return gittokens.CLISessionRef(cliSession)
	}
	return ""
}

type gitTokenDTO struct {
	ID         uuid.UUID   `json:"id"`
	Name       string      `json:"name"`
	Kind       string      `json:"kind"`
	Scope      string      `json:"scope"`
	Prefix     string      `json:"prefix"`
	Projects   []uuid.UUID `json:"projects"`
	CreatedAt  time.Time   `json:"created_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
	LastUsedAt *time.Time  `json:"last_used_at"`
	LastUsedIP string      `json:"last_used_ip,omitempty"`
	RevokedAt  *time.Time  `json:"revoked_at"`
	Token      string      `json:"token,omitempty"` // only in the creation response
}

func toTokenDTO(t *gittokens.Token, plain string) gitTokenDTO {
	p := t.ProjectIDs
	if p == nil {
		p = []uuid.UUID{}
	}
	return gitTokenDTO{ID: t.ID, Name: t.Name, Kind: t.Kind, Scope: t.Scope, Prefix: t.Prefix, Projects: p,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, LastUsedIP: t.LastUsedIP,
		RevokedAt: t.RevokedAt, Token: plain}
}

type gitTokenInput struct {
	Name          string      `json:"name"`
	Scope         string      `json:"scope"`
	Projects      []uuid.UUID `json:"projects"`
	ExpiresInDays int         `json:"expires_in_days"`
}

// paginate applies the offset cursor to an already bounded list.
func paginate[T any](items []T, cursor string, limit int) ([]T, *string) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	off := 0
	if cursor != "" {
		if b, err := base64.RawURLEncoding.DecodeString(cursor); err == nil {
			if n, err := strconv.Atoi(string(b)); err == nil && n >= 0 {
				off = n
			}
		}
	}
	if off > len(items) {
		off = len(items)
	}
	end := off + limit
	if end >= len(items) {
		return items[off:], nil
	}
	next := base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
	return items[off:end], &next
}

func writeTokenList(w http.ResponseWriter, r *http.Request, list []*gittokens.Token) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	page, next := paginate(list, r.URL.Query().Get("cursor"), limit)
	items := make([]gitTokenDTO, 0, len(page))
	for _, t := range page {
		items = append(items, toTokenDTO(t, ""))
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

// ---- credential helper ---------------------------------------------------------------------

// Issue handles POST /user/git-credentials (gitCredentialIssue).
func (h *GitTokensHandler) Issue(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	var body struct {
		Protocol     string `json:"protocol"`
		Host         string `json:"host"`
		Path         string `json:"path"`
		Scope        string `json:"scope"`
		CLISessionID string `json:"cli_session_id"`
	}
	if !decodeSmallJSON(w, r, &body) {
		return
	}
	if body.Protocol != "" && body.Protocol != "https" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "protocol must be https")
		return
	}
	if strings.TrimSpace(body.Host) == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "host is required")
		return
	}
	cred, err := h.svc.Issue(r.Context(), user.ID, gittokens.IssueInput{
		Path: body.Path, Scope: body.Scope, SessionRef: h.sessionRef(r, user, body.CLISessionID), IP: middleware.ClientIP(r),
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	gitNoStore(w)
	respondJSON(w, http.StatusOK, map[string]any{
		"username": cred.Username, "password": cred.Password,
		"expires_at": cred.ExpiresAt, "renew_after": cred.RenewAfter,
		"scope": cred.Scope, "project_id": cred.ProjectID,
	})
}

// ---- personal tokens -----------------------------------------------------------------------

// List handles GET /user/git-tokens (gitTokensList).
func (h *GitTokensHandler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	list, err := h.svc.ListUserTokens(r.Context(), user.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeTokenList(w, r, list)
}

// Create handles POST /user/git-tokens (gitTokenCreate).
func (h *GitTokensHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	var in gitTokenInput
	if !decodeSmallJSON(w, r, &in) {
		return
	}
	tok, plain, err := h.svc.CreatePersonal(r.Context(), user.ID, gittokens.CreateInput{
		Name: in.Name, Scope: in.Scope, ProjectIDs: in.Projects, ExpiresInDays: in.ExpiresInDays, IP: middleware.ClientIP(r),
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	gitNoStore(w)
	respondJSON(w, http.StatusCreated, toTokenDTO(tok, plain))
}

// Revoke handles DELETE /user/git-tokens/{tokenID} (gitTokenRevoke).
func (h *GitTokensHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid token id")
		return
	}
	if err := h.svc.RevokeOwn(r.Context(), user.ID, id, middleware.ClientIP(r)); err != nil {
		h.fail(w, err)
		return
	}
	respondNoContent(w)
}

// RevokeSession handles DELETE /user/git-tokens (gitTokensRevokeSession): revokes every ephemeral
// token of the caller's CLI session; capsule logout calls it. The session is the cap_ token used
// for the call, or ?session_id= for JWT logins.
func (h *GitTokensHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	ref := h.sessionRef(r, user, r.URL.Query().Get("session_id"))
	if ref == "" {
		respondError(w, http.StatusBadRequest, "BAD_REQUEST", "no CLI session to revoke")
		return
	}
	n, err := h.svc.RevokeSession(r.Context(), user.ID, ref, middleware.ClientIP(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

// ---- service tokens ------------------------------------------------------------------------

func (h *GitTokensHandler) projectIDs(w http.ResponseWriter, r *http.Request) (org, project uuid.UUID, ok bool) {
	org, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return uuid.Nil, uuid.Nil, false
	}
	project, err = uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return uuid.Nil, uuid.Nil, false
	}
	return org, project, true
}

// ListService handles GET .../git/service-tokens (serviceTokensList), x-permission git.admin.
func (h *GitTokensHandler) ListService(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	org, project, ok := h.projectIDs(w, r)
	if !ok {
		return
	}
	list, err := h.svc.ListServiceTokens(r.Context(), user.ID, org, project)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeTokenList(w, r, list)
}

// CreateService handles POST .../git/service-tokens (serviceTokenCreate), x-permission git.admin.
func (h *GitTokensHandler) CreateService(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	org, project, ok := h.projectIDs(w, r)
	if !ok {
		return
	}
	var in gitTokenInput
	if !decodeSmallJSON(w, r, &in) {
		return
	}
	tok, plain, err := h.svc.CreateService(r.Context(), user.ID, org, project, gittokens.CreateInput{
		Name: in.Name, Scope: in.Scope, ProjectIDs: in.Projects, ExpiresInDays: in.ExpiresInDays, IP: middleware.ClientIP(r),
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	gitNoStore(w)
	respondJSON(w, http.StatusCreated, toTokenDTO(tok, plain))
}

// RevokeService handles DELETE .../git/service-tokens/{tokenID} (serviceTokenRevoke).
func (h *GitTokensHandler) RevokeService(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	org, project, ok := h.projectIDs(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid token id")
		return
	}
	if err := h.svc.RevokeService(r.Context(), user.ID, org, project, id, middleware.ClientIP(r)); err != nil {
		h.fail(w, err)
		return
	}
	respondNoContent(w)
}
