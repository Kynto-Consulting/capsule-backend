package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitsource"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/internal/service"
)

// ProjectAuthorizer decides who may manage a project's git link (CanManage)
// and who may deploy/view its deployments (CanDeploy).
type ProjectAuthorizer interface {
	CanManage(ctx context.Context, userID, orgID, projectID uuid.UUID) (bool, error)
	CanDeploy(ctx context.Context, userID, orgID, projectID uuid.UUID) (bool, error)
}

// OrgRoleAuthorizer is the default authorizer: organization owner, admin and
// member roles may write; readonly may not. Not being a member denies both.
type OrgRoleAuthorizer struct{ Orgs domain.OrganizationRepository }

func (a OrgRoleAuthorizer) allowed(ctx context.Context, userID, orgID uuid.UUID) (bool, error) {
	role, err := a.Orgs.GetMemberRole(ctx, orgID, userID)
	if errors.Is(err, domain.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return role == "owner" || role == "admin" || role == "member", nil
}

func (a OrgRoleAuthorizer) CanManage(ctx context.Context, userID, orgID, _ uuid.UUID) (bool, error) {
	return a.allowed(ctx, userID, orgID)
}

func (a OrgRoleAuthorizer) CanDeploy(ctx context.Context, userID, orgID, _ uuid.UUID) (bool, error) {
	return a.allowed(ctx, userID, orgID)
}

// ActionChecker is satisfied by *authz.Service.
type ActionChecker interface {
	Can(ctx context.Context, userID, orgID, projectID uuid.UUID, a authz.Action) (bool, error)
}

// AuthzAuthorizer decides with the project role matrix (organization role x access mode x
// explicit project role) instead of the organization role alone: managing the link
// (credentials, auto-deploy, previews) needs project.ops, reading it only project.read, so a
// viewer sees the link but never manages it and a hidden user sees nothing.
type AuthzAuthorizer struct{ Svc ActionChecker }

func (a AuthzAuthorizer) CanManage(ctx context.Context, userID, orgID, projectID uuid.UUID) (bool, error) {
	return a.Svc.Can(ctx, userID, orgID, projectID, authz.ProjectOps)
}

func (a AuthzAuthorizer) CanDeploy(ctx context.Context, userID, orgID, projectID uuid.UUID) (bool, error) {
	return a.Svc.Can(ctx, userID, orgID, projectID, authz.ProjectRead)
}

// GitDeps wires the git handlers.
type GitDeps struct {
	Git        domain.GitRepository
	Projects   domain.ProjectRepository
	Orgs       domain.OrganizationRepository
	Authorizer ProjectAuthorizer // nil = OrgRoleAuthorizer
	Policy     gitsource.Policy
	Fetcher    gitsource.Fetcher
	Service    *service.GitService
	PublicHost string // host used to build webhook_url (falls back to the request host)
	Logger     *slog.Logger
	// CoreLinks (optional) returns web/clone URLs for links of the core Git service (provider forgejo).
	CoreLinks func(g *domain.ProjectGit) (web, https, ssh string)
}

// GitHandler serves the git link API and the public webhook receiver.
type GitHandler struct {
	GitDeps
}

func NewGitHandler(d GitDeps) *GitHandler {
	if d.Authorizer == nil {
		d.Authorizer = OrgRoleAuthorizer{Orgs: d.Orgs}
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return &GitHandler{GitDeps: d}
}

// SetAuthorizer swaps the permission check (RBAC wiring).
func (h *GitHandler) SetAuthorizer(a ProjectAuthorizer) { h.Authorizer = a }

type gitResponse struct {
	*domain.ProjectGit
	HasCredential bool   `json:"has_credential"`
	WebhookURL    string `json:"webhook_url"`
	// WebhookSecret is present ONLY on creation or rotation.
	WebhookSecret string `json:"webhook_secret,omitempty"`
	// Present when the provider is forgejo (core Git service).
	CloneURLHTTPS string `json:"clone_url_https,omitempty"`
	CloneURLSSH   string `json:"clone_url_ssh,omitempty"`
	WebURL        string `json:"web_url,omitempty"`
}

func (h *GitHandler) webhookURL(r *http.Request, projectID uuid.UUID) string {
	host := h.PublicHost
	if host == "" {
		host = r.Host
	}
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	return "https://" + strings.TrimRight(host, "/") + "/hooks/git/" + projectID.String()
}

func (h *GitHandler) toResponse(r *http.Request, g *domain.ProjectGit, secret string) gitResponse {
	resp := gitResponse{
		ProjectGit:    g,
		HasCredential: g.Credential != "",
		WebhookURL:    h.webhookURL(r, g.ProjectID),
		WebhookSecret: secret,
	}
	if h.CoreLinks != nil && g.Provider == "forgejo" {
		resp.WebURL, resp.CloneURLHTTPS, resp.CloneURLSSH = h.CoreLinks(g)
	}
	return resp
}

// scope parses ids, authorizes and loads the project. manage selects CanManage vs CanDeploy.
func (h *GitHandler) scope(w http.ResponseWriter, r *http.Request, manage bool) (orgID uuid.UUID, project *domain.Project, ok bool) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}
	var allowed bool
	if manage {
		allowed, err = h.Authorizer.CanManage(r.Context(), user.ID, orgID, projectID)
	} else {
		allowed, err = h.Authorizer.CanDeploy(r.Context(), user.ID, orgID, projectID)
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check permissions")
		return
	}
	if !allowed {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not allowed")
		return
	}
	p, err := h.Projects.GetByID(r.Context(), projectID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && p.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load project")
		return
	}
	return orgID, p, true
}

func newWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GET /orgs/{orgID}/projects/{projectID}/git
func (h *GitHandler) Get(w http.ResponseWriter, r *http.Request) {
	_, p, ok := h.scope(w, r, false)
	if !ok {
		return
	}
	g, err := h.Git.Get(r.Context(), p.ID)
	if errors.Is(err, domain.ErrNotFound) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project has no git link")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load git link")
		return
	}
	respondJSON(w, http.StatusOK, h.toResponse(r, g, ""))
}

type putGitRequest struct {
	Provider            *string `json:"provider"`
	RepoURL             *string `json:"repo_url"`
	Branch              *string `json:"branch"`
	AuthKind            *string `json:"auth_kind"`
	Token               *string `json:"token"`
	SSHKey              *string `json:"ssh_key"`
	AutoDeploy          *bool   `json:"auto_deploy"`
	PreviewEnabled      *bool   `json:"preview_enabled"`
	PreviewMax          *int    `json:"preview_max"`
	PreviewTTLHours     *int    `json:"preview_ttl_hours"`
	RotateWebhookSecret bool    `json:"rotate_webhook_secret"`
}

// PUT /orgs/{orgID}/projects/{projectID}/git
func (h *GitHandler) Put(w http.ResponseWriter, r *http.Request) {
	_, p, ok := h.scope(w, r, true)
	if !ok {
		return
	}
	if is, err := h.Git.IsPreview(r.Context(), p.ID); err == nil && is {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "preview projects cannot have a git link")
		return
	}
	var req putGitRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	existing, err := h.Git.Get(r.Context(), p.ID)
	creating := errors.Is(err, domain.ErrNotFound)
	if err != nil && !creating {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load git link")
		return
	}
	g := &domain.ProjectGit{ProjectID: p.ID, Branch: "main", AuthKind: "none", PreviewMax: 5, PreviewTTLHours: 168}
	if !creating {
		c := *existing
		g = &c
	}
	if req.RepoURL != nil {
		g.RepoURL = strings.TrimSpace(*req.RepoURL)
	}
	if g.RepoURL == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "repo_url required")
		return
	}
	ref, _, err := h.Policy.ValidateRepoURL(r.Context(), g.RepoURL)
	if err != nil {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
		return
	}
	if req.Provider != nil {
		g.Provider = strings.ToLower(strings.TrimSpace(*req.Provider))
	}
	if g.Provider == "" {
		g.Provider = "generic"
		if ref.Host == "github.com" {
			g.Provider = "github"
		}
	}
	switch g.Provider {
	case "github", "forgejo", "gitea", "generic":
	default:
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "provider must be one of github, forgejo, gitea, generic")
		return
	}
	if req.Branch != nil {
		g.Branch = strings.TrimSpace(*req.Branch)
	}
	if !gitsource.ValidBranch(g.Branch) {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "invalid branch name")
		return
	}

	prevKind := g.AuthKind
	if req.AuthKind != nil {
		g.AuthKind = strings.ToLower(strings.TrimSpace(*req.AuthKind))
	}
	switch g.AuthKind {
	case "none", "token", "ssh_key":
	default:
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "auth_kind must be one of token, ssh_key, none")
		return
	}
	if g.AuthKind != prevKind {
		g.Credential = "" // credentials never carry across kinds
	}
	switch g.AuthKind {
	case "none":
		g.Credential = ""
	case "token":
		if req.Token != nil && *req.Token != "" {
			g.Credential = strings.TrimSpace(*req.Token)
		}
		if g.Credential == "" || len(g.Credential) > 512 || strings.ContainsAny(g.Credential, "\r\n\x00 ") {
			respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "a valid token is required for auth_kind=token")
			return
		}
		if ref.Scheme != "https" {
			respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "token authentication requires an https repo_url")
			return
		}
	case "ssh_key":
		if req.SSHKey != nil && *req.SSHKey != "" {
			g.Credential = *req.SSHKey
		}
		if g.Credential == "" || len(g.Credential) > 16<<10 || !strings.Contains(g.Credential, "PRIVATE KEY") {
			respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "a valid private key is required for auth_kind=ssh_key")
			return
		}
		if ref.Scheme != "ssh" {
			respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "ssh_key authentication requires an ssh://git@host/path repo_url")
			return
		}
	}

	if req.AutoDeploy != nil {
		g.AutoDeploy = *req.AutoDeploy
	}
	if req.PreviewEnabled != nil {
		g.PreviewEnabled = *req.PreviewEnabled
	}
	if req.PreviewMax != nil {
		g.PreviewMax = *req.PreviewMax
	}
	if req.PreviewTTLHours != nil {
		g.PreviewTTLHours = *req.PreviewTTLHours
	}
	if g.PreviewMax < 1 || g.PreviewMax > 50 {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "preview_max must be between 1 and 50")
		return
	}
	if g.PreviewTTLHours < 1 || g.PreviewTTLHours > 24*90 {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "preview_ttl_hours must be between 1 and 2160")
		return
	}

	revealSecret := ""
	if creating || req.RotateWebhookSecret || g.WebhookSecret == "" {
		s, err := newWebhookSecret()
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate webhook secret")
			return
		}
		g.WebhookSecret, revealSecret = s, s
	}

	saved, err := h.Git.Upsert(r.Context(), g)
	if err != nil {
		h.Logger.Error("saving git link failed", "project_id", p.ID, "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save git link")
		return
	}
	status := http.StatusOK
	if creating {
		status = http.StatusCreated
	}
	respondJSON(w, status, h.toResponse(r, saved, revealSecret))
}

// DELETE /orgs/{orgID}/projects/{projectID}/git
func (h *GitHandler) Delete(w http.ResponseWriter, r *http.Request) {
	_, p, ok := h.scope(w, r, true)
	if !ok {
		return
	}
	if err := h.Git.Delete(r.Context(), p.ID); errors.Is(err, domain.ErrNotFound) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project has no git link")
		return
	} else if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete git link")
		return
	}
	respondNoContent(w)
}

// POST /orgs/{orgID}/projects/{projectID}/git/test
func (h *GitHandler) Test(w http.ResponseWriter, r *http.Request) {
	_, p, ok := h.scope(w, r, true)
	if !ok {
		return
	}
	g, err := h.Git.Get(r.Context(), p.ID)
	if errors.Is(err, domain.ErrNotFound) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project has no git link")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load git link")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	branches, err := h.Fetcher.ListBranches(ctx, g.RepoURL, gitsource.Auth{Kind: g.AuthKind, Credential: g.Credential})
	if err != nil {
		respondJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	found := false
	for _, b := range branches {
		if b == g.Branch {
			found = true
		}
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": true, "branches": branches, "branch_found": found})
}

type previewResponse struct {
	ProjectID        uuid.UUID  `json:"project_id"`
	Slug             string     `json:"slug"`
	PR               int        `json:"pr"`
	Status           string     `json:"status"`
	URL              string     `json:"url,omitempty"`
	DeploymentID     *uuid.UUID `json:"deployment_id,omitempty"`
	DeploymentStatus string     `json:"deployment_status,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// GET /orgs/{orgID}/projects/{projectID}/previews
func (h *GitHandler) Previews(w http.ResponseWriter, r *http.Request) {
	_, p, ok := h.scope(w, r, false)
	if !ok {
		return
	}
	list, err := h.Git.ListPreviews(r.Context(), p.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list previews")
		return
	}
	out := make([]previewResponse, 0, len(list))
	for _, pv := range list {
		url := ""
		if h.Service != nil {
			url = h.Service.AppURL(pv.Slug)
		}
		out = append(out, previewResponse{
			ProjectID: pv.ProjectID, Slug: pv.Slug, PR: pv.PR, Status: pv.Status, URL: url,
			DeploymentID: pv.LatestDeployment, DeploymentStatus: pv.DeploymentStatus,
			ExpiresAt: pv.ExpiresAt, CreatedAt: pv.CreatedAt,
		})
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": out})
}
