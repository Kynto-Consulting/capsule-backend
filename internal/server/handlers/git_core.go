package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/forgejo"
	"github.com/kynto/capsule/backend/internal/gitsource"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

const (
	gitViewTTL      = 20 * time.Second
	gitViewTimeout  = 15 * time.Second
	commitsPageSize = 30
	pullsLimit      = 50
	deploymentScan  = 100 // most recent deployments joined to commits
)

// GitCoreHandler serves the core-Git (Forgejo) endpoints and the Git views of
// the dashboard (branches, commits, pull requests) plus API-driven previews.
type GitCoreHandler struct {
	authzHolder
	gh          *GitHandler
	core        *forgejo.Core
	deployments domain.DeploymentRepository
	cache       *ttlCache
	// Test seams (nil = production behaviour).
	clientFor  func(*domain.ProjectGit) (*gitsource.ProviderClient, error)
	runPreview func(ctx context.Context, link *domain.ProjectGit, p *domain.Project, ev *gitsource.Event) error
	// previewWait is how long POST /previews waits for the build to be queued
	// before answering 202 (the work continues in the background).
	previewWait time.Duration
}

// NewGitCoreHandler wires the handler on top of the git link module.
func NewGitCoreHandler(gh *GitHandler, core *forgejo.Core, deployments domain.DeploymentRepository) *GitCoreHandler {
	return &GitCoreHandler{gh: gh, core: core, deployments: deployments, cache: newTTLCache(gitViewTTL), previewWait: 25 * time.Second}
}

// ---- tiny TTL cache ----------------------------------------------------------

type ttlEntry struct {
	v   any
	exp time.Time
}

type ttlCache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]ttlEntry
	now func() time.Time
}

func newTTLCache(ttl time.Duration) *ttlCache {
	return &ttlCache{ttl: ttl, m: map[string]ttlEntry{}, now: time.Now}
}

func (c *ttlCache) get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || !c.now().Before(e.exp) {
		delete(c.m, key)
		return nil, false
	}
	return e.v, true
}

func (c *ttlCache) put(key string, v any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.m) >= 512 {
		for k, e := range c.m {
			if !now.Before(e.exp) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= 512 {
			c.m = map[string]ttlEntry{}
		}
	}
	c.m[key] = ttlEntry{v: v, exp: now.Add(c.ttl)}
}

// ---- common ------------------------------------------------------------------

// project parses ids, authorizes act and loads the project (errors are written).
func (h *GitCoreHandler) project(w http.ResponseWriter, r *http.Request, act authz.Action) (*domain.Project, bool) {
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return nil, false
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return nil, false
	}
	if !h.authorize(w, r, h.gh.Orgs, orgID, projectID, act) {
		return nil, false
	}
	p, err := h.gh.Projects.GetByID(r.Context(), projectID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && p.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return nil, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load project")
		return nil, false
	}
	return p, true
}

func (h *GitCoreHandler) link(w http.ResponseWriter, r *http.Request, p *domain.Project) (*domain.ProjectGit, bool) {
	g, err := h.gh.Git.Get(r.Context(), p.ID)
	if errors.Is(err, domain.ErrNotFound) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project has no git link")
		return nil, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load git link")
		return nil, false
	}
	return g, true
}

// ---- POST/GET /git/repo --------------------------------------------------------

type repoURLs struct {
	WebURL     string `json:"web_url"`
	CloneHTTPS string `json:"clone_url_https"`
	CloneSSH   string `json:"clone_url_ssh"`
}

type createRepoRequest struct {
	ImportURL string `json:"import_url"`
}

// CreateRepo handles POST /orgs/{orgID}/projects/{projectID}/git/repo: creates the
// Forgejo repository (optionally importing import_url) and the git link.
func (h *GitCoreHandler) CreateRepo(w http.ResponseWriter, r *http.Request) {
	p, ok := h.project(w, r, authz.ProjectOps)
	if !ok {
		return
	}
	if !h.core.Enabled() {
		respondError(w, http.StatusNotImplemented, "NOT_CONFIGURED", "the core Git service is not configured on this server")
		return
	}
	var req createRepoRequest
	if body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10)); len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
			return
		}
	}
	if is, err := h.gh.Git.IsPreview(r.Context(), p.ID); err == nil && is {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "preview projects cannot have a git link")
		return
	}
	req.ImportURL = strings.TrimSpace(req.ImportURL)
	if req.ImportURL != "" {
		// Same SSRF validation as the git link module, answered immediately.
		if _, _, err := h.gh.Policy.ValidateRepoURL(r.Context(), req.ImportURL); err != nil {
			respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
			return
		}
	}

	type outcome struct {
		res *forgejo.Result
		err error
	}
	done := make(chan outcome, 1)
	h.core.Go(10*time.Minute, func(ctx context.Context) {
		res, err := h.core.Provision(ctx, p.ID, req.ImportURL)
		done <- outcome{res, err}
	})
	select {
	case o := <-done:
		if o.err != nil {
			h.repoError(w, p.ID, o.err)
			return
		}
		respondJSON(w, http.StatusOK, repoURLs{WebURL: o.res.WebURL, CloneHTTPS: o.res.CloneHTTPS, CloneSSH: o.res.CloneSSH})
	case <-time.After(h.previewWait):
		// Slow import: keep going in the background; status is visible at GET .../git/repo.
		respondJSON(w, http.StatusAccepted, h.pendingURLs(r.Context(), p))
	case <-r.Context().Done():
	}
}

func (h *GitCoreHandler) pendingURLs(ctx context.Context, p *domain.Project) repoURLs {
	if !h.core.Enabled() || h.core.Orgs == nil {
		return repoURLs{}
	}
	org, err := h.core.Orgs.GetByID(ctx, p.OrgID)
	if err != nil {
		return repoURLs{}
	}
	cfg := h.core.Client.Cfg
	return repoURLs{WebURL: cfg.WebURL(org.Slug, p.Slug), CloneHTTPS: cfg.CloneHTTPS(org.Slug, p.Slug), CloneSSH: cfg.CloneSSH(org.Slug, p.Slug)}
}

func (h *GitCoreHandler) repoError(w http.ResponseWriter, projectID uuid.UUID, err error) {
	switch {
	case errors.Is(err, forgejo.ErrAlreadyLinked):
		respondError(w, http.StatusConflict, "CONFLICT", "project already has a git link to another provider; remove it first")
	case errors.Is(err, forgejo.ErrInvalidImport):
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
	case errors.Is(err, forgejo.ErrDisabled):
		respondError(w, http.StatusNotImplemented, "NOT_CONFIGURED", "the core Git service is not configured on this server")
	case errors.Is(err, domain.ErrNotFound):
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
	default:
		h.gh.Logger.Warn("git core: provisioning request failed", "project_id", projectID, "error", err)
		respondError(w, http.StatusBadGateway, "GIT_SERVICE_ERROR", "the Git service could not provision the repository; it will be retried, see GET .../git/repo")
	}
}

type repoStatusResponse struct {
	Status    string `json:"status"` // pending | ready | failed
	Attempts  int    `json:"attempts"`
	LastError string `json:"last_error,omitempty"`
	repoURLs
}

// RepoStatus handles GET /orgs/{orgID}/projects/{projectID}/git/repo (provisioning state).
func (h *GitCoreHandler) RepoStatus(w http.ResponseWriter, r *http.Request) {
	p, ok := h.project(w, r, authz.ProjectRead)
	if !ok {
		return
	}
	if !h.core.Enabled() {
		respondError(w, http.StatusNotImplemented, "NOT_CONFIGURED", "the core Git service is not configured on this server")
		return
	}
	resp := repoStatusResponse{repoURLs: h.pendingURLs(r.Context(), p)}
	st, err := h.core.Status(r.Context(), p.ID)
	switch {
	case err == nil:
		resp.Status, resp.Attempts, resp.LastError = st.Status, st.Attempts, st.LastError
	case errors.Is(err, domain.ErrNotFound):
		g, gerr := h.gh.Git.Get(r.Context(), p.ID)
		if gerr != nil || g.Provider != "forgejo" {
			respondError(w, http.StatusNotFound, "NOT_FOUND", "project has no repository in the core Git service")
			return
		}
		resp.Status = domain.GitCoreReady
	default:
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load provisioning state")
		return
	}
	respondJSON(w, http.StatusOK, resp)
}

// ---- views -------------------------------------------------------------------

// viewClient builds the provider client for the link. Forgejo links without their
// own credential use the service token (only against the configured Forgejo host).
func (h *GitCoreHandler) viewClient(link *domain.ProjectGit) (*gitsource.ProviderClient, error) {
	if h.clientFor != nil {
		return h.clientFor(link)
	}
	switch link.Provider {
	case "forgejo", "gitea", "github":
	default:
		return nil, gitsource.ErrUnsupported
	}
	token := ""
	if link.AuthKind == "token" {
		token = link.Credential
	}
	if token == "" && link.Provider == "forgejo" && h.core.Enabled() {
		if ref, err := gitsource.ParseRepoURL(link.RepoURL); err == nil && ref.Host == h.core.Client.Cfg.Host() {
			token = h.core.Client.Cfg.Token
		}
	}
	return gitsource.NewReadClient(link.Provider, link.RepoURL, token, h.gh.Policy.NewHTTPClient(gitViewTimeout))
}

// viewScope authorizes ProjectRead and returns project, link and provider client.
func (h *GitCoreHandler) viewScope(w http.ResponseWriter, r *http.Request) (*domain.Project, *domain.ProjectGit, *gitsource.ProviderClient, bool) {
	p, ok := h.project(w, r, authz.ProjectRead)
	if !ok {
		return nil, nil, nil, false
	}
	link, ok := h.link(w, r, p)
	if !ok {
		return nil, nil, nil, false
	}
	c, err := h.viewClient(link)
	if err != nil {
		respondError(w, http.StatusUnprocessableEntity, "UNSUPPORTED_PROVIDER", "this view needs a forgejo, gitea or github repository")
		return nil, nil, nil, false
	}
	return p, link, c, true
}

func (h *GitCoreHandler) providerFailed(w http.ResponseWriter, p *domain.Project, what string, err error) {
	h.gh.Logger.Warn("git view failed", "project_id", p.ID, "view", what, "error", err)
	respondError(w, http.StatusBadGateway, "PROVIDER_ERROR", "could not read "+what+" from the git provider")
}

type branchView struct {
	Name      string `json:"name"`
	SHA       string `json:"sha"`
	Default   bool   `json:"default"`
	Protected bool   `json:"protected"`
}

// Branches handles GET .../git/branches.
func (h *GitCoreHandler) Branches(w http.ResponseWriter, r *http.Request) {
	p, link, c, ok := h.viewScope(w, r)
	if !ok {
		return
	}
	key := "branches|" + p.ID.String() + "|" + link.RepoURL
	var out []branchView
	if v, hit := h.cache.get(key); hit {
		out = v.([]branchView)
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), gitViewTimeout)
		defer cancel()
		branches, err := c.Branches(ctx)
		if err != nil {
			h.providerFailed(w, p, "branches", err)
			return
		}
		def, err := c.DefaultBranch(ctx)
		if err != nil || def == "" {
			def = link.Branch
		}
		out = make([]branchView, 0, len(branches))
		for _, b := range branches {
			out = append(out, branchView{Name: b.Name, SHA: b.SHA, Default: b.Name == def, Protected: b.Protected})
		}
		h.cache.put(key, out)
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": out})
}

type commitDeployment struct {
	ID     uuid.UUID `json:"id"`
	Status string    `json:"status"`
}

type commitView struct {
	SHA        string            `json:"sha"`
	ShortSHA   string            `json:"short_sha"`
	Message    string            `json:"message"`
	Author     string            `json:"author"`
	AuthoredAt time.Time         `json:"authored_at"`
	URL        string            `json:"url"`
	Deployment *commitDeployment `json:"deployment"`
}

type commitsPage struct {
	items []gitsource.CommitInfo
	more  bool
}

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

func subject(msg string) string {
	msg = strings.TrimSpace(msg)
	if i := strings.IndexAny(msg, "\r\n"); i >= 0 {
		msg = msg[:i]
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// deploymentsBySHA maps commit sha -> newest deployment of the project (full and 7-char keys).
func (h *GitCoreHandler) deploymentsBySHA(ctx context.Context, projectID uuid.UUID) map[string]*commitDeployment {
	out := map[string]*commitDeployment{}
	if h.deployments == nil {
		return out
	}
	list, _, err := h.deployments.ListByProject(ctx, projectID, 1, deploymentScan)
	if err != nil {
		return out
	}
	for _, d := range list { // newest first
		sha := strings.ToLower(d.GitSHA)
		if sha == "" {
			continue
		}
		cd := &commitDeployment{ID: d.ID, Status: d.Status}
		for _, k := range []string{sha, shortSHA(sha)} {
			if _, seen := out[k]; !seen {
				out[k] = cd
			}
		}
	}
	return out
}

// Commits handles GET .../git/commits?branch=&page=.
func (h *GitCoreHandler) Commits(w http.ResponseWriter, r *http.Request) {
	p, link, c, ok := h.viewScope(w, r)
	if !ok {
		return
	}
	branch := strings.TrimSpace(r.URL.Query().Get("branch"))
	if branch == "" {
		branch = link.Branch
	}
	if !gitsource.ValidBranch(branch) {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "invalid branch name")
		return
	}
	page := 1
	if v := r.URL.Query().Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "page must be between 1 and 1000")
			return
		}
		page = n
	}
	key := "commits|" + p.ID.String() + "|" + link.RepoURL + "|" + url.QueryEscape(branch) + "|" + strconv.Itoa(page)
	var cp commitsPage
	if v, hit := h.cache.get(key); hit {
		cp = v.(commitsPage)
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), gitViewTimeout)
		defer cancel()
		items, more, err := c.Commits(ctx, branch, page, commitsPageSize)
		if err != nil {
			h.providerFailed(w, p, "commits", err)
			return
		}
		cp = commitsPage{items: items, more: more}
		h.cache.put(key, cp)
	}
	deps := h.deploymentsBySHA(r.Context(), p.ID)
	out := make([]commitView, 0, len(cp.items))
	for _, it := range cp.items {
		sha := strings.ToLower(it.SHA)
		d := deps[sha]
		if d == nil {
			d = deps[shortSHA(sha)]
		}
		out = append(out, commitView{
			SHA: it.SHA, ShortSHA: shortSHA(it.SHA), Message: subject(it.Message), Author: it.Author,
			AuthoredAt: it.AuthoredAt, URL: it.URL, Deployment: d,
		})
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": out, "page": page, "has_more": cp.more})
}

type pullPreview struct {
	URL       string     `json:"url"`
	Status    string     `json:"status"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type pullView struct {
	Number  int          `json:"number"`
	Title   string       `json:"title"`
	Author  string       `json:"author"`
	State   string       `json:"state"`
	HeadRef string       `json:"head_ref"`
	BaseRef string       `json:"base_ref"`
	URL     string       `json:"url"`
	Preview *pullPreview `json:"preview"`
}

func (h *GitCoreHandler) appURL(slug string) string {
	if h.gh.Service == nil {
		return ""
	}
	return h.gh.Service.AppURL(slug)
}

// Pulls handles GET .../git/pulls?state=open|closed|all.
func (h *GitCoreHandler) Pulls(w http.ResponseWriter, r *http.Request) {
	p, link, c, ok := h.viewScope(w, r)
	if !ok {
		return
	}
	state := r.URL.Query().Get("state")
	if state == "" {
		state = "open"
	}
	if state != "open" && state != "closed" && state != "all" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "state must be one of open, closed, all")
		return
	}
	key := "pulls|" + p.ID.String() + "|" + link.RepoURL + "|" + state
	var pulls []gitsource.PullInfo
	if v, hit := h.cache.get(key); hit {
		pulls = v.([]gitsource.PullInfo)
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), gitViewTimeout)
		defer cancel()
		var err error
		if pulls, err = c.Pulls(ctx, state, pullsLimit); err != nil {
			h.providerFailed(w, p, "pull requests", err)
			return
		}
		h.cache.put(key, pulls)
	}
	previews := map[int]*domain.Preview{}
	if list, err := h.gh.Git.ListPreviews(r.Context(), p.ID); err == nil {
		for _, pv := range list {
			previews[pv.PR] = pv
		}
	}
	out := make([]pullView, 0, len(pulls))
	for _, pr := range pulls {
		v := pullView{Number: pr.Number, Title: pr.Title, Author: pr.Author, State: pr.State, HeadRef: pr.HeadRef, BaseRef: pr.BaseRef, URL: pr.URL}
		if pv := previews[pr.Number]; pv != nil {
			status := pv.DeploymentStatus
			if status == "" {
				status = pv.Status
			}
			v.Preview = &pullPreview{URL: h.appURL(pv.Slug), Status: status, ExpiresAt: pv.ExpiresAt}
		}
		out = append(out, v)
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": out})
}

// ---- previews by API -------------------------------------------------------------

type createPreviewRequest struct {
	PR  int    `json:"pr"`
	Ref string `json:"ref"`
	SHA string `json:"sha"`
}

type previewAPIResponse struct {
	PR           int        `json:"pr"`
	URL          string     `json:"url"`
	Status       string     `json:"status"`
	DeploymentID *uuid.UUID `json:"deployment_id"`
}

func previewStatus(pv *domain.Preview) string {
	if pv.DeploymentStatus != "" {
		return pv.DeploymentStatus
	}
	return "building"
}

// CreatePreview handles POST .../previews (CI without webhook): builds a preview of ref.
func (h *GitCoreHandler) CreatePreview(w http.ResponseWriter, r *http.Request) {
	p, ok := h.project(w, r, authz.ProjectDeploy)
	if !ok {
		return
	}
	var req createPreviewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	req.Ref, req.SHA = strings.TrimSpace(req.Ref), strings.TrimSpace(req.SHA)
	if req.PR < 1 || req.PR > 99999999 {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "pr must be a positive pull request number")
		return
	}
	if !gitsource.ValidBranch(req.Ref) {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "invalid ref")
		return
	}
	if req.SHA != "" && !gitsource.ValidSHA(req.SHA) {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "invalid sha")
		return
	}
	if is, err := h.gh.Git.IsPreview(r.Context(), p.ID); err == nil && is {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "previews cannot be created from a preview project")
		return
	}
	link, ok := h.link(w, r, p)
	if !ok {
		return
	}
	if !link.PreviewEnabled {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "previews are not enabled for this project (set preview_enabled on the git link)")
		return
	}
	if h.gh.Service == nil {
		respondError(w, http.StatusNotImplemented, "NOT_CONFIGURED", "previews are not configured on this server")
		return
	}
	_, existErr := h.gh.Git.GetPreview(r.Context(), p.ID, req.PR)
	existed := existErr == nil

	actor := "api"
	if u := middleware.GetUser(r.Context()); u != nil && u.Name != "" {
		actor = u.Name
	}
	ev := &gitsource.Event{
		Kind: gitsource.EventPullRequest, Action: "synchronize", PR: req.PR, Branch: req.Ref, SHA: req.SHA,
		Actor: actor, Provider: link.Provider,
	}
	done := make(chan error, 1)
	h.gh.Service.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		run := h.gh.Service.HandlePullRequest
		if h.runPreview != nil {
			run = h.runPreview
		}
		done <- run(ctx, link, p, ev)
	})
	select {
	case err := <-done:
		if err != nil {
			h.gh.Logger.Warn("preview via API failed", "project_id", p.ID, "pr", req.PR, "error", err)
			respondError(w, http.StatusBadGateway, "PREVIEW_FAILED", "the preview could not be started")
			return
		}
		pv, err := h.gh.Git.GetPreview(r.Context(), p.ID, req.PR)
		if err != nil {
			respondError(w, http.StatusConflict, "PREVIEW_SUPERSEDED", "the preview request was superseded by a newer one")
			return
		}
		status := http.StatusOK
		if !existed {
			status = http.StatusCreated
		}
		respondJSON(w, status, previewAPIResponse{PR: req.PR, URL: h.appURL(pv.Slug), Status: previewStatus(pv), DeploymentID: pv.LatestDeployment})
	case <-time.After(h.previewWait):
		slug, _ := gitsource.PreviewSlug(p.Slug, req.PR)
		respondJSON(w, http.StatusAccepted, previewAPIResponse{PR: req.PR, URL: h.appURL(slug), Status: "building"})
	case <-r.Context().Done():
	}
}

// DeletePreview handles DELETE .../previews/{pr}.
func (h *GitCoreHandler) DeletePreview(w http.ResponseWriter, r *http.Request) {
	p, ok := h.project(w, r, authz.ProjectDeploy)
	if !ok {
		return
	}
	pr, err := strconv.Atoi(chi.URLParam(r, "pr"))
	if err != nil || pr < 1 {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid pull request number")
		return
	}
	pv, err := h.gh.Git.GetPreview(r.Context(), p.ID, pr)
	if errors.Is(err, domain.ErrNotFound) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "preview not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load preview")
		return
	}
	if h.gh.Service == nil {
		respondError(w, http.StatusNotImplemented, "NOT_CONFIGURED", "previews are not configured on this server")
		return
	}
	link, _ := h.gh.Git.Get(r.Context(), p.ID) // nil link is fine: no PR comment is updated
	if err := h.gh.Service.DestroyPreview(r.Context(), link, pv, "closed"); err != nil {
		h.gh.Logger.Warn("deleting preview via API failed", "project_id", p.ID, "pr", pr, "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete preview")
		return
	}
	respondNoContent(w)
}
