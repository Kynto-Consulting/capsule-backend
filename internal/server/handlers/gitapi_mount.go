package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitsource"
	"github.com/kynto/capsule/backend/internal/oidc"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// Git Capsule package B1: the Git API (repo, tree/blob/compare, branches, tags, commits, pull
// requests, Actions, CI variables/secrets, activity, insights). Every route enforces the
// x-permission of docs/git-capsule/API.openapi.yaml with authz (404 for hidden projects, 403 for an
// insufficient role) and reaches Forgejo only through gitcore.

// GitAPIDeps is what MountGitAPI needs from the router. Everything but Authz/Orgs/Projects is
// optional.
type GitAPIDeps struct {
	Core        gitcore.Core // nil = gitcore.Shared()
	Authz       *authz.Service
	Orgs        domain.OrganizationRepository
	Projects    domain.ProjectRepository
	Git         *GitHandler     // link provider + preview URLs; nil = every project is treated as a Forgejo project, no previews
	Legacy      *GitCoreHandler // provisioning state and the pre-B1 views of non-Forgejo links; may be nil
	Deployments domain.DeploymentRepository
	Cache       gitcore.Cache // idempotency keys shared between instances; nil = memory only
	// Actor returns the Forgejo login a Capsule user acts as (Sudo). nil = the Legacy core's
	// derivation (OIDC preferred_username) or, without it, the sanitized e-mail local part.
	// Package A2 plugs its git_identities lookup here.
	Actor  func(ctx context.Context, u *domain.User) (string, error)
	Logger *slog.Logger
}

type gitAPI struct {
	authzHolder
	d    GitAPIDeps
	idem *gitapi.IdemStore
	lg   *slog.Logger
}

// MountGitAPI registers the B1 routes on the authenticated /api/v1 router.
func MountGitAPI(r chi.Router, d GitAPIDeps) {
	a := &gitAPI{d: d, idem: gitapi.NewIdemStore(d.Cache), lg: d.Logger}
	if a.lg == nil {
		a.lg = slog.Default()
	}
	a.svc = d.Authz
	const p = "/orgs/{orgID}/projects/{projectID}/git"
	const o = "/orgs/{orgID}/git"

	// Code
	r.Get(p+"/repo", a.repoGet)
	if d.Legacy != nil {
		r.Post(p+"/repo", a.repoProvision)
	}
	r.Patch(p+"/repo", a.repoUpdate)
	r.Get(p+"/tree", a.repoTree)
	r.Get(p+"/blob", a.repoBlob)
	r.Get(p+"/compare", a.repoCompare)
	// Branches and tags
	r.Get(p+"/branches", a.branchesList)
	r.Post(p+"/branches", a.branchCreate)
	r.Delete(p+"/branches/*", a.branchDelete) // wildcard: branch names contain slashes
	r.Get(p+"/tags", a.tagsList)
	r.Post(p+"/tags", a.tagCreate)
	r.Delete(p+"/tags/*", a.tagDelete)
	// Commits
	r.Get(p+"/commits", a.commitsList)
	r.Get(p+"/commits/{sha}", a.commitGet)
	r.Get(p+"/commits/{sha}/checks", a.commitChecks)
	// Pull requests
	r.Get(p+"/pulls", a.pullsList)
	r.Post(p+"/pulls", a.pullCreate)
	r.Get(p+"/pulls/{n}", a.pullGet)
	r.Patch(p+"/pulls/{n}", a.pullUpdate)
	r.Get(p+"/pulls/{n}/files", a.pullFiles)
	r.Get(p+"/pulls/{n}/commits", a.pullCommits)
	r.Get(p+"/pulls/{n}/reviews", a.reviewsList)
	r.Post(p+"/pulls/{n}/reviews", a.reviewCreate)
	r.Get(p+"/pulls/{n}/comments", a.commentsList)
	r.Post(p+"/pulls/{n}/comments", a.commentCreate)
	r.Post(p+"/pulls/{n}/merge", a.pullMerge)
	r.Post(p+"/pulls/{n}/update-branch", a.pullUpdateBranch)
	r.Get(p+"/pulls/{n}/checks", a.pullChecks)
	// Actions
	r.Get(p+"/workflows", a.workflowsList)
	r.Post(p+"/workflows/{workflowID}/dispatch", a.workflowDispatch)
	r.Get(p+"/runs", a.runsList)
	r.Get(p+"/runs/{runID}", a.runGet)
	r.Get(p+"/runs/{runID}/jobs/{jobID}/logs", a.jobLogs)
	r.Post(p+"/runs/{runID}/rerun", a.runRerun)
	r.Post(p+"/runs/{runID}/cancel", a.runCancel)
	r.Get(p+"/runs/{runID}/artifacts", a.artifactsList)
	r.Get(p+"/secrets", a.ciSecretsList)
	r.Put(p+"/secrets/{name}", a.ciSecretPut)
	r.Delete(p+"/secrets/{name}", a.ciSecretDelete)
	r.Get(p+"/variables", a.ciVarsList)
	r.Put(p+"/variables/{name}", a.ciVarPut)
	r.Delete(p+"/variables/{name}", a.ciVarDelete)
	r.Get(o+"/secrets", a.orgCiSecretsList)
	r.Put(o+"/secrets/{name}", a.orgCiSecretPut)
	r.Delete(o+"/secrets/{name}", a.orgCiSecretDelete)
	r.Get(o+"/variables", a.orgCiVarsList)
	r.Put(o+"/variables/{name}", a.orgCiVarPut)
	r.Delete(o+"/variables/{name}", a.orgCiVarDelete)
	r.Get(o+"/runners", a.runnersList)
	// Activity
	r.Get(p+"/activity", a.activityList)
	r.Get(p+"/insights", a.insights)
}

// ---- request scope --------------------------------------------------------------------------

type gitScope struct {
	proj *domain.Project
	org  *domain.Organization
	user *domain.User
	ref  gitcore.RepoRef
	core gitcore.Core
	ctx  context.Context
}

func (a *gitAPI) coreNow() gitcore.Core {
	if a.d.Core != nil {
		return a.d.Core
	}
	return gitcore.Shared()
}

// scope authorizes act on the project of the URL (404 hidden / 403 insufficient role), loads the
// project and organization and checks that the integration is on.
func (a *gitAPI) scope(w http.ResponseWriter, r *http.Request, act authz.Action) (*gitScope, bool) {
	sc, ok := a.scopeAuth(w, r, act)
	if !ok {
		return nil, false
	}
	if !sc.core.Enabled() {
		respondError(w, http.StatusServiceUnavailable, "GIT_NOT_READY", "the Git service is not configured on this server")
		return nil, false
	}
	return sc, true
}

// scopeAuth is scope without the "integration is on" check (used by the routes that can fall back
// to the pre-B1 views of non-Forgejo links).
func (a *gitAPI) scopeAuth(w http.ResponseWriter, r *http.Request, act authz.Action) (*gitScope, bool) {
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
	if !a.authorize(w, r, a.d.Orgs, orgID, projectID, act) {
		return nil, false
	}
	p, err := a.d.Projects.GetByID(r.Context(), projectID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && p.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return nil, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load project")
		return nil, false
	}
	org, err := a.d.Orgs.GetByID(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "organization not found")
		return nil, false
	}
	return &gitScope{proj: p, org: org, user: middleware.GetUser(r.Context()), ref: gitcore.RepoRef{Owner: org.Slug, Repo: p.Slug}, core: a.coreNow(), ctx: r.Context()}, true
}

// legacyProvider reports whether the project's git link points to a non-Forgejo provider (GitHub,
// Gitea): those keep the pre-B1 views served by GitCoreHandler.
func (a *gitAPI) legacyProvider(sc *gitScope) bool {
	if a.d.Git == nil || a.d.Legacy == nil {
		return false
	}
	g, err := a.d.Git.Git.Get(sc.ctx, sc.proj.ID)
	return err == nil && g.Provider != "forgejo"
}

// orgScope authorizes an organization-level route: any member, or admins/owners only.
func (a *gitAPI) orgScope(w http.ResponseWriter, r *http.Request, admin bool) (*gitScope, bool) {
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return nil, false
	}
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return nil, false
	}
	role, err := a.d.Orgs.GetMemberRole(r.Context(), orgID, user.ID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && role == "") {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return nil, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check permissions")
		return nil, false
	}
	if admin && !isOrgAdmin(role) {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "organization admin role required")
		return nil, false
	}
	org, err := a.d.Orgs.GetByID(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "organization not found")
		return nil, false
	}
	core := a.coreNow()
	if !core.Enabled() {
		respondError(w, http.StatusServiceUnavailable, "GIT_NOT_READY", "the Git service is not configured on this server")
		return nil, false
	}
	return &gitScope{org: org, user: user, ref: gitcore.RepoRef{Owner: org.Slug}, core: core, ctx: r.Context()}, true
}

// asUser returns the scope's context acting as the requesting user in Forgejo (Sudo). strict=true
// refuses to fall back to the service account (reviews, comments, merges, pull requests must carry
// the real author).
func (a *gitAPI) asUser(w http.ResponseWriter, sc *gitScope, strict bool) (context.Context, bool) {
	login := ""
	var err error
	if sc.user != nil {
		switch {
		case a.d.Actor != nil:
			login, err = a.d.Actor(sc.ctx, sc.user)
		case a.d.Legacy != nil && a.d.Legacy.core != nil && a.d.Legacy.core.Username != nil:
			login, err = a.d.Legacy.core.Username(sc.ctx, sc.user.ID, sc.user.Email)
		default:
			login = oidc.SanitizeUsername(sc.user.Email)
		}
	}
	if err != nil {
		a.lg.Warn("git api: resolving the Forgejo login failed", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to resolve your Git identity")
		return nil, false
	}
	if login == "" && strict {
		respondError(w, http.StatusServiceUnavailable, "GIT_NOT_READY", "your Git identity is not ready yet; sign in again and retry")
		return nil, false
	}
	return gitcore.WithActor(sc.ctx, login), true
}

// ---- errors ---------------------------------------------------------------------------------

// fail writes a gitcore error. protectedWrite marks writes where an upstream 403 means a branch or
// tag protection (409 PROTECTED_BRANCH) rather than a missing permission.
func (a *gitAPI) fail(w http.ResponseWriter, err error, protectedWrite bool) {
	e, ok := gitcore.AsError(err)
	if !ok {
		a.lg.Warn("git api: unexpected error", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		return
	}
	status, code := e.HTTPStatus(), string(e.Code)
	switch e.Code {
	case gitcore.CodeUnprocessed:
		code = "VALIDATION_ERROR"
	case gitcore.CodeForbidden:
		if protectedWrite {
			status, code = http.StatusConflict, "PROTECTED_BRANCH"
		}
	case gitcore.CodeConflict:
		if e.Status == http.StatusLocked {
			w.Header().Set("Retry-After", "2")
			code = "TRY_AGAIN"
			e = &gitcore.Error{Code: e.Code, Message: "Git is busy with this pull request; try again in a few seconds", Op: e.Op}
		}
	case gitcore.CodeUpstream, gitcore.CodeNotReady:
		if e.Retry || e.Code == gitcore.CodeNotReady {
			w.Header().Set("Retry-After", "5")
		}
	}
	respondError(w, status, code, e.Message)
}

func respondErrorDetails(w http.ResponseWriter, status int, code, message string, details map[string]any) {
	respondJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message, "details": details}})
}

func badRequest(w http.ResponseWriter, msg string) {
	respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", msg)
}

// notSupported answers capabilities gitcore does not expose yet.
func notSupported(w http.ResponseWriter, what string) {
	respondError(w, http.StatusNotImplemented, "NOT_SUPPORTED", what+" is not available from the Git service yet")
}

// ---- input helpers --------------------------------------------------------------------------

const maxBodyBytes = 256 << 10

// readBody reads (and bounds) the request body so it can be fingerprinted and decoded.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		respondError(w, http.StatusRequestEntityTooLarge, "TOO_LARGE", "request body too large")
		return nil, false
	}
	return b, true
}

// decodeStrict decodes JSON rejecting unknown fields and trailing data (an empty body decodes as {}
// when allowEmpty).
func decodeStrict(w http.ResponseWriter, body []byte, v any, allowEmpty bool) bool {
	if len(bytes.TrimSpace(body)) == 0 {
		if allowEmpty {
			return true
		}
		badRequest(w, "request body is required")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		badRequest(w, "invalid request body: "+err.Error())
		return false
	}
	if dec.More() {
		badRequest(w, "invalid request body: trailing data")
		return false
	}
	return true
}

func (a *gitAPI) readJSON(w http.ResponseWriter, r *http.Request, v any, allowEmpty bool) bool {
	b, ok := readBody(w, r)
	if !ok {
		return false
	}
	return decodeStrict(w, b, v, allowEmpty)
}

// pageParams reads ?cursor=&limit= (limit 1..100, default 30).
func pageParams(w http.ResponseWriter, r *http.Request) (gitcore.Page, bool) {
	p := gitcore.Page{Cursor: r.URL.Query().Get("cursor")}
	if len(p.Cursor) > 512 {
		badRequest(w, "invalid cursor")
		return p, false
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			badRequest(w, "limit must be an integer between 1 and 100")
			return p, false
		}
		if n > gitcore.MaxLimit {
			n = gitcore.MaxLimit
		}
		p.Limit = n
	}
	return p, true
}

type listOut[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

func newList[T any](items []T, next string) listOut[T] {
	if items == nil {
		items = []T{}
	}
	out := listOut[T]{Items: items}
	if next != "" {
		out.NextCursor = &next
	}
	return out
}

// legacyList is the pre-B1 envelope (data/has_more) that the CLI and the first dashboard read; it is
// the OpenAPI list plus those two keys.
type legacyList[T any] struct {
	listOut[T]
	Data    []T  `json:"data"`
	HasMore bool `json:"has_more"`
}

func newLegacyList[T any](items []T, next string) legacyList[T] {
	l := newList(items, next)
	return legacyList[T]{listOut: l, Data: l.Items, HasMore: next != ""}
}

func pathInt(r *http.Request, name string) (int, bool) {
	n, err := strconv.Atoi(chi.URLParam(r, name))
	return n, err == nil && n > 0
}

func pathInt64(r *http.Request, name string) (int64, bool) {
	n, err := strconv.ParseInt(chi.URLParam(r, name), 10, 64)
	return n, err == nil && n > 0
}

func pathName(r *http.Request, name string) string {
	v := chi.URLParam(r, name)
	if u, err := url.PathUnescape(v); err == nil {
		return u
	}
	return v
}

func validRefName(s string) bool { return gitsource.ValidBranch(s) || gitsource.ValidSHA(s) }

// cleanPath normalizes a repository path from a query: no leading slash, no "." / ".." segments,
// no NUL or backslash. ok=false means reject.
func cleanPath(p string) (string, bool) {
	if strings.ContainsAny(p, "\x00\\") || len(p) > 1024 {
		return "", false
	}
	p = strings.Trim(p, "/")
	if p == "" {
		return "", true
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", false
		}
	}
	return p, true
}

// defaultBranch returns the repository default branch (one cached upstream read).
func (a *gitAPI) defaultBranch(sc *gitScope) (string, *gitcore.Repository, error) {
	repo, err := sc.core.GetRepo(sc.ctx, sc.ref)
	if err != nil {
		return "", nil, err
	}
	return repo.DefaultBranch, repo, nil
}

// ---- idempotency ----------------------------------------------------------------------------

type captureWriter struct {
	h      http.Header
	status int
	buf    bytes.Buffer
}

func newCapture() *captureWriter { return &captureWriter{h: http.Header{}, status: http.StatusOK} }

func (c *captureWriter) Header() http.Header         { return c.h }
func (c *captureWriter) WriteHeader(s int)           { c.status = s }
func (c *captureWriter) Write(b []byte) (int, error) { return c.buf.Write(b) }

func (c *captureWriter) flushTo(w http.ResponseWriter) {
	for k, v := range c.h {
		for _, x := range v {
			w.Header().Add(k, x)
		}
	}
	w.WriteHeader(c.status)
	_, _ = w.Write(c.buf.Bytes())
}

// withIdempotency runs fn once per Idempotency-Key (24 h). A retry with the same key and request
// replays the stored 2xx response (header Idempotent-Replayed: true); the same key with another
// request, or while the first is still running, answers 409 IDEMPOTENCY_CONFLICT. Failed attempts
// are forgotten so they can be retried. Without the header fn runs directly.
func (a *gitAPI) withIdempotency(w http.ResponseWriter, r *http.Request, sc *gitScope, op string, body []byte, fn func(w http.ResponseWriter)) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		fn(w)
		return
	}
	if len(key) > 128 {
		badRequest(w, "Idempotency-Key must be at most 128 characters")
		return
	}
	uid := ""
	if sc.user != nil {
		uid = sc.user.ID.String()
	}
	scopeKey := uid + "|" + sc.ref.String() + "|" + op
	fp := gitapi.Fingerprint(r.Method, r.URL.Path, body)
	st, state, done := a.idem.Begin(r.Context(), scopeKey, key, fp)
	switch state {
	case gitapi.IdemReplay:
		if st.ContentType != "" {
			w.Header().Set("Content-Type", st.ContentType)
		}
		w.Header().Set("Idempotent-Replayed", "true")
		w.WriteHeader(st.Status)
		_, _ = w.Write(st.Body)
		return
	case gitapi.IdemConflict:
		respondError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "this Idempotency-Key was used for a different request or is still being processed")
		return
	}
	cw := newCapture()
	fn(cw)
	if cw.status >= 200 && cw.status < 300 {
		done(&gitapi.Stored{Status: cw.status, ContentType: cw.h.Get("Content-Type"), Body: cw.buf.Bytes()})
	} else {
		done(nil)
	}
	cw.flushTo(w)
}
