package handlers

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitreview"
	"github.com/kynto/capsule/backend/internal/oidc"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// Git Capsule package B8: CODEOWNERS, reviewers, dismissals, draft -> ready and auto-merge.
// pullUpdateBranch (also a B8 operationId) is served by B1 (gitapi_pulls.go): it is not mounted twice.

// GitReviewDeps is what MountGitReview needs.
type GitReviewDeps struct {
	Authz    *authz.Service
	Orgs     domain.OrganizationRepository
	Projects domain.ProjectRepository
	// Svc nil = gitreview.Shared() (published by the wiring), looked up per request.
	Svc  *gitreview.Service
	Core gitcore.Core // nil = gitcore.Shared()
	// Actor returns the Forgejo login a Capsule user acts as (Sudo); same hook as GitAPIDeps.Actor.
	Actor  func(ctx context.Context, u *domain.User) (string, error)
	Logger *slog.Logger
}

type gitReview struct {
	authzHolder
	d  GitReviewDeps
	lg *slog.Logger
}

// MountGitReview registers the B8 routes on the authenticated /api/v1 router.
func MountGitReview(r chi.Router, d GitReviewDeps) {
	h := &gitReview{d: d, lg: d.Logger}
	if h.lg == nil {
		h.lg = slog.Default()
	}
	h.svc = d.Authz
	const p = "/orgs/{orgID}/projects/{projectID}/git"
	r.Get(p+"/codeowners", h.codeownersGet)
	r.Put(p+"/pulls/{n}/auto-merge", h.autoMergeEnable)
	r.Delete(p+"/pulls/{n}/auto-merge", h.autoMergeDisable)
	r.Post(p+"/pulls/{n}/ready", h.pullReady)
	r.Post(p+"/pulls/{n}/reviewers", h.reviewersRequest)
	r.Post(p+"/pulls/{n}/reviews/{reviewID}/dismiss", h.reviewDismiss)
}

type reviewScope struct {
	svc  *gitreview.Service
	core gitcore.Core
	proj gitreview.Project
	user *domain.User
	ctx  context.Context
}

func (h *gitReview) scope(w http.ResponseWriter, r *http.Request, act authz.Action) (*reviewScope, bool) {
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
	if !h.authorize(w, r, h.d.Orgs, orgID, projectID, act) {
		return nil, false
	}
	svc := h.d.Svc
	if svc == nil {
		svc = gitreview.Shared()
	}
	core := h.d.Core
	if core == nil {
		core = gitcore.Shared()
	}
	if svc == nil {
		respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "code review automation is not configured")
		return nil, false
	}
	if !core.Enabled() {
		respondError(w, http.StatusServiceUnavailable, "GIT_NOT_READY", "the Git service is not configured on this server")
		return nil, false
	}
	p, err := h.d.Projects.GetByID(r.Context(), projectID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && p.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return nil, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load project")
		return nil, false
	}
	org, err := h.d.Orgs.GetByID(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "organization not found")
		return nil, false
	}
	return &reviewScope{svc: svc, core: core, user: middleware.GetUser(r.Context()), ctx: r.Context(),
		proj: gitreview.Project{ID: p.ID, OrgID: orgID, Ref: gitcore.RepoRef{Owner: org.Slug, Repo: p.Slug}}}, true
}

func (h *gitReview) pullScope(w http.ResponseWriter, r *http.Request, act authz.Action) (*reviewScope, int, bool) {
	sc, ok := h.scope(w, r, act)
	if !ok {
		return nil, 0, false
	}
	n, ok := pathInt(r, "n")
	if !ok {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid pull request number")
		return nil, 0, false
	}
	return sc, n, true
}

// login returns the Forgejo login of the requester ("" when it cannot be known).
func (h *gitReview) login(sc *reviewScope) (string, error) {
	if sc.user == nil {
		return "", nil
	}
	if h.d.Actor != nil {
		return h.d.Actor(sc.ctx, sc.user)
	}
	return oidc.SanitizeUsername(sc.user.Email), nil
}

// asUser acts as the requester in Forgejo; strict refuses to fall back to the service account.
func (h *gitReview) asUser(w http.ResponseWriter, sc *reviewScope, strict bool) (context.Context, string, bool) {
	login, err := h.login(sc)
	if err != nil {
		h.lg.Warn("git review: resolving the Forgejo login failed", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to resolve your Git identity")
		return nil, "", false
	}
	if login == "" && strict {
		respondError(w, http.StatusServiceUnavailable, "GIT_NOT_READY", "your Git identity is not ready yet; sign in again and retry")
		return nil, "", false
	}
	return gitcore.WithActor(sc.ctx, login), login, true
}

func (h *gitReview) fail(w http.ResponseWriter, err error, protectedWrite bool) {
	var ve *gitreview.ValidationError
	switch {
	case errors.As(err, &ve):
		badRequest(w, ve.Msg)
	case errors.Is(err, gitreview.ErrNotOpen):
		respondError(w, http.StatusConflict, "CONFLICT", "the pull request is not open")
	case errors.Is(err, gitreview.ErrHeadChanged):
		respondError(w, http.StatusConflict, "HEAD_CHANGED", "the head of the pull request changed; review it again and retry with the new head_sha")
	case errors.Is(err, gitreview.ErrDraft):
		respondError(w, http.StatusUnprocessableEntity, "DRAFT", "the pull request is a draft; mark it ready for review first")
	case errors.Is(err, gitreview.ErrReviewNotDismissable):
		respondError(w, http.StatusConflict, "CONFLICT", "only an approval or a change request can be dismissed")
	case errors.Is(err, gitreview.ErrNotSupported):
		respondError(w, http.StatusNotImplemented, "NOT_SUPPORTED", "dismissing reviews is not available from the Git service")
	default:
		if e, ok := gitcore.AsError(err); ok {
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
				}
			case gitcore.CodeUpstream, gitcore.CodeNotReady:
				w.Header().Set("Retry-After", "5")
			}
			respondError(w, status, code, e.Message)
			return
		}
		h.lg.Warn("git review: unexpected error", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
	}
}

// pullDoc builds the Pull document like B1 does (mergeability fails closed).
func (h *gitReview) pullDoc(sc *reviewScope, p gitcore.Pull) gitapi.PullOut {
	out := gitapi.ToPull(p)
	if as, err := gitapi.Assess(sc.ctx, sc.core, sc.proj.Ref, p); err != nil {
		h.lg.Warn("git review: mergeability could not be evaluated", "project_id", sc.proj.ID, "pr", p.Number, "error", err)
		out.Mergeable = &gitapi.Mergeability{Blockers: []gitapi.Blocker{{Code: gitapi.BlockPolicy,
			Message: "merge requirements could not be evaluated right now; try again"}}}
	} else {
		m := as.Mergeability
		out.Mergeable, out.ChecksState = &m, as.ChecksState()
	}
	gitapi.DecoratePull(sc.proj.Ref, p, &out)
	return out
}

// codeownersGet: GET .../git/codeowners?ref=
func (h *gitReview) codeownersGet(w http.ResponseWriter, r *http.Request) {
	sc, ok := h.scope(w, r, authz.GitRead)
	if !ok {
		return
	}
	ref := strings.TrimSpace(r.URL.Query().Get("ref"))
	if ref != "" && !validRefName(ref) {
		badRequest(w, "invalid ref")
		return
	}
	doc, err := sc.svc.CodeownersView(sc.ctx, sc.proj, ref)
	if err != nil {
		h.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusOK, doc)
}

type autoMergeIn struct {
	Style        string `json:"style"`
	Title        string `json:"title"`
	Message      string `json:"message"`
	DeleteBranch bool   `json:"delete_branch"`
	HeadSHA      string `json:"head_sha"`
}

var shaRe = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

// autoMergeEnable: PUT .../git/pulls/{n}/auto-merge
func (h *gitReview) autoMergeEnable(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := h.pullScope(w, r, authz.GitMerge)
	if !ok {
		return
	}
	var in autoMergeIn
	b, ok := readBody(w, r)
	if !ok || !decodeStrict(w, b, &in, false) {
		return
	}
	switch gitcore.MergeStyle(in.Style) {
	case gitcore.MergeCommit, gitcore.MergeSquash, gitcore.MergeRebase, gitcore.MergeFF:
	default:
		badRequest(w, "style must be merge, squash, rebase or fast-forward")
		return
	}
	if !validText(in.Title, maxTitleLen) || !validText(in.Message, maxMarkdown) {
		badRequest(w, "title or message too long or not valid text")
		return
	}
	if in.HeadSHA != "" && !shaRe.MatchString(in.HeadSHA) {
		badRequest(w, "head_sha must be a commit sha")
		return
	}
	_, login, ok := h.asUser(w, sc, true)
	if !ok {
		return
	}
	var uid uuid.UUID
	if sc.user != nil {
		uid = sc.user.ID
	}
	pr, _, err := sc.svc.EnableAutoMerge(sc.ctx, sc.proj, gitreview.Actor{UserID: uid, Login: login}, n,
		gitreview.MergeInput{Style: gitcore.MergeStyle(in.Style), Title: in.Title, Message: in.Message, DeleteBranch: in.DeleteBranch, HeadSHA: in.HeadSHA})
	if err != nil {
		h.fail(w, err, true)
		return
	}
	respondJSON(w, http.StatusOK, h.pullDoc(sc, *pr))
}

// autoMergeDisable: DELETE .../git/pulls/{n}/auto-merge
func (h *gitReview) autoMergeDisable(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := h.pullScope(w, r, authz.GitWrite)
	if !ok {
		return
	}
	if err := sc.svc.DisableAutoMerge(sc.ctx, sc.proj, n); err != nil {
		h.fail(w, err, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pullReady: POST .../git/pulls/{n}/ready
func (h *gitReview) pullReady(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := h.pullScope(w, r, authz.GitWrite)
	if !ok {
		return
	}
	ctx, _, ok := h.asUser(w, sc, true)
	if !ok {
		return
	}
	pr, err := sc.svc.MarkReady(ctx, sc.proj, n)
	if err != nil {
		h.fail(w, err, true)
		return
	}
	respondJSON(w, http.StatusOK, h.pullDoc(sc, *pr))
}

type reviewersIn struct {
	Users []string `json:"users"`
	Teams []string `json:"teams"`
}

// reviewersRequest: POST .../git/pulls/{n}/reviewers
func (h *gitReview) reviewersRequest(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := h.pullScope(w, r, authz.GitWrite)
	if !ok {
		return
	}
	var in reviewersIn
	b, ok := readBody(w, r)
	if !ok || !decodeStrict(w, b, &in, false) {
		return
	}
	if !validLogins(in.Users) || !validLogins(in.Teams) {
		badRequest(w, "users and teams must be valid logins (at most 20)")
		return
	}
	ctx, _, ok := h.asUser(w, sc, true)
	if !ok {
		return
	}
	pr, err := sc.svc.RequestReviewers(ctx, sc.proj, n, in.Users, in.Teams)
	if err != nil {
		h.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusOK, h.pullDoc(sc, *pr))
}

type reasonIn struct {
	Reason string `json:"reason"`
}

// reviewDismiss: POST .../git/pulls/{n}/reviews/{reviewID}/dismiss (git.admin)
func (h *gitReview) reviewDismiss(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := h.pullScope(w, r, authz.GitAdmin)
	if !ok {
		return
	}
	id, ok := pathInt64(r, "reviewID")
	if !ok {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid review id")
		return
	}
	var in reasonIn
	b, ok := readBody(w, r)
	if !ok || !decodeStrict(w, b, &in, false) {
		return
	}
	if len([]rune(strings.TrimSpace(in.Reason))) < 3 || !validText(in.Reason, 1000) {
		badRequest(w, "reason must have between 3 and 1000 characters")
		return
	}
	login, _ := h.login(sc)
	by := gitreview.Actor{Login: login}
	if sc.user != nil {
		by.UserID = sc.user.ID
	}
	rv, err := sc.svc.DismissReview(sc.ctx, sc.proj, n, id, by, in.Reason)
	if err != nil {
		h.fail(w, err, false)
		return
	}
	if out, ok := gitapi.ToReview(*rv); ok {
		respondJSON(w, http.StatusOK, out)
		return
	}
	respondJSON(w, http.StatusOK, rv)
}
