package handlers

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

const (
	maxTitleLen   = 256
	maxMarkdown   = 64 << 10
	maxInlineN    = 100
	maxReviewersN = 20
)

var loginRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// previewURLs maps pull request number -> preview URL for the project (empty without the git module).
func (a *gitAPI) previewURLs(ctx context.Context, sc *gitScope) map[int]string {
	out := map[int]string{}
	if a.d.Git == nil || a.d.Git.Service == nil {
		return out
	}
	list, err := a.d.Git.Git.ListPreviews(ctx, sc.proj.ID)
	if err != nil {
		return out
	}
	for _, pv := range list {
		if u := a.d.Git.Service.AppURL(pv.Slug); u != "" {
			out[pv.PR] = u
		}
	}
	return out
}

// pullDoc builds the Pull document. full=true also computes mergeability and checks state (several
// upstream reads); a failure to evaluate is reported as an unmergeable pull request, never as a
// mergeable one (fail closed).
func (a *gitAPI) pullDoc(sc *gitScope, p gitcore.Pull, full bool, previews map[int]string) gitapi.PullOut {
	out := gitapi.ToPull(p)
	if u, ok := previews[p.Number]; ok && u != "" {
		out.PreviewURL = &u
	}
	if full {
		as, err := gitapi.Assess(sc.ctx, sc.core, sc.ref, p)
		if err != nil {
			a.lg.Warn("git api: mergeability could not be evaluated", "project_id", sc.proj.ID, "pr", p.Number, "error", err)
			out.Mergeable = &gitapi.Mergeability{Blockers: []gitapi.Blocker{{Code: gitapi.BlockPolicy,
				Message: "merge requirements could not be evaluated right now; try again"}}}
		} else {
			m := as.Mergeability
			out.Mergeable, out.ChecksState = &m, as.ChecksState()
		}
	}
	gitapi.DecoratePull(sc.ref, p, &out)
	return out
}

// pullsList: GET .../git/pulls?state=&author=&base=
func (a *gitAPI) pullsList(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scopeAuth(w, r, authz.GitRead)
	if !ok {
		return
	}
	if a.legacyProvider(sc) {
		a.d.Legacy.Pulls(w, r)
		return
	}
	if !sc.core.Enabled() {
		respondError(w, http.StatusServiceUnavailable, "GIT_NOT_READY", "the Git service is not configured on this server")
		return
	}
	pg, ok := pageParams(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" {
		state = "open"
	}
	upstream := state
	switch state {
	case "open", "closed", "all":
	case "merged":
		upstream = "closed"
	default:
		badRequest(w, "state must be one of open, closed, merged, all")
		return
	}
	base := strings.TrimSpace(q.Get("base"))
	if base != "" && !gitsource.ValidBranch(base) {
		badRequest(w, "invalid base")
		return
	}
	author := strings.TrimSpace(q.Get("author"))
	l, err := sc.core.ListPulls(sc.ctx, sc.ref, gitcore.PullQuery{State: upstream, Base: base}, pg)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	previews := a.previewURLs(r.Context(), sc)
	items := make([]gitapi.PullOut, 0, len(l.Items))
	for _, p := range l.Items {
		if state == "merged" && !p.Merged {
			continue
		}
		if author != "" && !strings.EqualFold(p.Author.Login, author) {
			continue // filtered on the page: Forgejo has no author filter
		}
		items = append(items, a.pullDoc(sc, p, false, previews))
	}
	respondJSON(w, http.StatusOK, newLegacyList(items, l.NextCursor))
}

// pullGet: GET .../git/pulls/{n}
func (a *gitAPI) pullGet(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := a.pullScope(w, r, authz.GitRead)
	if !ok {
		return
	}
	p, err := sc.core.GetPull(sc.ctx, sc.ref, n)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusOK, a.pullDoc(sc, *p, true, a.previewURLs(r.Context(), sc)))
}

func (a *gitAPI) pullScope(w http.ResponseWriter, r *http.Request, act authz.Action) (*gitScope, int, bool) {
	sc, ok := a.scope(w, r, act)
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

func validLogins(ss []string) bool {
	if len(ss) > maxReviewersN {
		return false
	}
	for _, s := range ss {
		if !loginRe.MatchString(s) {
			return false
		}
	}
	return true
}

func validText(s string, max int) bool {
	return len(s) <= max && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

type pullCreateIn struct {
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	Head      string   `json:"head"`
	Base      string   `json:"base"`
	Draft     bool     `json:"draft"`
	Reviewers []string `json:"reviewers"`
}

// pullCreate: POST .../git/pulls
func (a *gitAPI) pullCreate(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitWrite)
	if !ok {
		return
	}
	var in pullCreateIn
	if !a.readJSON(w, r, &in, false) {
		return
	}
	in.Title, in.Head, in.Base = strings.TrimSpace(in.Title), strings.TrimSpace(in.Head), strings.TrimSpace(in.Base)
	switch {
	case in.Title == "" || !validText(in.Title, maxTitleLen) || strings.ContainsAny(in.Title, "\r\n"):
		badRequest(w, "title is required (single line, at most 256 characters)")
		return
	case !validText(in.Body, maxMarkdown):
		badRequest(w, "body is too long")
		return
	case !gitsource.ValidBranch(in.Head) || !gitsource.ValidBranch(in.Base):
		badRequest(w, "head and base must be branch names of this repository")
		return
	case in.Head == in.Base:
		badRequest(w, "head and base must be different branches")
		return
	case !validLogins(in.Reviewers):
		badRequest(w, "reviewers must be at most 20 valid user names")
		return
	}
	ctx, ok := a.asUser(w, sc, true)
	if !ok {
		return
	}
	p, err := sc.core.CreatePull(ctx, sc.ref, gitcore.PullCreate{Title: in.Title, Body: in.Body, Head: in.Head, Base: in.Base, Draft: in.Draft, Reviewers: in.Reviewers})
	if err != nil {
		a.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusCreated, a.pullDoc(sc, *p, true, a.previewURLs(r.Context(), sc)))
}

type pullUpdateIn struct {
	Title *string `json:"title"`
	Body  *string `json:"body"`
	Base  *string `json:"base"`
	State *string `json:"state"`
	Draft *bool   `json:"draft"`
}

// pullUpdate: PATCH .../git/pulls/{n}
func (a *gitAPI) pullUpdate(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := a.pullScope(w, r, authz.GitWrite)
	if !ok {
		return
	}
	var in pullUpdateIn
	if !a.readJSON(w, r, &in, false) {
		return
	}
	patch := gitcore.PullPatch{Title: in.Title, Body: in.Body, Base: in.Base, State: in.State, Draft: in.Draft}
	switch {
	case in.Title != nil && (strings.TrimSpace(*in.Title) == "" || !validText(*in.Title, maxTitleLen) || strings.ContainsAny(*in.Title, "\r\n")):
		badRequest(w, "title must be a single line of at most 256 characters")
		return
	case in.Body != nil && !validText(*in.Body, maxMarkdown):
		badRequest(w, "body is too long")
		return
	case in.Base != nil && !gitsource.ValidBranch(*in.Base):
		badRequest(w, "invalid base")
		return
	case in.State != nil && *in.State != "open" && *in.State != "closed":
		badRequest(w, "state must be open or closed")
		return
	case in.Title == nil && in.Body == nil && in.Base == nil && in.State == nil && in.Draft == nil:
		badRequest(w, "nothing to change")
		return
	}
	if in.Title != nil {
		t := strings.TrimSpace(*in.Title)
		patch.Title = &t
	}
	ctx, ok := a.asUser(w, sc, true)
	if !ok {
		return
	}
	p, err := sc.core.PatchPull(ctx, sc.ref, n, patch)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusOK, a.pullDoc(sc, *p, true, a.previewURLs(r.Context(), sc)))
}

type fileDiffPage struct {
	listOut[gitcore.FileDiff]
	Truncated bool `json:"truncated"`
}

// pullFiles: GET .../git/pulls/{n}/files (bounded diff; falls back to the file list over the cap).
func (a *gitAPI) pullFiles(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := a.pullScope(w, r, authz.GitRead)
	if !ok {
		return
	}
	pg, ok := pageParams(w, r)
	if !ok {
		return
	}
	d, err := sc.core.PullDiff(sc.ctx, sc.ref, n)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	items, next, err := gitapi.SliceByCursor(d.Files, pg)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusOK, fileDiffPage{listOut: newList(items, next), Truncated: d.Truncated})
}

// pullCommits: GET .../git/pulls/{n}/commits
func (a *gitAPI) pullCommits(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := a.pullScope(w, r, authz.GitRead)
	if !ok {
		return
	}
	pg, ok := pageParams(w, r)
	if !ok {
		return
	}
	l, err := sc.core.PullCommits(sc.ctx, sc.ref, n, pg)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusOK, newList(l.Items, l.NextCursor))
}

// reviewsList: GET .../git/pulls/{n}/reviews
func (a *gitAPI) reviewsList(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := a.pullScope(w, r, authz.GitRead)
	if !ok {
		return
	}
	p, err := sc.core.GetPull(sc.ctx, sc.ref, n)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	reviews, err := sc.core.ListReviews(sc.ctx, sc.ref, n)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	rules, err := sc.core.ListProtections(sc.ctx, sc.ref)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	rule := gitapi.MatchRule(rules, p.Base)
	out := gitapi.ReviewListOut{Items: []gitapi.ReviewOut{}, CodeOwnerPending: gitapi.CodeownersPending(sc.ctx, sc.ref, *p)}
	for _, rv := range reviews {
		if o, ok := gitapi.ToReview(rv); ok {
			out.Items = append(out.Items, o)
		}
	}
	if rule != nil {
		out.RequiredApproval = rule.RequiredApprovals
		out.Approvals = gitapi.CountApprovals(reviews, *rule)
	} else {
		out.Approvals = gitapi.CountApprovals(reviews, gitcore.ProtectionSpec{})
	}
	respondJSON(w, http.StatusOK, out)
}

type inlineIn struct {
	Path       string `json:"path"`
	Line       int    `json:"line"`
	Side       string `json:"side"`
	Body       string `json:"body"`
	Suggestion string `json:"suggestion"`
}

type reviewCreateIn struct {
	Event     string     `json:"event"`
	Body      string     `json:"body"`
	CommitSHA string     `json:"commit_sha"`
	Comments  []inlineIn `json:"comments"`
}

// reviewCreate: POST .../git/pulls/{n}/reviews, attributed to the real user. The author of a pull
// request cannot approve or request changes on it; a commit_sha that is no longer the head is a 409.
func (a *gitAPI) reviewCreate(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := a.pullScope(w, r, authz.GitReview)
	if !ok {
		return
	}
	var in reviewCreateIn
	if !a.readJSON(w, r, &in, false) {
		return
	}
	var ev gitcore.ReviewEvent
	switch in.Event {
	case "approve":
		ev = gitcore.ReviewApprove
	case "request_changes":
		ev = gitcore.ReviewRequestChanges
	case "comment":
		ev = gitcore.ReviewComment
	default:
		badRequest(w, "event must be approve, request_changes or comment")
		return
	}
	in.Body = strings.TrimSpace(in.Body)
	if !validText(in.Body, maxMarkdown) {
		badRequest(w, "body is too long")
		return
	}
	if len(in.Comments) > maxInlineN {
		badRequest(w, "at most 100 inline comments per review")
		return
	}
	var inline []gitcore.InlineComment
	for _, c := range in.Comments {
		c.Path = strings.Trim(c.Path, "/")
		if _, ok := cleanPath(c.Path); !ok || c.Path == "" || c.Line < 1 || strings.TrimSpace(c.Body) == "" && c.Suggestion == "" || !validText(c.Body, maxMarkdown) || !validText(c.Suggestion, maxMarkdown) {
			badRequest(w, "each inline comment needs path, line >= 1 and a body")
			return
		}
		switch c.Side {
		case "", "left", "right":
		default:
			badRequest(w, "side must be left or right")
			return
		}
		body := c.Body
		if c.Suggestion != "" {
			body = strings.TrimRight(body, "\n") + "\n\n```suggestion\n" + strings.TrimRight(c.Suggestion, "\n") + "\n```"
		}
		inline = append(inline, gitcore.InlineComment{Path: c.Path, Line: c.Line, Side: c.Side, Body: strings.TrimSpace(body)})
	}
	if ev != gitcore.ReviewApprove && in.Body == "" && len(inline) == 0 {
		badRequest(w, "a comment or change request needs a body or inline comments")
		return
	}
	if in.CommitSHA != "" && !gitsource.ValidSHA(in.CommitSHA) {
		badRequest(w, "invalid commit_sha")
		return
	}
	ctx, ok := a.asUser(w, sc, true)
	if !ok {
		return
	}
	p, err := sc.core.GetPull(sc.ctx, sc.ref, n)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	if ev != gitcore.ReviewComment && strings.EqualFold(p.Author.Login, gitcore.ActorFrom(ctx)) {
		respondError(w, http.StatusUnprocessableEntity, "SELF_APPROVAL_FORBIDDEN", "you cannot approve or request changes on your own pull request")
		return
	}
	if in.CommitSHA != "" && p.HeadSHA != "" && !strings.HasPrefix(p.HeadSHA, strings.ToLower(in.CommitSHA)) {
		respondErrorDetails(w, http.StatusConflict, "HEAD_CHANGED", "the pull request changed since you looked at it; reload and review again",
			map[string]any{"head_sha": p.HeadSHA})
		return
	}
	rv, err := sc.core.CreateReview(ctx, sc.ref, n, gitcore.ReviewCreate{Event: ev, Body: in.Body, CommitID: in.CommitSHA, Comments: inline})
	if err != nil {
		a.fail(w, err, false)
		return
	}
	out, _ := gitapi.ToReview(*rv)
	respondJSON(w, http.StatusCreated, out)
}

// commentsList: GET .../git/pulls/{n}/comments
func (a *gitAPI) commentsList(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := a.pullScope(w, r, authz.GitRead)
	if !ok {
		return
	}
	pg, ok := pageParams(w, r)
	if !ok {
		return
	}
	l, err := sc.core.ListComments(sc.ctx, sc.ref, n, pg)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusOK, newList(l.Items, l.NextCursor))
}

// commentCreate: POST .../git/pulls/{n}/comments
func (a *gitAPI) commentCreate(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := a.pullScope(w, r, authz.GitReview)
	if !ok {
		return
	}
	var in struct {
		Body string `json:"body"`
	}
	if !a.readJSON(w, r, &in, false) {
		return
	}
	in.Body = strings.TrimSpace(in.Body)
	if in.Body == "" || !validText(in.Body, maxMarkdown) {
		badRequest(w, "body is required (at most 64 KiB)")
		return
	}
	ctx, ok := a.asUser(w, sc, true)
	if !ok {
		return
	}
	c, err := sc.core.CreateComment(ctx, sc.ref, n, in.Body)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusCreated, c)
}

type mergeIn struct {
	Style        string `json:"style"`
	Title        string `json:"title"`
	Message      string `json:"message"`
	DeleteBranch *bool  `json:"delete_branch"`
	HeadSHA      string `json:"head_sha"`
}

// blockerStatus maps a blocker code to the HTTP status of the contract: 409 for the state of the
// pull request (checks, reviews, conflicts, ...), 422 for policy and approval rules.
func blockerStatus(code string) int {
	switch code {
	case gitapi.BlockPolicy, gitapi.BlockApproval:
		return http.StatusUnprocessableEntity
	}
	return http.StatusConflict
}

// pullMerge: POST .../git/pulls/{n}/merge (Idempotency-Key). The head is pinned: Forgejo gets the
// head SHA Capsule just evaluated, so a push between the check and the merge cannot slip through.
func (a *gitAPI) pullMerge(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := a.pullScope(w, r, authz.GitMerge)
	if !ok {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var in mergeIn
	if !decodeStrict(w, body, &in, false) {
		return
	}
	var style gitcore.MergeStyle
	switch in.Style {
	case "merge":
		style = gitcore.MergeCommit
	case "squash":
		style = gitcore.MergeSquash
	case "rebase":
		style = gitcore.MergeRebase
	case "fast-forward":
		style = gitcore.MergeFF
	default:
		badRequest(w, "style must be merge, squash, rebase or fast-forward")
		return
	}
	if !validText(in.Title, maxTitleLen) || strings.ContainsAny(in.Title, "\r\n") || !validText(in.Message, maxMarkdown) {
		badRequest(w, "title must be a single line of at most 256 characters")
		return
	}
	if in.HeadSHA != "" && !gitsource.ValidSHA(in.HeadSHA) {
		badRequest(w, "invalid head_sha")
		return
	}
	ctx, ok := a.asUser(w, sc, true)
	if !ok {
		return
	}
	a.withIdempotency(w, r, sc, "pullMerge:"+itoa(n), body, func(out http.ResponseWriter) {
		repo, err := sc.core.GetRepo(sc.ctx, sc.ref)
		if err != nil {
			a.fail(out, err, false)
			return
		}
		if len(repo.AllowedMergeStyles) > 0 && !containsStr(repo.AllowedMergeStyles, in.Style) {
			badRequest(out, "this repository does not allow the "+in.Style+" merge style (allowed: "+strings.Join(repo.AllowedMergeStyles, ", ")+")")
			return
		}
		p, err := sc.core.GetPull(sc.ctx, sc.ref, n)
		if err != nil {
			a.fail(out, err, false)
			return
		}
		if p.State != gitcore.PullOpen {
			respondError(out, http.StatusConflict, "CONFLICT", "the pull request is not open")
			return
		}
		if in.HeadSHA != "" && !strings.HasPrefix(p.HeadSHA, strings.ToLower(in.HeadSHA)) {
			respondErrorDetails(out, http.StatusConflict, "HEAD_CHANGED", "the pull request changed since you looked at it; reload and try again",
				map[string]any{"head_sha": p.HeadSHA})
			return
		}
		as, err := gitapi.Assess(sc.ctx, sc.core, sc.ref, *p)
		if err != nil {
			a.fail(out, err, false) // cannot evaluate: do not merge
			return
		}
		if !as.Mergeability.CanMerge {
			first := as.Mergeability.Blockers[0]
			respondErrorDetails(out, blockerStatus(first.Code), first.Code, "the pull request cannot be merged: "+first.Message,
				map[string]any{"blockers": as.Mergeability.Blockers})
			return
		}
		del := repo.DeleteBranchOnPR
		if in.DeleteBranch != nil {
			del = *in.DeleteBranch
		}
		res, err := sc.core.MergePull(ctx, sc.ref, n, gitcore.MergeRequest{Style: style, Title: in.Title, Message: in.Message, DeleteBranch: del, HeadSHA: p.HeadSHA})
		if err != nil {
			a.fail(out, err, true)
			return
		}
		respondJSON(out, http.StatusOK, res)
	})
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func itoa(n int) string { return strconv.Itoa(n) }

// pullUpdateBranch: POST .../git/pulls/{n}/update-branch (merges the base into the head branch).
func (a *gitAPI) pullUpdateBranch(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := a.pullScope(w, r, authz.GitWrite)
	if !ok {
		return
	}
	ctx, ok := a.asUser(w, sc, true)
	if !ok {
		return
	}
	p, err := sc.core.GetPull(sc.ctx, sc.ref, n)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	if p.State != gitcore.PullOpen {
		respondError(w, http.StatusConflict, "CONFLICT", "the pull request is not open")
		return
	}
	if err := sc.core.UpdatePullBranch(ctx, sc.ref, n); err != nil {
		a.fail(w, err, true)
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{"id": uuid.NewString(), "status": "success", "detail": "the base branch was merged into " + p.Head})
}

// pullChecks: GET .../git/pulls/{n}/checks
func (a *gitAPI) pullChecks(w http.ResponseWriter, r *http.Request) {
	sc, n, ok := a.pullScope(w, r, authz.GitRead)
	if !ok {
		return
	}
	p, err := sc.core.GetPull(sc.ctx, sc.ref, n)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	cs, err := sc.core.ListChecks(sc.ctx, sc.ref, p.HeadSHA)
	if err != nil && !errors.Is(err, gitcore.ErrNotFound) {
		a.fail(w, err, false)
		return
	}
	var rule *gitcore.ProtectionSpec
	if rules, err := sc.core.ListProtections(sc.ctx, sc.ref); err == nil {
		rule = gitapi.MatchRule(rules, p.Base)
	}
	respondJSON(w, http.StatusOK, gitapi.ToCheckList(cs, rule))
}
