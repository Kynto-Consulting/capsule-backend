package gitcore

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

type fgLabel struct {
	Name string `json:"name"`
}

type fgBranchInfo struct {
	Ref string `json:"ref"`
	SHA string `json:"sha"`
}

type fgPull struct {
	Number         int          `json:"number"`
	Title          string       `json:"title"`
	Body           string       `json:"body"`
	State          string       `json:"state"`
	Draft          bool         `json:"draft"`
	Head           fgBranchInfo `json:"head"`
	Base           fgBranchInfo `json:"base"`
	User           fgUser       `json:"user"`
	Reviewers      []fgUser     `json:"requested_reviewers"`
	Labels         []fgLabel    `json:"labels"`
	Mergeable      bool         `json:"mergeable"`
	Merged         bool         `json:"merged"`
	MergeCommitSHA string       `json:"merge_commit_sha"`
	MergeBase      string       `json:"merge_base"`
	HTMLURL        string       `json:"html_url"`
	CreatedAt      string       `json:"created_at"`
	UpdatedAt      string       `json:"updated_at"`
	MergedAt       string       `json:"merged_at"`
}

// wipPrefixes are Forgejo's default work-in-progress title prefixes (?) — configurable per
// instance in [repository.pull-request] WORK_IN_PROGRESS_PREFIXES; "WIP:" is the first default.
var wipPrefixes = []string{"WIP:", "[WIP]"}

func isWIPTitle(t string) bool {
	u := strings.ToUpper(strings.TrimSpace(t))
	for _, p := range wipPrefixes {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return false
}

func stripWIP(t string) string {
	t = strings.TrimSpace(t)
	for isWIPTitle(t) {
		for _, p := range wipPrefixes {
			if strings.HasPrefix(strings.ToUpper(t), p) {
				t = strings.TrimSpace(t[len(p):])
				break
			}
		}
	}
	return t
}

func (f fgPull) pull() Pull {
	p := Pull{Number: f.Number, Title: f.Title, Body: f.Body, State: PullOpen, Draft: f.Draft || isWIPTitle(f.Title),
		Head: f.Head.Ref, Base: f.Base.Ref, HeadSHA: f.Head.SHA, BaseSHA: f.MergeBase, Author: f.User.person(),
		Reviewers: []Person{}, Labels: []string{}, Mergeable: f.Mergeable, Merged: f.Merged, MergeCommitSHA: f.MergeCommitSHA,
		HTMLURL: f.HTMLURL, CreatedAt: parseTime(f.CreatedAt), UpdatedAt: parseTime(f.UpdatedAt), MergedAt: parseTimePtr(f.MergedAt)}
	switch {
	case f.Merged:
		p.State = PullMerged
	case f.State == "closed":
		p.State = PullClosed
	}
	for _, u := range f.Reviewers {
		p.Reviewers = append(p.Reviewers, u.person())
	}
	for _, l := range f.Labels {
		p.Labels = append(p.Labels, l.Name)
	}
	return p
}

func (s *Service) ListPulls(ctx context.Context, r RepoRef, q PullQuery, p Page) (List[Pull], error) {
	if err := r.valid(); err != nil {
		return List[Pull]{}, err
	}
	state := q.State
	if state == "" {
		state = "open"
	}
	if state != "open" && state != "closed" && state != "all" {
		return List[Pull]{}, invalid("state must be open, closed or all")
	}
	key := s.listKey(ctx, r, "pulls", state, q.Base, q.Head, p.Cursor, itoa(clampLimit(p.Limit)))
	return cached(ctx, s, key, s.cfg.ListTTL, func() (List[Pull], error) {
		qv := url.Values{"state": {state}}
		if q.Base != "" {
			qv.Set("base", q.Base)
		}
		if q.Head != "" {
			qv.Set("head", q.Head)
		}
		items, next, err := fetchPaged[fgPull](ctx, s, req{method: http.MethodGet, path: r.base() + "/pulls", op: "/repos/{o}/{r}/pulls", query: qv}, p, "", nil)
		if err != nil {
			return List[Pull]{}, err
		}
		out := List[Pull]{Items: make([]Pull, 0, len(items)), NextCursor: next}
		for _, f := range items {
			out.Items = append(out.Items, f.pull())
		}
		return out, nil
	})
}

func (s *Service) fetchPull(ctx context.Context, r RepoRef, n int) (Pull, error) {
	var f fgPull
	if _, err := s.do(ctx, req{method: http.MethodGet, path: r.base() + "/pulls/" + itoa(n), op: "/repos/{o}/{r}/pulls/{n}"}, &f); err != nil {
		return Pull{}, err
	}
	return f.pull(), nil
}

func (s *Service) GetPull(ctx context.Context, r RepoRef, n int) (*Pull, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if n < 1 {
		return nil, invalid("pull request number must be positive")
	}
	p, err := cached(ctx, s, s.listKey(ctx, r, "pull", itoa(n)), s.cfg.ListTTL, func() (Pull, error) { return s.fetchPull(ctx, r, n) })
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Service) CreatePull(ctx context.Context, r RepoRef, in PullCreate) (*Pull, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Title) == "" || in.Head == "" || in.Base == "" {
		return nil, invalid("title, head and base are required")
	}
	title := in.Title
	if in.Draft && !isWIPTitle(title) {
		title = "WIP: " + title
	}
	var f fgPull
	_, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/pulls", op: "/repos/{o}/{r}/pulls",
		body: map[string]any{"title": title, "body": in.Body, "head": in.Head, "base": in.Base}}, &f)
	if err != nil {
		return nil, err
	}
	_ = s.InvalidateRepo(ctx, r)
	pl := f.pull()
	if len(in.Reviewers) > 0 {
		// A reviewer that cannot be requested must not undo the created PR.
		if rerr := s.RequestReviewers(ctx, r, pl.Number, in.Reviewers, nil); rerr != nil {
			s.log.Warn("gitcore: requesting reviewers failed", "code", errCode(rerr))
		}
	}
	return &pl, nil
}

func errCode(err error) string {
	if e, ok := AsError(err); ok {
		return string(e.Code)
	}
	return "unknown"
}

func (s *Service) PatchPull(ctx context.Context, r RepoRef, n int, in PullPatch) (*Pull, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if n < 1 {
		return nil, invalid("pull request number must be positive")
	}
	body := map[string]any{}
	title := in.Title
	if in.Draft != nil {
		cur := ""
		if title != nil {
			cur = *title
		} else {
			p, err := s.fetchPull(ctx, r, n)
			if err != nil {
				return nil, err
			}
			cur = p.Title
		}
		cur = stripWIP(cur)
		if *in.Draft {
			cur = "WIP: " + cur
		}
		title = &cur
	}
	if title != nil {
		body["title"] = *title
	}
	if in.Body != nil {
		body["body"] = *in.Body
	}
	if in.Base != nil {
		body["base"] = *in.Base
	}
	if in.State != nil {
		if *in.State != "open" && *in.State != "closed" {
			return nil, invalid("state must be open or closed")
		}
		body["state"] = *in.State
	}
	var f fgPull
	if _, err := s.do(ctx, req{method: http.MethodPatch, path: r.base() + "/pulls/" + itoa(n), op: "/repos/{o}/{r}/pulls/{n}", body: body}, &f); err != nil {
		return nil, err
	}
	_ = s.InvalidateRepo(ctx, r)
	pl := f.pull()
	return &pl, nil
}

func (s *Service) PullDiff(ctx context.Context, r RepoRef, n int) (*Diff, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	pl, err := s.GetPull(ctx, r, n)
	if err != nil {
		return nil, err
	}
	fetch := func() (Diff, error) {
		res, err := s.do(ctx, req{method: http.MethodGet, path: r.base() + "/pulls/" + itoa(n) + ".diff", op: "/repos/{o}/{r}/pulls/{n}.diff", accept: "text/plain"}, nil)
		if errIs(err, CodeTooLarge) {
			return s.pullFilesOnly(ctx, r, n)
		}
		if err != nil {
			return Diff{}, err
		}
		return parseDiff(string(res.body), MaxDiffBytes), nil
	}
	var d Diff
	if isHexSHA(pl.HeadSHA) && pl.BaseSHA != "" {
		// head + merge base fully determine the three-dot diff: immutable.
		d, err = cached(ctx, s, immKey(r, "pdiff", itoa(n), pl.HeadSHA, pl.BaseSHA), s.cfg.ImmutableTTL, fetch)
	} else {
		d, err = fetch()
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// pullFilesOnly is the fallback when the raw diff exceeds the transport cap: file list with
// counts and no patches, Truncated=true.
func (s *Service) pullFilesOnly(ctx context.Context, r RepoRef, n int) (Diff, error) {
	type fgChanged struct {
		Filename string `json:"filename"`
		Previous string `json:"previous_filename"`
		Status   string `json:"status"`
		Adds     int    `json:"additions"`
		Dels     int    `json:"deletions"`
	}
	d := Diff{Files: []FileDiff{}, Truncated: true}
	cur := ""
	for i := 0; i < 20; i++ {
		items, next, err := fetchPaged[fgChanged](ctx, s, req{method: http.MethodGet, path: r.base() + "/pulls/" + itoa(n) + "/files", op: "/repos/{o}/{r}/pulls/{n}/files"}, Page{Cursor: cur, Limit: MaxLimit}, "", nil)
		if err != nil {
			return Diff{}, err
		}
		for _, c := range items {
			d.Files = append(d.Files, FileDiff{Path: c.Filename, OldPath: c.Previous, Status: normStatus(c.Status), Additions: c.Adds, Deletions: c.Dels, Truncated: true})
		}
		if next == "" {
			break
		}
		cur = next
	}
	return d, nil
}

func (s *Service) PullCommits(ctx context.Context, r RepoRef, n int, p Page) (List[Commit], error) {
	if err := r.valid(); err != nil {
		return List[Commit]{}, err
	}
	items, next, err := fetchPaged[fgCommit](ctx, s, req{method: http.MethodGet, path: r.base() + "/pulls/" + itoa(n) + "/commits", op: "/repos/{o}/{r}/pulls/{n}/commits"}, p, "", nil)
	if err != nil {
		return List[Commit]{}, err
	}
	out := List[Commit]{Items: make([]Commit, 0, len(items)), NextCursor: next}
	for _, c := range items {
		out.Items = append(out.Items, c.commit())
	}
	return out, nil
}

func (s *Service) UpdatePullBranch(ctx context.Context, r RepoRef, n int) error {
	if err := r.valid(); err != nil {
		return err
	}
	_, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/pulls/" + itoa(n) + "/update", op: "/repos/{o}/{r}/pulls/{n}/update"}, nil)
	if err == nil {
		_ = s.InvalidateRepo(ctx, r)
	}
	return err
}

func (s *Service) RequestReviewers(ctx context.Context, r RepoRef, n int, users, teams []string) error {
	if err := r.valid(); err != nil {
		return err
	}
	if len(users) == 0 && len(teams) == 0 {
		return nil
	}
	_, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/pulls/" + itoa(n) + "/requested_reviewers", op: "/repos/{o}/{r}/pulls/{n}/requested_reviewers",
		body: map[string]any{"reviewers": users, "team_reviewers": teams}}, nil)
	if err == nil {
		_ = s.InvalidateRepo(ctx, r)
	}
	return err
}

// ---- reviews -----------------------------------------------------------------------------------

type fgReview struct {
	ID        int64  `json:"id"`
	State     string `json:"state"`
	Body      string `json:"body"`
	User      fgUser `json:"user"`
	CommitID  string `json:"commit_id"`
	Stale     bool   `json:"stale"`
	Official  bool   `json:"official"`
	Dismissed bool   `json:"dismissed"`
	Comments  int    `json:"comments_count"`
	Submitted string `json:"submitted_at"`
}

func (f fgReview) review() Review {
	st := strings.ToLower(f.State)
	switch st {
	case "approved":
	case "request_changes":
		st = "changes_requested"
	case "comment":
		st = "commented"
	}
	if f.Dismissed {
		st = "dismissed"
	}
	return Review{ID: f.ID, State: st, Body: f.Body, Author: f.User.person(), CommitSHA: f.CommitID, Stale: f.Stale,
		Official: f.Official, CommentsN: f.Comments, SubmittedAt: parseTime(f.Submitted)}
}

func (s *Service) ListReviews(ctx context.Context, r RepoRef, n int) ([]Review, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	out := []Review{}
	cur := ""
	for i := 0; i < 10; i++ { // up to 1000 reviews
		items, next, err := fetchPaged[fgReview](ctx, s, req{method: http.MethodGet, path: r.base() + "/pulls/" + itoa(n) + "/reviews", op: "/repos/{o}/{r}/pulls/{n}/reviews"}, Page{Cursor: cur, Limit: MaxLimit}, "", nil)
		if err != nil {
			return nil, err
		}
		for _, f := range items {
			out = append(out, f.review())
		}
		if next == "" {
			break
		}
		cur = next
	}
	return out, nil
}

func (s *Service) CreateReview(ctx context.Context, r RepoRef, n int, in ReviewCreate) (*Review, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	ev := ""
	switch in.Event {
	case ReviewApprove:
		ev = "APPROVED"
	case ReviewRequestChanges:
		ev = "REQUEST_CHANGES"
	case ReviewComment:
		ev = "COMMENT"
	default:
		return nil, invalid("review event must be approve, request_changes or comment")
	}
	if in.Event != ReviewApprove && strings.TrimSpace(in.Body) == "" && len(in.Comments) == 0 {
		return nil, invalid("a review that is not an approval needs a body or comments")
	}
	body := map[string]any{"event": ev, "body": in.Body}
	if in.CommitID != "" {
		body["commit_id"] = in.CommitID
	}
	if len(in.Comments) > 0 {
		cs := make([]map[string]any, 0, len(in.Comments))
		for _, c := range in.Comments {
			if c.Path == "" || c.Line < 1 || strings.TrimSpace(c.Body) == "" {
				return nil, invalid("inline comments need path, line >= 1 and body")
			}
			m := map[string]any{"path": c.Path, "body": c.Body}
			if c.Side == "left" {
				m["old_position"] = c.Line
			} else {
				m["new_position"] = c.Line
			}
			cs = append(cs, m)
		}
		body["comments"] = cs
	}
	var f fgReview
	if _, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/pulls/" + itoa(n) + "/reviews", op: "/repos/{o}/{r}/pulls/{n}/reviews", body: body}, &f); err != nil {
		return nil, err
	}
	_ = s.InvalidateRepo(ctx, r)
	rv := f.review()
	return &rv, nil
}

// ---- comments ----------------------------------------------------------------------------------

type fgComment struct {
	ID        int64  `json:"id"`
	Body      string `json:"body"`
	User      fgUser `json:"user"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func (f fgComment) comment() Comment {
	c := Comment{ID: f.ID, Body: f.Body, Author: f.User.person(), CreatedAt: parseTime(f.CreatedAt)}
	if u := parseTime(f.UpdatedAt); !u.IsZero() && u.After(c.CreatedAt) {
		c.EditedAt = &u
	}
	return c
}

func (s *Service) ListComments(ctx context.Context, r RepoRef, n int, p Page) (List[Comment], error) {
	if err := r.valid(); err != nil {
		return List[Comment]{}, err
	}
	items, next, err := fetchPaged[fgComment](ctx, s, req{method: http.MethodGet, path: r.base() + "/issues/" + itoa(n) + "/comments", op: "/repos/{o}/{r}/issues/{n}/comments"}, p, "", nil)
	if err != nil {
		return List[Comment]{}, err
	}
	out := List[Comment]{Items: make([]Comment, 0, len(items)), NextCursor: next}
	for _, f := range items {
		out.Items = append(out.Items, f.comment())
	}
	return out, nil
}

func (s *Service) CreateComment(ctx context.Context, r RepoRef, n int, body string) (*Comment, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(body) == "" {
		return nil, invalid("comment body is required")
	}
	var f fgComment
	if _, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/issues/" + itoa(n) + "/comments", op: "/repos/{o}/{r}/issues/{n}/comments", body: map[string]any{"body": body}}, &f); err != nil {
		return nil, err
	}
	c := f.comment()
	return &c, nil
}

// ---- merge -------------------------------------------------------------------------------------

func (s *Service) MergePull(ctx context.Context, r RepoRef, n int, in MergeRequest) (*MergeResult, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	var do string
	switch in.Style {
	case MergeCommit:
		do = "merge"
	case MergeSquash:
		do = "squash"
	case MergeRebase:
		do = "rebase"
	case MergeFF:
		do = "fast-forward-only"
	default:
		return nil, invalid("merge style must be merge, squash, rebase or fast-forward")
	}
	body := map[string]any{"Do": do, "delete_branch_after_merge": in.DeleteBranch}
	if in.Title != "" {
		body["MergeTitleField"] = in.Title
	}
	if in.Message != "" {
		body["MergeMessageField"] = in.Message
	}
	if in.HeadSHA != "" {
		body["head_commit_id"] = in.HeadSHA
	}
	if in.WhenChecks {
		body["merge_when_checks_succeed"] = true
	}
	if in.Force {
		body["force_merge"] = true
	}
	_, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/pulls/" + itoa(n) + "/merge", op: "/repos/{o}/{r}/pulls/{n}/merge", body: body}, nil)
	if err != nil {
		return nil, err
	}
	_ = s.InvalidateRepo(ctx, r)
	res := &MergeResult{}
	if pl, gerr := s.fetchPull(ctx, r, n); gerr == nil {
		res.Merged, res.SHA = pl.Merged, pl.MergeCommitSHA
		res.Queued = !pl.Merged && in.WhenChecks
	} else {
		// The merge call succeeded; only the confirmation read failed.
		res.Merged = !in.WhenChecks
		res.Queued = in.WhenChecks
	}
	return res, nil
}

func (s *Service) CancelAutoMerge(ctx context.Context, r RepoRef, n int) error {
	if err := r.valid(); err != nil {
		return err
	}
	_, err := s.do(ctx, req{method: http.MethodDelete, path: r.base() + "/pulls/" + itoa(n) + "/merge", op: "/repos/{o}/{r}/pulls/{n}/merge"}, nil)
	if err == nil {
		_ = s.InvalidateRepo(ctx, r)
	}
	return err
}

// ---- checks (commit statuses) ----------------------------------------------------------------

type fgStatus struct {
	Context     string `json:"context"`
	Status      string `json:"status"`
	TargetURL   string `json:"target_url"`
	Description string `json:"description"`
	UpdatedAt   string `json:"updated_at"`
}

func normCheck(st string) CheckState {
	switch st {
	case "success", "warning":
		return CheckSuccess
	case "failure":
		return CheckFailure
	case "error":
		return CheckError
	case "skipped":
		return CheckSkipped
	}
	return CheckPending
}

func (f fgStatus) check() Check {
	return Check{Context: f.Context, State: normCheck(f.Status), TargetURL: f.TargetURL, Description: f.Description, UpdatedAt: parseTime(f.UpdatedAt)}
}

// ListChecks returns the combined status of ref. Checks change by the second, so they are not cached.
func (s *Service) ListChecks(ctx context.Context, r RepoRef, ref string) (*CheckSet, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if ref == "" {
		return nil, invalid("ref is required")
	}
	var f struct {
		State    string     `json:"state"`
		Statuses []fgStatus `json:"statuses"`
	}
	if _, err := s.do(ctx, req{method: http.MethodGet, path: r.base() + "/commits/" + escPath(ref) + "/status", op: "/repos/{o}/{r}/commits/{ref}/status",
		query: url.Values{"limit": {"100"}}}, &f); err != nil {
		return nil, err
	}
	out := &CheckSet{State: CheckPending, Items: make([]Check, 0, len(f.Statuses))}
	switch f.State {
	case "success", "warning":
		out.State = CheckSuccess
	case "failure", "error":
		out.State = CheckFailure
	}
	if len(f.Statuses) == 0 {
		out.State = CheckPending
	}
	for _, st := range f.Statuses {
		out.Items = append(out.Items, st.check())
	}
	return out, nil
}

func (s *Service) SetCheck(ctx context.Context, r RepoRef, sha string, in CheckInput) (*Check, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if !isHexSHA(sha) {
		return nil, invalid("a full commit sha is required")
	}
	if in.Context == "" {
		return nil, invalid("check context is required")
	}
	switch in.State {
	case CheckPending, CheckSuccess, CheckFailure, CheckError, CheckSkipped:
	default:
		return nil, invalid("invalid check state")
	}
	var f fgStatus
	_, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/statuses/" + esc(sha), op: "/repos/{o}/{r}/statuses/{sha}",
		body: map[string]any{"context": in.Context, "state": string(in.State), "target_url": in.TargetURL, "description": in.Description}}, &f)
	if err != nil {
		return nil, err
	}
	c := f.check()
	if c.Context == "" {
		c.Context, c.State = in.Context, in.State
	}
	return &c, nil
}
