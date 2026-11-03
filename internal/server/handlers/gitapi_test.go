package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitprotect"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

var gapiRef = gitcore.RepoRef{Owner: gapiOrgSlug, Repo: gapiRepoSlug}

func TestGitAPIRead(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})

	// repo document: OpenAPI keys plus the legacy ones
	rec := g.do("GET", "/repo", nil)
	gapiWant(t, rec, 200)
	repo := gapiMap(t, rec)
	if repo["provision_status"] != "ready" || repo["status"] != "ready" || repo["default_branch"] != "main" {
		t.Fatalf("repo: %v", repo)
	}
	if clone, _ := repo["clone"].(map[string]any); clone == nil || clone["capsule"].(map[string]any)["command"] != "capsule git clone acme/shop" {
		t.Fatalf("clone options: %v", repo["clone"])
	}

	// tree (root and sub directory), blob and language
	root := gapiItems(t, gapiMap(t, g.do("GET", "/tree", nil)))
	var names []string
	for _, e := range root {
		names = append(names, e.(map[string]any)["name"].(string))
	}
	if !strings.Contains(strings.Join(names, ","), "src") || !strings.Contains(strings.Join(names, ","), "README.md") {
		t.Fatalf("root entries %v", names)
	}
	if sub := gapiItems(t, gapiMap(t, g.do("GET", "/tree?path=src", nil))); len(sub) != 1 {
		t.Fatalf("src entries %v", sub)
	}
	blob := gapiMap(t, g.do("GET", "/blob?path=src/app.go&ref=main", nil))
	if blob["language"] != "go" || !strings.Contains(blob["content"].(string), "package main") || blob["truncated"] != false {
		t.Fatalf("blob %v", blob)
	}
	if g.do("GET", "/blob", nil).Code != 422 || g.do("GET", "/blob?path=../etc/passwd", nil).Code != 422 || g.do("GET", "/tree?path=a/../b", nil).Code != 422 {
		t.Fatal("blob without path and traversal must be 422")
	}
	if g.do("GET", "/tree?ref=-evil", nil).Code != 422 || g.do("GET", "/tree?ref=a..b", nil).Code != 422 {
		t.Fatal("hostile refs must be 422")
	}
	gapiWant(t, g.do("GET", "/blob?path=nope.txt", nil), 404)

	// compare: ahead and behind
	cmp := gapiMap(t, g.do("GET", "/compare?base=main&head=feature", nil))
	if cmp["ahead_by"].(float64) < 1 || len(gapiList(cmp, "commits")) < 1 || len(gapiList(cmp, "files")) < 1 {
		t.Fatalf("compare %v", cmp)
	}
	gapiWant(t, g.do("GET", "/compare?base=main", nil), 422)

	// branches: OpenAPI list plus legacy envelope
	br := gapiMap(t, g.do("GET", "/branches", nil))
	if len(gapiItems(t, br)) < 3 || br["next_cursor"] != nil || br["has_more"] != false || len(br["data"].([]any)) != len(gapiItems(t, br)) {
		t.Fatalf("branches %v", br)
	}
	// commits and one commit with its files
	cm := gapiMap(t, g.do("GET", "/commits?branch=feature", nil))
	if len(gapiItems(t, cm)) < 1 {
		t.Fatalf("commits %v", cm)
	}
	one := gapiMap(t, g.do("GET", "/commits/"+g.feature, nil))
	if files := one["files"].([]any); len(files) != 1 || files[0].(map[string]any)["path"] != "x.txt" {
		t.Fatalf("commit files %v", one["files"])
	}
	gapiWant(t, g.do("GET", "/commits/"+strings.Repeat("0", 40), nil), 404)
	// tags
	if tags := gapiItems(t, gapiMap(t, g.do("GET", "/tags", nil))); len(tags) != 1 {
		t.Fatalf("tags %v", tags)
	}

	// workflows parsed from the default branch
	wf := gapiItems(t, gapiMap(t, g.do("GET", "/workflows", nil)))
	if len(wf) != 1 {
		t.Fatalf("workflows %v", wf)
	}
	w0 := wf[0].(map[string]any)
	if w0["id"] != "ci.yml" || w0["name"] != "CI" || len(w0["triggers"].([]any)) != 2 {
		t.Fatalf("workflow %v", w0)
	}
}

func gapiList(m map[string]any, k string) []any { l, _ := m[k].([]any); return l }

func TestGitAPIRunsAndLogs(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	runs := gapiItems(t, gapiMap(t, g.do("GET", "/runs", nil)))
	if len(runs) != 1 || runs[0].(map[string]any)["status"] != "success" || runs[0].(map[string]any)["id"] != "1" {
		t.Fatalf("runs %v", runs)
	}
	if got := gapiItems(t, gapiMap(t, g.do("GET", "/runs?workflow=other.yml", nil))); len(got) != 0 {
		t.Fatalf("workflow filter: %v", got)
	}
	run := gapiMap(t, g.do("GET", "/runs/1", nil))
	if jobs := run["jobs"].([]any); len(jobs) != 1 || jobs[0].(map[string]any)["id"] != "1001" {
		t.Fatalf("run %v", run)
	}
	rec := g.do("GET", "/runs/1/jobs/1001/logs", nil)
	gapiWant(t, rec, 200)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("logs must not be cached")
	}
	lg := gapiMap(t, rec)
	joined := strings.Join(gapiStrings(lg["lines"]), "\n")
	if strings.Contains(joined, "abc123supersecret") || strings.Contains(joined, "cgt_0123456789") {
		t.Fatalf("log leaked a secret: %s", joined)
	}
	if !strings.Contains(joined, "step 1") || lg["complete"] != true || lg["next_cursor"] != nil {
		t.Fatalf("log chunk %v", lg)
	}
	// a job of another run cannot be read through this run
	gapiWant(t, g.do("GET", "/runs/1/jobs/9999/logs", nil), 404)
	gapiWant(t, g.do("GET", "/runs/1/jobs/1001/logs?cursor=@@", nil), 400)
	gapiWant(t, g.do("GET", "/runs/abc", nil), 400)
	gapiWant(t, g.do("GET", "/runs?status=bogus", nil), 422)
	gapiWant(t, g.do("GET", "/runs?workflow=../x", nil), 422)
}

func gapiStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestLogPaging(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	var sb strings.Builder
	for i := 0; i < 4500; i++ {
		sb.WriteString("line\n")
	}
	_, job := g.fs.AddRun(gapiOrgSlug, gapiRepoSlug, "running", sb.String())
	var all int
	cursor := ""
	for i := 0; i < 5; i++ {
		path := "/runs/2/jobs/" + itoa(int(job)) + "/logs"
		if cursor != "" {
			path += "?cursor=" + cursor
		}
		lg := gapiMap(t, g.do("GET", path, nil))
		all += len(lg["lines"].([]any))
		if lg["next_cursor"] == nil {
			if lg["complete"] != false { // the job is still running: more may come
				t.Fatalf("a running job is never complete: %v", lg["complete"])
			}
			break
		}
		cursor = lg["next_cursor"].(string)
		if lg["complete"] != false {
			t.Fatal("complete with more lines pending")
		}
	}
	if all != 4501 { // 4500 lines + the "##[step] build" header gitcore writes before each step
		t.Fatalf("read %d lines, want 4501", all)
	}
}

func TestPullDocumentAndMerge(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	list := gapiMap(t, g.do("GET", "/pulls", nil))
	pr := gapiItems(t, list)[0].(map[string]any)
	if pr["number"].(float64) != 1 || pr["head_ref"] != "feature" || pr["state"] != "open" || pr["mergeable"] != nil {
		t.Fatalf("pull list item %v", pr)
	}
	doc := gapiMap(t, g.do("GET", "/pulls/1", nil))
	m := doc["mergeable"].(map[string]any)
	if m["can_merge"] != true || len(m["blockers"].([]any)) != 0 || doc["checks_state"] == nil || doc["auto_merge"] != nil {
		t.Fatalf("pull doc %v", doc)
	}

	body := map[string]any{"style": "squash", "head_sha": g.feature}
	rec := g.do("POST", "/pulls/1/merge", body, "Idempotency-Key", "k-1")
	gapiWant(t, rec, 200)
	first := rec.Body.String()
	if gapiMap(t, rec)["merged"] != true {
		t.Fatalf("merge result %s", first)
	}
	// replay: same body, no second merge call upstream
	merges := g.fs.Count("POST", "/api/v1/repos/acme/shop/pulls/1/merge")
	rec = g.do("POST", "/pulls/1/merge", body, "Idempotency-Key", "k-1")
	gapiWant(t, rec, 200)
	if rec.Body.String() != first || rec.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay differs: %s", rec.Body.String())
	}
	if g.fs.Count("POST", "/api/v1/repos/acme/shop/pulls/1/merge") != merges {
		t.Fatal("replay must not call Forgejo again")
	}
	// same key, other request
	rec = g.do("POST", "/pulls/1/merge", map[string]any{"style": "merge"}, "Idempotency-Key", "k-1")
	gapiWant(t, rec, 409)
	if gapiErrCode(t, rec) != "IDEMPOTENCY_CONFLICT" {
		t.Fatal("want IDEMPOTENCY_CONFLICT")
	}
	// the merge was made as the real user
	var sudo string
	for _, rq := range g.fs.Requests() {
		if rq.Method == "POST" && strings.HasSuffix(rq.Path, "/pulls/1/merge") {
			sudo = rq.Sudo
			if !strings.Contains(rq.Body, g.feature) {
				t.Fatalf("head SHA must be pinned in the merge call: %s", rq.Body)
			}
		}
	}
	if sudo != gapiActor {
		t.Fatalf("merge made as %q, want %q", sudo, gapiActor)
	}
	// merged pull request: state merged, nothing left to merge
	doc = gapiMap(t, g.do("GET", "/pulls/1", nil))
	if doc["state"] != "merged" || doc["mergeable"].(map[string]any)["can_merge"] != false {
		t.Fatalf("after merge: %v", doc)
	}
	gapiWant(t, g.do("POST", "/pulls/1/merge", map[string]any{"style": "squash"}), 409)
}

func TestMergeValidationAndHeadRace(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	gapiWant(t, g.do("POST", "/pulls/1/merge", map[string]any{"style": "yolo"}), 422)
	gapiWant(t, g.do("POST", "/pulls/1/merge", map[string]any{}), 422)
	gapiWant(t, g.do("POST", "/pulls/1/merge", "", ""), 422)
	gapiWant(t, g.do("POST", "/pulls/1/merge", `{"style":"squash","bogus":1}`), 422)
	gapiWant(t, g.do("POST", "/pulls/1/merge", map[string]any{"style": "squash", "head_sha": "zzz"}), 422)
	rec := g.do("POST", "/pulls/1/merge", map[string]any{"style": "squash", "head_sha": strings.Repeat("a", 40)})
	gapiWant(t, rec, 409)
	if gapiErrCode(t, rec) != "HEAD_CHANGED" {
		t.Fatalf("want HEAD_CHANGED, got %s", rec.Body.String())
	}
	gapiWant(t, g.do("POST", "/pulls/99/merge", map[string]any{"style": "squash"}), 404)
	gapiWant(t, g.do("POST", "/pulls/x/merge", map[string]any{"style": "squash"}), 400)
}

func TestMergeBlockersFromProtection(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	ctx := context.Background()
	_, err := g.core.UpsertProtection(ctx, gapiRef, gitcore.ProtectionSpec{RuleName: "main", EnableStatusCheck: true,
		StatusCheckContexts: []string{"ci / build (push)"}, RequiredApprovals: 1, BlockOnRejectedReviews: true})
	gapiMust(t, err)

	doc := gapiMap(t, g.do("GET", "/pulls/1", nil))
	m := doc["mergeable"].(map[string]any)
	var got []string
	for _, b := range m["blockers"].([]any) {
		got = append(got, b.(map[string]any)["code"].(string))
	}
	if m["can_merge"] != false || strings.Join(got, ",") != "CHECKS_REQUIRED,REVIEWS_REQUIRED" {
		t.Fatalf("blockers %v in %v", got, m)
	}

	rec := g.do("POST", "/pulls/1/merge", map[string]any{"style": "squash"})
	gapiWant(t, rec, 409)
	if gapiErrCode(t, rec) != "CHECKS_REQUIRED" {
		t.Fatalf("code %s", rec.Body.String())
	}
	details := gapiMap(t, rec)["error"].(map[string]any)["details"].(map[string]any)
	if len(details["blockers"].([]any)) != 2 {
		t.Fatalf("details %v", details)
	}
	if g.fs.Count("POST", "/api/v1/repos/acme/shop/pulls/1/merge") != 0 {
		t.Fatal("a blocked merge must never reach Forgejo")
	}

	// green check + an approval from someone else lifts the blockers
	_, err = g.core.SetCheck(ctx, gapiRef, g.feature, gitcore.CheckInput{Context: "ci / build (push)", State: gitcore.CheckSuccess})
	gapiMust(t, err)
	_, err = g.core.CreateReview(gitcore.WithActor(ctx, gapiActor), gapiRef, 1, gitcore.ReviewCreate{Event: gitcore.ReviewApprove})
	gapiMust(t, err)
	doc = gapiMap(t, g.do("GET", "/pulls/1", nil))
	if m = doc["mergeable"].(map[string]any); m["can_merge"] != true {
		t.Fatalf("after approval and green check: %v", m)
	}
	gapiWant(t, g.do("POST", "/pulls/1/merge", map[string]any{"style": "squash"}), 200)
}

func TestDraftBlocksMerge(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	rec := g.do("POST", "/pulls", map[string]any{"title": "Add y", "head": "feature2", "base": "main", "draft": true})
	gapiWant(t, rec, 201)
	doc := gapiMap(t, rec)
	if doc["draft"] != true {
		t.Fatalf("draft flag: %v", doc)
	}
	rec = g.do("POST", "/pulls/2/merge", map[string]any{"style": "merge"})
	gapiWant(t, rec, 409)
	if gapiErrCode(t, rec) != "DRAFT" {
		t.Fatalf("want DRAFT, got %s", rec.Body.String())
	}
}

func TestMergeUpstreamErrorsMapping(t *testing.T) {
	cases := []struct {
		name   string
		err    *gitcore.Error
		status int
		code   string
		retry  bool
	}{
		{"locked right after create", &gitcore.Error{Code: gitcore.CodeConflict, Status: 423, Message: "Please try again later", Retry: true}, 409, "TRY_AGAIN", true},
		{"405 not allowed now", &gitcore.Error{Code: gitcore.CodeConflict, Status: 405, Message: "not mergeable"}, 409, "CONFLICT", false},
		{"protection refuses", &gitcore.Error{Code: gitcore.CodeForbidden, Status: 403, Message: "protected"}, 409, "PROTECTED_BRANCH", false},
		{"upstream down", &gitcore.Error{Code: gitcore.CodeUpstream, Status: 502, Message: "down", Retry: true}, 502, "UPSTREAM_GIT_ERROR", true},
		{"breaker open", &gitcore.Error{Code: gitcore.CodeNotReady, Message: "circuit open"}, 503, "GIT_NOT_READY", true},
	}
	for _, c := range cases {
		c := c
		g := newGapiRig(t, gapiOpts{core: func(s *gitcore.Service) gitcore.Core { return &mergeFails{Core: s, err: c.err} }})
		rec := g.do("POST", "/pulls/1/merge", map[string]any{"style": "squash"})
		if rec.Code != c.status || gapiErrCode(t, rec) != c.code {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body.String())
		}
		if c.retry && rec.Header().Get("Retry-After") == "" {
			t.Errorf("%s: missing Retry-After", c.name)
		}
		if strings.Contains(rec.Body.String(), "fake-service-token") {
			t.Errorf("%s: token leaked", c.name)
		}
	}
}

type mergeFails struct {
	gitcore.Core
	err *gitcore.Error
}

func (m *mergeFails) MergePull(context.Context, gitcore.RepoRef, int, gitcore.MergeRequest) (*gitcore.MergeResult, error) {
	return nil, m.err
}

func TestMergeFailsClosedWhenPolicyCannotBeEvaluated(t *testing.T) {
	g := newGapiRig(t, gapiOpts{core: func(s *gitcore.Service) gitcore.Core { return &protectionDown{Core: s} }})
	doc := gapiMap(t, g.do("GET", "/pulls/1", nil))
	m := doc["mergeable"].(map[string]any)
	if m["can_merge"] != false || m["blockers"].([]any)[0].(map[string]any)["code"] != "POLICY_BLOCKED" {
		t.Fatalf("an unevaluable pull request must be unmergeable: %v", m)
	}
	rec := g.do("POST", "/pulls/1/merge", map[string]any{"style": "squash"})
	if rec.Code != 502 {
		t.Fatalf("merge must refuse when the policy cannot be read: %d %s", rec.Code, rec.Body.String())
	}
	if g.fs.Count("POST", "/api/v1/repos/acme/shop/pulls/1/merge") != 0 {
		t.Fatal("must not merge blind")
	}
}

type protectionDown struct{ gitcore.Core }

func (protectionDown) ListProtections(context.Context, gitcore.RepoRef) ([]gitcore.Protection, error) {
	return nil, &gitcore.Error{Code: gitcore.CodeUpstream, Message: "down", Retry: true}
}

func TestReviewsAndComments(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	// bob is not the author (alice): can review
	rec := g.do("POST", "/pulls/1/reviews", map[string]any{"event": "request_changes", "body": "please fix", "commit_sha": g.feature,
		"comments": []map[string]any{{"path": "x.txt", "line": 1, "body": "nit", "suggestion": "y"}}})
	gapiWant(t, rec, 201)
	rv := gapiMap(t, rec)
	if rv["state"] != "changes_requested" || rv["author"].(map[string]any)["login"] != gapiActor {
		t.Fatalf("review %v", rv)
	}
	var sawSuggestion bool
	for _, rq := range g.fs.Requests() {
		if rq.Method == "POST" && strings.HasSuffix(rq.Path, "/reviews") {
			sawSuggestion = strings.Contains(rq.Body, "```suggestion")
			if rq.Sudo != gapiActor {
				t.Fatalf("review attributed to %q", rq.Sudo)
			}
		}
	}
	if !sawSuggestion {
		t.Fatal("suggestion block missing from the inline comment")
	}
	list := gapiMap(t, g.do("GET", "/pulls/1/reviews", nil))
	if len(gapiItems(t, list)) != 1 || list["approvals"].(float64) != 0 || list["code_owner_pending"] == nil {
		t.Fatalf("reviews %v", list)
	}
	// validation
	gapiWant(t, g.do("POST", "/pulls/1/reviews", map[string]any{"event": "nope"}), 422)
	gapiWant(t, g.do("POST", "/pulls/1/reviews", map[string]any{"event": "comment"}), 422)
	gapiWant(t, g.do("POST", "/pulls/1/reviews", map[string]any{"event": "comment", "body": "x", "comments": []map[string]any{{"path": "../x", "line": 1, "body": "b"}}}), 422)
	gapiWant(t, g.do("POST", "/pulls/1/reviews", map[string]any{"event": "comment", "body": "x", "comments": []map[string]any{{"path": "a", "line": 0, "body": "b"}}}), 422)
	// stale commit
	rec = g.do("POST", "/pulls/1/reviews", map[string]any{"event": "approve", "commit_sha": strings.Repeat("b", 40)})
	gapiWant(t, rec, 409)
	if gapiErrCode(t, rec) != "HEAD_CHANGED" {
		t.Fatal("want HEAD_CHANGED")
	}
	// comments
	gapiWant(t, g.do("POST", "/pulls/1/comments", map[string]any{"body": "  "}), 422)
	rec = g.do("POST", "/pulls/1/comments", map[string]any{"body": "looks good"})
	gapiWant(t, rec, 201)
	if c := gapiMap(t, rec); c["body"] != "looks good" || c["author"].(map[string]any)["login"] != gapiActor {
		t.Fatalf("comment %v", c)
	}
	if got := gapiItems(t, gapiMap(t, g.do("GET", "/pulls/1/comments", nil))); len(got) != 1 {
		t.Fatalf("comments %v", got)
	}
}

func TestSelfApprovalForbidden(t *testing.T) {
	// the requesting user IS the pull request author (alice)
	g := newGapiRig(t, gapiOpts{})
	g.as("alice")
	rec := g.do("POST", "/pulls/1/reviews", map[string]any{"event": "approve"})
	gapiWant(t, rec, 422)
	if gapiErrCode(t, rec) != "SELF_APPROVAL_FORBIDDEN" {
		t.Fatalf("code %s", rec.Body.String())
	}
	// but the author may comment
	gapiWant(t, g.do("POST", "/pulls/1/reviews", map[string]any{"event": "comment", "body": "note to self"}), 201)
}

func TestIdentityNotReadyIsNotServiceAccount(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	g.as("")
	rec := g.do("POST", "/pulls/1/comments", map[string]any{"body": "x"})
	gapiWant(t, rec, 503)
	if g.fs.Count("POST", "/api/v1/repos/acme/shop/issues") != 0 {
		t.Fatal("a comment must never be posted as the service account")
	}
}

func TestPullCreateUpdateAndValidation(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	gapiWant(t, g.do("POST", "/pulls", map[string]any{"title": "", "head": "feature2", "base": "main"}), 422)
	gapiWant(t, g.do("POST", "/pulls", map[string]any{"title": "x\ny", "head": "feature2", "base": "main"}), 422)
	gapiWant(t, g.do("POST", "/pulls", map[string]any{"title": "t", "head": "main", "base": "main"}), 422)
	gapiWant(t, g.do("POST", "/pulls", map[string]any{"title": "t", "head": "fork:feat", "base": "main"}), 422)
	gapiWant(t, g.do("POST", "/pulls", map[string]any{"title": "t", "head": "feature2", "base": "main", "reviewers": []string{"a b"}}), 422)
	gapiWant(t, g.do("POST", "/pulls", map[string]any{"title": "t", "head": "ghost", "base": "main"}), 404)
	rec := g.do("POST", "/pulls", map[string]any{"title": "Add y", "head": "feature2", "base": "main", "body": "why"})
	gapiWant(t, rec, 201)
	if d := gapiMap(t, rec); d["number"].(float64) != 2 || d["author"].(map[string]any)["login"] != gapiActor || d["mergeable"] == nil {
		t.Fatalf("created %v", d)
	}
	gapiWant(t, g.do("PATCH", "/pulls/2", map[string]any{}), 422)
	gapiWant(t, g.do("PATCH", "/pulls/2", map[string]any{"state": "merged"}), 422)
	gapiWant(t, g.do("PATCH", "/pulls/2", map[string]any{"title": "Renamed"}), 200)
	rec = g.do("PATCH", "/pulls/2", map[string]any{"state": "closed"})
	gapiWant(t, rec, 200)
	if gapiMap(t, rec)["state"] != "closed" {
		t.Fatalf("closed: %s", rec.Body.String())
	}
	if got := gapiItems(t, gapiMap(t, g.do("GET", "/pulls?state=closed", nil))); len(got) != 1 {
		t.Fatalf("closed list %v", got)
	}
	gapiWant(t, g.do("GET", "/pulls?state=weird", nil), 422)
	if got := gapiItems(t, gapiMap(t, g.do("GET", "/pulls?author=nobody", nil))); len(got) != 0 {
		t.Fatalf("author filter %v", got)
	}
	// files and commits
	if files := gapiMap(t, g.do("GET", "/pulls/1/files", nil)); len(gapiItems(t, files)) != 1 || files["truncated"] != false {
		t.Fatalf("files %v", files)
	}
	if got := gapiItems(t, gapiMap(t, g.do("GET", "/pulls/1/commits", nil))); len(got) < 1 {
		t.Fatalf("commits %v", got)
	}
	// update-branch is accepted and answers a job
	rec = g.do("POST", "/pulls/1/update-branch", nil)
	gapiWant(t, rec, 202)
	if j := gapiMap(t, rec); j["status"] != "success" || j["id"] == "" {
		t.Fatalf("job %v", j)
	}
	// checks
	if ck := gapiMap(t, g.do("GET", "/pulls/1/checks", nil)); ck["state"] == nil || ck["items"] == nil {
		t.Fatalf("checks %v", ck)
	}
}

func TestBranchesAndTagsWrite(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	gapiWant(t, g.do("POST", "/branches", map[string]any{"name": "-bad", "from": "main"}), 422)
	gapiWant(t, g.do("POST", "/branches", map[string]any{"name": "ok", "from": "ma..in"}), 422)
	gapiWant(t, g.do("POST", "/branches", `{"name":"ok","from":"main","x":1}`), 422)
	rec := g.do("POST", "/branches", map[string]any{"name": "topic/one", "from": "main"})
	gapiWant(t, rec, 201)
	if gapiMap(t, rec)["name"] != "topic/one" {
		t.Fatalf("created %s", rec.Body.String())
	}
	// a branch with a slash is deletable both raw and url-encoded
	gapiWant(t, g.do("DELETE", "/branches/topic%2Fone", nil), 204)
	g.do("POST", "/branches", map[string]any{"name": "topic/two", "from": "main"})
	gapiWant(t, g.do("DELETE", "/branches/topic/two", nil), 204)
	// default branch cannot be deleted
	rec = g.do("DELETE", "/branches/main", nil)
	gapiWant(t, rec, 409)
	if gapiErrCode(t, rec) != "PROTECTED_BRANCH" {
		t.Fatal("want PROTECTED_BRANCH")
	}
	gapiWant(t, g.do("DELETE", "/branches/ghost", nil), 404)
	// tags
	gapiWant(t, g.do("POST", "/tags", map[string]any{"name": "v2", "target": "main", "message": "second"}), 201)
	gapiWant(t, g.do("DELETE", "/tags/v2", nil), 204)
	gapiWant(t, g.do("POST", "/tags", map[string]any{"name": "v3", "target": "-x"}), 422)
}

func TestBranchPagination(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	for _, n := range []string{"b1", "b2", "b3", "b4"} {
		g.fs.Commit(gapiOrgSlug, gapiRepoSlug, n, "c "+n, map[string]string{n: n})
	}
	seen := map[string]bool{}
	cursor := ""
	for i := 0; i < 10; i++ {
		path := "/branches?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		page := gapiMap(t, g.do("GET", path, nil))
		its := gapiItems(t, page)
		if len(its) > 2 {
			t.Fatalf("page too big: %d", len(its))
		}
		for _, b := range its {
			seen[b.(map[string]any)["name"].(string)] = true
		}
		if page["next_cursor"] == nil {
			break
		}
		cursor = page["next_cursor"].(string)
	}
	if len(seen) < 7 { // main, feature, feature2, b1..b4
		t.Fatalf("cursor walk saw %v", seen)
	}
	gapiWant(t, g.do("GET", "/branches?limit=0", nil), 422)
	gapiWant(t, g.do("GET", "/branches?limit=abc", nil), 422)
	if rec := g.do("GET", "/branches?cursor=!!!", nil); rec.Code != 400 {
		t.Fatalf("bad cursor: %d %s", rec.Code, rec.Body.String())
	}
}

func TestBlobTruncatedOverLimit(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	g.fs.Commit(gapiOrgSlug, gapiRepoSlug, "main", "big", map[string]string{"big.txt": strings.Repeat("a", gitcore.MaxBlobBytes+10)})
	b := gapiMap(t, g.do("GET", "/blob?path=big.txt", nil))
	if b["truncated"] != true || b["content"] != nil && b["content"] != "" {
		t.Fatalf("blob over the limit must be truncated without content: truncated=%v len=%v", b["truncated"], len(b["content"].(string)))
	}
}

func TestDispatchRerunCancelAndGuards(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	gapiWant(t, g.do("POST", "/workflows/..%2Fx.yml/dispatch", map[string]any{"ref": "main"}), 422)
	gapiWant(t, g.do("POST", "/workflows/ci.txt/dispatch", map[string]any{"ref": "main"}), 422)
	gapiWant(t, g.do("POST", "/workflows/ci.yml/dispatch", map[string]any{"ref": "-x"}), 422)
	gapiWant(t, g.do("POST", "/workflows/ci.yml/dispatch", map[string]any{"ref": "main", "inputs": map[string]string{"bad name": "x"}}), 422)
	if rec := g.do("POST", "/workflows/ci.yml/dispatch", map[string]any{"ref": "main", "inputs": map[string]string{"env": "prod"}}, "Idempotency-Key", "d1"); rec.Code != 202 {
		t.Fatalf("dispatch %d %s", rec.Code, rec.Body.String())
	}
	n := g.fs.Count("POST", "/api/v1/repos/acme/shop/actions/workflows/ci.yml/dispatches")
	rec := g.do("POST", "/workflows/ci.yml/dispatch", map[string]any{"ref": "main", "inputs": map[string]string{"env": "prod"}}, "Idempotency-Key", "d1")
	if rec.Code != 202 || rec.Header().Get("Idempotent-Replayed") != "true" || g.fs.Count("POST", "/api/v1/repos/acme/shop/actions/workflows/ci.yml/dispatches") != n || n != 1 {
		t.Fatalf("dispatch replay: %d replayed=%q upstream=%d", rec.Code, rec.Header().Get("Idempotent-Replayed"), n)
	}
	// web session on: cancel works, re-run restarts the SAME run (Forgejo new attempt), only the failed
	// jobs when asked, and a run without failed jobs says so
	gapiWant(t, g.do("POST", "/runs/1/cancel", nil), 202)
	g.fs.SetRunStatus("acme", "shop", 1, "failure")
	gapiWant(t, g.do("POST", "/runs/1/rerun?failed=true", nil), 202)
	gapiWant(t, g.do("POST", "/runs/1/rerun?failed=maybe", nil), 422)
	g.fs.SetRunStatus("acme", "shop", 1, "success")
	gapiWant(t, g.do("POST", "/runs/1/rerun?failed=true", nil), 409)
	n = g.fs.Count("POST", "/acme/shop/actions/runs/1/rerun")
	for i := 0; i < 2; i++ {
		rec = g.do("POST", "/runs/1/rerun", nil, "Idempotency-Key", "r1")
		gapiWant(t, rec, 202)
		if gapiMap(t, rec)["id"] != "1" {
			t.Fatalf("rerun %s", rec.Body.String())
		}
	}
	if got := g.fs.Count("POST", "/acme/shop/actions/runs/1/rerun"); got != n+1 {
		t.Fatalf("rerun posted %d times for one Idempotency-Key", got-n)
	}
	g.fs.AddArtifact("acme", "shop", 1, "bundle", "hello")
	arts := gapiItems(t, gapiMap(t, g.do("GET", "/runs/1/artifacts", nil)))
	if len(arts) != 1 || arts[0].(map[string]any)["name"] != "bundle" {
		t.Fatalf("artifacts: %v", arts)
	}

	// WITHOUT the web session (no CAPSULE_GIT_BOT_PASSWORD) everything that needs it degrades honestly
	g0 := newGapiRig(t, gapiOpts{noWeb: true})
	for _, c := range []struct{ m, p string }{{"POST", "/runs/1/cancel"}, {"POST", "/runs/1/rerun?failed=true"}, {"GET", "/runs/1/artifacts"}, {"GET", "/runs/1/jobs/1001/logs"}} {
		rec = g0.do(c.m, c.p, nil)
		gapiWant(t, rec, 501)
		if gapiErrCode(t, rec) != "NOT_SUPPORTED" || !strings.Contains(rec.Body.String(), "CAPSULE_GIT_BOT_PASSWORD") || !strings.Contains(rec.Body.String(), "/actions") {
			t.Fatalf("%s %s: %s", c.m, c.p, rec.Body.String())
		}
	}
	// the run page still opens, without jobs, with the reason
	run0 := gapiMap(t, g0.do("GET", "/runs/1", nil))
	if run0["id"] != "1" || run0["jobs"] != nil || !strings.Contains(gapiStr(run0["jobs_unavailable"]), "CAPSULE_GIT_BOT_PASSWORD") {
		t.Fatalf("run without web session: %v", run0)
	}
	// whole-run re-run falls back to dispatching the workflow (a NEW run)
	rec = g0.do("POST", "/runs/1/rerun", nil)
	gapiWant(t, rec, 202)
	if gapiMap(t, rec)["id"] != "2" {
		t.Fatalf("fallback rerun %s", rec.Body.String())
	}
	g.fs.AddRunner("org", gapiOrgSlug, "", "r1", "idle", "ubuntu")
	g.fs.AddRunner("repo", gapiOrgSlug, gapiRepoSlug, "r-repo", "offline")
	runners := gapiItems(t, gapiMap(t, g.do("GET", g.orgPath("/git/runners"), nil)))
	if len(runners) != 1 || runners[0].(map[string]any)["status"] != "online" || runners[0].(map[string]any)["trusted"] != true {
		t.Fatalf("runners: %v", runners)
	}
	if err := g.core.SetSecret(context.Background(), gitcore.RepoRef{Owner: gapiOrgSlug, Repo: gapiRepoSlug}, "DB_PASSWORD", "hunter2"); err != nil {
		t.Fatal(err)
	}
	rec = g.do("GET", "/secrets", nil)
	if got := gapiItems(t, gapiMap(t, rec)); len(got) != 2 || !strings.Contains(rec.Body.String(), "DB_PASSWORD") || strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("secrets list must carry names only: %s", rec.Body.String())
	}
	gapiWant(t, g.do("PUT", g.orgPath("/git/secrets/TEAM_SECRET"), map[string]any{"value": "t"}), 204)
	if got := gapiItems(t, gapiMap(t, g.do("GET", g.orgPath("/git/secrets"), nil))); len(got) != 2 || got[1].(map[string]any)["scope"] != "org" || got[1].(map[string]any)["name"] != "TEAM_SECRET" {
		t.Fatalf("org secrets: %v", got)
	}

	// a core that supplies the gitapi-typed capabilities itself (legacy rig) still works
	var ext *gapiExt
	g2 := newGapiRig(t, gapiOpts{core: func(s *gitcore.Service) gitcore.Core { ext = &gapiExt{Core: s}; return ext }})
	rec = g2.do("POST", "/runs/1/rerun", nil, "Idempotency-Key", "r1")
	gapiWant(t, rec, 202)
	if ext.reruns != 1 || gapiMap(t, rec)["id"] != "101" {
		t.Fatalf("rig rerun %s (%d)", rec.Body.String(), ext.reruns)
	}
	gapiWant(t, g2.do("GET", "/runs/1/artifacts", nil), 200)

	// without the capability at all: 501, never a fake success
	g3 := newGapiRig(t, gapiOpts{core: func(s *gitcore.Service) gitcore.Core { return gapiBare{Core: s} }})
	gapiWant(t, g3.do("GET", "/secrets", nil), 501)
	gapiWant(t, g3.do("GET", "/runs/1/artifacts", nil), 501)
}

// gapiBare hides every optional capability of the wrapped core (only the Core interface shows).
type gapiBare struct{ gitcore.Core }

func TestCIVariablesAndSecrets(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	vars := gapiItems(t, gapiMap(t, g.do("GET", "/variables", nil)))
	scopes := map[string]string{}
	for _, v := range vars {
		m := v.(map[string]any)
		scopes[m["name"].(string)] = m["scope"].(string)
	}
	if scopes["MY_VAR"] != "repo" || scopes["ORG_VAR"] != "org" {
		t.Fatalf("variables %v", scopes)
	}
	gapiWant(t, g.do("PUT", "/variables/NEW_VAR", map[string]any{"value": "v"}), 204)
	gapiWant(t, g.do("PUT", "/variables/bad-name", map[string]any{"value": "v"}), 422)
	gapiWant(t, g.do("PUT", "/variables/GITHUB_TOKEN", map[string]any{"value": "v"}), 422)
	gapiWant(t, g.do("PUT", "/variables/FORGEJO_X", map[string]any{"value": "v"}), 422)
	gapiWant(t, g.do("PUT", "/variables/OK", map[string]any{"value": ""}), 422)
	gapiWant(t, g.do("PUT", "/variables/OK", map[string]any{"value": strings.Repeat("x", maxCIValue+1)}), 422)
	gapiWant(t, g.do("DELETE", "/variables/NEW_VAR", nil), 204)
	gapiWant(t, g.do("PUT", "/secrets/DB_PASSWORD", map[string]any{"value": "hunter2"}), 204)
	if v, ok := g.fs.HasVar(gapiOrgSlug, gapiRepoSlug, "NEW_VAR"); ok {
		t.Fatalf("variable still there: %s", v)
	}
	gapiWant(t, g.do("DELETE", "/secrets/DB_PASSWORD", nil), 204)
	// org level
	gapiWant(t, g.do("PUT", g.orgPath("/git/variables/TEAM_VAR"), map[string]any{"value": "t"}), 204)
	if got := gapiItems(t, gapiMap(t, g.do("GET", g.orgPath("/git/variables"), nil))); len(got) < 2 {
		t.Fatalf("org vars %v", got)
	}
	gapiWant(t, g.do("PUT", g.orgPath("/git/secrets/TEAM_SECRET"), map[string]any{"value": "t"}), 204)
	gapiWant(t, g.do("DELETE", g.orgPath("/git/secrets/TEAM_SECRET"), nil), 204)
	gapiWant(t, g.do("DELETE", g.orgPath("/git/variables/TEAM_VAR"), nil), 204)
}

func TestActivityAndInsights(t *testing.T) {
	g := newGapiRig(t, gapiOpts{})
	act := gapiMap(t, g.do("GET", "/activity?limit=100", nil))
	types := map[string]bool{}
	for _, e := range gapiItems(t, act) {
		types[e.(map[string]any)["type"].(string)] = true
	}
	for _, want := range []string{"push", "pull_request.opened", "workflow_run"} {
		if !types[want] {
			t.Fatalf("activity types %v", types)
		}
	}
	first := gapiMap(t, g.do("GET", "/activity?limit=2", nil))
	if len(gapiItems(t, first)) != 2 || first["next_cursor"] == nil {
		t.Fatalf("activity page %v", first)
	}
	if got := gapiItems(t, gapiMap(t, g.do("GET", "/activity?limit=2&cursor="+first["next_cursor"].(string), nil))); len(got) == 0 {
		t.Fatal("second activity page empty")
	}
	// the fake's commits are dated 2026-11-02
	in := gapiMap(t, g.do("GET", "/insights?since=2026-10-01&until=2026-12-01", nil))
	if in["commits"].(float64) < 2 || in["prs_opened"].(float64) != 1 || len(in["contributors"].([]any)) < 1 {
		t.Fatalf("insights %v", in)
	}
	gapiWant(t, g.do("GET", "/insights?since=yesterday", nil), 422)
	gapiWant(t, g.do("GET", "/insights?since=2020-01-01&until=2026-12-01", nil), 422)
	gapiWant(t, g.do("GET", "/insights?since=2026-12-01&until=2026-10-01", nil), 422)
}

func TestPermissionsAndAvailability(t *testing.T) {
	// hidden project in restricted mode: 404, not 403
	g := newGapiRig(t, gapiOpts{role: "hidden"})
	if rec := g.do("GET", "/branches", nil); rec.Code != 404 {
		t.Fatalf("hidden: %d", rec.Code)
	}
	// not a member: 403
	g = newGapiRig(t, gapiOpts{role: "none"})
	if rec := g.do("GET", "/branches", nil); rec.Code != 403 {
		t.Fatalf("outsider: %d", rec.Code)
	}
	// viewer reads but cannot write
	g = newGapiRig(t, gapiOpts{role: "viewer"})
	gapiWant(t, g.do("GET", "/branches", nil), 200)
	gapiWant(t, g.do("POST", "/branches", map[string]any{"name": "x", "from": "main"}), 403)
	gapiWant(t, g.do("POST", "/pulls/1/merge", map[string]any{"style": "squash"}), 403)
	gapiWant(t, g.do("POST", "/pulls/1/reviews", map[string]any{"event": "comment", "body": "x"}), 403)
	gapiWant(t, g.do("PATCH", "/repo", map[string]any{"archived": true}), 403)
	gapiWant(t, g.do("GET", "/secrets", nil), 403)
	// deployer writes but is not a git admin
	g = newGapiRig(t, gapiOpts{role: "deployer"})
	gapiWant(t, g.do("POST", "/branches", map[string]any{"name": "x", "from": "main"}), 201)
	gapiWant(t, g.do("PATCH", "/repo", map[string]any{"archived": true}), 403)
	gapiWant(t, g.do("PUT", "/variables/X", map[string]any{"value": "1"}), 403)
	gapiWant(t, g.do("PUT", g.orgPath("/git/variables/X"), map[string]any{"value": "1"}), 403)
	gapiWant(t, g.do("GET", g.orgPath("/git/variables"), nil), 200)
	// another project of the URL: the pair org/project must match
	other := "/orgs/" + g.org.ID.String() + "/projects/" + "00000000-0000-0000-0000-000000000001" + "/git/branches"
	if rec := g.do("GET", other, nil); rec.Code != 404 && rec.Code != 403 {
		t.Fatalf("foreign project: %d", rec.Code)
	}
	// integration off: 503 GIT_NOT_READY (after authorization)
	g = newGapiRig(t, gapiOpts{disabled: true})
	rec := g.do("GET", "/tree", nil)
	gapiWant(t, rec, 503)
	if gapiErrCode(t, rec) != "GIT_NOT_READY" {
		t.Fatalf("code %s", rec.Body.String())
	}
	g = newGapiRig(t, gapiOpts{disabled: true, role: "none"})
	gapiWant(t, g.do("GET", "/tree", nil), 403)
}

func TestLegacyProviderFallback(t *testing.T) {
	// A GitHub-linked project keeps the pre-B1 view even when the core Git service is off.
	g := newGapiRig(t, gapiOpts{disabled: true, link: &domain.ProjectGit{Provider: "github", RepoURL: "https://github.com/a/b", Branch: "main"}})
	withLegacyClient(t, g)
	rec := g.do("GET", "/branches", nil)
	if rec.Code != 200 || len(gapiMap(t, rec)["data"].([]any)) != 1 {
		t.Fatalf("legacy branches: %d %s", rec.Code, rec.Body.String())
	}
	// A Forgejo link goes through the new implementation (and needs the core).
	g = newGapiRig(t, gapiOpts{disabled: true, link: &domain.ProjectGit{Provider: "forgejo", RepoURL: "https://git.example.com/a/b", Branch: "main"}})
	gapiWant(t, g.do("GET", "/branches", nil), 503)
}

func TestMountedRoutesMatchTheContract(t *testing.T) {
	// every mounted route must exist in API.openapi.yaml (see TestContract for the reverse)
	g := newGapiRig(t, gapiOpts{legacy: true})
	for _, rt := range g.routes() {
		if _, ok := gapiContractOps(t)[rt]; !ok {
			t.Errorf("route %s is mounted but not in API.openapi.yaml", rt)
		}
	}
}

// withLegacyClient points the pre-B1 views at a stub provider API.
func withLegacyClient(t *testing.T, g *gapiRig) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/repos/a/b":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/api/v1/repos/a/b/branches":
			_, _ = w.Write([]byte(`[{"name":"main","commit":{"id":"aaaaaaaa11111111"},"protected":true}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	g.legacy.clientFor = func(*domain.ProjectGit) (*gitsource.ProviderClient, error) {
		return &gitsource.ProviderClient{Kind: "forgejo", APIBase: srv.URL + "/api/v1", Owner: "a", Repo: "b", Token: "t", HTTP: srv.Client()}, nil
	}
}

// repoStub is a core whose repository settings behave like Forgejo's (the fake only models the
// default branch): PATCH applies the flags, GET reports them.
type repoStub struct {
	gitcore.Core
	repo  gitcore.Repository
	patch gitcore.RepoPatch
}

func (r *repoStub) GetRepo(context.Context, gitcore.RepoRef) (*gitcore.Repository, error) {
	c := r.repo
	return &c, nil
}

func (r *repoStub) PatchRepo(_ context.Context, _ gitcore.RepoRef, p gitcore.RepoPatch) (*gitcore.Repository, error) {
	r.patch = p
	if p.DefaultBranch != nil {
		r.repo.DefaultBranch = *p.DefaultBranch
	}
	if p.DeleteBranchOnPR != nil {
		r.repo.DeleteBranchOnPR = *p.DeleteBranchOnPR
	}
	if p.Archived != nil {
		r.repo.Archived = *p.Archived
	}
	if p.AllowedMergeStyles != nil {
		r.repo.AllowedMergeStyles = p.AllowedMergeStyles
	}
	c := r.repo
	return &c, nil
}

func TestRepoUpdate(t *testing.T) {
	stub := &repoStub{repo: gitcore.Repository{Owner: gapiOrgSlug, Name: gapiRepoSlug, DefaultBranch: "main", AllowedMergeStyles: []string{"merge", "squash", "rebase"}}}
	g := newGapiRig(t, gapiOpts{core: func(s *gitcore.Service) gitcore.Core { stub.Core = s; return stub }})
	gapiWant(t, g.do("PATCH", "/repo", map[string]any{}), 422)
	gapiWant(t, g.do("PATCH", "/repo", map[string]any{"allowed_merge_styles": []string{}}), 422)
	gapiWant(t, g.do("PATCH", "/repo", map[string]any{"allowed_merge_styles": []string{"yolo"}}), 422)
	gapiWant(t, g.do("PATCH", "/repo", map[string]any{"allowed_merge_styles": []string{"squash", "squash"}}), 422)
	gapiWant(t, g.do("PATCH", "/repo", map[string]any{"default_branch": "ghost"}), 422)
	gapiWant(t, g.do("PATCH", "/repo", map[string]any{"default_branch": "-x"}), 422)
	gapiWant(t, g.do("PATCH", "/repo", `{"nope":1}`), 422)
	rec := g.do("PATCH", "/repo", map[string]any{"default_branch": "feature", "delete_branch_on_merge": true, "allowed_merge_styles": []string{"squash"}})
	gapiWant(t, rec, 200)
	d := gapiMap(t, rec)
	if d["default_branch"] != "feature" || d["delete_branch_on_merge"] != true {
		t.Fatalf("repo %v", d)
	}
	if stub.patch.DeleteBranchOnPR == nil || !*stub.patch.DeleteBranchOnPR || len(stub.patch.AllowedMergeStyles) != 1 || stub.patch.AllowedMergeStyles[0] != "squash" {
		t.Fatalf("patch sent to the core: %+v", stub.patch)
	}
	// the allowed styles are enforced by the merge route before Forgejo is called
	rec = g.do("POST", "/pulls/1/merge", map[string]any{"style": "rebase"})
	gapiWant(t, rec, 422)
	if !strings.Contains(rec.Body.String(), "squash") {
		t.Fatalf("message should list the allowed styles: %s", rec.Body.String())
	}
	// the repo default for "delete branch" is applied when the request does not say
	gapiWant(t, g.do("POST", "/pulls/1/merge", map[string]any{"style": "squash"}), 200)
	var del string
	for _, rq := range g.fs.Requests() {
		if rq.Method == "POST" && strings.HasSuffix(rq.Path, "/pulls/1/merge") {
			del = rq.Body
		}
	}
	if !strings.Contains(del, `"delete_branch_after_merge":true`) {
		t.Fatalf("merge body %s", del)
	}
}

// linearStore answers only ListRules: a project with one rule that requires linear history.
type linearStore struct{ gitprotect.Store }

func (linearStore) ListRules(context.Context, uuid.UUID) ([]gitprotect.Rule, error) {
	return []gitprotect.Rule{{Pattern: "main", RequireLinearHistory: true}}, nil
}

func TestProtectedTagAndMergeStyleHooks(t *testing.T) {
	prev := gitprotect.Shared()
	gitprotect.SetShared(gitprotect.New(linearStore{}, nil, gitprotect.DefaultConfig(), nil))
	t.Cleanup(func() { gitprotect.SetShared(prev) })

	dep := newGapiRig(t, gapiOpts{role: "deployer"})
	rec := dep.do("POST", "/tags", map[string]any{"name": "v1.0.0", "target": "main"})
	gapiWant(t, rec, 403)
	if gapiErrCode(t, rec) != "PROTECTED_TAG" {
		t.Fatalf("code %s", rec.Body.String())
	}
	gapiWant(t, dep.do("POST", "/tags", map[string]any{"name": "nightly-1", "target": "main"}), 201)
	gapiWant(t, dep.do("DELETE", "/tags/v1", nil), 403)

	adm := newGapiRig(t, gapiOpts{role: "admin"})
	gapiWant(t, adm.do("POST", "/tags", map[string]any{"name": "v1.0.0", "target": "main"}), 201)
	gapiWant(t, adm.do("DELETE", "/tags/v1.0.0", nil), 204)

	rec = adm.do("PATCH", "/repo", map[string]any{"allowed_merge_styles": []string{"merge", "rebase"}})
	gapiWant(t, rec, 422)
	if gapiErrCode(t, rec) != "POLICY_BLOCKED" {
		t.Fatalf("code %s", rec.Body.String())
	}
	gapiWant(t, adm.do("PATCH", "/repo", map[string]any{"allowed_merge_styles": []string{"rebase"}}), 200)
}

func gapiStr(v any) string { s, _ := v.(string); return s }
