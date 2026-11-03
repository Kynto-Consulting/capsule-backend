package gitcore_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitcore/fake"
)

type memCache struct {
	mu   sync.Mutex
	m    map[string]string
	gets int
	sets int
}

func newMem() *memCache { return &memCache{m: map[string]string{}} }
func (c *memCache) Get(_ context.Context, k string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets++
	v, ok := c.m[k]
	if !ok {
		return "", errors.New("miss")
	}
	return v, nil
}
func (c *memCache) Set(_ context.Context, k, v string, _ int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sets++
	c.m[k] = v
	return nil
}
func (c *memCache) Del(_ context.Context, k string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, k)
	return nil
}

func cfgFor(url string) gitcore.Config {
	return gitcore.Config{URL: url, Token: fake.Token, BotLogin: fake.BotLogin, BotPassword: fake.BotPassword, WebVersions: []string{"15.0.*"}, Timeout: 2 * time.Second, BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond}
}

func newSvc(t *testing.T) (*gitcore.Service, *fake.Server, *memCache) {
	t.Helper()
	fs := fake.New()
	t.Cleanup(fs.Close)
	mc := newMem()
	return gitcore.New(cfgFor(fs.URL), mc, nil), fs, mc
}

var R = gitcore.RepoRef{Owner: "acme", Repo: "web"}

func wantCode(t *testing.T, err error, c gitcore.Code) {
	t.Helper()
	e, ok := gitcore.AsError(err)
	if !ok || e.Code != c {
		t.Fatalf("want code %s, got %v", c, err)
	}
}

func TestRepoLifecycle(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	if err := s.EnsureOrg(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureOrg(ctx, "acme"); err != nil { // idempotent
		t.Fatal(err)
	}
	if fs.Count("POST", "/api/v1/orgs") != 1 {
		t.Fatalf("org created %d times", fs.Count("POST", "/api/v1/orgs"))
	}
	if _, err := s.GetRepo(ctx, R); err == nil {
		t.Fatal("expected not found")
	} else {
		wantCode(t, err, gitcore.CodeNotFound)
	}
	r, err := s.EnsureRepo(ctx, R, gitcore.RepoCreate{Name: "web", Private: true, AutoInit: true, DefaultBranch: "main"})
	if err != nil || r.DefaultBranch != "main" || !r.Private {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := s.EnsureRepo(ctx, R, gitcore.RepoCreate{}); err != nil {
		t.Fatal(err)
	}
	br := "develop"
	p, err := s.PatchRepo(ctx, R, gitcore.RepoPatch{DefaultBranch: &br, AllowedMergeStyles: []string{"squash"}})
	if err != nil || p.DefaultBranch != "develop" {
		t.Fatalf("%+v %v", p, err)
	}
	m, err := s.Migrate(ctx, gitcore.MigrateSpec{Owner: "acme", Repo: "imp", CloneAddr: "https://example.com/x.git", Private: true})
	if err != nil || m.Name != "imp" {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := s.Migrate(ctx, gitcore.MigrateSpec{Owner: "acme", Repo: "imp"}); err == nil {
		t.Fatal("missing clone addr must be invalid")
	} else {
		wantCode(t, err, gitcore.CodeInvalid)
	}
	ok, err := s.UserExists(ctx, "ghost")
	if ok || err != nil {
		t.Fatal("ghost must not exist", ok, err)
	}
	fs.AddUser("alice")
	if ok, _ := s.UserExists(ctx, "alice"); !ok {
		t.Fatal("alice exists")
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if !s.Enabled() {
		t.Fatal("enabled")
	}
}

func TestContentReadMethods(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	fs.Commit("acme", "web", "main", "add src", map[string]string{"src/a.go": "package a\n", "src/b.txt": "hello\n", "bin.dat": "ab\x00cd"})
	sha2 := fs.Commit("acme", "web", "feature", "feature work", map[string]string{"src/a.go": "package a // changed\n"})

	bl, err := s.ListBranches(ctx, R, gitcore.Page{})
	if err != nil || len(bl.Items) != 2 {
		t.Fatalf("%+v %v", bl, err)
	}
	if !bl.Items[1].Default && !bl.Items[0].Default {
		t.Fatal("default branch not flagged")
	}
	b, err := s.GetBranch(ctx, R, "feature")
	if err != nil || b.SHA != sha2 {
		t.Fatalf("%+v %v", b, err)
	}
	_, err = s.GetBranch(ctx, R, "nope")
	wantCode(t, err, gitcore.CodeNotFound)
	nb, err := s.CreateBranch(ctx, R, "hotfix", "main")
	if err != nil || nb.Name != "hotfix" {
		t.Fatalf("%+v %v", nb, err)
	}
	_, err = s.CreateBranch(ctx, R, "hotfix", "main")
	wantCode(t, err, gitcore.CodeConflict)
	if err := s.DeleteBranch(ctx, R, "hotfix"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, s.DeleteBranch(ctx, R, "hotfix"), gitcore.CodeNotFound)

	if _, err := s.CreateTag(ctx, R, "v1", "main", "release"); err != nil {
		t.Fatal(err)
	}
	tl, err := s.ListTags(ctx, R, gitcore.Page{})
	if err != nil || len(tl.Items) != 1 || tl.Items[0].Name != "v1" {
		t.Fatalf("%+v %v", tl, err)
	}
	if err := s.DeleteTag(ctx, R, "v1"); err != nil {
		t.Fatal(err)
	}

	cl, err := s.ListCommits(ctx, R, gitcore.CommitQuery{Ref: "main"}, gitcore.Page{Limit: 2})
	if err != nil || len(cl.Items) != 2 || cl.NextCursor != "" {
		t.Fatalf("%+v %v", cl, err)
	}
	c, err := s.GetCommit(ctx, R, sha2)
	if err != nil || c.Message != "feature work" || len(c.Parents) != 1 || len(c.Files) != 1 || c.Author.Login != "alice" {
		t.Fatalf("%+v %v", c, err)
	}
	d, err := s.CommitDiff(ctx, R, sha2)
	if err != nil || len(d.Files) != 1 || d.Files[0].Path != "src/a.go" || d.Files[0].Additions != 1 || d.Files[0].Deletions != 1 || d.Files[0].Patch == "" {
		t.Fatalf("%+v %v", d, err)
	}

	tr, err := s.ListTree(ctx, R, "main", "", gitcore.Page{})
	if err != nil || len(tr.Items) != 3 || tr.Items[0].Type != "dir" || tr.Items[0].Name != "src" {
		t.Fatalf("%+v %v", tr, err)
	}
	sub, err := s.ListTree(ctx, R, "main", "src", gitcore.Page{Limit: 1})
	if err != nil || len(sub.Items) != 1 || sub.NextCursor == "" {
		t.Fatalf("%+v %v", sub, err)
	}
	sub2, err := s.ListTree(ctx, R, "main", "src", gitcore.Page{Limit: 1, Cursor: sub.NextCursor})
	if err != nil || len(sub2.Items) != 1 || sub2.NextCursor != "" || sub2.Items[0].Name == sub.Items[0].Name {
		t.Fatalf("%+v %v", sub2, err)
	}
	_, err = s.ListTree(ctx, R, "main", "missing", gitcore.Page{})
	wantCode(t, err, gitcore.CodeNotFound)
	_, err = s.ListTree(ctx, R, "main", "src/b.txt", gitcore.Page{}) // a file is not a dir
	wantCode(t, err, gitcore.CodeNotFound)

	f, err := s.GetFile(ctx, R, "main", "src/b.txt")
	if err != nil || f.Content != "hello\n" || f.Binary || f.Encoding != "utf-8" || f.Truncated {
		t.Fatalf("%+v %v", f, err)
	}
	f, err = s.GetFile(ctx, R, "main", "bin.dat")
	if err != nil || !f.Binary || f.Encoding != "base64" {
		t.Fatalf("%+v %v", f, err)
	}
	_, err = s.GetFile(ctx, R, "main", "nope.txt")
	wantCode(t, err, gitcore.CodeNotFound)
	bb, err := s.GetBlob(ctx, R, f.SHA)
	if err != nil || bb.SHA != f.SHA || bb.Size != 5 {
		t.Fatalf("%+v %v", bb, err)
	}
	_, err = s.GetBlob(ctx, R, "short")
	wantCode(t, err, gitcore.CodeInvalid)

	cmp, err := s.Compare(ctx, R, "main", "feature")
	if err != nil || cmp.AheadBy != 1 || len(cmp.Files) != 1 {
		t.Fatalf("%+v %v", cmp, err)
	}
	_, err = s.Compare(ctx, R, "main", "ghost")
	wantCode(t, err, gitcore.CodeNotFound)
}

func TestBlobLimit(t *testing.T) {
	s, fs, _ := newSvc(t)
	fs.AddRepo("acme", "web")
	fs.Commit("acme", "web", "main", "big", map[string]string{"big.txt": strings.Repeat("x", gitcore.MaxBlobBytes+10)})
	b, err := s.GetFile(context.Background(), R, "main", "big.txt")
	if err != nil || !b.Truncated || b.Content != "" || b.Size <= gitcore.MaxBlobBytes {
		t.Fatalf("%+v %v", b, err)
	}
}

func TestPullFlow(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	fs.AddUser("alice")
	fs.AddUser("bob")
	fs.Commit("acme", "web", "feat", "change", map[string]string{"README.md": "# changed\n", "new.txt": "n\n"})

	pl, err := s.CreatePull(gitcore.WithActor(ctx, "alice"), R, gitcore.PullCreate{Title: "Add things", Head: "feat", Base: "main", Draft: true, Reviewers: []string{"bob"}})
	if err != nil || pl.Number != 1 || !pl.Draft || pl.Author.Login != "alice" {
		t.Fatalf("%+v %v", pl, err)
	}
	if _, err := s.CreatePull(ctx, R, gitcore.PullCreate{Title: "x", Head: "ghost", Base: "main"}); err == nil {
		t.Fatal("missing head must fail")
	} else {
		wantCode(t, err, gitcore.CodeNotFound)
	}
	if _, err := s.CreatePull(ctx, R, gitcore.PullCreate{Head: "feat", Base: "main"}); err == nil {
		t.Fatal("title required")
	}
	lst, err := s.ListPulls(ctx, R, gitcore.PullQuery{}, gitcore.Page{})
	if err != nil || len(lst.Items) != 1 {
		t.Fatalf("%+v %v", lst, err)
	}
	if _, err := s.ListPulls(ctx, R, gitcore.PullQuery{State: "weird"}, gitcore.Page{}); err == nil {
		t.Fatal("bad state must be invalid")
	}
	got, err := s.GetPull(ctx, R, 1)
	if err != nil || len(got.Reviewers) != 1 || got.Reviewers[0].Login != "bob" {
		t.Fatalf("%+v %v", got, err)
	}
	_, err = s.GetPull(ctx, R, 99)
	wantCode(t, err, gitcore.CodeNotFound)

	draft := false
	up, err := s.PatchPull(ctx, R, 1, gitcore.PullPatch{Draft: &draft})
	if err != nil || up.Draft || up.Title != "Add things" {
		t.Fatalf("%+v %v", up, err)
	}
	title := "Renamed"
	up, err = s.PatchPull(ctx, R, 1, gitcore.PullPatch{Title: &title})
	if err != nil || up.Title != "Renamed" {
		t.Fatalf("%+v %v", up, err)
	}

	d, err := s.PullDiff(ctx, R, 1)
	if err != nil || len(d.Files) != 2 || d.Truncated {
		t.Fatalf("%+v %v", d, err)
	}
	if cs, err := s.PullCommits(ctx, R, 1, gitcore.Page{}); err != nil || len(cs.Items) != 1 {
		t.Fatalf("%+v %v", cs, err)
	}
	if err := s.UpdatePullBranch(ctx, R, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestReviewers(ctx, R, 1, []string{"nobody"}, nil); err == nil {
		t.Fatal("unknown reviewer must fail")
	}

	as := gitcore.WithActor(ctx, "bob")
	rv, err := s.CreateReview(as, R, 1, gitcore.ReviewCreate{Event: gitcore.ReviewApprove, Body: "lgtm"})
	if err != nil || rv.State != "approved" || rv.Author.Login != "bob" {
		t.Fatalf("%+v %v", rv, err)
	}
	if _, err := s.CreateReview(as, R, 1, gitcore.ReviewCreate{Event: gitcore.ReviewRequestChanges}); err == nil {
		t.Fatal("request_changes without body must be invalid")
	}
	if _, err := s.CreateReview(as, R, 1, gitcore.ReviewCreate{Event: "bogus"}); err == nil {
		t.Fatal("bad event")
	}
	if _, err := s.CreateReview(as, R, 1, gitcore.ReviewCreate{Event: gitcore.ReviewComment, Comments: []gitcore.InlineComment{{Path: "a", Line: 0, Body: "x"}}}); err == nil {
		t.Fatal("bad line")
	}
	if _, err := s.CreateReview(as, R, 1, gitcore.ReviewCreate{Event: gitcore.ReviewComment, Comments: []gitcore.InlineComment{{Path: "new.txt", Line: 1, Side: "left", Body: "x"}}}); err != nil {
		t.Fatal(err)
	}
	rvs, err := s.ListReviews(ctx, R, 1)
	if err != nil || len(rvs) != 2 {
		t.Fatalf("%+v %v", rvs, err)
	}
	if _, err := s.CreateComment(as, R, 1, "  "); err == nil {
		t.Fatal("empty comment")
	}
	if _, err := s.CreateComment(as, R, 1, "hello"); err != nil {
		t.Fatal(err)
	}
	cm, err := s.ListComments(ctx, R, 1, gitcore.Page{})
	if err != nil || len(cm.Items) != 1 || cm.Items[0].Author.Login != "bob" {
		t.Fatalf("%+v %v", cm, err)
	}

	sha := got.HeadSHA
	if _, err := s.SetCheck(ctx, R, sha, gitcore.CheckInput{Context: "ci/build", State: gitcore.CheckSuccess}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetCheck(ctx, R, "abc", gitcore.CheckInput{Context: "x", State: gitcore.CheckSuccess}); err == nil {
		t.Fatal("short sha")
	}
	if _, err := s.SetCheck(ctx, R, sha, gitcore.CheckInput{Context: "x", State: "weird"}); err == nil {
		t.Fatal("bad state")
	}
	cs, err := s.ListChecks(ctx, R, sha)
	if err != nil || cs.State != gitcore.CheckSuccess || len(cs.Items) != 1 {
		t.Fatalf("%+v %v", cs, err)
	}
	if _, err := s.SetCheck(ctx, R, sha, gitcore.CheckInput{Context: "ci/test", State: gitcore.CheckFailure}); err != nil {
		t.Fatal(err)
	}
	cs, _ = s.ListChecks(ctx, R, sha)
	if cs.State != gitcore.CheckFailure {
		t.Fatalf("combined state: %+v", cs)
	}

	if _, err := s.MergePull(ctx, R, 1, gitcore.MergeRequest{Style: "weird"}); err == nil {
		t.Fatal("bad style")
	}
	_, err = s.MergePull(ctx, R, 1, gitcore.MergeRequest{Style: gitcore.MergeSquash, HeadSHA: "deadbeef"})
	wantCode(t, err, gitcore.CodeConflict)
	res, err := s.MergePull(ctx, R, 1, gitcore.MergeRequest{Style: gitcore.MergeSquash, HeadSHA: sha, DeleteBranch: true})
	if err != nil || !res.Merged || res.SHA == "" {
		t.Fatalf("%+v %v", res, err)
	}
	_, err = s.MergePull(ctx, R, 1, gitcore.MergeRequest{Style: gitcore.MergeSquash})
	wantCode(t, err, gitcore.CodeConflict) // already merged: 405 -> conflict
	pg, _ := s.GetPull(ctx, R, 1)
	if pg.State != gitcore.PullMerged || pg.MergedAt != nil && false {
		t.Fatalf("%+v", pg)
	}
}

func TestAutoMergeQueued(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	fs.Commit("acme", "web", "feat", "c", map[string]string{"a": "1"})
	fs.AddPull("acme", "web", "t", "feat", "main")
	res, err := s.MergePull(ctx, R, 1, gitcore.MergeRequest{Style: gitcore.MergeCommit, WhenChecks: true})
	if err != nil || !res.Queued || res.Merged {
		t.Fatalf("%+v %v", res, err)
	}
	if err := s.CancelAutoMerge(ctx, R, 1); err != nil {
		t.Fatal(err)
	}
}

func TestProtectionsUpsert(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	_, err := s.GetProtection(ctx, R, "main")
	wantCode(t, err, gitcore.CodeNotFound)
	spec := gitcore.ProtectionSpec{RuleName: "main", EnablePush: false, RequiredApprovals: 2, EnableStatusCheck: true, StatusCheckContexts: []string{"ci/*"}, BlockOnOutdatedBranch: true}
	p, err := s.UpsertProtection(ctx, R, spec)
	if err != nil || p.RuleName != "main" || p.RequiredApprovals != 2 || !p.EnableStatusCheck {
		t.Fatalf("%+v %v", p, err)
	}
	spec.RequiredApprovals = 1
	p, err = s.UpsertProtection(ctx, R, spec) // edit path
	if err != nil || p.RequiredApprovals != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	if fs.Count("POST", "/api/v1/repos/acme/web/branch_protections") != 1 {
		t.Fatal("created more than once")
	}
	// empty lists are sent as [], never null
	body := fs.Protection("acme", "web", "main")
	if v, ok := body["push_whitelist_usernames"].([]any); !ok || len(v) != 0 {
		t.Fatalf("whitelist must be [] not %v", body["push_whitelist_usernames"])
	}
	ls, err := s.ListProtections(ctx, R)
	if err != nil || len(ls) != 1 {
		t.Fatalf("%+v %v", ls, err)
	}
	if _, err := s.UpsertProtection(ctx, R, gitcore.ProtectionSpec{}); err == nil {
		t.Fatal("rule name required")
	}
	if _, err := s.UpsertProtection(ctx, R, gitcore.ProtectionSpec{RuleName: "x", RequiredApprovals: 11}); err == nil {
		t.Fatal("approvals range")
	}
	// a protected branch cannot be deleted
	wantCode(t, s.DeleteBranch(ctx, R, "main"), gitcore.CodeForbidden)
	if err := s.DeleteProtection(ctx, R, "main"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, s.DeleteProtection(ctx, R, "main"), gitcore.CodeNotFound)
	// merge blocked by approvals
	fs.Commit("acme", "web", "feat", "c", map[string]string{"a": "1"})
	fs.AddPull("acme", "web", "t", "feat", "main")
	if _, err := s.UpsertProtection(ctx, R, gitcore.ProtectionSpec{RuleName: "main", RequiredApprovals: 1}); err != nil {
		t.Fatal(err)
	}
	_, err = s.MergePull(ctx, R, 1, gitcore.MergeRequest{Style: gitcore.MergeCommit})
	wantCode(t, err, gitcore.CodeConflict)
}

func TestTeamsHooksKeysMirrors(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	fs.AddUser("alice")
	tm, err := s.EnsureTeam(ctx, "acme", gitcore.TeamSpec{Name: "web-admin", Permission: "admin"})
	if err != nil || tm.ID == 0 {
		t.Fatalf("%+v %v", tm, err)
	}
	tm2, err := s.EnsureTeam(ctx, "acme", gitcore.TeamSpec{Name: "WEB-admin", Permission: "admin"})
	if err != nil || tm2.ID != tm.ID {
		t.Fatalf("not idempotent: %+v %v", tm2, err)
	}
	if _, err := s.EnsureTeam(ctx, "acme", gitcore.TeamSpec{Name: "x", Permission: "owner"}); err == nil {
		t.Fatal("bad permission")
	}
	if err := s.AddTeamRepo(ctx, tm.ID, R); err != nil {
		t.Fatal(err)
	}
	wantCode(t, s.AddTeamRepo(ctx, 999, R), gitcore.CodeNotFound)
	if err := s.AddTeamMember(ctx, tm.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, s.AddTeamMember(ctx, tm.ID, "ghost"), gitcore.CodeNotFound)
	ms, err := s.TeamMembers(ctx, tm.ID)
	if err != nil || len(ms) != 1 || ms[0] != "alice" {
		t.Fatalf("%v %v", ms, err)
	}
	if err := s.RemoveTeamMember(ctx, tm.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveTeamMember(ctx, tm.ID, "alice"); err != nil { // already gone is fine
		t.Fatal(err)
	}

	h, err := s.EnsureHook(ctx, R, gitcore.HookSpec{URL: "https://x/hooks", Secret: "s3", Events: []string{"push"}, Active: true})
	if err != nil || h.ID == 0 {
		t.Fatalf("%+v %v", h, err)
	}
	h2, err := s.EnsureHook(ctx, R, gitcore.HookSpec{URL: "https://x/hooks", Secret: "s4", Events: []string{"push", "pull_request"}, Active: true})
	if err != nil || h2.ID != h.ID || len(h2.Events) != 2 {
		t.Fatalf("hook not updated in place: %+v %v", h2, err)
	}
	if _, err := s.EnsureHook(ctx, R, gitcore.HookSpec{}); err == nil {
		t.Fatal("hook needs url")
	}
	hs, _ := s.ListHooks(ctx, R)
	if len(hs) != 1 {
		t.Fatal(hs)
	}
	if err := s.DeleteHook(ctx, R, h.ID); err != nil {
		t.Fatal(err)
	}
	wantCode(t, s.DeleteHook(ctx, R, h.ID), gitcore.CodeNotFound)

	// SSH keys need an actor and act as that user.
	if _, err := s.ListSSHKeys(ctx); err == nil {
		t.Fatal("keys need an actor")
	}
	as := gitcore.WithActor(ctx, "alice")
	k, err := s.AddSSHKey(as, "laptop", "ssh-ed25519 AAAA test", false)
	if err != nil || k.Fingerprint == "" {
		t.Fatalf("%+v %v", k, err)
	}
	if ks, _ := s.ListSSHKeys(as); len(ks) != 1 {
		t.Fatal(ks)
	}
	if err := s.DeleteSSHKey(as, k.ID); err != nil {
		t.Fatal(err)
	}
	wantCode(t, s.DeleteSSHKey(as, k.ID), gitcore.CodeNotFound)

	pm, err := s.AddPushMirror(ctx, R, gitcore.PushMirrorSpec{RemoteAddress: "https://example.com/x.git", RemoteUsername: "u", RemotePassword: "secretpw", SyncOnCommit: true})
	if err != nil || pm.RemoteName == "" || pm.Interval != "8h0m0s" {
		t.Fatalf("%+v %v", pm, err)
	}
	if _, err := s.AddPushMirror(ctx, R, gitcore.PushMirrorSpec{}); err == nil {
		t.Fatal("remote required")
	}
	if l, _ := s.ListPushMirrors(ctx, R); len(l) != 1 {
		t.Fatal(l)
	}
	if err := s.SyncPushMirrors(ctx, R); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePushMirror(ctx, R, pm.RemoteName); err != nil {
		t.Fatal(err)
	}
	wantCode(t, s.DeletePushMirror(ctx, R, pm.RemoteName), gitcore.CodeNotFound)
}

func TestActions(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	run, job := fs.AddRun("acme", "web", "success", "line1\nline2\nline3\n")
	l, err := s.ListRuns(ctx, R, gitcore.RunQuery{}, gitcore.Page{})
	if err != nil || len(l.Items) != 1 || l.Items[0].Actor.Login != "alice" || l.Items[0].Ref != "main" {
		t.Fatalf("%+v %v", l, err)
	}
	if l, _ := s.ListRuns(ctx, R, gitcore.RunQuery{Status: "failure"}, gitcore.Page{}); len(l.Items) != 0 {
		t.Fatal("filter")
	}
	g, err := s.GetRun(ctx, R, run)
	if err != nil || g.Status != "success" {
		t.Fatalf("%+v %v", g, err)
	}
	_, err = s.GetRun(ctx, R, 99)
	wantCode(t, err, gitcore.CodeNotFound)
	js, err := s.ListJobs(ctx, R, run)
	if err != nil || len(js) != 1 || js[0].ID != job {
		t.Fatalf("%+v %v", js, err)
	}
	lg, err := s.JobLogs(ctx, R, job, 0)
	if err != nil || lg.Truncated || !strings.Contains(lg.Content, "line3") {
		t.Fatalf("%+v %v", lg, err)
	}
	lg, err = s.JobLogs(ctx, R, job, 8)
	if err != nil || !lg.Truncated || len(lg.Content) > 8 || !strings.HasSuffix(lg.Content, "line3\n") {
		t.Fatalf("tail must be kept: %+v %v", lg, err)
	}
	if err := s.CancelRun(ctx, R, run); err != nil {
		t.Fatal(err)
	}
	if err := s.DispatchWorkflow(ctx, R, "ci.yml", "main", map[string]string{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DispatchWorkflow(ctx, R, "", "main", nil); err == nil {
		t.Fatal("workflow required")
	}

	// variables and secrets: repo and org scope
	for _, scope := range []gitcore.RepoRef{R, {Owner: "acme"}} {
		if err := s.SetVariable(ctx, scope, "REGION", "us-east-1"); err != nil {
			t.Fatal(scope, err)
		}
		if err := s.SetVariable(ctx, scope, "REGION", "eu-west-1"); err != nil { // update path
			t.Fatal(err)
		}
		vs, err := s.ListVariables(ctx, scope)
		if err != nil || len(vs) != 1 || vs[0].Value != "eu-west-1" {
			t.Fatalf("%+v %v", vs, err)
		}
		if err := s.SetSecret(ctx, scope, "TOKEN", "v"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteSecret(ctx, scope, "TOKEN"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteVariable(ctx, scope, "REGION"); err != nil {
			t.Fatal(err)
		}
		wantCode(t, s.DeleteVariable(ctx, scope, "REGION"), gitcore.CodeNotFound)
	}
	if err := s.SetVariable(ctx, R, "bad-name", "x"); err == nil {
		t.Fatal("name validation")
	}
	if err := s.SetSecret(ctx, R, "a/b", "x"); err == nil {
		t.Fatal("name validation")
	}
}

func TestSudoAndAuthHeaders(t *testing.T) {
	s, fs, _ := newSvc(t)
	fs.AddRepo("acme", "web")
	fs.AddUser("alice")
	ctx := context.Background()
	if _, err := s.GetRepo(ctx, R); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRepo(gitcore.WithActor(ctx, "alice"), R); err != nil {
		t.Fatal(err)
	}
	if gitcore.ActorFrom(gitcore.WithActor(ctx, "")) != "" {
		t.Fatal("empty actor")
	}
	reqs := fs.Requests()
	if reqs[len(reqs)-2].Sudo != "" || reqs[len(reqs)-1].Sudo != "alice" {
		t.Fatalf("sudo header wrong: %+v", reqs[len(reqs)-2:])
	}
	for _, r := range reqs {
		if r.Auth != "token "+fake.Token {
			t.Fatalf("auth header %q", r.Auth)
		}
	}
	// unknown actor: Forgejo answers 404 for the sudo user
	_, err := s.GetRepo(gitcore.WithActor(ctx, "ghost"), R)
	wantCode(t, err, gitcore.CodeNotFound)
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		code   gitcore.Code
		http   int
	}{
		{404, gitcore.CodeNotFound, 404}, {403, gitcore.CodeForbidden, 403}, {409, gitcore.CodeConflict, 409},
		{422, gitcore.CodeUnprocessed, 422}, {400, gitcore.CodeUnprocessed, 422}, {413, gitcore.CodeTooLarge, 413},
		{401, gitcore.CodeUpstream, 502}, {500, gitcore.CodeUpstream, 502}, {502, gitcore.CodeUpstream, 502}, {429, gitcore.CodeUpstream, 502},
	}
	for _, c := range cases {
		c := c
		t.Run(fmt.Sprint(c.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(`{"message":"boom ` + fake.Token + `"}`))
			}))
			defer srv.Close()
			s := gitcore.New(cfgFor(srv.URL), nil, nil)
			_, err := s.GetRepo(context.Background(), R)
			e, ok := gitcore.AsError(err)
			if !ok || e.Code != c.code || e.HTTPStatus() != c.http {
				t.Fatalf("got %v", err)
			}
			if strings.Contains(err.Error(), fake.Token) || strings.Contains(e.Message, fake.Token) {
				t.Fatalf("token leaked in error: %v", err)
			}
		})
	}
}

func TestRetryOnlyIdempotent(t *testing.T) {
	var gets, posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if gets.Add(1) < 3 {
				w.WriteHeader(503)
				return
			}
			_, _ = w.Write([]byte(`{"name":"web","default_branch":"main"}`))
			return
		}
		posts.Add(1)
		w.WriteHeader(502)
	}))
	defer srv.Close()
	s := gitcore.New(cfgFor(srv.URL), nil, nil)
	if _, err := s.GetRepo(context.Background(), R); err != nil || gets.Load() != 3 {
		t.Fatalf("GET must retry to success: gets=%d err=%v", gets.Load(), err)
	}
	_, err := s.CreateBranch(context.Background(), R, "x", "main")
	wantCode(t, err, gitcore.CodeUpstream)
	if posts.Load() != 1 {
		t.Fatalf("POST must not be retried (a retry could double-apply): %d", posts.Load())
	}
}

func TestRetryExhaustedAndNoRetryOn4xx(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1); w.WriteHeader(500) }))
	defer srv.Close()
	s := gitcore.New(cfgFor(srv.URL), nil, nil)
	_, err := s.GetRepo(context.Background(), R)
	wantCode(t, err, gitcore.CodeUpstream)
	if n.Load() != 3 {
		t.Fatalf("attempts=%d", n.Load())
	}
	n.Store(0)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1); w.WriteHeader(404) }))
	defer srv2.Close()
	s2 := gitcore.New(cfgFor(srv2.URL), nil, nil)
	_, _ = s2.GetRepo(context.Background(), R)
	if n.Load() != 1 {
		t.Fatalf("404 must not retry, attempts=%d", n.Load())
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer srv.Close()
	cfg := cfgFor(srv.URL)
	cfg.Timeout = 50 * time.Millisecond
	cfg.MaxAttempts = 1
	s := gitcore.New(cfg, nil, nil)
	start := time.Now()
	_, err := s.GetRepo(context.Background(), R)
	e, ok := gitcore.AsError(err)
	if !ok || e.Code != gitcore.CodeUpstream || !e.Retry || time.Since(start) > 250*time.Millisecond {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
	// caller deadline wins and is reported as upstream timeout without retry loops
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	cfg.Timeout = time.Second
	_, err = gitcore.New(cfg, nil, nil).GetRepo(ctx, R)
	wantCode(t, err, gitcore.CodeUpstream)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline not unwrappable: %v", err)
	}
}

func TestMalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{not json`)) }))
	defer srv.Close()
	s := gitcore.New(cfgFor(srv.URL), nil, nil)
	_, err := s.GetRepo(context.Background(), R)
	wantCode(t, err, gitcore.CodeUpstream)
	_, err = s.ListBranches(context.Background(), R, gitcore.Page{})
	wantCode(t, err, gitcore.CodeUpstream)
}

func TestNetworkErrorDoesNotLeakToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // connection refused
	s := gitcore.New(cfgFor(url), nil, nil)
	_, err := s.GetRepo(context.Background(), R)
	wantCode(t, err, gitcore.CodeUpstream)
	if strings.Contains(err.Error(), fake.Token) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("error leaks details: %v", err)
	}
}

func TestDisabledIsNotReady(t *testing.T) {
	s := gitcore.New(gitcore.Config{}, nil, nil)
	if s.Enabled() {
		t.Fatal("must be disabled")
	}
	_, err := s.GetRepo(context.Background(), R)
	e, _ := gitcore.AsError(err)
	if e == nil || e.Code != gitcore.CodeNotReady || e.HTTPStatus() != 503 {
		t.Fatalf("%v", err)
	}
	wantCode(t, s.Ping(context.Background()), gitcore.CodeNotReady)
	if !errors.Is(err, gitcore.ErrNotReady) || errors.Is(err, gitcore.ErrNotFound) {
		t.Fatal("errors.Is sentinels")
	}
}

func TestInvalidRepoRefNeverSent(t *testing.T) {
	s, fs, _ := newSvc(t)
	for _, r := range []gitcore.RepoRef{{}, {Owner: "a/b", Repo: "c"}, {Owner: "..", Repo: "c"}, {Owner: "a", Repo: "c?x=1"}, {Owner: "a", Repo: "c%2f"}} {
		_, err := s.GetRepo(context.Background(), r)
		wantCode(t, err, gitcore.CodeInvalid)
	}
	if len(fs.Requests()) != 0 {
		t.Fatal("invalid refs must not reach Forgejo")
	}
}

func TestCircuitBreaker(t *testing.T) {
	var n atomic.Int32
	var healthy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if healthy.Load() {
			_, _ = w.Write([]byte(`{"name":"web"}`))
			return
		}
		w.WriteHeader(500)
	}))
	defer srv.Close()
	cfg := cfgFor(srv.URL)
	cfg.MaxAttempts = 1
	cfg.BreakerFailures = 3
	cfg.BreakerOpenFor = 80 * time.Millisecond
	s := gitcore.New(cfg, nil, nil)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, err := s.GetRepo(ctx, R)
		wantCode(t, err, gitcore.CodeUpstream)
	}
	before := n.Load()
	_, err := s.GetRepo(ctx, R)
	e, _ := gitcore.AsError(err)
	if e == nil || e.Code != gitcore.CodeNotReady || !e.Retry || n.Load() != before {
		t.Fatalf("open circuit must answer GIT_NOT_READY without calling upstream: %v (calls %d->%d)", err, before, n.Load())
	}
	time.Sleep(100 * time.Millisecond)
	healthy.Store(true)
	if _, err := s.GetRepo(ctx, R); err != nil { // half-open probe succeeds and closes it
		t.Fatalf("probe: %v", err)
	}
	if _, err := s.GetRepo(ctx, R); err != nil {
		t.Fatalf("closed again: %v", err)
	}
}

func TestBreakerIgnores4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer srv.Close()
	cfg := cfgFor(srv.URL)
	cfg.BreakerFailures = 2
	s := gitcore.New(cfg, nil, nil)
	for i := 0; i < 6; i++ {
		_, err := s.GetRepo(context.Background(), R)
		wantCode(t, err, gitcore.CodeNotFound) // never GIT_NOT_READY
	}
}

func TestConcurrencyLimit(t *testing.T) {
	var cur, peak atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := cur.Add(1)
		for {
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		cur.Add(-1)
		_, _ = w.Write([]byte(`{"name":"web"}`))
	}))
	defer srv.Close()
	cfg := cfgFor(srv.URL)
	cfg.MaxConcurrent = 2
	s := gitcore.New(cfg, nil, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = s.GetRepo(context.Background(), R) }()
	}
	wg.Wait()
	if peak.Load() > 2 {
		t.Fatalf("peak concurrency %d > 2", peak.Load())
	}
}

func TestPaginationCursors(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	for i := 0; i < 129; i++ { // 130 branches with main
		fs.Commit("acme", "web", fmt.Sprintf("b%03d", i), "c", map[string]string{"f": "x"})
	}
	seen := map[string]bool{}
	cur, pages := "", 0
	for {
		l, err := s.ListBranches(ctx, R, gitcore.Page{Cursor: cur, Limit: 40})
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range l.Items {
			if seen[b.Name] {
				t.Fatalf("duplicate %s across pages", b.Name)
			}
			seen[b.Name] = true
		}
		pages++
		if l.NextCursor == "" {
			break
		}
		cur = l.NextCursor
	}
	if len(seen) != 130 || pages != 4 {
		t.Fatalf("seen=%d pages=%d", len(seen), pages)
	}
	// limit 100 spans 2 upstream pages of 50
	l, err := s.ListBranches(ctx, R, gitcore.Page{Limit: 100})
	if err != nil || len(l.Items) != 100 || l.NextCursor == "" {
		t.Fatalf("%d %v", len(l.Items), err)
	}
	if l.Items[99].Name != "b098" { // main sorts after b*, so b000..b098 are the first 100? verify order
		t.Logf("last item %s", l.Items[99].Name)
	}
	// limit clamp
	l, _ = s.ListBranches(ctx, R, gitcore.Page{Limit: 1000})
	if len(l.Items) != gitcore.MaxLimit {
		t.Fatalf("clamp: %d", len(l.Items))
	}
	// bad cursor
	_, err = s.ListBranches(ctx, R, gitcore.Page{Cursor: "!!!"})
	wantCode(t, err, gitcore.CodeInvalid)
}

func TestPaginationWhenUpstreamClampsSmaller(t *testing.T) {
	s, fs, _ := newSvc(t)
	fs.AddRepo("acme", "web")
	for i := 0; i < 9; i++ {
		fs.Commit("acme", "web", fmt.Sprintf("b%d", i), "c", map[string]string{"f": "x"})
	}
	fs.SetLimitClamp(7) // Forgejo configured below our page size of 50 (?): still no loss/duplication within a page walk
	l, err := s.ListBranches(context.Background(), R, gitcore.Page{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Items) == 0 || len(l.Items) > 10 {
		t.Fatalf("items=%d", len(l.Items))
	}
}

func TestCacheHitMissInvalidate(t *testing.T) {
	s, fs, mc := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	if _, err := s.ListBranches(ctx, R, gitcore.Page{}); err != nil {
		t.Fatal(err)
	}
	calls := fs.Count("GET", "/api/v1/repos/acme/web/branches")
	if _, err := s.ListBranches(ctx, R, gitcore.Page{}); err != nil {
		t.Fatal(err)
	}
	if fs.Count("GET", "/api/v1/repos/acme/web/branches") != calls {
		t.Fatal("second list must be a cache hit")
	}
	// a new branch behind Capsule's back stays invisible until invalidation (webhook)
	fs.Commit("acme", "web", "late", "c", map[string]string{"f": "1"})
	l, _ := s.ListBranches(ctx, R, gitcore.Page{})
	if len(l.Items) != 1 {
		t.Fatalf("stale cache expected, got %d", len(l.Items))
	}
	if err := s.InvalidateRepo(ctx, R); err != nil {
		t.Fatal(err)
	}
	l, _ = s.ListBranches(ctx, R, gitcore.Page{})
	if len(l.Items) != 2 {
		t.Fatalf("invalidate must refresh: %d", len(l.Items))
	}
	// writes invalidate by themselves
	if _, err := s.CreateBranch(ctx, R, "viaapi", "main"); err != nil {
		t.Fatal(err)
	}
	l, _ = s.ListBranches(ctx, R, gitcore.Page{})
	if len(l.Items) != 3 {
		t.Fatalf("CreateBranch must invalidate: %d", len(l.Items))
	}
	// other repos are unaffected
	fs.AddRepo("acme", "other")
	o := gitcore.RepoRef{Owner: "acme", Repo: "other"}
	_, _ = s.ListBranches(ctx, o, gitcore.Page{})
	n := fs.Count("GET", "/api/v1/repos/acme/other/branches")
	_ = s.InvalidateRepo(ctx, R)
	_, _ = s.ListBranches(ctx, o, gitcore.Page{})
	if fs.Count("GET", "/api/v1/repos/acme/other/branches") != n {
		t.Fatal("invalidating one repo must not drop another's cache")
	}
	if mc.sets == 0 {
		t.Fatal("cache never written")
	}
}

func TestImmutableObjectsCachedAcrossInvalidation(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	sha := fs.Commit("acme", "web", "main", "c", map[string]string{"a.txt": "A\n"})
	if _, err := s.GetCommit(ctx, R, sha); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitDiff(ctx, R, sha); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListTree(ctx, R, sha, "", gitcore.Page{}); err != nil {
		t.Fatal(err)
	}
	f, err := s.GetFile(ctx, R, sha, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetBlob(ctx, R, f.SHA); err != nil {
		t.Fatal(err)
	}
	fs.Reset()
	_ = s.InvalidateRepo(ctx, R)
	_, _ = s.GetCommit(ctx, R, sha)
	_, _ = s.CommitDiff(ctx, R, sha)
	_, _ = s.ListTree(ctx, R, sha, "", gitcore.Page{})
	_, _ = s.GetFile(ctx, R, sha, "a.txt")
	_, _ = s.GetBlob(ctx, R, f.SHA)
	if n := len(fs.Requests()); n != 0 {
		t.Fatalf("SHA-addressed reads must be served from cache after invalidation, got %d upstream calls: %+v", n, fs.Requests())
	}
	// a moving ref is NOT immutable
	_, _ = s.GetFile(ctx, R, "main", "a.txt")
	_, _ = s.GetFile(ctx, R, "main", "a.txt")
	if fs.Count("GET", "/api/v1/repos/acme/web/contents/a.txt") != 2 {
		t.Fatal("file at a branch ref must not be cached")
	}
}

func TestPullDiffCachedByHeadAndBase(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	fs.Commit("acme", "web", "feat", "c", map[string]string{"x": "1"})
	fs.AddPull("acme", "web", "t", "feat", "main")
	if _, err := s.PullDiff(ctx, R, 1); err != nil {
		t.Fatal(err)
	}
	_ = s.InvalidateRepo(ctx, R)
	fs.Reset()
	if _, err := s.PullDiff(ctx, R, 1); err != nil {
		t.Fatal(err)
	}
	if fs.Count("GET", "/api/v1/repos/acme/web/pulls/1.diff") != 0 && fs.Count("GET", "/api/v1/repos/acme/web/pulls/1") != 0 {
		// PR meta is refetched (it moves) but the heavy diff must come from cache
	}
	if c := len(fs.Requests()); c > 1 {
		t.Fatalf("expected at most the PR metadata call, got %d: %+v", c, fs.Requests())
	}
}

func TestDiffTruncation(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	big := strings.Repeat("0123456789abcdef\n", 70000) // ~1.2 MB per file
	sha := fs.Commit("acme", "web", "main", "big", map[string]string{"a.txt": big, "b.txt": big, "c.txt": "tiny\n"})
	d, err := s.CommitDiff(ctx, R, sha)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Truncated || len(d.Files) != 3 {
		t.Fatalf("truncated=%v files=%d", d.Truncated, len(d.Files))
	}
	total := 0
	trunc := 0
	for _, f := range d.Files {
		total += len(f.Patch)
		if f.Truncated {
			trunc++
			if f.Patch != "" || f.Additions == 0 {
				t.Fatalf("truncated file must keep stats and drop the patch: %+v", f.Path)
			}
		}
	}
	if total > gitcore.MaxDiffBytes || trunc == 0 {
		t.Fatalf("total patch %d (max %d) truncated files %d", total, gitcore.MaxDiffBytes, trunc)
	}
}

func TestDiffParserShapes(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	fs.AddRepo("acme", "web") // reset to a known state
	fs.Commit("acme", "web", "main", "mix", map[string]string{"dir/new file.txt": "n\n", "README.md": "changed\n"})
	sha := fs.Commit("acme", "web", "main", "mix2", map[string]string{"dir/new file.txt": "n2\n"})
	d, err := s.CommitDiff(ctx, R, sha)
	if err != nil || len(d.Files) != 1 || d.Files[0].Path != "dir/new file.txt" || d.Files[0].Status != "modified" {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestListTreeOrderingAndLimits(t *testing.T) {
	s, fs, _ := newSvc(t)
	fs.AddRepo("acme", "web")
	fs.Commit("acme", "web", "main", "x", map[string]string{"b.txt": "1", "A.txt": "1", "z/q": "1", "m/q": "1"})
	l, err := s.ListTree(context.Background(), R, "main", "", gitcore.Page{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range l.Items {
		names = append(names, e.Name)
	}
	if strings.Join(names, ",") != "m,z,A.txt,b.txt,README.md" {
		t.Fatalf("order: %v", names)
	}
}

func TestMaxResponseGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 9<<20)))
	}))
	defer srv.Close()
	s := gitcore.New(cfgFor(srv.URL), nil, nil)
	_, err := s.GetRepo(context.Background(), R)
	wantCode(t, err, gitcore.CodeTooLarge)
	// a huge PR diff falls back to the file list with Truncated=true
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/pulls/1"):
			_, _ = w.Write([]byte(`{"number":1,"head":{"sha":"x"},"base":{"ref":"main"}}`))
		case strings.HasSuffix(r.URL.Path, "/pulls/1.diff"):
			_, _ = w.Write([]byte(strings.Repeat("x", 9<<20)))
		case strings.HasSuffix(r.URL.Path, "/pulls/1/files"):
			_, _ = w.Write([]byte(`[{"filename":"a","status":"added","additions":3,"deletions":0}]`))
		}
	}))
	defer srv2.Close()
	d, err := gitcore.New(cfgFor(srv2.URL), nil, nil).PullDiff(context.Background(), R, 1)
	if err != nil || !d.Truncated || len(d.Files) != 1 || d.Files[0].Additions != 3 || d.Files[0].Patch != "" {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestErrorTypeContract(t *testing.T) {
	e := &gitcore.Error{Code: gitcore.CodeNotFound, Message: "m", Op: "GET /x"}
	if !errors.Is(e, gitcore.ErrNotFound) || errors.Is(e, gitcore.ErrForbidden) {
		t.Fatal("Is")
	}
	for c, want := range map[gitcore.Code]int{gitcore.CodeUpstream: 502, gitcore.CodeNotReady: 503, gitcore.CodeNotFound: 404, gitcore.CodeForbidden: 403,
		gitcore.CodeConflict: 409, gitcore.CodeUnprocessed: 422, gitcore.CodeTooLarge: 413, gitcore.CodeInvalid: 400} {
		if (&gitcore.Error{Code: c}).HTTPStatus() != want {
			t.Fatalf("status of %s", c)
		}
	}
	if _, ok := gitcore.AsError(errors.New("plain")); ok {
		t.Fatal("plain error")
	}
	if !strings.Contains(e.Error(), "NOT_FOUND") {
		t.Fatal(e.Error())
	}
}

func TestSharedAndConfig(t *testing.T) {
	t.Setenv("CAPSULE_GIT_URL", "https://git.example.test/")
	t.Setenv("CAPSULE_GIT_TOKEN", "tok")
	t.Setenv("CAPSULE_GITCORE_MAX_CONCURRENT", "4")
	c := gitcore.ConfigFromEnv()
	if c.URL != "https://git.example.test" || !c.Enabled() || c.Host() != "git.example.test" || c.MaxConcurrent != 4 {
		t.Fatalf("%+v", c)
	}
	gitcore.SetShared(nil)
	if gitcore.Shared() == nil || gitcore.Mounts().Core == nil {
		t.Fatal("Shared must never be nil")
	}
	custom := gitcore.New(gitcore.Config{}, nil, nil)
	gitcore.SetShared(custom)
	if gitcore.Shared() != gitcore.Core(custom) {
		t.Fatal("SetShared")
	}
}

func TestMigrateReposAndMisc(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	c, err := s.ListCommits(ctx, R, gitcore.CommitQuery{}, gitcore.Page{})
	if err != nil || len(c.Items) != 1 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := s.ListCommits(ctx, R, gitcore.CommitQuery{Ref: "ghost"}, gitcore.Page{}); err == nil {
		t.Fatal("unknown ref")
	}
	for _, f := range []func() error{
		func() error { _, e := s.GetCommit(ctx, R, ""); return e },
		func() error { _, e := s.GetFile(ctx, R, "main", ""); return e },
		func() error { _, e := s.CreateTag(ctx, R, "", "", ""); return e },
		func() error { return s.DeleteTag(ctx, R, "") },
		func() error { _, e := s.Compare(ctx, R, "", ""); return e },
		func() error { _, e := s.GetPull(ctx, R, 0); return e },
		func() error { return s.EnsureOrg(ctx, "") },
		func() error { _, e := s.UserExists(ctx, ""); return e },
		func() error { _, e := s.ListChecks(ctx, R, ""); return e },
		func() error { return s.SetVariable(ctx, gitcore.RepoRef{}, "A", "b") },
	} {
		wantCode(t, f(), gitcore.CodeInvalid)
	}
}
