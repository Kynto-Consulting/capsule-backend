//go:build forgejo

// Package itest runs gitcore against a REAL Forgejo (WORKBREAKDOWN A1 acceptance).
//
// Run (Forgejo 15.0.11 started locally with SQLite, registration off, admin token via the forgejo CLI):
//
//	GITCORE_ITEST_URL=http://127.0.0.1:3399 GITCORE_ITEST_TOKEN=<admin token> \
//	GITCORE_ITEST_USERS=alice,bob go test -tags=forgejo ./internal/gitcore/itest/ -count=1 -v
//
// The token must belong to a site administrator (Sudo needs it) and GITCORE_ITEST_USERS must
// be two existing regular users. Each run uses a fresh organization (itest-<unix>).
package itest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

type env struct {
	s          *gitcore.Service
	url, token string
	org        string
	r          gitcore.RepoRef
	u1, u2     string
}

func setup(t *testing.T) *env {
	t.Helper()
	url, tok, users := os.Getenv("GITCORE_ITEST_URL"), os.Getenv("GITCORE_ITEST_TOKEN"), strings.Split(os.Getenv("GITCORE_ITEST_USERS"), ",")
	if url == "" || tok == "" || len(users) < 2 {
		t.Skip("GITCORE_ITEST_URL / GITCORE_ITEST_TOKEN / GITCORE_ITEST_USERS not set")
	}
	org := fmt.Sprintf("itest-%d", time.Now().Unix())
	return &env{s: gitcore.New(gitcore.Config{URL: url, Token: tok}, nil, nil), url: url, token: tok, org: org,
		r: gitcore.RepoRef{Owner: org, Repo: "web"}, u1: users[0], u2: users[1]}
}

// rawPost is a SETUP helper only (creating file content has no gitcore method on purpose).
func (e *env) rawPost(t *testing.T, path string, body any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.url+"/api/v1"+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "token "+e.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		d, _ := io.ReadAll(res.Body)
		t.Fatalf("setup POST %s: %d %s", path, res.StatusCode, d)
	}
}

func (e *env) putFile(t *testing.T, branch, newBranch, path, content, msg string) {
	body := map[string]any{"content": base64.StdEncoding.EncodeToString([]byte(content)), "message": msg, "branch": branch}
	if newBranch != "" {
		body["new_branch"] = newBranch
	}
	e.rawPost(t, "/repos/"+e.org+"/web/contents/"+path, body)
}

func TestForgejoReadAndWrite(t *testing.T) {
	e := setup(t)
	s, ctx := e.s, context.Background()

	if err := s.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := s.EnsureOrg(ctx, e.org); err != nil {
		t.Fatalf("EnsureOrg: %v", err)
	}
	if err := s.EnsureOrg(ctx, e.org); err != nil {
		t.Fatalf("EnsureOrg idempotent: %v", err)
	}
	repo, err := s.EnsureRepo(ctx, e.r, gitcore.RepoCreate{Name: "web", Private: true, AutoInit: true, DefaultBranch: "main"})
	if err != nil || repo.DefaultBranch != "main" || !repo.Private {
		t.Fatalf("EnsureRepo: %+v %v", repo, err)
	}
	if _, err := s.EnsureRepo(ctx, e.r, gitcore.RepoCreate{}); err != nil {
		t.Fatalf("EnsureRepo idempotent: %v", err)
	}
	if ok, err := s.UserExists(ctx, e.u1); !ok || err != nil {
		t.Fatalf("UserExists: %v %v", ok, err)
	}
	if ok, _ := s.UserExists(ctx, "no-such-user-xyz"); ok {
		t.Fatal("ghost exists")
	}

	// teams: Capsule's role projection
	for _, role := range []struct{ name, perm string }{{"web-admin", "admin"}, {"web-deployer", "write"}, {"web-viewer", "read"}} {
		tm, err := s.EnsureTeam(ctx, e.org, gitcore.TeamSpec{Name: role.name, Permission: role.perm})
		if err != nil || tm.ID == 0 {
			t.Fatalf("EnsureTeam %s: %+v %v", role.name, tm, err)
		}
		if tm2, err := s.EnsureTeam(ctx, e.org, gitcore.TeamSpec{Name: role.name, Permission: role.perm}); err != nil || tm2.ID != tm.ID {
			t.Fatalf("EnsureTeam idempotent %s: %+v %v", role.name, tm2, err)
		}
		if err := s.AddTeamRepo(ctx, tm.ID, e.r); err != nil {
			t.Fatalf("AddTeamRepo: %v", err)
		}
		if role.perm == "write" {
			for _, u := range []string{e.u1, e.u2} {
				if err := s.AddTeamMember(ctx, tm.ID, u); err != nil {
					t.Fatalf("AddTeamMember: %v", err)
				}
			}
			ms, err := s.TeamMembers(ctx, tm.ID)
			if err != nil || len(ms) != 2 {
				t.Fatalf("TeamMembers: %v %v", ms, err)
			}
			if err := s.RemoveTeamMember(ctx, tm.ID, e.u2); err != nil {
				t.Fatal(err)
			}
			if err := s.RemoveTeamMember(ctx, tm.ID, e.u2); err != nil {
				t.Fatalf("second remove must be fine: %v", err)
			}
			if err := s.AddTeamMember(ctx, tm.ID, e.u2); err != nil {
				t.Fatal(err)
			}
		}
	}

	// content
	e.putFile(t, "main", "", "src/a.go", "package a\n", "add a")
	e.putFile(t, "main", "feat", "src/b.txt", "hello\n", "add b on feat")
	bl, err := s.ListBranches(ctx, e.r, gitcore.Page{})
	if err != nil || len(bl.Items) != 2 {
		t.Fatalf("ListBranches: %+v %v", bl, err)
	}
	var mainSHA, featSHA string
	for _, b := range bl.Items {
		if b.Name == "main" {
			mainSHA = b.SHA
			if !b.Default {
				t.Error("main not flagged default")
			}
		} else {
			featSHA = b.SHA
		}
	}
	if gb, err := s.GetBranch(ctx, e.r, "feat"); err != nil || gb.SHA != featSHA {
		t.Fatalf("GetBranch: %+v %v", gb, err)
	}
	if _, err := s.CreateBranch(ctx, e.r, "hotfix", "main"); err != nil {
		t.Fatalf("CreateBranch: %v", err)
	}
	if err := s.DeleteBranch(ctx, e.r, "hotfix"); err != nil {
		t.Fatalf("DeleteBranch: %v", err)
	}
	if _, err := s.CreateTag(ctx, e.r, "v1", "main", "release 1"); err != nil {
		t.Fatalf("CreateTag: %v", err)
	}
	if tl, err := s.ListTags(ctx, e.r, gitcore.Page{}); err != nil || len(tl.Items) != 1 || tl.Items[0].SHA != mainSHA {
		t.Fatalf("ListTags: %+v %v (main %s)", tl, err, mainSHA)
	}
	if err := s.DeleteTag(ctx, e.r, "v1"); err != nil {
		t.Fatalf("DeleteTag: %v", err)
	}
	cl, err := s.ListCommits(ctx, e.r, gitcore.CommitQuery{Ref: "feat"}, gitcore.Page{})
	if err != nil || len(cl.Items) < 3 {
		t.Fatalf("ListCommits: %+v %v", cl, err)
	}
	cm, err := s.GetCommit(ctx, e.r, featSHA)
	if err != nil || cm.Message == "" || len(cm.Parents) != 1 || len(cm.Files) == 0 {
		t.Fatalf("GetCommit: %+v %v", cm, err)
	}
	d, err := s.CommitDiff(ctx, e.r, featSHA)
	if err != nil || len(d.Files) != 1 || d.Files[0].Path != "src/b.txt" || d.Files[0].Status != "added" || d.Files[0].Additions != 1 {
		t.Fatalf("CommitDiff: %+v %v", d, err)
	}
	tr, err := s.ListTree(ctx, e.r, mainSHA, "", gitcore.Page{})
	if err != nil || len(tr.Items) < 2 || tr.Items[0].Type != "dir" {
		t.Fatalf("ListTree: %+v %v", tr, err)
	}
	if _, err := s.ListTree(ctx, e.r, "main", "src", gitcore.Page{}); err != nil {
		t.Fatalf("ListTree dir: %v", err)
	}
	f, err := s.GetFile(ctx, e.r, "feat", "src/b.txt")
	if err != nil || f.Content != "hello\n" || f.Binary {
		t.Fatalf("GetFile: %+v %v", f, err)
	}
	bb, err := s.GetBlob(ctx, e.r, f.SHA)
	if err != nil || bb.Content != "hello\n" {
		t.Fatalf("GetBlob: %+v %v", bb, err)
	}
	cmp, err := s.Compare(ctx, e.r, "main", "feat")
	if err != nil || cmp.AheadBy != 1 || len(cmp.Files) != 1 {
		t.Fatalf("Compare: %+v %v", cmp, err)
	}

	// protections: field names verified by reading them back
	spec := gitcore.ProtectionSpec{RuleName: "main", EnablePush: false, RequiredApprovals: 1, EnableStatusCheck: true,
		StatusCheckContexts: []string{"ci/build"}, BlockOnOutdatedBranch: true, DismissStaleApprovals: true, BlockOnRejectedReviews: true,
		EnableMergeWhitelist: true, MergeWhitelistUsers: []string{e.u1}, ApplyToAdmins: true}
	p, err := s.UpsertProtection(ctx, e.r, spec)
	if err != nil {
		t.Fatalf("UpsertProtection create: %v", err)
	}
	got, err := s.GetProtection(ctx, e.r, "main")
	if err != nil || got.RequiredApprovals != 1 || !got.EnableStatusCheck || len(got.StatusCheckContexts) != 1 || !got.BlockOnOutdatedBranch ||
		!got.DismissStaleApprovals || !got.BlockOnRejectedReviews || !got.EnableMergeWhitelist || len(got.MergeWhitelistUsers) != 1 || !got.ApplyToAdmins || got.EnablePush {
		t.Fatalf("protection did not round-trip: %+v (created %+v) %v", got, p, err)
	}
	spec.RequiredApprovals = 2
	spec.StatusCheckContexts = []string{"ci/build", "ci/test"}
	if _, err := s.UpsertProtection(ctx, e.r, spec); err != nil {
		t.Fatalf("UpsertProtection edit: %v", err)
	}
	got, _ = s.GetProtection(ctx, e.r, "main")
	if got.RequiredApprovals != 2 || len(got.StatusCheckContexts) != 2 {
		t.Fatalf("edit not applied: %+v", got)
	}
	if ps, err := s.ListProtections(ctx, e.r); err != nil || len(ps) != 1 {
		t.Fatalf("ListProtections: %+v %v", ps, err)
	}
	// a glob rule name with slash and star (A4 patterns)
	if _, err := s.UpsertProtection(ctx, e.r, gitcore.ProtectionSpec{RuleName: "release/*", RequiredApprovals: 1}); err != nil {
		t.Errorf("(?) glob rule name release/*: %v", err)
	} else if _, err := s.GetProtection(ctx, e.r, "release/*"); err != nil {
		t.Errorf("(?) GetProtection with slash in name: %v", err)
	} else if err := s.DeleteProtection(ctx, e.r, "release/*"); err != nil {
		t.Errorf("(?) DeleteProtection with slash in name: %v", err)
	}
	// loosen so the PR flow below can merge
	spec = gitcore.ProtectionSpec{RuleName: "main", RequiredApprovals: 1}
	if _, err := s.UpsertProtection(ctx, e.r, spec); err != nil {
		t.Fatal(err)
	}

	// pull requests with Sudo
	as1, as2 := gitcore.WithActor(ctx, e.u1), gitcore.WithActor(ctx, e.u2)
	pl, err := s.CreatePull(as1, e.r, gitcore.PullCreate{Title: "Add b", Body: "body", Head: "feat", Base: "main", Draft: true, Reviewers: []string{e.u2}})
	if err != nil || pl.Number != 1 || pl.Author.Login != e.u1 {
		t.Fatalf("CreatePull as %s: %+v %v", e.u1, pl, err)
	}
	if !pl.Draft {
		t.Errorf("(?) draft via WIP prefix not reported as draft: %+v", pl)
	}
	nodraft := false
	if pl, err = s.PatchPull(ctx, e.r, 1, gitcore.PullPatch{Draft: &nodraft}); err != nil || pl.Draft || pl.Title != "Add b" {
		t.Fatalf("PatchPull draft off: %+v %v", pl, err)
	}
	if lst, err := s.ListPulls(ctx, e.r, gitcore.PullQuery{State: "open"}, gitcore.Page{}); err != nil || len(lst.Items) != 1 {
		t.Fatalf("ListPulls: %+v %v", lst, err)
	}
	gp, err := s.GetPull(ctx, e.r, 1)
	if err != nil || gp.HeadSHA != featSHA || gp.Base != "main" || len(gp.Reviewers) != 1 {
		t.Fatalf("GetPull: %+v %v", gp, err)
	}
	pd, err := s.PullDiff(ctx, e.r, 1)
	if err != nil || len(pd.Files) != 1 || pd.Files[0].Path != "src/b.txt" {
		t.Fatalf("PullDiff: %+v %v", pd, err)
	}
	if pc, err := s.PullCommits(ctx, e.r, 1, gitcore.Page{}); err != nil || len(pc.Items) != 1 {
		t.Fatalf("PullCommits: %+v %v", pc, err)
	}
	if _, err := s.CreateComment(as1, e.r, 1, "first comment"); err != nil {
		t.Fatalf("CreateComment: %v", err)
	}
	if cs, err := s.ListComments(ctx, e.r, 1, gitcore.Page{}); err != nil || len(cs.Items) != 1 || cs.Items[0].Author.Login != e.u1 {
		t.Fatalf("ListComments: %+v %v", cs, err)
	}
	if rv, err := s.CreateReview(as2, e.r, 1, gitcore.ReviewCreate{Event: gitcore.ReviewComment, Body: "inline", CommitID: featSHA,
		Comments: []gitcore.InlineComment{{Path: "src/b.txt", Line: 1, Body: "nice"}}}); err != nil {
		t.Errorf("CreateReview comment with inline: %v (%+v)", err, rv)
	}
	if _, err := s.CreateReview(as2, e.r, 1, gitcore.ReviewCreate{Event: gitcore.ReviewRequestChanges, Body: "please change"}); err != nil {
		t.Errorf("CreateReview request_changes: %v", err)
	}
	if _, err := s.CreateReview(as2, e.r, 1, gitcore.ReviewCreate{Event: gitcore.ReviewApprove, Body: "ok"}); err != nil {
		t.Fatalf("CreateReview approve: %v", err)
	}
	rvs, err := s.ListReviews(ctx, e.r, 1)
	if err != nil || len(rvs) == 0 {
		t.Fatalf("ListReviews: %+v %v", rvs, err)
	}
	states := map[string]bool{}
	for _, r := range rvs {
		states[r.State] = true
	}
	if !states["approved"] {
		t.Errorf("no approved review among %+v", rvs)
	}
	// status checks
	if _, err := s.SetCheck(ctx, e.r, featSHA, gitcore.CheckInput{Context: "ci/build", State: gitcore.CheckSuccess, Description: "ok", TargetURL: "https://ci.example.test/1"}); err != nil {
		t.Fatalf("SetCheck: %v", err)
	}
	cs, err := s.ListChecks(ctx, e.r, featSHA)
	if err != nil || cs.State != gitcore.CheckSuccess || len(cs.Items) != 1 || cs.Items[0].Context != "ci/build" {
		t.Fatalf("ListChecks: %+v %v", cs, err)
	}
	// merge
	if _, err := s.MergePull(ctx, e.r, 1, gitcore.MergeRequest{Style: gitcore.MergeSquash, HeadSHA: "0000000000000000000000000000000000000000"}); err == nil {
		t.Error("(?) merge with stale head_commit_id should fail")
	}
	res, err := s.MergePull(ctx, e.r, 1, gitcore.MergeRequest{Style: gitcore.MergeSquash, HeadSHA: featSHA, DeleteBranch: true, Title: "Add b (#1)"})
	if err != nil || !res.Merged {
		t.Fatalf("MergePull: %+v %v", res, err)
	}
	if res.SHA == "" {
		t.Errorf("(?) merge result has no SHA (merge_commit_sha empty right after merge)")
	}
	if gp, _ := s.GetPull(ctx, e.r, 1); gp == nil || gp.State != gitcore.PullMerged {
		t.Errorf("pull not merged: %+v", gp)
	}

	// hooks
	h, err := s.EnsureHook(ctx, e.r, gitcore.HookSpec{URL: "https://backend.example.test/hooks/git/1", Secret: "s3cret", Events: []string{"push", "pull_request"}, Active: true})
	if err != nil || h.ID == 0 {
		t.Fatalf("EnsureHook: %+v %v", h, err)
	}
	h2, err := s.EnsureHook(ctx, e.r, gitcore.HookSpec{URL: "https://backend.example.test/hooks/git/1", Secret: "s3cret2", Events: []string{"push"}, Active: true})
	if err != nil || h2.ID != h.ID {
		t.Fatalf("EnsureHook update in place: %+v %v", h2, err)
	}
	if hs, _ := s.ListHooks(ctx, e.r); len(hs) != 1 || len(hs[0].Events) != 1 {
		t.Fatalf("hooks: %+v", hs)
	}
	if err := s.DeleteHook(ctx, e.r, h.ID); err != nil {
		t.Fatal(err)
	}

	// repo settings
	del := true
	if pr, err := s.PatchRepo(ctx, e.r, gitcore.RepoPatch{DeleteBranchOnPR: &del, AllowedMergeStyles: []string{"squash", "rebase"}}); err != nil {
		t.Errorf("(?) PatchRepo merge styles: %v", err)
	} else if !pr.DeleteBranchOnPR || len(pr.AllowedMergeStyles) != 2 {
		t.Errorf("(?) PatchRepo flags did not round-trip: %+v", pr)
	}

	// actions: variables and secrets in repo and org scope, runs list
	for _, sc := range []gitcore.RepoRef{e.r, {Owner: e.org}} {
		if err := s.SetVariable(ctx, sc, "REGION", "us-east-1"); err != nil {
			t.Errorf("(?) SetVariable create %v: %v", sc, err)
			continue
		}
		if err := s.SetVariable(ctx, sc, "REGION", "eu-west-1"); err != nil {
			t.Errorf("(?) SetVariable update %v: %v", sc, err)
		}
		vs, err := s.ListVariables(ctx, sc)
		if err != nil || len(vs) != 1 || vs[0].Value != "eu-west-1" {
			t.Errorf("ListVariables %v: %+v %v", sc, vs, err)
		}
		if err := s.SetSecret(ctx, sc, "TOKEN", "v"); err != nil {
			t.Errorf("(?) SetSecret %v: %v", sc, err)
		}
		if err := s.DeleteSecret(ctx, sc, "TOKEN"); err != nil {
			t.Errorf("DeleteSecret %v: %v", sc, err)
		}
		if err := s.DeleteVariable(ctx, sc, "REGION"); err != nil {
			t.Errorf("DeleteVariable %v: %v", sc, err)
		}
	}
	if rl, err := s.ListRuns(ctx, e.r, gitcore.RunQuery{}, gitcore.Page{}); err != nil {
		t.Errorf("(?) ListRuns: %v", err)
	} else {
		t.Logf("ListRuns ok (%d runs)", len(rl.Items))
	}

	// SSH keys as a user
	const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl itest"
	if k, err := s.AddSSHKey(as1, "itest", pub, false); err != nil {
		t.Errorf("(?) AddSSHKey as %s: %v", e.u1, err)
	} else {
		if ks, err := s.ListSSHKeys(as1); err != nil || len(ks) != 1 {
			t.Errorf("ListSSHKeys: %+v %v", ks, err)
		}
		if err := s.DeleteSSHKey(as1, k.ID); err != nil {
			t.Errorf("DeleteSSHKey: %v", err)
		}
	}

	// push mirror (needs outbound access to the remote; failure is reported, not fatal)
	if pm, err := s.AddPushMirror(ctx, e.r, gitcore.PushMirrorSpec{RemoteAddress: "https://127.0.0.1:9/none.git", Interval: "8h0m0s"}); err != nil {
		t.Logf("(?) AddPushMirror: %v", err)
	} else {
		t.Logf("AddPushMirror ok: %s", pm.RemoteName)
		if l, err := s.ListPushMirrors(ctx, e.r); err != nil || len(l) == 0 {
			t.Errorf("ListPushMirrors: %+v %v", l, err)
		}
		if err := s.DeletePushMirror(ctx, e.r, pm.RemoteName); err != nil {
			t.Errorf("DeletePushMirror: %v", err)
		}
	}

	// error mapping against the real thing
	if _, err := s.GetRepo(ctx, gitcore.RepoRef{Owner: e.org, Repo: "missing"}); !isCode(err, gitcore.CodeNotFound) {
		t.Errorf("missing repo must be NOT_FOUND: %v", err)
	}
	if _, err := s.GetRepo(gitcore.WithActor(ctx, "no-such-user-xyz"), e.r); err == nil {
		t.Errorf("(?) sudo as a non-existent user must fail")
	} else {
		t.Logf("sudo as missing user -> %v", err)
	}
	// a regular user's token cannot Sudo: use alice-less check by calling with a bad token
	bad := gitcore.New(gitcore.Config{URL: e.url, Token: "0000000000000000000000000000000000000000"}, nil, nil)
	if _, err := bad.GetRepo(ctx, e.r); !isCode(err, gitcore.CodeUpstream) {
		t.Errorf("bad service token must be UPSTREAM_GIT_ERROR: %v", err)
	}
}

func isCode(err error, c gitcore.Code) bool {
	ge, ok := gitcore.AsError(err)
	return ok && ge.Code == c
}
