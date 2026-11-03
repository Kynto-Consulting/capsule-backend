package gitcore_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// Every method must surface an upstream refusal as a normalized *Error (never panic, never nil).
func TestEveryMethodMapsUpstreamRefusal(t *testing.T) {
	for _, status := range []int{403, 404} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"message":"refused"}`))
		}))
		s := gitcore.New(cfgFor(srv.URL), nil, nil)
		ctx := gitcore.WithActor(context.Background(), "alice")
		sha := "0123456789012345678901234567890123456789"
		h := "x"
		calls := map[string]func() error{
			"EnsureOrg":  func() error { return s.EnsureOrg(ctx, "o") },
			"GetRepo":    func() error { _, e := s.GetRepo(ctx, R); return e },
			"EnsureRepo": func() error { _, e := s.EnsureRepo(ctx, R, gitcore.RepoCreate{}); return e },
			"PatchRepo":  func() error { _, e := s.PatchRepo(ctx, R, gitcore.RepoPatch{DefaultBranch: &h}); return e },
			"Migrate": func() error {
				_, e := s.Migrate(ctx, gitcore.MigrateSpec{Owner: "a", Repo: "b", CloneAddr: "u"})
				return e
			},
			"ListBranches": func() error { _, e := s.ListBranches(ctx, R, gitcore.Page{}); return e },
			"GetBranch":    func() error { _, e := s.GetBranch(ctx, R, "b"); return e },
			"CreateBranch": func() error { _, e := s.CreateBranch(ctx, R, "b", "main"); return e },
			"DeleteBranch": func() error { return s.DeleteBranch(ctx, R, "b") },
			"ListTags":     func() error { _, e := s.ListTags(ctx, R, gitcore.Page{}); return e },
			"CreateTag":    func() error { _, e := s.CreateTag(ctx, R, "t", "main", ""); return e },
			"DeleteTag":    func() error { return s.DeleteTag(ctx, R, "t") },
			"ListCommits":  func() error { _, e := s.ListCommits(ctx, R, gitcore.CommitQuery{Ref: sha}, gitcore.Page{}); return e },
			"GetCommit":    func() error { _, e := s.GetCommit(ctx, R, sha); return e },
			"GetCommitRef": func() error { _, e := s.GetCommit(ctx, R, "main"); return e },
			"CommitDiff":   func() error { _, e := s.CommitDiff(ctx, R, sha); return e },
			"ListTree":     func() error { _, e := s.ListTree(ctx, R, sha, "d", gitcore.Page{}); return e },
			"GetFile":      func() error { _, e := s.GetFile(ctx, R, sha, "f"); return e },
			"GetBlob":      func() error { _, e := s.GetBlob(ctx, R, sha); return e },
			"Compare":      func() error { _, e := s.Compare(ctx, R, sha, sha); return e },
			"ListPulls": func() error {
				_, e := s.ListPulls(ctx, R, gitcore.PullQuery{State: "all", Base: "m", Head: "h"}, gitcore.Page{})
				return e
			},
			"GetPull": func() error { _, e := s.GetPull(ctx, R, 1); return e },
			"CreatePull": func() error {
				_, e := s.CreatePull(ctx, R, gitcore.PullCreate{Title: "t", Head: "h", Base: "b"})
				return e
			},
			"PatchPullDraft": func() error { d := true; _, e := s.PatchPull(ctx, R, 1, gitcore.PullPatch{Draft: &d}); return e },
			"PatchPull": func() error {
				st := "closed"
				_, e := s.PatchPull(ctx, R, 1, gitcore.PullPatch{State: &st, Body: &h, Base: &h})
				return e
			},
			"PullDiff":         func() error { _, e := s.PullDiff(ctx, R, 1); return e },
			"PullCommits":      func() error { _, e := s.PullCommits(ctx, R, 1, gitcore.Page{}); return e },
			"UpdatePullBranch": func() error { return s.UpdatePullBranch(ctx, R, 1) },
			"RequestReviewers": func() error { return s.RequestReviewers(ctx, R, 1, []string{"u"}, nil) },
			"ListReviews":      func() error { _, e := s.ListReviews(ctx, R, 1); return e },
			"CreateReview": func() error {
				_, e := s.CreateReview(ctx, R, 1, gitcore.ReviewCreate{Event: gitcore.ReviewApprove})
				return e
			},
			"ListComments":  func() error { _, e := s.ListComments(ctx, R, 1, gitcore.Page{}); return e },
			"CreateComment": func() error { _, e := s.CreateComment(ctx, R, 1, "x"); return e },
			"MergePull": func() error {
				_, e := s.MergePull(ctx, R, 1, gitcore.MergeRequest{Style: gitcore.MergeFF, Title: "t", Message: "m", Force: true})
				return e
			},
			"CancelAutoMerge": func() error { return s.CancelAutoMerge(ctx, R, 1) },
			"ListChecks":      func() error { _, e := s.ListChecks(ctx, R, "main"); return e },
			"SetCheck": func() error {
				_, e := s.SetCheck(ctx, R, sha, gitcore.CheckInput{Context: "c", State: gitcore.CheckPending})
				return e
			},
			"ListProtections":  func() error { _, e := s.ListProtections(ctx, R); return e },
			"GetProtection":    func() error { _, e := s.GetProtection(ctx, R, "main"); return e },
			"UpsertProtection": func() error { _, e := s.UpsertProtection(ctx, R, gitcore.ProtectionSpec{RuleName: "main"}); return e },
			"DeleteProtection": func() error { return s.DeleteProtection(ctx, R, "main") },
			"EnsureTeam": func() error {
				_, e := s.EnsureTeam(ctx, "o", gitcore.TeamSpec{Name: "t", Permission: "read"})
				return e
			},
			"AddTeamRepo":   func() error { return s.AddTeamRepo(ctx, 1, R) },
			"TeamMembers":   func() error { _, e := s.TeamMembers(ctx, 1); return e },
			"AddTeamMember": func() error { return s.AddTeamMember(ctx, 1, "u") },
			"ListHooks":     func() error { _, e := s.ListHooks(ctx, R); return e },
			"EnsureHook": func() error {
				_, e := s.EnsureHook(ctx, R, gitcore.HookSpec{URL: "u", Events: []string{"push"}})
				return e
			},
			"DeleteHook":      func() error { return s.DeleteHook(ctx, R, 1) },
			"ListSSHKeys":     func() error { _, e := s.ListSSHKeys(ctx); return e },
			"AddSSHKey":       func() error { _, e := s.AddSSHKey(ctx, "t", "k", true); return e },
			"DeleteSSHKey":    func() error { return s.DeleteSSHKey(ctx, 1) },
			"ListPushMirrors": func() error { _, e := s.ListPushMirrors(ctx, R); return e },
			"AddPushMirror": func() error {
				_, e := s.AddPushMirror(ctx, R, gitcore.PushMirrorSpec{RemoteAddress: "a", Interval: "1h", BranchFilter: "main", RemoteUsername: "u", RemotePassword: "p"})
				return e
			},
			"DeletePushMirror": func() error { return s.DeletePushMirror(ctx, R, "m") },
			"SyncPushMirrors":  func() error { return s.SyncPushMirrors(ctx, R) },
			"ListRuns": func() error {
				_, e := s.ListRuns(ctx, R, gitcore.RunQuery{Status: "s", Event: "e", Ref: "r", HeadSHA: "h"}, gitcore.Page{})
				return e
			},
			"GetRun":         func() error { _, e := s.GetRun(ctx, R, 1); return e },
			"ListJobs":       func() error { _, e := s.ListJobs(ctx, R, 1); return e },
			"JobLogs":        func() error { _, e := s.JobLogs(ctx, R, 1, 10); return e },
			"CancelRun":      func() error { return s.CancelRun(ctx, R, 1) },
			"Dispatch":       func() error { return s.DispatchWorkflow(ctx, R, "ci.yml", "main", nil) },
			"ListVariables":  func() error { _, e := s.ListVariables(ctx, R); return e },
			"SetVariable":    func() error { return s.SetVariable(ctx, R, "A", "b") },
			"DeleteVariable": func() error { return s.DeleteVariable(ctx, R, "A") },
			"SetSecret":      func() error { return s.SetSecret(ctx, R, "A", "b") },
			"DeleteSecret":   func() error { return s.DeleteSecret(ctx, R, "A") },
			"Ping":           func() error { return s.Ping(ctx) },
		}
		want := gitcore.CodeForbidden
		if status == 404 {
			want = gitcore.CodeNotFound
		}
		for name, f := range calls {
			err := f()
			e, ok := gitcore.AsError(err)
			if !ok {
				t.Errorf("%s/%d: not a normalized error: %v", name, status, err)
				continue
			}
			// Idempotent deletes treat 404 as success.
			if status == 404 && err == nil {
				continue
			}
			if e.Code != want && !(status == 404 && e.Code == gitcore.CodeNotFound) {
				t.Errorf("%s/%d: code %s want %s", name, status, e.Code, want)
			}
		}
		srv.Close()
	}
}

func TestRetryAfterIsHonoured(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		_, _ = w.Write([]byte(`{"name":"web"}`))
	}))
	defer srv.Close()
	s := gitcore.New(cfgFor(srv.URL), nil, nil)
	if _, err := s.GetRepo(context.Background(), R); err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestLockedPostIsRetried(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n < 3 {
			w.WriteHeader(423)
			_, _ = w.Write([]byte(`{"message":"Please try again later"}`))
			return
		}
		_, _ = w.Write([]byte(`{"number":1,"merged":true,"merge_commit_sha":"abc"}`))
	}))
	defer srv.Close()
	s := gitcore.New(cfgFor(srv.URL), nil, nil)
	res, err := s.MergePull(context.Background(), R, 1, gitcore.MergeRequest{Style: gitcore.MergeCommit})
	if err != nil || !res.Merged || n != 4 { // 2 locked + 1 merge ok + 1 confirmation read
		t.Fatalf("n=%d res=%+v err=%v", n, res, err)
	}
	// still locked after all attempts: Conflict with Retry so the caller can try again later
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(423) }))
	defer srv2.Close()
	_, err = gitcore.New(cfgFor(srv2.URL), nil, nil).MergePull(context.Background(), R, 1, gitcore.MergeRequest{Style: gitcore.MergeCommit})
	e, _ := gitcore.AsError(err)
	if e == nil || e.Code != gitcore.CodeConflict || !e.Retry {
		t.Fatalf("%v", err)
	}
}
