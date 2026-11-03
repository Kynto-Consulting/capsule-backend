package gitapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"main", "main", true},
		{"main", "main2", false},
		{"release/*", "release/1.0", true},
		{"release/*", "release/1.0/hotfix", false},
		{"release/**", "release/1.0/hotfix", true},
		{"feature/**", "feature/a/b/c", true},
		{"*", "main", true},
		{"*", "a/b", false},
		{"**", "a/b", true},
		{"v?.0", "v1.0", true},
		{"v?.0", "v10.0", false},
		{"rel-{a,b}", "rel-a", true},
		{"rel-{a,b}", "rel-c", false},
		{"x[0-9]", "x5", true},
		{"x[!0-9]", "x5", false},
		{"a.b", "aXb", false}, // dots are literal
		{"ci / build (push)", "ci / build (push)", true},
		{"ci / *", "ci / build (push)", true},
	}
	for _, c := range cases {
		if got := MatchGlob(c.pat, c.name); got != c.want {
			t.Errorf("MatchGlob(%q,%q)=%v want %v", c.pat, c.name, got, c.want)
		}
	}
}

func rule(f func(*gitcore.ProtectionSpec)) *gitcore.ProtectionSpec {
	r := &gitcore.ProtectionSpec{RuleName: "main"}
	f(r)
	return r
}

func okPull() gitcore.Pull {
	return gitcore.Pull{Number: 1, State: gitcore.PullOpen, Base: "main", Head: "f", HeadSHA: "abc", Mergeable: true,
		Author: gitcore.Person{Login: "alice"}}
}

func codes(m Mergeability) []string {
	out := []string{}
	for _, b := range m.Blockers {
		out = append(out, b.Code)
	}
	return out
}

func rv(id int64, login, state string, official, stale bool) gitcore.Review {
	return gitcore.Review{ID: id, State: state, Author: gitcore.Person{Login: login}, Official: official, Stale: stale}
}

func TestEvaluateBlockers(t *testing.T) {
	green := &gitcore.CheckSet{State: gitcore.CheckSuccess, Items: []gitcore.Check{{Context: "ci / build (push)", State: gitcore.CheckSuccess}}}
	draft := okPull()
	draft.Draft = true
	conflict := okPull()
	conflict.Mergeable = false
	closed := okPull()
	closed.State = gitcore.PullClosed
	closed.Mergeable = false
	pending := okPull()
	pending.Reviewers = []gitcore.Person{{Login: "bob"}}

	cases := []struct {
		name string
		in   Inputs
		want []string
	}{
		{"clean, no rule", Inputs{Pull: okPull()}, []string{}},
		{"closed pr is never blocked", Inputs{Pull: closed}, []string{}},
		{"draft", Inputs{Pull: draft}, []string{BlockDraft}},
		{"conflicts", Inputs{Pull: conflict}, []string{BlockConflicts}},
		{"draft and conflicts keep a stable order", Inputs{Pull: func() gitcore.Pull { p := draft; p.Mergeable = false; return p }()}, []string{BlockDraft, BlockConflicts}},
		{"required check missing", Inputs{Pull: okPull(), Checks: &gitcore.CheckSet{},
			Rule: rule(func(r *gitcore.ProtectionSpec) {
				r.EnableStatusCheck, r.StatusCheckContexts = true, []string{"ci / build (push)"}
			})}, []string{BlockChecks}},
		{"required check green", Inputs{Pull: okPull(), Checks: green,
			Rule: rule(func(r *gitcore.ProtectionSpec) {
				r.EnableStatusCheck, r.StatusCheckContexts = true, []string{"ci / build (push)"}
			})}, []string{}},
		{"required check by glob green", Inputs{Pull: okPull(), Checks: green,
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.EnableStatusCheck, r.StatusCheckContexts = true, []string{"ci / *"} })}, []string{}},
		{"required check pending", Inputs{Pull: okPull(), Checks: &gitcore.CheckSet{Items: []gitcore.Check{{Context: "ci", State: gitcore.CheckPending}}},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.EnableStatusCheck, r.StatusCheckContexts = true, []string{"ci"} })}, []string{BlockChecks}},
		{"required check failed", Inputs{Pull: okPull(), Checks: &gitcore.CheckSet{Items: []gitcore.Check{{Context: "ci", State: gitcore.CheckFailure}}},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.EnableStatusCheck, r.StatusCheckContexts = true, []string{"ci"} })}, []string{BlockChecks}},
		{"required check skipped counts as passed", Inputs{Pull: okPull(), Checks: &gitcore.CheckSet{Items: []gitcore.Check{{Context: "ci", State: gitcore.CheckSkipped}}},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.EnableStatusCheck, r.StatusCheckContexts = true, []string{"ci"} })}, []string{}},
		{"checks not enforced when the rule does not enable them", Inputs{Pull: okPull(), Checks: &gitcore.CheckSet{Items: []gitcore.Check{{Context: "ci", State: gitcore.CheckFailure}}},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.StatusCheckContexts = []string{"ci"} })}, []string{}},
		{"needs 2 approvals, has 1", Inputs{Pull: okPull(), Reviews: []gitcore.Review{rv(1, "bob", "approved", true, false)},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.RequiredApprovals = 2 })}, []string{BlockReviews}},
		{"2 approvals ok", Inputs{Pull: okPull(), Reviews: []gitcore.Review{rv(1, "bob", "approved", true, false), rv(2, "carol", "approved", true, false)},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.RequiredApprovals = 2 })}, []string{}},
		{"same reviewer twice counts once", Inputs{Pull: okPull(), Reviews: []gitcore.Review{rv(1, "bob", "approved", true, false), rv(2, "bob", "approved", true, false)},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.RequiredApprovals = 2 })}, []string{BlockReviews}},
		{"non official approval does not count", Inputs{Pull: okPull(), Reviews: []gitcore.Review{rv(1, "bob", "approved", false, false)},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.RequiredApprovals = 1 })}, []string{BlockReviews}},
		{"stale approval counts unless ignored", Inputs{Pull: okPull(), Reviews: []gitcore.Review{rv(1, "bob", "approved", true, true)},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.RequiredApprovals = 1 })}, []string{}},
		{"stale approval ignored", Inputs{Pull: okPull(), Reviews: []gitcore.Review{rv(1, "bob", "approved", true, true)},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.RequiredApprovals, r.IgnoreStaleApprovals = 1, true })}, []string{BlockReviews}},
		{"dismissed approval does not count", Inputs{Pull: okPull(), Reviews: []gitcore.Review{rv(1, "bob", "approved", true, false), rv(2, "bob", "dismissed", true, false)},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.RequiredApprovals = 1 })}, []string{BlockReviews}},
		{"approval after changes requested", Inputs{Pull: okPull(), Reviews: []gitcore.Review{rv(1, "bob", "changes_requested", true, false), rv(2, "bob", "approved", true, false)},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.RequiredApprovals, r.BlockOnRejectedReviews = 1, true })}, []string{}},
		{"changes requested blocks", Inputs{Pull: okPull(), Reviews: []gitcore.Review{rv(1, "bob", "approved", true, false), rv(2, "carol", "changes_requested", true, false)},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.RequiredApprovals, r.BlockOnRejectedReviews = 1, true })}, []string{BlockReviews}},
		{"changes requested ignored without the flag", Inputs{Pull: okPull(), Reviews: []gitcore.Review{rv(1, "bob", "approved", true, false), rv(2, "carol", "changes_requested", true, false)},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.RequiredApprovals = 1 })}, []string{}},
		{"a plain comment never counts", Inputs{Pull: okPull(), Reviews: []gitcore.Review{rv(1, "bob", "commented", true, false)},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.RequiredApprovals = 1 })}, []string{BlockReviews}},
		{"pending review request blocks", Inputs{Pull: pending,
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.BlockOnOfficialReviewRequest = true })}, []string{BlockReviews}},
		{"pending review request ignored without the flag", Inputs{Pull: pending, Rule: rule(func(r *gitcore.ProtectionSpec) {})}, []string{}},
		{"behind base", Inputs{Pull: okPull(), BehindBase: true,
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.BlockOnOutdatedBranch = true })}, []string{BlockOutOfDate}},
		{"behind base allowed without the flag", Inputs{Pull: okPull(), BehindBase: true, Rule: rule(func(r *gitcore.ProtectionSpec) {})}, []string{}},
		{"unsigned commits", Inputs{Pull: okPull(), Unsigned: []string{"abc1234"},
			Rule: rule(func(r *gitcore.ProtectionSpec) { r.RequireSignedCommits = true })}, []string{BlockSignature}},
		{"unsigned commits ignored without the flag", Inputs{Pull: okPull(), Unsigned: []string{"abc1234"}, Rule: rule(func(r *gitcore.ProtectionSpec) {})}, []string{}},
		{"extra blockers (codeowners, policy, approval) are appended", Inputs{Pull: okPull(),
			Extra: []Blocker{{Code: BlockCodeowner, Message: "x"}, {Code: BlockPolicy, Message: "y"}, {Code: BlockApproval, Message: "z"}}},
			[]string{BlockCodeowner, BlockPolicy, BlockApproval}},
		{"everything at once", Inputs{Pull: func() gitcore.Pull { p := draft; p.Mergeable = false; return p }(), BehindBase: true, Unsigned: []string{"a"},
			Checks: &gitcore.CheckSet{}, Reviews: nil,
			Rule: rule(func(r *gitcore.ProtectionSpec) {
				r.EnableStatusCheck, r.StatusCheckContexts, r.RequiredApprovals = true, []string{"ci"}, 1
				r.BlockOnOutdatedBranch, r.RequireSignedCommits = true, true
			}), Extra: []Blocker{{Code: BlockCodeowner, Message: "o"}}},
			[]string{BlockDraft, BlockConflicts, BlockChecks, BlockReviews, BlockOutOfDate, BlockSignature, BlockCodeowner}},
	}
	for _, c := range cases {
		got := Evaluate(c.in)
		if !reflect.DeepEqual(codes(got), c.want) {
			t.Errorf("%s: blockers %v want %v", c.name, codes(got), c.want)
		}
		if got.CanMerge != (len(c.want) == 0 && c.in.Pull.State == gitcore.PullOpen) {
			t.Errorf("%s: can_merge=%v with blockers %v", c.name, got.CanMerge, codes(got))
		}
		if got.Blockers == nil {
			t.Errorf("%s: blockers must never be nil", c.name)
		}
	}
}

func TestMatchRule(t *testing.T) {
	mk := func(names ...string) []gitcore.Protection {
		var out []gitcore.Protection
		for _, n := range names {
			out = append(out, gitcore.Protection{ProtectionSpec: gitcore.ProtectionSpec{RuleName: n}})
		}
		return out
	}
	if r := MatchRule(mk("release/*", "main"), "main"); r == nil || r.RuleName != "main" {
		t.Fatal("exact rule must win")
	}
	if r := MatchRule(mk("**", "release/*"), "release/1"); r == nil || r.RuleName != "release/*" {
		t.Fatalf("longest glob must win, got %+v", r)
	}
	if r := MatchRule(mk("release/*"), "main"); r != nil {
		t.Fatal("no rule must match")
	}
}

func TestBlockerSourceFailsClosed(t *testing.T) {
	RegisterBlockerSource(func(context.Context, gitcore.RepoRef, gitcore.Pull) ([]Blocker, error) {
		return nil, errors.New("boom")
	})
	defer func() { srcMu.Lock(); sources = nil; srcMu.Unlock() }()
	bs := extraBlockers(context.Background(), gitcore.RepoRef{}, okPull())
	if len(bs) != 1 || bs[0].Code != BlockPolicy {
		t.Fatalf("a failing source must block with POLICY_BLOCKED, got %v", bs)
	}
}

func TestCombinedState(t *testing.T) {
	if CombinedState(nil) != "success" {
		t.Fatal("no checks = success")
	}
	if CombinedState(&gitcore.CheckSet{State: gitcore.CheckPending}) != "pending" {
		t.Fatal("pending")
	}
	if CombinedState(&gitcore.CheckSet{State: gitcore.CheckSuccess, Items: []gitcore.Check{{State: gitcore.CheckFailure}}}) != "failure" {
		t.Fatal("an item failure wins over a stale combined state")
	}
}

func TestRedactLog(t *testing.T) {
	in := strings.Join([]string{
		"::add-mask::supersecretvalue",
		"echo supersecretvalue and again supersecretvalue",
		"token: cgt_0123456789abcdef0123456789",
		"AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP",
		"Authorization: Bearer abc.def.ghi",
		"git clone https://bot:hunter2pass@git.example.com/o/r.git",
		"password = \"p4ssw0rd!\"",
		"API_KEY=${{ secrets.API_KEY }}",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
		"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"a plain build line, nothing to hide",
	}, "\n")
	out := RedactLog(in)
	for _, leak := range []string{"supersecretvalue", "cgt_0123456789", "AKIAABCDEFGHIJKLMNOP", "abc.def.ghi", "hunter2pass", "p4ssw0rd", "MIIEow", "eyJhbGciOiJIUzI1NiJ9"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q in:\n%s", leak, out)
		}
	}
	for _, keep := range []string{"a plain build line, nothing to hide", "${{ secrets.API_KEY }}", "git.example.com/o/r.git"} {
		if !strings.Contains(out, keep) {
			t.Errorf("over-redacted, lost %q in:\n%s", keep, out)
		}
	}
	if got := RedactLog("value=known-secret-123 end", "known-secret-123"); strings.Contains(got, "known-secret-123") {
		t.Errorf("caller supplied secret leaked: %s", got)
	}
	if RedactLog("") != "" {
		t.Error("empty stays empty")
	}
	SetLogRedactor(func(c string, _ ...string) string { return "X" + c })
	if RedactLog("a") != "Xa" {
		t.Error("custom redactor not used")
	}
	SetLogRedactor(nil)
	if RedactLog("a") != "a" {
		t.Error("default redactor not restored")
	}
}

type memCache struct{ m map[string]string }

func (c *memCache) Get(_ context.Context, k string) (string, error) {
	if v, ok := c.m[k]; ok {
		return v, nil
	}
	return "", errors.New("miss")
}
func (c *memCache) Set(_ context.Context, k, v string, _ int) error { c.m[k] = v; return nil }
func (c *memCache) Del(_ context.Context, k string) error           { delete(c.m, k); return nil }

func TestIdempotency(t *testing.T) {
	ctx := context.Background()
	cache := &memCache{m: map[string]string{}}
	s := NewIdemStore(cache)
	fp := Fingerprint("POST", "/merge", []byte(`{"style":"squash"}`))

	_, st, done := s.Begin(ctx, "u|r|merge", "k1", fp)
	if st != IdemNew {
		t.Fatalf("first call must be new, got %v", st)
	}
	if _, st2, _ := s.Begin(ctx, "u|r|merge", "k1", fp); st2 != IdemConflict {
		t.Fatalf("a concurrent duplicate must conflict, got %v", st2)
	}
	done(&Stored{Status: 200, Body: []byte(`{"merged":true}`)})
	got, st, _ := s.Begin(ctx, "u|r|merge", "k1", fp)
	if st != IdemReplay || got.Status != 200 || string(got.Body) != `{"merged":true}` {
		t.Fatalf("replay: %v %+v", st, got)
	}
	if _, st, _ := s.Begin(ctx, "u|r|merge", "k1", Fingerprint("POST", "/merge", []byte(`{"style":"merge"}`))); st != IdemConflict {
		t.Fatalf("same key with another body must conflict, got %v", st)
	}
	// Another user (scope) with the same key is independent.
	if _, st, _ := s.Begin(ctx, "other|r|merge", "k1", fp); st != IdemNew {
		t.Fatalf("keys are scoped per user, got %v", st)
	}
	// A new instance (fresh memory) replays from the shared cache.
	s2 := NewIdemStore(cache)
	if got, st, _ := s2.Begin(ctx, "u|r|merge", "k1", fp); st != IdemReplay || got.Status != 200 {
		t.Fatalf("cache replay across instances: %v", st)
	}
	// A failed attempt is forgotten and can be retried.
	_, st, done = s.Begin(ctx, "u|r|merge", "k2", fp)
	done(nil)
	if _, st, _ = s.Begin(ctx, "u|r|merge", "k2", fp); st != IdemNew {
		t.Fatalf("failure must release the key, got %v", st)
	}
	// Expiry.
	s3 := NewIdemStore(nil)
	now := time.Now()
	s3.now = func() time.Time { return now }
	_, _, d3 := s3.Begin(ctx, "s", "k", fp)
	d3(&Stored{Status: 200})
	s3.now = func() time.Time { return now.Add(IdemTTL + time.Second) }
	if _, st, _ := s3.Begin(ctx, "s", "k", fp); st != IdemNew {
		t.Fatalf("expired key must be new, got %v", st)
	}
}

func TestParseWorkflow(t *testing.T) {
	cases := []struct {
		src      string
		name     string
		triggers []string
	}{
		{"name: CI\non: push\njobs:\n  a:\n    runs-on: x\n", "CI", []string{"push"}},
		{"name: \"Build & Test\"\non: [push, pull_request]\n", "Build & Test", []string{"push", "pull_request"}},
		{"name: Deploy\non:\n  push:\n    branches: [main]\n  workflow_dispatch:\n    inputs:\n      env:\n        type: string\njobs: {}\n", "Deploy", []string{"push", "workflow_dispatch"}},
		{"on:\n  - push\n  - schedule\n", "", []string{"push", "schedule"}},
		{"# comment\nname: X # trailing\n'on':\n  pull_request:\n", "X", []string{"pull_request"}},
		{"jobs:\n  name: not-top-level\n", "", nil},
	}
	for _, c := range cases {
		n, tr := ParseWorkflow(c.src)
		if n != c.name || !reflect.DeepEqual(tr, c.triggers) {
			t.Errorf("%q => %q %v, want %q %v", c.src, n, tr, c.name, c.triggers)
		}
	}
	for id, want := range map[string]bool{"ci.yml": true, "deploy-prod.yaml": true, "../x.yml": false, "a/b.yml": false, "x.txt": false, ".yml": false} {
		if ValidWorkflowID(id) != want {
			t.Errorf("ValidWorkflowID(%q) != %v", id, want)
		}
	}
}

func TestCursorSlicing(t *testing.T) {
	all := []int{1, 2, 3, 4, 5}
	items, next, err := SliceByCursor(all, gitcore.Page{Limit: 2})
	if err != nil || !reflect.DeepEqual(items, []int{1, 2}) || next == "" {
		t.Fatalf("%v %q %v", items, next, err)
	}
	items, next, _ = SliceByCursor(all, gitcore.Page{Cursor: next, Limit: 2})
	if !reflect.DeepEqual(items, []int{3, 4}) || next == "" {
		t.Fatalf("%v %q", items, next)
	}
	items, next, _ = SliceByCursor(all, gitcore.Page{Cursor: next, Limit: 2})
	if !reflect.DeepEqual(items, []int{5}) || next != "" {
		t.Fatalf("%v %q", items, next)
	}
	if _, _, err := SliceByCursor(all, gitcore.Page{Cursor: "garbage!"}); err == nil {
		t.Fatal("bad cursor must fail")
	} else if e, _ := gitcore.AsError(err); e == nil || e.Code != gitcore.CodeInvalid {
		t.Fatalf("want INVALID_ARGUMENT, got %v", err)
	}
	items, _, _ = SliceByCursor(all, gitcore.Page{Cursor: OffsetCursor(99)})
	if len(items) != 0 {
		t.Fatal("past the end is empty")
	}
}

func TestStatusMappingAndMedian(t *testing.T) {
	for in, want := range map[string]string{"waiting": "queued", "running": "running", "success": "success", "failure": "failure", "cancelled": "cancelled", "skipped": "cancelled", "blocked": "waiting_approval", "weird": "queued"} {
		if got := RunStatus(in, false); got != want {
			t.Errorf("RunStatus(%q)=%q want %q", in, got, want)
		}
	}
	if RunStatus("waiting", true) != "waiting_approval" {
		t.Error("need_approval wins")
	}
	if !JobFinished("success") || JobFinished("running") || JobFinished("waiting") {
		t.Error("JobFinished")
	}
	d := func(s ...int) []time.Duration {
		var out []time.Duration
		for _, x := range s {
			out = append(out, time.Duration(x)*time.Second)
		}
		return out
	}
	for _, c := range []struct {
		in   []time.Duration
		want int
	}{{nil, 0}, {d(5), 5}, {d(9, 1, 5), 5}, {d(1, 3, 5, 7), 4}, {d(10, 2), 6}} {
		if got := MedianSeconds(c.in); got != c.want {
			t.Errorf("median %v = %d want %d", c.in, got, c.want)
		}
	}
	run := ToRun(gitcore.Run{ID: 7, Ref: "pull/12/head", Status: "success"})
	if run.ID != "7" || run.PR == nil || *run.PR != 12 {
		t.Errorf("run mapping %+v", run)
	}
	if CheckSource("capsule/security") != "security" || CheckSource("capsule/policy") != "capsule" ||
		CheckSource("CI / build (push)") != "actions" || CheckSource("jenkins") != "external" {
		t.Error("CheckSource")
	}
	if LanguageOf("a/b/main.go") != "go" || LanguageOf("Dockerfile") != "dockerfile" || LanguageOf("x.unknown") != "" {
		t.Error("LanguageOf")
	}
}
