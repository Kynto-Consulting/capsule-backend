package environments

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

var sha1 = strings.Repeat("a", 40)
var sha2 = strings.Repeat("b", 40)

type rig struct {
	t      *testing.T
	svc    *Service
	st     *memStore
	forge  *fakeForge
	dep    *fakeDeployer
	dir    fakeDir
	pub    *fakePub
	clock  *fakeClock
	tgt    Target
	admin1 Actor
	admin2 Actor
	admin3 Actor
	dev    Actor
	viewer Actor
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, st: newMemStore(), forge: newForge(), dep: &fakeDeployer{}, pub: &fakePub{},
		clock: &fakeClock{t: time.Date(2026, 11, 4, 15, 0, 0, 0, time.UTC)}} // a Wednesday
	org, proj := uuid.New(), uuid.New()
	r.tgt = Target{ProjectID: proj, OrgID: org, OrgSlug: "evvg", ProjectSlug: "app"}
	r.st.targets[proj] = r.tgt
	mk := func(role authz.Role) Actor { return Actor{UserID: uuid.New(), Role: role} }
	r.admin1, r.admin2, r.admin3 = mk(authz.RoleAdmin), mk(authz.RoleAdmin), mk(authz.RoleAdmin)
	r.dev, r.viewer = mk(authz.RoleDeployer), mk(authz.RoleViewer)
	r.dir = fakeDir{admins: 3, roles: map[uuid.UUID]authz.Role{}}
	for _, a := range []Actor{r.admin1, r.admin2, r.admin3, r.dev, r.viewer} {
		r.dir.roles[a.UserID] = a.Role
	}
	r.forge.branches["main"] = sha1
	r.forge.checks[sha1] = []gitcore.Check{{Context: "ci", State: gitcore.CheckSuccess}}
	r.forge.checks[sha2] = []gitcore.Check{{Context: "ci", State: gitcore.CheckSuccess}}
	r.forge.ancestor["main|"+sha2] = true
	r.st.addArtifact(proj, sha1)
	r.st.addArtifact(proj, sha2)
	r.svc = New(r.st, r.forge, r.dep, r.dir, r.pub, Config{}, nil)
	r.svc.now = r.clock.now
	return r
}

func (r *rig) env(in Input) *EnvView {
	r.t.Helper()
	v, err := r.svc.CreateEnv(context.Background(), r.tgt, r.admin1, in)
	if err != nil {
		r.t.Fatalf("create env %q: %v", in.Name, err)
	}
	return v
}

func (r *rig) prod() *EnvView { return r.env(Input{Name: "production", Kind: "production"}) }

func (r *rig) request(a Actor, env, sha, key string) (PromotionView, error) {
	v, _, err := r.svc.CreatePromotion(context.Background(), r.tgt, a, PromotionRequest{Environment: env, SHA: sha}, key)
	return v, err
}

func (r *rig) mustRequest(a Actor, env, sha string) PromotionView {
	r.t.Helper()
	v, err := r.request(a, env, sha, "")
	if err != nil {
		r.t.Fatalf("request: %v", err)
	}
	return v
}

func (r *rig) get(id uuid.UUID) Promotion {
	p, err := r.st.GetPromotion(context.Background(), id)
	if err != nil {
		r.t.Fatal(err)
	}
	return *p
}

func code(err error) string {
	var f *ForbiddenError
	var c *ConflictError
	var p *PolicyError
	switch {
	case errors.As(err, &f):
		return f.Code
	case errors.As(err, &c):
		return c.Code
	case errors.As(err, &p):
		return p.Code
	case err == nil:
		return ""
	}
	return err.Error()
}

func (r *rig) approve(a Actor, id uuid.UUID) error {
	_, err := r.svc.Approve(context.Background(), r.tgt, a, id, "ok")
	return err
}

func TestProductionFlowReusesArtifactWithoutBuilding(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.prod()
	v := r.mustRequest(r.dev, "production", sha1)
	if v.Status != StatusPending || v.RequiredApprovals != 1 || v.Project.Slug != "app" || v.Branch != "main" {
		t.Fatalf("created: %+v", v)
	}
	if c := r.forge.lastCheck(); c.Context != "capsule/env:production" || c.State != gitcore.CheckPending {
		t.Fatalf("check on creation: %+v", c)
	}
	// a deployer is not on the approver list (the role alone grants nothing)
	if got := code(r.approve(r.dev, v.ID)); got != "NOT_AN_APPROVER" {
		t.Fatalf("deployer approve: %s", got)
	}
	if err := r.approve(r.admin1, v.ID); err != nil {
		t.Fatal(err)
	}
	if p := r.get(v.ID); p.Status != StatusApproved {
		t.Fatalf("after approval: %s", p.Status)
	}
	r.svc.Tick(ctx)
	if p := r.get(v.ID); p.Status != StatusDeploying || p.DeploymentID == nil {
		t.Fatalf("after tick: %+v", p)
	}
	want := r.st.artifacts[r.tgt.ProjectID.String()+"|"+sha1]
	if len(r.dep.calls) != 1 || r.dep.calls[0].SourceKey != want.SourceKey || r.dep.calls[0].DeploymentID != want.DeploymentID {
		t.Fatalf("the promotion must redeploy the stored source of the existing deployment: %+v", r.dep.calls)
	}
	r.dep.status = "success"
	r.svc.Tick(ctx)
	if p := r.get(v.ID); p.Status != StatusSuccess {
		t.Fatalf("final: %s", p.Status)
	}
	if c := r.forge.lastCheck(); c.State != gitcore.CheckSuccess {
		t.Fatalf("final check: %+v", c)
	}
	names := strings.Join(r.pub.names(), ",")
	for _, n := range []string{"approval.requested", "approval.decided", "promotion.completed"} {
		if !strings.Contains(names, n) {
			t.Fatalf("missing event %s in %s", n, names)
		}
	}
	acts := strings.Join(r.st.actions(), ",")
	for _, n := range []string{"promotion.request", "promotion.approve", "promotion.deploy", "promotion.complete"} {
		if !strings.Contains(acts, n) {
			t.Fatalf("missing audit %s in %s", n, acts)
		}
	}
}

func TestSelfApprovalForbidden(t *testing.T) {
	r := newRig(t)
	r.prod()
	v := r.mustRequest(r.admin1, "production", sha1)
	if got := code(r.approve(r.admin1, v.ID)); got != "SELF_APPROVAL_FORBIDDEN" {
		t.Fatalf("got %s", got)
	}
}

func TestAdminNotListedCannotApprove(t *testing.T) {
	r := newRig(t)
	u2, u3 := r.admin2.UserID, r.admin3.UserID
	r.env(Input{Name: "production", Kind: "production", Reviewers: []Reviewer{{Type: "user", UserID: &u2}, {Type: "user", UserID: &u3}}})
	v := r.mustRequest(r.dev, "production", sha1)
	if got := code(r.approve(r.admin1, v.ID)); got != "NOT_AN_APPROVER" {
		t.Fatalf("an admin who is not listed must not approve: %s", got)
	}
	if err := r.approve(r.admin2, v.ID); err != nil {
		t.Fatal(err)
	}
}

func TestApproverWithoutProjectRoleIsRefused(t *testing.T) {
	r := newRig(t)
	r.prod()
	v := r.mustRequest(r.dev, "production", sha1)
	if got := code(r.approve(Actor{UserID: uuid.New(), Role: ""}, v.ID)); got != "NOT_AN_APPROVER" {
		t.Fatalf("got %s", got)
	}
}

func TestSelfApprovalOnlyWhenConfiguredAndAudited(t *testing.T) {
	r := newRig(t)
	r.dir.admins = 1
	r.svc.dir = r.dir
	// single admin, no self approval: refused up front instead of waiting 72 h
	r.prod()
	if _, err := r.request(r.admin1, "production", sha1, ""); code(err) != "NO_ELIGIBLE_APPROVER" {
		t.Fatalf("got %v", err)
	}
	// explicit opt-in
	yes := true
	if _, err := r.svc.PutEnv(context.Background(), r.tgt, r.admin1, "production", Input{Name: "production", Kind: "production", AllowSelfApproval: &yes}); err != nil {
		t.Fatal(err)
	}
	v := r.mustRequest(r.admin1, "production", sha1)
	if err := r.approve(r.admin1, v.ID); err != nil {
		t.Fatalf("explicit self approval: %v", err)
	}
	if p := r.get(v.ID); p.Status != StatusApproved {
		t.Fatalf("status %s", p.Status)
	}
	acts := strings.Join(r.st.actions(), ",")
	if !strings.Contains(acts, "promotion.self_approve") || !strings.Contains(acts, "environment.self_approval_enabled") {
		t.Fatalf("self approval must be audited: %s", acts)
	}
}

func TestProductionDefaultsAndValidation(t *testing.T) {
	r := newRig(t)
	v := r.prod()
	if v.RequiredApprovals != 1 || v.AllowSelfApproval || len(v.Reviewers) != 1 || v.Reviewers[0].Role != "admin" || !v.RequireChecksOnSHA {
		t.Fatalf("defaults: %+v", v.Environment)
	}
	zero := 0
	_, err := r.svc.CreateEnv(context.Background(), r.tgt, r.admin1, Input{Name: "prod2", Kind: "production", RequiredApprovals: &zero})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("production with 0 approvals must be refused: %v", err)
	}
	_, err = r.svc.CreateEnv(context.Background(), r.tgt, r.admin1, Input{Name: "prod3", Kind: "production", Reviewers: []Reviewer{{Type: "role", Role: "deployer"}}})
	if !errors.As(err, &ve) {
		t.Fatalf("deployer approvers in production must be refused: %v", err)
	}
	_, err = r.svc.CreateEnv(context.Background(), r.tgt, r.admin1, Input{Name: "Bad Name", Kind: "other"})
	if !errors.As(err, &ve) {
		t.Fatalf("bad name: %v", err)
	}
}

func TestIdempotencyKey(t *testing.T) {
	r := newRig(t)
	r.env(Input{Name: "staging", Kind: "staging"})
	ctx := context.Background()
	a, created, err := r.svc.CreatePromotion(ctx, r.tgt, r.dev, PromotionRequest{Environment: "staging", SHA: sha1}, "k1")
	if err != nil || !created {
		t.Fatal(err, created)
	}
	b, created, err := r.svc.CreatePromotion(ctx, r.tgt, r.dev, PromotionRequest{Environment: "staging", SHA: sha1}, "k1")
	if err != nil || created || b.ID != a.ID {
		t.Fatalf("replay must return the same promotion: %v %v %v", err, created, b.ID == a.ID)
	}
	_, _, err = r.svc.CreatePromotion(ctx, r.tgt, r.dev, PromotionRequest{Environment: "staging", SHA: sha2}, "k1")
	if code(err) != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("different body, same key: %v", err)
	}
	_, _, err = r.svc.CreatePromotion(ctx, r.tgt, r.dev, PromotionRequest{Environment: "staging", SHA: sha1}, "k2")
	if code(err) != "PROMOTION_ACTIVE" {
		t.Fatalf("same sha already active: %v", err)
	}
}

func TestQueuePerEnvironment(t *testing.T) {
	r := newRig(t)
	r.env(Input{Name: "staging", Kind: "staging"})
	ctx := context.Background()
	a := r.mustRequest(r.dev, "staging", sha1)
	r.clock.t = r.clock.t.Add(time.Second)
	b := r.mustRequest(r.dev, "staging", sha2)
	r.svc.Tick(ctx)
	if len(r.dep.calls) != 1 {
		t.Fatalf("only one deployment per environment at a time, got %d", len(r.dep.calls))
	}
	first, second := r.get(a.ID), r.get(b.ID)
	if first.Status != StatusDeploying || second.Status != StatusApproved {
		t.Fatalf("states: %s %s", first.Status, second.Status)
	}
	r.dep.status = "success"
	r.svc.Tick(ctx) // finishes the first
	r.dep.status = ""
	r.svc.Tick(ctx) // starts the second
	if r.get(a.ID).Status != StatusSuccess || r.get(b.ID).Status != StatusDeploying || len(r.dep.calls) != 2 {
		t.Fatalf("queue did not advance: %s %s", r.get(a.ID).Status, r.get(b.ID).Status)
	}
}

func TestExpiryAfter72Hours(t *testing.T) {
	r := newRig(t)
	r.prod()
	v := r.mustRequest(r.dev, "production", sha1)
	r.clock.t = r.clock.t.Add(71 * time.Hour)
	r.svc.Tick(context.Background())
	if r.get(v.ID).Status != StatusPending {
		t.Fatal("must still be pending at 71 h")
	}
	r.clock.t = r.clock.t.Add(2 * time.Hour)
	r.svc.Tick(context.Background())
	if r.get(v.ID).Status != StatusExpired {
		t.Fatalf("status %s", r.get(v.ID).Status)
	}
	if c := r.forge.lastCheck(); c.State != gitcore.CheckFailure {
		t.Fatalf("check %+v", c)
	}
	if !strings.Contains(strings.Join(r.pub.names(), ","), "promotion.completed") {
		t.Fatal("no completion event")
	}
}

func TestWaitMinutes(t *testing.T) {
	r := newRig(t)
	w := 30
	r.env(Input{Name: "qa", Kind: "other", WaitMinutes: &w})
	v := r.mustRequest(r.dev, "qa", sha1)
	p := r.get(v.ID)
	if p.Status != StatusWaiting || p.NotBefore == nil || !p.NotBefore.Equal(r.clock.t.Add(30*time.Minute)) {
		t.Fatalf("%+v", p)
	}
	r.clock.t = r.clock.t.Add(10 * time.Minute)
	r.svc.Tick(context.Background())
	if r.get(v.ID).Status != StatusWaiting || len(r.dep.calls) != 0 {
		t.Fatal("must keep waiting")
	}
	r.clock.t = r.clock.t.Add(21 * time.Minute)
	r.svc.Tick(context.Background())
	if r.get(v.ID).Status != StatusDeploying {
		t.Fatalf("status %s", r.get(v.ID).Status)
	}
}

func TestWindowWithTimeZone(t *testing.T) {
	r := newRig(t)
	win := []Window{{Days: []string{"mon", "tue", "wed", "thu", "fri"}, From: "09:00", To: "18:00", TZ: "America/Lima"}}
	r.env(Input{Name: "qa", Kind: "other", Windows: win})
	// Saturday 12:00 UTC = 07:00 in Lima: closed until Monday 09:00 Lima = 14:00 UTC
	r.clock.t = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	v := r.mustRequest(r.dev, "qa", sha1)
	p := r.get(v.ID)
	want := time.Date(2026, 11, 9, 14, 0, 0, 0, time.UTC)
	if p.Status != StatusWaiting || p.NotBefore == nil || !p.NotBefore.Equal(want) {
		t.Fatalf("expected waiting until %s, got %s %v", want, p.Status, p.NotBefore)
	}
	r.clock.t = want.Add(time.Minute)
	r.svc.Tick(context.Background())
	if r.get(v.ID).Status != StatusDeploying {
		t.Fatalf("status %s", r.get(v.ID).Status)
	}
}

func TestWindowClosingMovesApprovedBackToWaiting(t *testing.T) {
	r := newRig(t)
	win := []Window{{Days: []string{}, From: "09:00", To: "18:00", TZ: "America/Lima"}}
	r.env(Input{Name: "qa", Kind: "other", Windows: win})
	r.clock.t = time.Date(2026, 11, 4, 22, 59, 0, 0, time.UTC) // 17:59 Lima, open
	a := r.mustRequest(r.dev, "qa", sha1)
	b := r.mustRequest(r.dev, "qa", sha2)
	if r.get(a.ID).Status != StatusApproved {
		t.Fatalf("open window: %s", r.get(a.ID).Status)
	}
	r.clock.t = r.clock.t.Add(2 * time.Minute) // 18:01 Lima, closed before the queue started it
	r.svc.Tick(context.Background())
	if r.get(a.ID).Status != StatusWaiting || r.get(b.ID).Status != StatusWaiting || len(r.dep.calls) != 0 {
		t.Fatalf("%s %s calls=%d", r.get(a.ID).Status, r.get(b.ID).Status, len(r.dep.calls))
	}
}

func TestBranchNotAllowedAndChecks(t *testing.T) {
	r := newRig(t)
	r.prod()
	other := strings.Repeat("c", 40)
	r.st.addArtifact(r.tgt.ProjectID, other)
	r.forge.checks[other] = []gitcore.Check{{Context: "ci", State: gitcore.CheckSuccess}}
	if _, err := r.request(r.dev, "production", other, ""); code(err) != "PROTECTED_BRANCH" {
		t.Fatalf("got %v", err)
	}
	r.forge.checks[sha1] = []gitcore.Check{{Context: "ci", State: gitcore.CheckFailure}}
	if _, err := r.request(r.dev, "production", sha1, ""); code(err) != "CHECKS_REQUIRED" {
		t.Fatalf("got %v", err)
	}
	// our own environment status must never gate another environment
	r.forge.checks[sha1] = []gitcore.Check{{Context: "ci", State: gitcore.CheckSuccess}, {Context: "capsule/env:staging", State: gitcore.CheckPending}}
	if _, err := r.request(r.dev, "production", sha1, ""); err != nil {
		t.Fatalf("capsule/env:* must be ignored: %v", err)
	}
}

func TestSourceEnvironmentAndMissingArtifact(t *testing.T) {
	r := newRig(t)
	r.env(Input{Name: "staging", Kind: "staging"})
	src := "staging"
	r.env(Input{Name: "production", Kind: "production", RequireSourceEnvironment: &src})
	ctx := context.Background()
	if _, err := r.request(r.dev, "production", sha1, ""); code(err) != "SOURCE_ENVIRONMENT_REQUIRED" {
		t.Fatalf("got %v", err)
	}
	s := r.mustRequest(r.dev, "staging", sha1)
	r.svc.Tick(ctx)
	r.dep.status = "success"
	r.svc.Tick(ctx)
	if r.get(s.ID).Status != StatusSuccess {
		t.Fatal("staging did not succeed")
	}
	if _, err := r.request(r.dev, "production", sha1, ""); err != nil {
		t.Fatalf("after staging success: %v", err)
	}
	// no deployment of the commit exists anywhere
	delete(r.st.artifacts, r.tgt.ProjectID.String()+"|"+sha2)
	if _, err := r.request(r.dev, "staging", sha2, ""); code(err) != "ARTIFACT_NOT_FOUND" {
		t.Fatalf("got %v", err)
	}
}

func TestSecurityPolicyBlocks(t *testing.T) {
	r := newRig(t)
	r.svc.WithSecurity(blockAll{})
	r.prod()
	if _, err := r.request(r.dev, "production", sha1, ""); code(err) != "POLICY_BLOCKED" {
		t.Fatalf("got %v", err)
	}
}

type blockAll struct{}

func (blockAll) Blocked(context.Context, uuid.UUID, string) (bool, string, error) {
	return true, "1 critical alert", nil
}

func TestPolicyChangeCancelsPending(t *testing.T) {
	r := newRig(t)
	r.prod()
	v := r.mustRequest(r.dev, "production", sha1)
	_, err := r.svc.PutEnv(context.Background(), r.tgt, r.admin1, "production",
		Input{Name: "production", Kind: "production", BranchPatterns: []string{"release/*"}})
	if err != nil {
		t.Fatal(err)
	}
	p := r.get(v.ID)
	if p.Status != StatusCancelled || !strings.Contains(p.StatusReason, "policy_changed") {
		t.Fatalf("%s %q", p.Status, p.StatusReason)
	}
}

func TestPolicyChangeLoweringApprovalsAdvances(t *testing.T) {
	r := newRig(t)
	two := 2
	r.env(Input{Name: "production", Kind: "production", RequiredApprovals: &two})
	v := r.mustRequest(r.dev, "production", sha1)
	if err := r.approve(r.admin1, v.ID); err != nil {
		t.Fatal(err)
	}
	if r.get(v.ID).Status != StatusPending {
		t.Fatal("needs two approvals")
	}
	if _, err := r.svc.PutEnv(context.Background(), r.tgt, r.admin1, "production", Input{Name: "production", Kind: "production"}); err != nil {
		t.Fatal(err)
	}
	if got := r.get(v.ID).Status; got != StatusApproved {
		t.Fatalf("status %s", got)
	}
}

func TestRejectDuringWaitAndCancel(t *testing.T) {
	r := newRig(t)
	w := 60
	one := 1
	u2 := r.admin2.UserID
	u3 := r.admin3.UserID
	r.env(Input{Name: "production", Kind: "production", WaitMinutes: &w, RequiredApprovals: &one,
		Reviewers: []Reviewer{{Type: "user", UserID: &u2}, {Type: "user", UserID: &u3}}})
	v := r.mustRequest(r.dev, "production", sha1)
	if err := r.approve(r.admin2, v.ID); err != nil {
		t.Fatal(err)
	}
	if r.get(v.ID).Status != StatusWaiting {
		t.Fatal("expected waiting")
	}
	if _, err := r.svc.Reject(context.Background(), r.tgt, r.admin3, v.ID, "not today"); err != nil {
		t.Fatal(err)
	}
	if r.get(v.ID).Status != StatusRejected {
		t.Fatalf("status %s", r.get(v.ID).Status)
	}
	// a viewer cannot cancel somebody else's promotion; the requester can
	w2 := r.mustRequest(r.dev, "production", sha2)
	if _, err := r.svc.Cancel(context.Background(), r.tgt, r.viewer, w2.ID); code(err) != "FORBIDDEN" {
		t.Fatalf("viewer cancel: %v", err)
	}
	if _, err := r.svc.Cancel(context.Background(), r.tgt, r.dev, w2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Cancel(context.Background(), r.tgt, r.dev, w2.ID); code(err) != "INVALID_STATE" {
		t.Fatalf("second cancel: %v", err)
	}
}

func TestSimultaneousApprovalsReachQuorumOnce(t *testing.T) {
	r := newRig(t)
	two := 2
	u2, u3, u4 := r.admin2.UserID, r.admin3.UserID, r.admin1.UserID
	r.env(Input{Name: "production", Kind: "production", RequiredApprovals: &two,
		Reviewers: []Reviewer{{Type: "user", UserID: &u2}, {Type: "user", UserID: &u3}, {Type: "user", UserID: &u4}}})
	v := r.mustRequest(r.dev, "production", sha1)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, a := range []Actor{r.admin2, r.admin3} {
		wg.Add(1)
		go func(i int, a Actor) { defer wg.Done(); errs[i] = r.approve(a, v.ID) }(i, a)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("%v %v", errs[0], errs[1])
	}
	if got := r.get(v.ID).Status; got != StatusApproved {
		t.Fatalf("two simultaneous approvals must reach the quorum, got %s", got)
	}
	if err := r.approve(r.admin2, v.ID); code(err) != "INVALID_STATE" && code(err) != "ALREADY_DECIDED" {
		t.Fatalf("got %v", err)
	}
}

func TestApprovalsPendingInbox(t *testing.T) {
	r := newRig(t)
	r.prod()
	v := r.mustRequest(r.dev, "production", sha1)
	items, _, err := r.svc.Pending(context.Background(), r.tgt.OrgID, r.admin2.UserID, "", 30)
	if err != nil || len(items) != 1 || items[0].ID != v.ID || items[0].Project.ID != r.tgt.ProjectID || items[0].Project.Slug != "app" || !items[0].CanDecide {
		t.Fatalf("admin inbox: %v %+v", err, items)
	}
	for name, u := range map[string]Actor{"requester-deployer": r.dev, "viewer": r.viewer} {
		items, _, err := r.svc.Pending(context.Background(), r.tgt.OrgID, u.UserID, "", 30)
		if err != nil || len(items) != 0 {
			t.Fatalf("%s must see nothing: %v %+v", name, err, items)
		}
	}
	// once decided it leaves the inbox of that approver
	if err := r.approve(r.admin2, v.ID); err != nil {
		t.Fatal(err)
	}
	if items, _, _ := r.svc.Pending(context.Background(), r.tgt.OrgID, r.admin2.UserID, "", 30); len(items) != 0 {
		t.Fatalf("decided promotion still listed: %+v", items)
	}
}

func TestDeployFailureAndMissingDeployment(t *testing.T) {
	r := newRig(t)
	r.env(Input{Name: "staging", Kind: "staging"})
	r.dep.failErr = errors.New("db down")
	v := r.mustRequest(r.dev, "staging", sha1)
	r.svc.Tick(context.Background())
	p := r.get(v.ID)
	if p.Status != StatusFailed || !strings.Contains(p.StatusReason, "could not create") {
		t.Fatalf("%s %q", p.Status, p.StatusReason)
	}
	if c := r.forge.lastCheck(); c.State != gitcore.CheckFailure {
		t.Fatalf("%+v", c)
	}
}

func TestDeleteEnvRefusedWhileActive(t *testing.T) {
	r := newRig(t)
	r.prod()
	r.mustRequest(r.dev, "production", sha1)
	if err := r.svc.DeleteEnv(context.Background(), r.tgt, r.admin1, "production"); code(err) != "ENV_HAS_ACTIVE_PROMOTIONS" {
		t.Fatalf("got %v", err)
	}
}

func TestAutoPromote(t *testing.T) {
	r := newRig(t)
	yes := true
	r.env(Input{Name: "staging", Kind: "staging", BranchPatterns: []string{"main"}, AutoDeploy: &yes})
	r.svc.AutoPromote(context.Background(), r.tgt, "main", sha1)
	r.svc.Tick(context.Background())
	if len(r.dep.calls) != 1 {
		t.Fatalf("auto_deploy did not deploy: %d", len(r.dep.calls))
	}
}
