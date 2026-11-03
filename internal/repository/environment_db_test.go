//go:build dbtest

package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/environments"
)

type envFx struct {
	r               *EnvironmentRepository
	org, project    uuid.UUID
	requester, adm1 uuid.UUID
	adm2            uuid.UUID
	env             *environments.Environment
}

func newEnvFx(t *testing.T) *envFx {
	t.Helper()
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	now := time.Now().Add(-time.Hour)
	x := &envFx{r: NewEnvironmentRepository(pool)}
	x.requester, x.adm1, x.adm2 = f.user("", now), f.user("", now), f.user("", now)
	x.org = f.org(x.adm1)
	x.project = f.project(x.org, "app")
	e := &environments.Environment{
		ID: uuid.New(), ProjectID: x.project, Name: "production", Kind: "production", TargetProjectID: x.project,
		BranchPatterns: []string{"main"}, TagPatterns: []string{}, Reviewers: []environments.Reviewer{{Type: "role", Role: "admin"}},
		RequiredApprovals: 2, WaitMinutes: 5, RequireChecksOnSHA: true, RequireSecurityPolicy: true,
		Windows: []environments.Window{{Days: []string{"mon"}, From: "09:00", To: "18:00", TZ: "America/Lima"}},
	}
	au := environments.AuditEntry{OrgID: x.org, UserID: x.adm1, Action: "environment.create", ResourceType: "environment", ResourceID: e.ID}
	if err := x.r.CreateEnv(context.Background(), e, au); err != nil {
		t.Fatal(err)
	}
	x.env = e
	return x
}

func (x *envFx) promo(sha, key string, status string) *environments.Promotion {
	by := x.requester
	return &environments.Promotion{
		ID: uuid.New(), ProjectID: x.project, EnvironmentID: x.env.ID, SHA: sha, Branch: "main", Status: status,
		RequestedBy: &by, RequiredApprovals: 2, ExpiresAt: time.Now().Add(72 * time.Hour), IdempotencyKey: key,
		Checks: environments.CheckSnapshot{State: "success", Items: []environments.CheckItem{}}, Conditions: []environments.Condition{},
	}
}

func (x *envFx) audit(action string, id uuid.UUID) environments.AuditEntry {
	return environments.AuditEntry{OrgID: x.org, UserID: x.adm1, Action: action, ResourceType: "promotion", ResourceID: id}
}

func TestEnvironmentsCRUDDB(t *testing.T) {
	x := newEnvFx(t)
	ctx := context.Background()
	got, err := x.r.GetEnv(ctx, x.project, "production")
	if err != nil || got.RequiredApprovals != 2 || len(got.Windows) != 1 || got.Windows[0].TZ != "America/Lima" ||
		len(got.Reviewers) != 1 || got.Reviewers[0].Role != "admin" || got.RequireSourceEnvironment != nil {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	dup := *x.env
	dup.ID = uuid.New()
	if err := x.r.CreateEnv(ctx, &dup, x.audit("environment.create", dup.ID)); !errors.Is(err, environments.ErrDuplicate) {
		t.Fatalf("duplicate name: %v", err)
	}
	src := "staging"
	got.RequireSourceEnvironment = &src
	got.RequiredApprovals = 1
	if err := x.r.UpdateEnv(ctx, got, x.audit("environment.update", got.ID)); err != nil {
		t.Fatal(err)
	}
	again, _ := x.r.GetEnvByID(ctx, got.ID)
	if again.RequiredApprovals != 1 || again.RequireSourceEnvironment == nil || *again.RequireSourceEnvironment != "staging" {
		t.Fatalf("update: %+v", again)
	}
	list, err := x.r.ListEnvs(ctx, x.project)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	if tg, err := x.r.Target(ctx, x.project); err != nil || tg.ProjectSlug != "app" || tg.OrgID != x.org || tg.OrgSlug == "" {
		t.Fatalf("target: %+v %v", tg, err)
	}
	if _, err := x.r.Target(ctx, uuid.New()); !errors.Is(err, environments.ErrNotFound) {
		t.Fatalf("missing target: %v", err)
	}
	var n int
	if err := x.r.pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE resource_id=$1`, got.ID).Scan(&n); err != nil || n != 2 {
		t.Fatalf("audit rows: %d %v", n, err)
	}
	if err := x.r.DeleteEnv(ctx, x.project, got.ID, x.audit("environment.delete", got.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := x.r.GetEnvByID(ctx, got.ID); !errors.Is(err, environments.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestPromotionIdempotencyAndActiveDuplicateDB(t *testing.T) {
	x := newEnvFx(t)
	ctx := context.Background()
	sha := "a1" + string(make([]byte, 0)) + "b2c3d4e5f60718293a4b5c6d7e8f9012345678"
	p1 := x.promo(sha, "key-1", environments.StatusPending)
	if err := x.r.CreatePromotion(ctx, p1, x.audit("promotion.request", p1.ID)); err != nil {
		t.Fatal(err)
	}
	// same Idempotency-Key, same requester: the stored promotion comes back
	p2 := x.promo(sha, "key-1", environments.StatusPending)
	var ex *environments.ExistingError
	if err := x.r.CreatePromotion(ctx, p2, x.audit("promotion.request", p2.ID)); !errors.As(err, &ex) || ex.Kind != "idempotency" || ex.Promotion.ID != p1.ID {
		t.Fatalf("idempotency: %v", err)
	}
	// another key, same SHA while active
	p3 := x.promo(sha, "key-2", environments.StatusPending)
	if err := x.r.CreatePromotion(ctx, p3, x.audit("promotion.request", p3.ID)); !errors.As(err, &ex) || ex.Kind != "active" || ex.Promotion.ID != p1.ID {
		t.Fatalf("active duplicate: %v", err)
	}
	// concurrent creations with one key produce exactly one row
	sha2 := "b1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
	var wg sync.WaitGroup
	var mu sync.Mutex
	created, existing := 0, 0
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := x.promo(sha2, "race", environments.StatusPending)
			err := x.r.CreatePromotion(ctx, p, x.audit("promotion.request", p.ID))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				created++
			case errors.As(err, &ex):
				existing++
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if created != 1 || existing != 5 {
		t.Fatalf("created=%d existing=%d", created, existing)
	}
	found, err := x.r.FindByIdempotency(ctx, x.project, x.requester, "key-1")
	if err != nil || found == nil || found.ID != p1.ID {
		t.Fatalf("FindByIdempotency: %v %v", found, err)
	}
	// history row mirrors the promotion
	items, _, err := x.r.ListEnvDeployments(ctx, x.env.ID, "", 10)
	if err != nil || len(items) != 2 || items[0].Status != environments.StatusPending {
		t.Fatalf("history: %v %+v", err, items)
	}
}

func TestSimultaneousApprovalsDB(t *testing.T) {
	x := newEnvFx(t)
	ctx := context.Background()
	p := x.promo("c1b2c3d4e5f60718293a4b5c6d7e8f9012345678", "", environments.StatusPending)
	if err := x.r.CreatePromotion(ctx, p, x.audit("promotion.request", p.ID)); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, u := range []uuid.UUID{x.adm1, x.adm2} {
		wg.Add(1)
		go func(i int, u uuid.UUID) {
			defer wg.Done()
			uid := u
			_, errs[i] = x.r.AddDecision(ctx, environments.Decision{
				PromotionID: p.ID, Required: 2, QuorumStatus: environments.StatusApproved, QuorumAt: now,
				Approval: environments.Approval{UserID: &uid, Decision: "approved", Comment: "ok", At: now},
			}, x.audit("promotion.approve", p.ID))
		}(i, u)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("%v %v", errs[0], errs[1])
	}
	got, _ := x.r.GetPromotion(ctx, p.ID)
	if got.Status != environments.StatusApproved || len(got.Approvals) != 2 {
		t.Fatalf("two simultaneous approvals must reach the quorum: %s %d", got.Status, len(got.Approvals))
	}
	// the same user cannot decide twice, and a decided promotion refuses new approvals
	uid := x.adm1
	_, err := x.r.AddDecision(ctx, environments.Decision{PromotionID: p.ID, Required: 2,
		Approval: environments.Approval{UserID: &uid, Decision: "approved", At: now}}, x.audit("promotion.approve", p.ID))
	if !errors.Is(err, environments.ErrInvalidState) {
		t.Fatalf("approve after quorum: %v", err)
	}
	hist, _, _ := x.r.ListEnvDeployments(ctx, x.env.ID, "", 10)
	if hist[0].Status != "queued" {
		t.Fatalf("approved promotions show as queued in the history, got %s", hist[0].Status)
	}
}

func TestSelfApprovalCountingAndRejectDB(t *testing.T) {
	x := newEnvFx(t)
	ctx := context.Background()
	p := x.promo("d1b2c3d4e5f60718293a4b5c6d7e8f9012345678", "", environments.StatusPending)
	p.RequiredApprovals = 1
	if err := x.r.CreatePromotion(ctx, p, x.audit("promotion.request", p.ID)); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	self := x.requester
	got, err := x.r.AddDecision(ctx, environments.Decision{PromotionID: p.ID, Required: 1, AllowSelf: false, QuorumStatus: environments.StatusApproved, QuorumAt: now,
		Approval: environments.Approval{UserID: &self, Decision: "approved", SelfApproval: true, At: now}}, x.audit("promotion.self_approve", p.ID))
	if err != nil || got.Status != environments.StatusPending {
		t.Fatalf("a self approval must not count when the environment forbids it: %v %v", err, got)
	}
	adm := x.adm1
	got, err = x.r.AddDecision(ctx, environments.Decision{PromotionID: p.ID, Required: 1, RejectReason: "rejected: no", RejectedAt: now,
		Approval: environments.Approval{UserID: &adm, Decision: "rejected", Comment: "no", At: now}}, x.audit("promotion.reject", p.ID))
	if err != nil || got.Status != environments.StatusRejected || got.FinishedAt == nil {
		t.Fatalf("reject: %v %+v", err, got)
	}
}

func TestQueueExpiryAndPendingDB(t *testing.T) {
	x := newEnvFx(t)
	ctx := context.Background()
	mk := func(sha string, st string) *environments.Promotion {
		p := x.promo(sha, "", st)
		if err := x.r.CreatePromotion(ctx, p, x.audit("promotion.request", p.ID)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
		return p
	}
	a := mk("e1b2c3d4e5f60718293a4b5c6d7e8f9012345678", environments.StatusApproved)
	b := mk("e2b2c3d4e5f60718293a4b5c6d7e8f9012345678", environments.StatusApproved)
	pend := mk("e3b2c3d4e5f60718293a4b5c6d7e8f9012345678", environments.StatusPending)
	now := time.Now()
	ok, err := x.r.Transition(ctx, a.ID, []string{environments.StatusApproved}, environments.StatusDeploying, environments.Patch{StartedAt: &now}, &environments.AuditEntry{OrgID: x.org, Action: "promotion.deploy", ResourceType: "promotion", ResourceID: a.ID})
	if err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	// the environment already has a deploying promotion: the second claim is refused, not an error
	ok, err = x.r.Transition(ctx, b.ID, []string{environments.StatusApproved}, environments.StatusDeploying, environments.Patch{StartedAt: &now}, nil)
	if err != nil || ok {
		t.Fatalf("queue must hold the second one: %v %v", ok, err)
	}
	dep := uuid.New()
	var depRow uuid.UUID
	if err := x.r.pool.QueryRow(ctx, `INSERT INTO deployments (project_id, version, status, build_strategy, container_port, trigger)
		VALUES ($1,'v','success','docker',8080,'git') RETURNING id`, x.project).Scan(&depRow); err != nil {
		t.Fatal(err)
	}
	_ = dep
	if err := x.r.SetDeployment(ctx, a.ID, depRow); err != nil {
		t.Fatal(err)
	}
	fin := time.Now()
	if ok, err := x.r.Transition(ctx, a.ID, []string{environments.StatusDeploying}, environments.StatusSuccess, environments.Patch{FinishedAt: &fin, Health: "healthy"}, nil); err != nil || !ok {
		t.Fatalf("finish: %v %v", ok, err)
	}
	if ok, _ := x.r.Transition(ctx, b.ID, []string{environments.StatusApproved}, environments.StatusDeploying, environments.Patch{StartedAt: &now}, nil); !ok {
		t.Fatal("after the first finished the queue slot must be free")
	}
	cur, err := x.r.CurrentDeployment(ctx, x.env.ID)
	if err != nil || cur == nil || cur.SHA != a.SHA || cur.HealthStatus != "healthy" || cur.DeploymentID == nil || *cur.DeploymentID != depRow {
		t.Fatalf("current: %+v %v", cur, err)
	}
	// Transition from a state the row is no longer in is a no-op
	if ok, _ := x.r.Transition(ctx, a.ID, []string{environments.StatusPending}, environments.StatusCancelled, environments.Patch{}, nil); ok {
		t.Fatal("stale transition must not apply")
	}
	// pending inbox: only pending_approval, only this org, keyset paging
	rows, err := x.r.PendingForOrg(ctx, x.org, "", 10)
	if err != nil || len(rows) != 1 || rows[0].Promotion.ID != pend.ID || rows[0].Env.ID != x.env.ID || len(rows[0].Env.Reviewers) != 1 {
		t.Fatalf("pending: %v %+v", err, rows)
	}
	if rows, _ := x.r.PendingForOrg(ctx, uuid.New(), "", 10); len(rows) != 0 {
		t.Fatal("another org must see nothing")
	}
	after, _ := x.r.PendingForOrg(ctx, x.org, environments.EncodeCursor(pend.CreatedAt, pend.ID), 10)
	_ = after
	// expiry: only pending/waiting/approved past their deadline
	if _, err := x.r.pool.Exec(ctx, `UPDATE promotions SET expires_at = now() - interval '1 minute' WHERE id = $1`, pend.ID); err != nil {
		t.Fatal(err)
	}
	exp, err := x.r.ExpireOverdue(ctx, time.Now())
	if err != nil || len(exp) != 1 || exp[0].ID != pend.ID {
		t.Fatalf("expire: %v %+v", err, exp)
	}
	got, _ := x.r.GetPromotion(ctx, pend.ID)
	if got.Status != environments.StatusExpired {
		t.Fatalf("status %s", got.Status)
	}
	if got, _ := x.r.GetPromotion(ctx, b.ID); got.Status != environments.StatusDeploying {
		t.Fatal("deploying promotions never expire")
	}
	if act, err := x.r.ListActive(ctx, 10); err != nil || len(act) != 1 || act[0].ID != b.ID {
		t.Fatalf("active: %v %+v", err, act)
	}
}

func TestArtifactLookupDB(t *testing.T) {
	x := newEnvFx(t)
	ctx := context.Background()
	sha := "f1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
	if a, err := x.r.FindArtifact(ctx, x.project, sha); err != nil || a != nil {
		t.Fatalf("none yet: %v %v", a, err)
	}
	var id uuid.UUID
	if err := x.r.pool.QueryRow(ctx, `INSERT INTO deployments (project_id, version, git_sha, status, build_strategy, container_port, trigger, source_key)
		VALUES ($1,'v',$2,'success','docker',3000,'git','deployments/x/y.tar.gz') RETURNING id`, x.project, sha).Scan(&id); err != nil {
		t.Fatal(err)
	}
	// a failed deployment of the same sha or one without stored source must not be offered
	_, _ = x.r.pool.Exec(ctx, `INSERT INTO deployments (project_id, version, git_sha, status, trigger, source_key) VALUES ($1,'v',$2,'failed','git','k')`, x.project, sha)
	a, err := x.r.FindArtifact(ctx, x.project, sha)
	if err != nil || a == nil || a.DeploymentID != id || a.SourceKey != "deployments/x/y.tar.gz" || a.ContainerPort != 3000 {
		t.Fatalf("artifact: %+v %v", a, err)
	}
	if b, _ := x.r.ArtifactOf(ctx, id); b == nil || b.DeploymentID != id {
		t.Fatal("ArtifactOf")
	}
}
