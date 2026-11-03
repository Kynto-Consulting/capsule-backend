//go:build dbtest

package repository

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitcore/fake"
	"github.com/kynto/capsule/backend/internal/gitprotect"
)

func bpRule(project uuid.UUID, pattern string) *gitprotect.Rule {
	return &gitprotect.Rule{ID: uuid.New(), ProjectID: project, Pattern: pattern, RequirePullRequest: true, RequiredApprovals: 2,
		DismissStaleApprovals: true, BlockOnRejectedReviews: true, RequiredChecks: []string{"ci/build", "capsule/preview"},
		BlockForcePush: true, BlockDeletion: true, PushAllowRoles: []string{"admin"}, MergeAllowRoles: []string{"admin", "deployer"},
		EnforceForAdmins: true}
}

func bpAudit(org, user uuid.UUID, rule *gitprotect.Rule, op string) gitprotect.AuditEntry {
	return gitprotect.AuditEntry{OrgID: org, UserID: user, Action: gitprotect.ActionProtectionChange, ResourceType: gitprotect.ResourceProtection,
		ResourceID: rule.ID, IP: "203.0.113.9", NewValues: map[string]any{"op": op, "pattern": rule.Pattern}}
}

func TestBranchProtectionCRUDDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewBranchProtectionRepository(pool)
	ctx := context.Background()
	owner := f.user("", time.Now())
	org := f.org(owner)
	p1, p2 := f.project(org, ""), f.project(org, "")

	// create: rule + pending sync row + audit entry in one transaction
	a := bpRule(p1, "main")
	a.CreatedBy = &owner
	if err := r.CreateRule(ctx, a, bpAudit(org, owner, a, "create")); err != nil {
		t.Fatal(err)
	}
	if a.CreatedAt.IsZero() || a.UpdatedAt.IsZero() {
		t.Fatal("CreateRule must fill timestamps")
	}
	got, err := r.GetRule(ctx, p1, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Pattern != "main" || got.RequiredApprovals != 2 || len(got.RequiredChecks) != 2 || got.RequiredChecks[1] != "capsule/preview" ||
		len(got.PushAllowRoles) != 1 || len(got.MergeAllowRoles) != 2 || !got.EnforceForAdmins || !got.BlockForcePush || got.CreatedBy == nil || *got.CreatedBy != owner {
		t.Fatalf("round trip: %+v", got)
	}
	syncs, err := r.ListSync(ctx, p1)
	if err != nil || len(syncs) != 1 || syncs[a.ID].Status != "pending" || syncs[a.ID].ProjectID != p1 {
		t.Fatalf("initial sync row: %+v %v", syncs, err)
	}
	var n int
	var ip, action string
	if err := pool.QueryRow(ctx, `SELECT count(*), max(host(ip_address)), max(action) FROM audit_logs WHERE resource_type='branch_protection' AND resource_id=$1 AND user_id=$2 AND org_id=$3`, a.ID, owner, org).Scan(&n, &ip, &action); err != nil {
		t.Fatal(err)
	}
	if n != 1 || ip != "203.0.113.9" || action != "git.protection.change" {
		t.Fatalf("audit row: n=%d ip=%s action=%s", n, ip, action)
	}

	// empty lists are stored as empty arrays (NOT NULL), and nil CreatedBy is NULL
	b := bpRule(p1, "release/*")
	b.RequiredChecks, b.PushAllowRoles, b.MergeAllowRoles = nil, nil, nil
	if err := r.CreateRule(ctx, b, bpAudit(org, uuid.Nil, b, "create")); err != nil {
		t.Fatal(err)
	}
	gb, _ := r.GetRule(ctx, p1, b.ID)
	if gb.RequiredChecks == nil || len(gb.RequiredChecks) != 0 || gb.CreatedBy != nil {
		t.Fatalf("nil lists / created_by: %+v", gb)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE resource_id=$1 AND user_id IS NULL`, b.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("audit with no user: %d %v", n, err)
	}

	// duplicate pattern: error, and neither a rule nor an audit row is left behind
	dup := bpRule(p1, "main")
	if err := r.CreateRule(ctx, dup, bpAudit(org, owner, dup, "create")); !errors.Is(err, gitprotect.ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE resource_id=$1`, dup.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed create left an audit row: %d %v", n, err)
	}
	// same pattern in another project is fine
	other := bpRule(p2, "main")
	if err := r.CreateRule(ctx, other, bpAudit(org, owner, other, "create")); err != nil {
		t.Fatal(err)
	}

	// list: oldest first, per project
	list, err := r.ListRules(ctx, p1)
	if err != nil || len(list) != 2 || list[0].Pattern != "main" || list[1].Pattern != "release/*" {
		t.Fatalf("list: %+v %v", list, err)
	}
	// a rule of another project is invisible
	if _, err := r.GetRule(ctx, p2, a.ID); !errors.Is(err, gitprotect.ErrNotFound) {
		t.Fatalf("cross-project get: %v", err)
	}

	// update
	a.Pattern, a.RequiredApprovals, a.EnforceForAdmins = "main-2", 0, false
	if err := r.UpdateRule(ctx, a, bpAudit(org, owner, a, "update")); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetRule(ctx, p1, a.ID)
	if got.Pattern != "main-2" || got.RequiredApprovals != 0 || got.EnforceForAdmins || !got.UpdatedAt.After(got.CreatedAt.Add(-time.Second)) {
		t.Fatalf("after update: %+v", got)
	}
	a.Pattern = "release/*"
	if err := r.UpdateRule(ctx, a, bpAudit(org, owner, a, "update")); !errors.Is(err, gitprotect.ErrDuplicate) {
		t.Fatalf("update to duplicate: %v", err)
	}
	ghost := bpRule(p1, "ghost")
	if err := r.UpdateRule(ctx, ghost, bpAudit(org, owner, ghost, "update")); !errors.Is(err, gitprotect.ErrNotFound) {
		t.Fatalf("update of unknown rule: %v", err)
	}
	wrongProject := *a
	wrongProject.ProjectID, wrongProject.Pattern = p2, "zzz"
	if err := r.UpdateRule(ctx, &wrongProject, bpAudit(org, owner, &wrongProject, "update")); !errors.Is(err, gitprotect.ErrNotFound) {
		t.Fatalf("cross-project update: %v", err)
	}

	// CHECK constraint on approvals
	bad := bpRule(p1, "toomany")
	bad.RequiredApprovals = 11
	if err := r.CreateRule(ctx, bad, bpAudit(org, owner, bad, "create")); err == nil {
		t.Fatal("11 approvals must violate the CHECK constraint")
	}

	// sync state upsert round trip
	now := time.Now().UTC().Truncate(time.Microsecond)
	st := gitprotect.SyncState{RuleID: a.ID, ProjectID: p1, Status: "error", ForgejoRuleName: "main", StaleRuleNames: []string{"old-a", "old-b"},
		SpecHash: "abc", Attempts: 3, LastError: "UPSTREAM_GIT_ERROR: boom", LastSyncedAt: &now, LastDriftAt: &now, DriftCount: 2}
	if err := r.PutSync(ctx, st); err != nil {
		t.Fatal(err)
	}
	st.Status, st.LastError, st.StaleRuleNames = "synced", "", nil
	if err := r.PutSync(ctx, st); err != nil {
		t.Fatal(err)
	}
	syncs, _ = r.ListSync(ctx, p1)
	g := syncs[a.ID]
	if g.Status != "synced" || g.ForgejoRuleName != "main" || len(g.StaleRuleNames) != 0 || g.SpecHash != "abc" || g.DriftCount != 2 || g.LastSyncedAt == nil || !g.LastSyncedAt.Equal(now) {
		t.Fatalf("sync round trip: %+v", g)
	}
	if err := r.PutSync(ctx, gitprotect.SyncState{RuleID: uuid.New(), ProjectID: p1, Status: "pending"}); err == nil {
		t.Fatal("a sync row for an unknown rule must violate the foreign key")
	}
	if err := r.PutSync(ctx, gitprotect.SyncState{RuleID: a.ID, ProjectID: p1, Status: "weird"}); err == nil {
		t.Fatal("an unknown status must violate the CHECK constraint")
	}

	// delete cascades the sync row and audits
	if err := r.DeleteRule(ctx, p1, a.ID, bpAudit(org, owner, a, "delete")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetRule(ctx, p1, a.ID); !errors.Is(err, gitprotect.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM branch_protection_sync WHERE rule_id=$1`, a.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("sync row must cascade: %d %v", n, err)
	}
	if err := r.DeleteRule(ctx, p1, a.ID, bpAudit(org, owner, a, "delete")); !errors.Is(err, gitprotect.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE resource_id=$1`, a.ID).Scan(&n); err != nil || n != 3 {
		t.Fatalf("audit rows of the rule (create, update, delete): %d %v", n, err)
	}

	// deleting the user keeps the rule (created_by SET NULL); deleting the project cascades everything
	if _, err := pool.Exec(ctx, `DELETE FROM projects WHERE id=$1`, p2); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM branch_protection_rules WHERE project_id=$1) + (SELECT count(*) FROM branch_protection_sync WHERE project_id=$1)`, p2).Scan(&n); err != nil || n != 0 {
		t.Fatalf("project delete must cascade: %d %v", n, err)
	}
}

func TestBranchProtectionProjectsWithRulesDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewBranchProtectionRepository(pool)
	ctx := context.Background()
	owner := f.user("", time.Now())
	org := f.org(owner)
	ready, pending, noRules, deleted := f.project(org, ""), f.project(org, ""), f.project(org, ""), f.project(org, "")
	for p, status := range map[uuid.UUID]string{ready: "ready", pending: "pending", noRules: "ready", deleted: "ready"} {
		if _, err := pool.Exec(ctx, `INSERT INTO git_core_state (project_id, status) VALUES ($1, $2)`, p, status); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []uuid.UUID{ready, pending, deleted} {
		for _, pat := range []string{"main", "dev"} { // two rules must still list the project once
			x := bpRule(p, pat)
			if err := r.CreateRule(ctx, x, bpAudit(org, owner, x, "create")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE projects SET deleted_at = now() WHERE id=$1`, deleted); err != nil {
		t.Fatal(err)
	}
	ts, err := r.ProjectsWithRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var mine []gitprotect.Target
	for _, x := range ts {
		if x.OrgID == org {
			mine = append(mine, x)
		}
	}
	if len(mine) != 1 || mine[0].ProjectID != ready || mine[0].ProjectSlug == "" || mine[0].OrgSlug == "" {
		t.Fatalf("targets: %+v", mine)
	}
	// WriteAudit
	if err := r.WriteAudit(ctx, gitprotect.AuditEntry{OrgID: org, Action: gitprotect.ActionProtectionDrift, ResourceType: gitprotect.ResourceProtection, ResourceID: ready,
		OldValues: map[string]any{"required_approvals": map[string]any{"forgejo": 0, "desired": 2}}, NewValues: map[string]any{"kind": "modified"}}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='git.protection.drift' AND user_id IS NULL AND old_values->'required_approvals'->>'desired' = '2'`, org).Scan(&n); err != nil || n != 1 {
		t.Fatalf("drift audit row: %d %v", n, err)
	}
}

// The acceptance of A4 against Postgres: CRUD through the service and idempotent projection
// (applying the same rules again, or reconciling, writes nothing to Forgejo and nothing new to
// the database), with the Forgejo side served by A1's fake.
func TestBranchProtectionServiceOnPostgresDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	ctx := context.Background()
	owner := f.user("", time.Now())
	org := f.org(owner)
	project := f.project(org, "")
	if _, err := pool.Exec(ctx, `INSERT INTO git_core_state (project_id, status) VALUES ($1, 'ready')`, project); err != nil {
		t.Fatal(err)
	}
	fs := fake.New()
	t.Cleanup(fs.Close)
	fs.AddRepo("acme", "web")
	core := gitcore.New(gitcore.Config{URL: fs.URL, Token: fake.Token, Timeout: 2 * time.Second, BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond}, nil, nil)
	svc := gitprotect.New(NewBranchProtectionRepository(pool), core, gitprotect.DefaultConfig(), nil)
	tgt := gitprotect.Target{ProjectID: project, OrgID: org, OrgSlug: "acme", ProjectSlug: "web"}
	actor := gitprotect.Actor{UserID: owner, IP: "198.51.100.4"}
	tr := true

	m, err := svc.Create(ctx, tgt, actor, gitprotect.Input{Pattern: "main", RequireSignedCommits: &tr})
	if err != nil || !m.ForgejoSynced {
		t.Fatalf("create main: %+v %v", m, err)
	}
	rel, err := svc.Create(ctx, tgt, actor, gitprotect.Input{Pattern: "release/*", RequiredChecks: []string{"ci/build"}})
	if err != nil || !rel.ForgejoSynced {
		t.Fatalf("create release/*: %+v %v", rel, err)
	}
	// warm-up: the first reconcile legitimately creates the protected-tag rule ("v*"), which
	// Create does not write; only the converged state must be write-free.
	if _, err := svc.ReconcileProject(ctx, tgt); err != nil {
		t.Fatalf("warm-up reconcile: %v", err)
	}
	fs.Reset()
	for i := 0; i < 2; i++ {
		rep, err := svc.ReconcileProject(ctx, tgt)
		if err != nil || rep.Fixed != 0 || rep.Synced != 2 || len(rep.Drifts) != 0 {
			t.Fatalf("reconcile %d: %+v %v", i, rep, err)
		}
	}
	for _, q := range fs.Requests() {
		if q.Method != http.MethodGet {
			t.Fatalf("an idempotent reconcile wrote to Forgejo: %s %s", q.Method, q.Path)
		}
	}

	// drift: someone edits Forgejo; reconcile corrects it and the audit row is in Postgres
	if _, err := core.UpsertProtection(ctx, gitcore.RepoRef{Owner: "acme", Repo: "web"}, gitcore.ProtectionSpec{RuleName: "main", EnablePush: true}); err != nil {
		t.Fatal(err)
	}
	rep, err := svc.ReconcileProject(ctx, tgt)
	if err != nil || len(rep.Drifts) != 1 || rep.Drifts[0].Kind != "modified" || !rep.Drifts[0].Corrected {
		t.Fatalf("drift: %+v %v", rep, err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='git.protection.drift' AND resource_id=$2`, org, m.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("drift audit: %d %v", n, err)
	}
	list, err := svc.List(ctx, tgt)
	if err != nil || len(list) != 2 || list[0].Pattern != "main" || list[0].DriftCount != 1 || !list[0].ForgejoSynced {
		t.Fatalf("list: %+v %v", list, err)
	}

	// replace with rename, then evaluate and delete
	put, err := svc.Replace(ctx, tgt, actor, rel.ID, gitprotect.Input{Pattern: "rel/**"})
	if err != nil || fs.HasProtection("acme", "web", "release/*") || !fs.HasProtection("acme", "web", "rel/**") || !put.ForgejoSynced {
		t.Fatalf("rename: %+v %v", put, err)
	}
	ev, err := svc.Evaluate(ctx, tgt, "rel/1/2")
	if err != nil || ev.Rule == nil || ev.Rule.Pattern != "rel/**" || ev.Forgejo == nil || !ev.Forgejo.InSync {
		t.Fatalf("evaluate: %+v %v", ev, err)
	}
	if _, err := svc.Delete(ctx, tgt, actor, m.ID); err != nil || fs.HasProtection("acme", "web", "main") {
		t.Fatalf("delete: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='git.protection.change' AND user_id=$2`, org, owner).Scan(&n); err != nil || n != 4 {
		t.Fatalf("change audit rows (2 creates, 1 update, 1 delete): %d %v", n, err)
	}
}

func TestBranchProtectionMigrationsDB(t *testing.T) {
	pool := freshDB(t)
	ctx := context.Background()
	applyUpTo(t, pool, 37)
	read := func(name string) string {
		b, err := MigrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	up1, up2 := read("000036_branch_protection_rules.up.sql"), read("000037_branch_protection_sync.up.sql")
	down1, down2 := read("000036_branch_protection_rules.down.sql"), read("000037_branch_protection_sync.down.sql")
	exists := func(tbl string) bool {
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+tbl).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !exists("branch_protection_rules") || !exists("branch_protection_sync") {
		t.Fatal("tables missing after migrating")
	}
	// IF NOT EXISTS: running the up files again must be harmless
	for _, s := range []string{up1, up2} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("re-running up: %v", err)
		}
	}
	// down (reverse order) removes both; down twice is harmless; up recreates them
	for i := 0; i < 2; i++ {
		for _, s := range []string{down2, down1} {
			if _, err := pool.Exec(ctx, s); err != nil {
				t.Fatalf("down: %v", err)
			}
		}
	}
	if exists("branch_protection_rules") || exists("branch_protection_sync") {
		t.Fatal("tables must be gone after down")
	}
	for _, s := range []string{up1, up2} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("up after down: %v", err)
		}
	}
	if !exists("branch_protection_rules") || !exists("branch_protection_sync") {
		t.Fatal("tables missing after up-down-up")
	}
}
