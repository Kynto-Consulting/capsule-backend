//go:build dbtest

package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitcore/fake"
	"github.com/kynto/capsule/backend/internal/gitsync"
)

func TestGitIdentitiesDB(t *testing.T) {
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	r := NewGitIdentityRepository(pool)
	ctx := context.Background()
	now := time.Now().Add(-time.Hour)
	u1, u2 := f.user("", now), f.user("", now)

	if _, err := r.Get(ctx, u1); !errors.Is(err, gitsync.ErrNoIdentity) {
		t.Fatalf("missing: %v", err)
	}
	a, err := r.Ensure(ctx, u1, "ana")
	if err != nil || a.ForgejoUsername != "ana" || a.LinkedAt != nil || a.ForgejoUserID != nil {
		t.Fatalf("ensure: %+v %v", a, err)
	}
	// Ensure never changes the stored login
	b, err := r.Ensure(ctx, u1, "other")
	if err != nil || b.ForgejoUsername != "ana" {
		t.Fatalf("ensure again: %+v %v", b, err)
	}
	// logins are unique case-insensitively across users
	if _, err := r.Ensure(ctx, u2, "ANA"); !errors.Is(err, gitsync.ErrUsernameTaken) {
		t.Fatalf("collision: %v", err)
	}
	// MarkLinked without id, then with id; linked_at keeps the first time
	if err := r.MarkLinked(ctx, u1, 0); err != nil {
		t.Fatal(err)
	}
	g1, _ := r.Get(ctx, u1)
	if g1.LinkedAt == nil || g1.ForgejoUserID != nil {
		t.Fatalf("linked: %+v", g1)
	}
	if err := r.MarkLinked(ctx, u1, 42); err != nil {
		t.Fatal(err)
	}
	g2, _ := r.Get(ctx, u1)
	if g2.ForgejoUserID == nil || *g2.ForgejoUserID != 42 || !g2.LinkedAt.Equal(*g1.LinkedAt) {
		t.Fatalf("linked with id: %+v", g2)
	}
	// the forgejo id is unique too
	if _, err := r.Ensure(ctx, u2, "bea"); err != nil {
		t.Fatal(err)
	}
	if err := r.MarkLinked(ctx, u2, 42); err == nil {
		t.Fatal("two users must not share a forgejo id")
	}
	// deleting the user deletes the identity
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, u2); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, u2); !errors.Is(err, gitsync.ErrNoIdentity) {
		t.Fatalf("cascade: %v", err)
	}
}

func TestGitTeamStateDB(t *testing.T) {
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	r := NewGitTeamStateRepository(pool)
	ctx := context.Background()
	owner := f.user("", time.Now())
	org := f.org(owner)
	p := f.project(org, "")
	at := time.Now().Truncate(time.Microsecond)

	st := gitsync.TeamState{ProjectID: p, Role: authz.RoleAdmin, TeamID: 7, TeamName: "x-admin", Permission: "write", Members: 2, LastSyncedAt: at}
	if err := r.PutTeamState(ctx, st, false); err != nil {
		t.Fatal(err)
	}
	st.Members, st.LastDriftAdded, st.LastDriftRemoved = 3, 1, 2
	if err := r.PutTeamState(ctx, st, true); err != nil {
		t.Fatal(err)
	}
	st.Members, st.LastDriftAdded, st.LastDriftRemoved = 3, 0, 0
	if err := r.PutTeamState(ctx, st, false); err != nil { // a clean pass keeps the drift history
		t.Fatal(err)
	}
	got, err := r.ListTeamStates(ctx, p)
	if err != nil || len(got) != 1 {
		t.Fatalf("list: %+v %v", got, err)
	}
	g := got[0]
	if g.Role != authz.RoleAdmin || g.TeamID != 7 || g.Members != 3 || g.DriftEvents != 1 || g.LastDriftAdded != 1 || g.LastDriftRemoved != 2 || g.LastDriftAt == nil {
		t.Fatalf("state: %+v", g)
	}
	bad := gitsync.TeamState{ProjectID: p, Role: "root", TeamID: 1, TeamName: "n", Permission: "read", LastSyncedAt: at}
	if err := r.PutTeamState(ctx, bad, false); err == nil {
		t.Fatal("invalid role must be rejected by the CHECK constraint")
	}

	// audit without a user
	if err := r.AuditDrift(ctx, org, p, "git.team_drift", map[string]any{"added": []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'git.team_drift' AND user_id IS NULL AND resource_id = $1`, p).Scan(&n); err != nil || n != 1 {
		t.Fatalf("audit rows: %d %v", n, err)
	}
}

func TestListForgejoProjectsDB(t *testing.T) {
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	r := NewGitTeamStateRepository(pool)
	ctx := context.Background()
	org := f.org(f.user("", time.Now()))
	var want []uuid.UUID
	for i := 0; i < 5; i++ {
		p := f.project(org, "")
		prov := "forgejo"
		if i == 3 {
			prov = "github"
		}
		if _, err := pool.Exec(ctx, `INSERT INTO project_git (project_id, provider, repo_url) VALUES ($1, $2, 'https://git.x/o/r.git')`, p, prov); err != nil {
			t.Fatal(err)
		}
		if i == 4 { // soft-deleted
			if _, err := pool.Exec(ctx, `UPDATE projects SET deleted_at = now() WHERE id = $1`, p); err != nil {
				t.Fatal(err)
			}
		} else if prov == "forgejo" {
			want = append(want, p)
		}
	}
	var all []uuid.UUID
	after := uuid.Nil
	for {
		page, err := r.ListForgejoProjects(ctx, after, 2) // pages of 2
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, page...)
		if len(page) < 2 {
			break
		}
		after = page[len(page)-1]
	}
	if len(all) != len(want) {
		t.Fatalf("got %d projects, want %d", len(all), len(want))
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range all {
		seen[id] = true
	}
	for _, id := range want {
		if !seen[id] {
			t.Errorf("missing %s", id)
		}
	}
}

// The real repositories under the reconciler (the same objects main wires), against the fake Forgejo.
func TestReconcileAgainstPostgresIsIdempotent(t *testing.T) {
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	ctx := context.Background()
	now := time.Now().Add(-time.Hour)

	owner := f.user("owner@x.io", now)
	member := f.user("mem@x.io", now)
	viewerU := f.user("view@x.io", now)
	ghost := f.user("ghost@x.io", now) // never logged into Forgejo
	ro := f.user("ro@x.io", now)       // readonly, restricted mode, no row: hidden
	org := f.org(owner)
	f.member(org, owner, "owner")
	f.member(org, member, "member")
	f.member(org, viewerU, "member")
	f.member(org, ghost, "member")
	f.member(org, ro, "readonly")
	p := f.project(org, "api")
	if _, err := pool.Exec(ctx, `UPDATE organizations SET slug = 'acme' WHERE id = $1`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_git (project_id, provider, repo_url) VALUES ($1, 'forgejo', 'https://git.x/acme/api.git')`, p); err != nil {
		t.Fatal(err)
	}
	members := NewProjectMemberRepository(pool)
	if err := members.SetOrgAccessMode(ctx, org, "restricted"); err != nil {
		t.Fatal(err)
	}
	for u, role := range map[uuid.UUID]string{viewerU: "viewer", member: "deployer", ghost: "deployer"} {
		if err := members.UpsertMember(ctx, p, u, role, owner); err != nil {
			t.Fatal(err)
		}
	}

	fs := fake.New()
	t.Cleanup(fs.Close)
	fs.AddRepo("acme", "api") // the repo named by project_git.repo_url; the team-repo grants need it
	svc := gitcore.New(gitcore.Config{URL: fs.URL, Token: fake.Token, Timeout: 2 * time.Second}, nil, nil)
	for _, l := range []string{"owner", "mem", "view", "ro"} {
		fs.AddUser(l)
	}
	rec := &gitsync.Reconciler{
		Forge: svc,
		Dir: gitsync.DomainDirectory{Projects: NewProjectRepository(pool), Orgs: NewOrgRepository(pool),
			Git: NewGitRepository(pool, "test-secret-key"), Roles: members},
		IDs:     &gitsync.Identities{Store: NewGitIdentityRepository(pool), Taken: NewOIDCRepository(pool).UsernameTaken},
		States:  NewGitTeamStateRepository(pool),
		Pending: NewGitCoreRepository(pool),
	}

	rep, err := rec.Reconcile(ctx, p, gitsync.TriggerEvent)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Added) != 3 || len(rep.Pending) != 1 || rep.Pending[0] != ghost {
		t.Fatalf("first pass: %+v", rep)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM git_team_sync WHERE project_id = $1 AND user_id = $2`, p, ghost).Scan(&n); err != nil || n != 1 {
		t.Fatalf("pending queue: %d %v", n, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM git_identities WHERE linked_at IS NOT NULL`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("linked identities: %d %v", n, err)
	}
	// the hidden readonly user is in no team
	for _, tn := range []string{"api-admin", "api-deployer", "api-viewer"} {
		team, err := svc.EnsureTeam(ctx, "acme", gitcore.TeamSpec{Name: tn, Permission: "write"})
		if err != nil {
			t.Fatal(err)
		}
		ms, _ := svc.TeamMembers(ctx, team.ID)
		for _, m := range ms {
			if m == "ro" {
				t.Errorf("hidden readonly user is in %s", tn)
			}
		}
	}

	// idempotent, and the ghost joins after its first login
	rep, err = rec.Reconcile(ctx, p, gitsync.TriggerPeriodic)
	if err != nil || len(rep.Added)+len(rep.Removed) != 0 || rep.Drift {
		t.Fatalf("second pass: %+v %v", rep, err)
	}
	fs.AddUser("ghost")
	rep, err = rec.Reconcile(ctx, p, gitsync.TriggerEvent)
	if err != nil || len(rep.Added) != 1 || len(rep.Pending) != 0 {
		t.Fatalf("after first login: %+v %v", rep, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM git_team_sync WHERE project_id = $1`, p).Scan(&n); err != nil || n != 0 {
		t.Fatalf("pending queue not cleared: %d %v", n, err)
	}

	// removing the role removes the user from the team (restricted mode, row deleted)
	if _, err := members.RemoveMember(ctx, p, member); err != nil {
		t.Fatal(err)
	}
	rep, err = rec.Reconcile(ctx, p, gitsync.TriggerEvent)
	if err != nil || len(rep.Removed) != 1 || rep.Removed[0] != "mem" {
		t.Fatalf("after removing the role: %+v %v", rep, err)
	}

	// whole-platform pass over the real project listing
	sum, err := rec.ReconcileAll(ctx, gitsync.TriggerManual)
	if err != nil || sum.Projects != 1 || sum.Failed != 0 {
		t.Fatalf("reconcile all: %+v %v", sum, err)
	}
}
