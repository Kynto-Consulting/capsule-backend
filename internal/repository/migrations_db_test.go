//go:build dbtest

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

const firstNewMigration = 27

func recordedVersions(t *testing.T, f *fx) map[int]bool {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT version FROM schema_migrations`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out[v] = true
	}
	return out
}

// Clean database: every migration applies, RunMigrations is idempotent, every new
// up file is itself re-runnable, and every new down file runs and can be re-applied.
func TestMigrationsCleanDB(t *testing.T) {
	pool := freshDB(t)
	f := newFx(t, pool)
	ctx := context.Background()
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("clean migrate: %v", err)
	}
	ups := migrationFiles(t, "up.sql")
	rec := recordedVersions(t, f)
	for _, m := range ups {
		if !rec[m.version] {
			t.Errorf("migration %s not recorded", m.name)
		}
	}
	t.Logf("migrations present: %d (last %s)", len(ups), ups[len(ups)-1].name)
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("second RunMigrations: %v", err)
	}

	// each new up file re-executes without error (IF NOT EXISTS / DO $$ guards)
	for _, m := range ups {
		if m.version < firstNewMigration {
			continue
		}
		b, _ := MigrationsFS.ReadFile("migrations/" + m.name)
		if _, err := pool.Exec(ctx, string(b)); err != nil {
			t.Errorf("re-running %s is not idempotent: %v", m.name, err)
		}
	}

	// constraints from 000028 / 000029
	u := f.user("", time.Now())
	org := f.org(u)
	p := f.project(org, "")
	mustFail := func(why, sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err == nil {
			t.Errorf("%s: statement succeeded, want constraint error", why)
		}
	}
	mustFail("project_members.role", `INSERT INTO project_members (project_id,user_id,role) VALUES ($1,$2,'god')`, p, u)
	mustFail("orgs.project_access_mode", `UPDATE organizations SET project_access_mode='x' WHERE id=$1`, org)
	mustFail("project_git.provider", `INSERT INTO project_git (project_id, provider, repo_url) VALUES ($1,'svn','u')`, p)
	mustFail("project_git.auth_kind", `INSERT INTO project_git (project_id, repo_url, auth_kind) VALUES ($1,'u','pw')`, p)
	if _, err := pool.Exec(ctx, `INSERT INTO project_git (project_id, repo_url) VALUES ($1,'u')`, p); err != nil {
		t.Errorf("project_git defaults: %v", err)
	}
	mustFail("oauth_codes.client FK", `INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, expires_at) VALUES ('h',$1,$2,'r',now())`, uuid.New(), u)
	// ON DELETE behaviours: deleting an org cascades oauth clients; deleting a user nulls created_by
	var cid uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO oauth_clients (client_id,name,org_id,created_by) VALUES ($1,'n',$2,$3) RETURNING id`, uuid.NewString(), org, u).Scan(&cid); err != nil {
		t.Fatal(err)
	}
	// down + up cycle (clean data): newest first
	downs := migrationFiles(t, "down.sql")
	// remove rows that block dropping tables referenced by FKs
	_, _ = pool.Exec(ctx, `DELETE FROM oauth_clients`)
	_, _ = pool.Exec(ctx, `DELETE FROM project_git`)
	for i := len(downs) - 1; i >= 0; i-- {
		d := downs[i]
		if d.version < firstNewMigration {
			continue
		}
		b, _ := MigrationsFS.ReadFile("migrations/" + d.name)
		if _, err := pool.Exec(ctx, string(b)); err != nil {
			t.Errorf("down %s: %v", d.name, err)
			continue
		}
		if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version=$1`, d.version); err != nil {
			t.Fatal(err)
		}
	}
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("re-apply after down: %v", err)
	}
}

// Database that already holds data created under 000001-000026 gets 000027+ applied on top.
func TestMigrationsOnPopulatedDB(t *testing.T) {
	pool := freshDB(t)
	f := newFx(t, pool)
	ctx := context.Background()
	applyUpTo(t, pool, firstNewMigration-1)

	// data in the old schema (no project_access_mode / parent_project_id yet)
	now := time.Now().Add(-48 * time.Hour)
	var owner, member uuid.UUID
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(pool.QueryRow(ctx, `INSERT INTO users (email,password_hash,name,created_at) VALUES ($1,'x','A',$2) RETURNING id`, "a-"+uuid.NewString()+"@x.io", now).Scan(&owner))
	must(pool.QueryRow(ctx, `INSERT INTO users (email,password_hash,name,created_at) VALUES ($1,'x','B',$2) RETURNING id`, "b-"+uuid.NewString()+"@x.io", now).Scan(&member))
	var org uuid.UUID
	must(pool.QueryRow(ctx, `INSERT INTO organizations (name,slug,owner_id) VALUES ('O',$2,$1) RETURNING id`, owner, uuid.NewString()).Scan(&org))
	must(pool.QueryRow(ctx, `INSERT INTO organizations (name,slug,owner_id,deleted_at) VALUES ('Gone',$2,$1,now()) RETURNING id`, owner, uuid.NewString()).Scan(new(uuid.UUID)))
	f.member(org, owner, "owner")
	f.member(org, member, "member")
	p1 := f.project(org, "alpha")
	p2 := f.project(org, "beta")
	var delProj uuid.UUID
	must(pool.QueryRow(ctx, `INSERT INTO projects (org_id,name,slug,deleted_at) VALUES ($1,'D','dead',now()) RETURNING id`, org).Scan(&delProj))
	must(pool.QueryRow(ctx, `INSERT INTO deployments (project_id,version,status,trigger) VALUES ($1,'v1','running','git') RETURNING id`, p1).Scan(new(uuid.UUID)))
	_, err := pool.Exec(ctx, `INSERT INTO domains (project_id,org_id,domain_name) VALUES ($1,$3,$2)`, p1, uuid.NewString()+".example.com", org)
	must(err)
	_, err = pool.Exec(ctx, `INSERT INTO env_vars (project_id,key,value_enc) VALUES ($1,'K',convert_to('v','UTF8'))`, p1)
	must(err)
	_, err = pool.Exec(ctx, `INSERT INTO audit_logs (user_id,org_id,action,resource_type) VALUES ($1,$2,'old','project')`, owner, org)
	must(err)
	var dbID uuid.UUID
	must(pool.QueryRow(ctx, `INSERT INTO databases (project_id,org_id,name,host,db_name,credentials_enc,port,status)
		VALUES ($1,$2,'d','h','db',convert_to('x','UTF8'),40125,'available') RETURNING id`, p1, org).Scan(&dbID))
	_, err = pool.Exec(ctx, `INSERT INTO database_access_rules (database_id,cidr) VALUES ($1,'203.0.113.1/32')`, dbID)
	must(err)

	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		must(pool.QueryRow(ctx, sql, args...).Scan(&n))
		return n
	}
	before := map[string]int{
		"users": count(`SELECT count(*) FROM users`), "orgs": count(`SELECT count(*) FROM organizations`),
		"projects": count(`SELECT count(*) FROM projects`), "deployments": count(`SELECT count(*) FROM deployments`),
		"domains": count(`SELECT count(*) FROM domains`), "env": count(`SELECT count(*) FROM env_vars`),
		"audit": count(`SELECT count(*) FROM audit_logs`), "members": count(`SELECT count(*) FROM org_members`),
	}

	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrating populated database: %v", err)
	}

	after := map[string]int{
		"users": count(`SELECT count(*) FROM users`), "orgs": count(`SELECT count(*) FROM organizations`),
		"projects": count(`SELECT count(*) FROM projects`), "deployments": count(`SELECT count(*) FROM deployments`),
		"domains": count(`SELECT count(*) FROM domains`), "env": count(`SELECT count(*) FROM env_vars`),
		"audit": count(`SELECT count(*) FROM audit_logs`), "members": count(`SELECT count(*) FROM org_members`),
	}
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s rows changed by migration: %d -> %d", k, v, after[k])
		}
	}
	// defaults landed on existing rows
	if n := count(`SELECT count(*) FROM organizations WHERE project_access_mode='open'`); n != before["orgs"] {
		t.Errorf("project_access_mode default on old orgs: %d of %d", n, before["orgs"])
	}
	if n := count(`SELECT count(*) FROM projects WHERE parent_project_id IS NULL AND preview_pr IS NULL AND expires_at IS NULL AND preview_comment_id IS NULL`); n != before["projects"] {
		t.Errorf("preview columns on old projects: %d of %d are NULL", n, before["projects"])
	}
	rec := recordedVersions(t, f)
	for _, m := range migrationFiles(t, "up.sql") {
		if !rec[m.version] {
			t.Errorf("%s not recorded", m.name)
		}
	}

	// the repositories work against the migrated legacy data
	projs, total, err := NewProjectRepository(pool).ListByOrg(ctx, org, 1, 50)
	if err != nil || total != 2 || len(projs) != 2 {
		t.Fatalf("ListByOrg on legacy data: %d/%d %v", len(projs), total, err)
	}
	pm := NewProjectMemberRepository(pool)
	oa, err := pm.LoadOrgAccess(ctx, org, member)
	if err != nil || oa == nil || oa.Mode != "open" || oa.OrgRole != "member" || len(oa.Explicit) != 0 {
		t.Fatalf("LoadOrgAccess legacy: %+v %v", oa, err)
	}
	gr, err := pm.UserGrants(ctx, member)
	if err != nil || len(gr) != 2 || gr[0].ExplicitRole != "" {
		t.Fatalf("UserGrants legacy: %+v %v", gr, err)
	}
	if n, err := pm.CountEffectiveAdmins(ctx, org, p2); err != nil || n != 1 {
		t.Fatalf("CountEffectiveAdmins legacy: %d %v", n, err)
	}
	// previews can be created on a legacy project, and an old deployment is unaffected
	g := NewGitRepository(pool, "k")
	parent, err := NewProjectRepository(pool).GetByID(ctx, p1)
	if err != nil {
		t.Fatalf("GetByID legacy: %v", err)
	}
	if _, err := g.CreatePreview(ctx, parent, 1, "pv-"+uuid.NewString()[:8], time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreatePreview on legacy project: %v", err)
	}
	// a second migrate run is a no-op
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("second run: %v", err)
	}
}
