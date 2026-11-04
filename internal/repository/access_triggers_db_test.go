//go:build dbtest

package repository

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func epochOf(t *testing.T, pool *pgxpool.Pool, org uuid.UUID) int {
	return qInt(t, pool, `SELECT access_epoch FROM organizations WHERE id=$1`, org)
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func pgCode(err error) string {
	if pe, ok := err.(*pgconn.PgError); ok {
		return pe.Code
	}
	return ""
}

type tfx struct {
	pool            *pgxpool.Pool
	f               *fx
	owner, org      uuid.UUID
	user, p1        uuid.UUID
	viewerTpl, depl uuid.UUID
}

func newTfx(t *testing.T) *tfx {
	pool := accessDB(t)
	f := newFx(t, pool)
	x := &tfx{pool: pool, f: f}
	x.owner = f.user("", timeNow())
	x.org = f.org(x.owner)
	f.member(x.org, x.owner, "owner")
	x.user = f.user("", timeNow())
	f.member(x.org, x.user, "member")
	x.p1 = f.project(x.org, "p1")
	x.viewerTpl, x.depl = SystemTemplateID("project", "viewer"), SystemTemplateID("project", "deployer")
	return x
}

// liveLegacy returns slug of the single live mirrored assignment of (user, project), "" if none.
func (x *tfx) liveLegacy(t *testing.T, user, project uuid.UUID) string {
	t.Helper()
	rows, err := x.pool.Query(context.Background(), `
		SELECT t.slug FROM access_assignments a JOIN role_templates t ON t.id=a.template_id
		 WHERE a.subject_type='user' AND a.subject_id=$1 AND a.scope_type='project' AND a.scope_id=$2 AND a.revoked_at IS NULL`, user, project)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	if len(out) > 1 {
		t.Fatalf("more than one live assignment: %v", out)
	}
	if len(out) == 0 {
		return ""
	}
	return out[0]
}

func TestTriggerProjectMembersToAssignments(t *testing.T) {
	x := newTfx(t)
	e0 := epochOf(t, x.pool, x.org)
	mustExec(t, x.pool, `INSERT INTO project_members (project_id,user_id,role,created_by) VALUES ($1,$2,'viewer',$3)`, x.p1, x.user, x.owner)
	if got := x.liveLegacy(t, x.user, x.p1); got != "viewer" {
		t.Fatalf("after insert: assignment %q, want viewer", got)
	}
	if src := qStr(t, x.pool, `SELECT source FROM access_assignments WHERE subject_id=$1 AND revoked_at IS NULL`, x.user); src != "legacy-api" {
		t.Errorf("source = %s", src)
	}
	if by := qStr(t, x.pool, `SELECT created_by::text FROM access_assignments WHERE subject_id=$1 AND revoked_at IS NULL`, x.user); by != x.owner.String() {
		t.Errorf("created_by not copied: %s", by)
	}
	e1 := epochOf(t, x.pool, x.org)
	if e1 <= e0 {
		t.Errorf("epoch did not increase on legacy write: %d -> %d", e0, e1)
	}
	// role change replaces the assignment (the old one is revoked, one live row)
	mustExec(t, x.pool, `UPDATE project_members SET role='deployer' WHERE project_id=$1 AND user_id=$2`, x.p1, x.user)
	if got := x.liveLegacy(t, x.user, x.p1); got != "deployer" {
		t.Fatalf("after update: %q, want deployer", got)
	}
	if n := qInt(t, x.pool, `SELECT count(*) FROM access_assignments WHERE subject_id=$1 AND revoked_at IS NOT NULL`, x.user); n != 1 {
		t.Errorf("revoked tombstones = %d, want 1", n)
	}
	// same role upsert (ON CONFLICT DO UPDATE with equal value) does not duplicate
	mustExec(t, x.pool, `UPDATE project_members SET role='deployer' WHERE project_id=$1 AND user_id=$2`, x.p1, x.user)
	if n := qInt(t, x.pool, `SELECT count(*) FROM access_assignments WHERE subject_id=$1 AND revoked_at IS NULL`, x.user); n != 1 {
		t.Errorf("duplicate live assignments: %d", n)
	}
	mustExec(t, x.pool, `DELETE FROM project_members WHERE project_id=$1 AND user_id=$2`, x.p1, x.user)
	if got := x.liveLegacy(t, x.user, x.p1); got != "" {
		t.Errorf("after delete: live %q, want none", got)
	}
	if epochOf(t, x.pool, x.org) <= e1 {
		t.Errorf("epoch did not increase on delete")
	}
}

func TestTriggerAssignmentsToProjectMembers(t *testing.T) {
	x := newTfx(t)
	// a legacy-api assignment appears in project_members
	mustExec(t, x.pool, `INSERT INTO access_assignments (org_id,subject_type,subject_id,scope_type,scope_id,template_id,source,created_by)
		VALUES ($1,'user',$2,'project',$3,$4,'legacy-api',$5)`, x.org, x.user, x.p1, x.viewerTpl, x.owner)
	if got := qStr(t, x.pool, `SELECT role FROM project_members WHERE project_id=$1 AND user_id=$2`, x.p1, x.user); got != "viewer" {
		t.Fatalf("project_members role = %q", got)
	}
	// revoking removes it
	mustExec(t, x.pool, `UPDATE access_assignments SET revoked_at=now() WHERE subject_id=$1`, x.user)
	if n := qInt(t, x.pool, `SELECT count(*) FROM project_members WHERE user_id=$1`, x.user); n != 0 {
		t.Errorf("project_members row survived revoke")
	}
	// manual assignments and group/expiring shapes the legacy table cannot express are NOT mirrored
	mustExec(t, x.pool, `INSERT INTO access_assignments (org_id,subject_type,subject_id,scope_type,scope_id,template_id,source) VALUES ($1,'user',$2,'project',$3,$4,'manual')`,
		x.org, x.user, x.p1, x.depl)
	if n := qInt(t, x.pool, `SELECT count(*) FROM project_members WHERE user_id=$1`, x.user); n != 0 {
		t.Errorf("manual assignment leaked into project_members")
	}
	var grp uuid.UUID
	if err := x.pool.QueryRow(context.Background(), `INSERT INTO groups (org_id,slug,name) VALUES ($1,'g','G') RETURNING id`, x.org).Scan(&grp); err != nil {
		t.Fatal(err)
	}
	mustExec(t, x.pool, `INSERT INTO access_assignments (org_id,subject_type,subject_id,scope_type,scope_id,template_id,source) VALUES ($1,'group',$2,'project',$3,$4,'legacy-api')`,
		x.org, grp, x.p1, x.depl)
	if n := qInt(t, x.pool, `SELECT count(*) FROM project_members`); n != 0 {
		t.Errorf("group assignment leaked into project_members")
	}
	// hard delete of the assignment also mirrors
	mustExec(t, x.pool, `INSERT INTO access_assignments (org_id,subject_type,subject_id,scope_type,scope_id,template_id,source) VALUES ($1,'user',$2,'project',$3,$4,'legacy-api')`,
		x.org, x.user, x.p1, x.viewerTpl)
	if n := qInt(t, x.pool, `SELECT count(*) FROM project_members WHERE user_id=$1 AND role='viewer'`, x.user); n != 1 {
		t.Fatalf("expected mirrored viewer row")
	}
	mustExec(t, x.pool, `DELETE FROM access_assignments WHERE subject_id=$1 AND source='legacy-api'`, x.user)
	if n := qInt(t, x.pool, `SELECT count(*) FROM project_members WHERE user_id=$1`, x.user); n != 0 {
		t.Errorf("project_members survived assignment delete")
	}
}

// The probe triggers log every write to both tables with its nesting depth: one legacy write must produce exactly the original
// write plus ONE mirror write, and nothing after that (no ping-pong), in both directions.
func TestTriggersDoNotLoop(t *testing.T) {
	x := newTfx(t)
	ctx := context.Background()
	mustExec(t, x.pool, `CREATE TABLE probe (id bigserial PRIMARY KEY, tbl text, op text, depth int)`)
	mustExec(t, x.pool, `CREATE FUNCTION probe_fn() RETURNS trigger AS $$ BEGIN INSERT INTO probe(tbl,op,depth) VALUES (TG_TABLE_NAME, TG_OP, pg_trigger_depth()); RETURN NULL; END $$ LANGUAGE plpgsql`)
	for _, tbl := range []string{"project_members", "access_assignments", "org_members", "users"} {
		mustExec(t, x.pool, `CREATE TRIGGER zz_probe AFTER INSERT OR UPDATE OR DELETE ON `+tbl+` FOR EACH ROW EXECUTE FUNCTION probe_fn()`)
	}
	writes := func(tbl string) int { return qInt(t, x.pool, `SELECT count(*) FROM probe WHERE tbl=$1`, tbl) }
	reset := func() { mustExec(t, x.pool, `TRUNCATE probe`) }

	mustExec(t, x.pool, `INSERT INTO project_members (project_id,user_id,role,created_by) VALUES ($1,$2,'viewer',$3)`, x.p1, x.user, x.owner)
	if pm, a := writes("project_members"), writes("access_assignments"); pm != 1 || a != 1 {
		t.Errorf("project_members insert: %d pm writes, %d assignment writes; want 1 and 1", pm, a)
	}
	reset()
	mustExec(t, x.pool, `UPDATE project_members SET role='admin' WHERE project_id=$1 AND user_id=$2`, x.p1, x.user)
	// update: 1 pm write; mirror = 1 revoke (UPDATE) + 1 insert
	if pm, a := writes("project_members"), writes("access_assignments"); pm != 1 || a != 2 {
		t.Errorf("project_members update: %d pm writes, %d assignment writes; want 1 and 2", pm, a)
	}
	reset()
	mustExec(t, x.pool, `INSERT INTO access_assignments (org_id,subject_type,subject_id,scope_type,scope_id,template_id,source)
		VALUES ($1,'user',$2,'project',$3,$4,'legacy-api')`, x.org, x.owner, x.p1, x.depl)
	if pm, a := writes("project_members"), writes("access_assignments"); pm != 1 || a != 1 {
		t.Errorf("assignment insert: %d pm writes, %d assignment writes; want 1 and 1", pm, a)
	}
	reset()
	mustExec(t, x.pool, `UPDATE users SET role='suspended' WHERE id=$1`, x.user)
	if u := writes("users"); u != 1 {
		t.Errorf("users update wrote %d rows, want 1", u)
	}
	reset()
	mustExec(t, x.pool, `UPDATE org_members SET role='admin' WHERE org_id=$1 AND user_id=$2`, x.org, x.user)
	if om := writes("org_members"); om != 1 {
		t.Errorf("org_members update wrote %d rows, want 1", om)
	}
	// the probe saw every nested write at depth > 1 for mirrors and never an unbounded chain
	if n := qInt(t, x.pool, `SELECT coalesce(max(depth),0) FROM probe`); n > 3 {
		t.Errorf("max trigger depth %d", n)
	}
	_ = ctx

	// hard delete of a project (FK cascade -> nested triggers) leaves no assignments behind and does not error
	p2 := x.f.project(x.org, "p2")
	mustExec(t, x.pool, `INSERT INTO project_members (project_id,user_id,role) VALUES ($1,$2,'viewer')`, p2, x.user)
	mustExec(t, x.pool, `DELETE FROM projects WHERE id=$1`, p2)
	if n := qInt(t, x.pool, `SELECT count(*) FROM access_assignments WHERE scope_id=$1`, p2); n != 0 {
		t.Errorf("assignments of a deleted project survived: %d", n)
	}
	// deleting a user cascades org_members/project_members and leaves no assignments
	mustExec(t, x.pool, `DELETE FROM users WHERE id=$1`, x.user)
	if n := qInt(t, x.pool, `SELECT count(*) FROM access_assignments WHERE subject_id=$1`, x.user); n != 0 {
		t.Errorf("assignments of a deleted user survived: %d", n)
	}
}

func TestTriggerOrgMemberRoleTemplate(t *testing.T) {
	x := newTfx(t)
	tpl := func(user uuid.UUID) string {
		return qStr(t, x.pool, `SELECT coalesce((SELECT slug FROM role_templates WHERE id=om.template_id),'<null>') FROM org_members om WHERE org_id=$1 AND user_id=$2`, x.org, user)
	}
	role := func(user uuid.UUID) string {
		return qStr(t, x.pool, `SELECT role FROM org_members WHERE org_id=$1 AND user_id=$2`, x.org, user)
	}
	if tpl(x.user) != "member" || tpl(x.owner) != "owner" {
		t.Fatalf("insert did not link templates: %s %s", tpl(x.user), tpl(x.owner))
	}
	e := epochOf(t, x.pool, x.org)
	mustExec(t, x.pool, `UPDATE org_members SET role='readonly' WHERE org_id=$1 AND user_id=$2`, x.org, x.user)
	if tpl(x.user) != "readonly" {
		t.Errorf("role->template: %s", tpl(x.user))
	}
	if epochOf(t, x.pool, x.org) <= e {
		t.Errorf("epoch not bumped by role change")
	}
	// template -> role for system templates
	mustExec(t, x.pool, `UPDATE org_members SET template_id=$3 WHERE org_id=$1 AND user_id=$2`, x.org, x.user, SystemTemplateID("org", "admin"))
	if role(x.user) != "admin" {
		t.Errorf("template->role: %s", role(x.user))
	}
	// unknown role closes (template NULL) and keeps the label
	mustExec(t, x.pool, `UPDATE org_members SET role='godmode' WHERE org_id=$1 AND user_id=$2`, x.org, x.user)
	if tpl(x.user) != "<null>" || role(x.user) != "godmode" {
		t.Errorf("unknown role: tpl=%s role=%s", tpl(x.user), role(x.user))
	}
	// project template is not a valid organization template
	_, err := x.pool.Exec(context.Background(), `UPDATE org_members SET template_id=$3 WHERE org_id=$1 AND user_id=$2`, x.org, x.user, x.depl)
	if pgCode(err) != "23514" {
		t.Errorf("project template as org template: %v", err)
	}
	// custom template: both fields given by the writer are kept; later legacy role writes replace the custom template
	store := NewAccessStore(x.pool)
	ct, err := store.CreateTemplate(context.Background(), x.org, NewTemplate{Kind: "org", Slug: "support", Name: "Support", Permissions: []string{"org:read", "member:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetOrgTemplate(context.Background(), x.org, x.user, ct.ID, nil, "member"); err != nil {
		t.Fatal(err)
	}
	if tpl(x.user) != "support" || role(x.user) != "member" {
		t.Errorf("custom template: tpl=%s role=%s", tpl(x.user), role(x.user))
	}
	mustExec(t, x.pool, `UPDATE org_members SET role='admin' WHERE org_id=$1 AND user_id=$2`, x.org, x.user)
	if tpl(x.user) != "admin" {
		t.Errorf("legacy role write must replace custom template: %s", tpl(x.user))
	}
	// insert with unknown role
	u2 := x.f.user("", timeNow())
	x.f.member(x.org, u2, "bogus")
	if tpl(u2) != "<null>" {
		t.Errorf("insert with unknown role: %s", tpl(u2))
	}
}

func TestTriggerUsersRoleStatus(t *testing.T) {
	x := newTfx(t)
	get := func(id uuid.UUID) (role, status, plat string, epoch int) {
		if err := x.pool.QueryRow(context.Background(), `SELECT role,status,platform_role,access_epoch FROM users WHERE id=$1`, id).Scan(&role, &status, &plat, &epoch); err != nil {
			t.Fatal(err)
		}
		return
	}
	u := x.user
	_, _, _, e0 := get(u)
	mustExec(t, x.pool, `UPDATE users SET role='suspended' WHERE id=$1`, u)
	if r, s, p, e := get(u); r != "suspended" || s != "suspended" || p != "user" || e <= e0 {
		t.Errorf("suspend via role: %s %s %s epoch %d->%d", r, s, p, e0, e)
	}
	mustExec(t, x.pool, `UPDATE users SET role='member' WHERE id=$1`, u) // legacy unsuspend
	if r, s, p, _ := get(u); r != "member" || s != "active" || p != "user" {
		t.Errorf("unsuspend via role: %s %s %s", r, s, p)
	}
	mustExec(t, x.pool, `UPDATE users SET role='admin' WHERE id=$1`, u)
	if r, s, p, _ := get(u); r != "admin" || s != "active" || p != "admin" {
		t.Errorf("admin via role: %s %s %s", r, s, p)
	}
	// new columns drive the legacy role
	mustExec(t, x.pool, `UPDATE users SET status='suspended' WHERE id=$1`, u)
	if r, s, p, _ := get(u); r != "suspended" || s != "suspended" || p != "admin" {
		t.Errorf("suspend via status keeps platform_role: %s %s %s", r, s, p)
	}
	mustExec(t, x.pool, `UPDATE users SET status='active' WHERE id=$1`, u)
	if r, _, p, _ := get(u); r != "admin" || p != "admin" {
		t.Errorf("reactivate restores admin label: %s %s", r, p)
	}
	mustExec(t, x.pool, `UPDATE users SET platform_role='user' WHERE id=$1`, u)
	if r, _, _, _ := get(u); r != "member" {
		t.Errorf("platform_role user -> role %s", r)
	}
	// unknown legacy role: not admin, not suspended, recorded as anomaly
	mustExec(t, x.pool, `UPDATE users SET role='weird' WHERE id=$1`, u)
	if r, s, p, _ := get(u); r != "weird" || s != "active" || p != "user" {
		t.Errorf("unknown role: %s %s %s", r, s, p)
	}
	if n := qInt(t, x.pool, `SELECT count(*) FROM access_anomalies WHERE kind='users.role.unknown' AND user_id=$1`, u); n != 1 {
		t.Errorf("anomaly rows = %d", n)
	}
	// inserts
	var a, s2, w uuid.UUID
	for _, c := range []struct {
		role string
		id   *uuid.UUID
	}{{"admin", &a}, {"suspended", &s2}, {"hacker", &w}} {
		if err := x.pool.QueryRow(context.Background(), `INSERT INTO users (email,password_hash,name,role) VALUES ($1,'x','n',$2) RETURNING id`, uuid.NewString()+"@x.io", c.role).Scan(c.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, s, p, _ := get(a); s != "active" || p != "admin" {
		t.Errorf("insert admin: %s %s", s, p)
	}
	if _, s, p, _ := get(s2); s != "suspended" || p != "user" {
		t.Errorf("insert suspended: %s %s", s, p)
	}
	if _, s, p, _ := get(w); s != "active" || p != "user" {
		t.Errorf("insert unknown: %s %s", s, p)
	}
	// new code inserting the new columns directly
	var n uuid.UUID
	if err := x.pool.QueryRow(context.Background(), `INSERT INTO users (email,password_hash,name,status,platform_role) VALUES ($1,'x','n','suspended','admin') RETURNING id`, uuid.NewString()+"@x.io").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if r, s, p, _ := get(n); r != "suspended" || s != "suspended" || p != "admin" {
		t.Errorf("insert with new columns: %s %s %s", r, s, p)
	}
	// constraints
	_, err := x.pool.Exec(context.Background(), `UPDATE users SET status='nope' WHERE id=$1`, u)
	if pgCode(err) != "23514" {
		t.Errorf("status CHECK: %v", err)
	}
}

func TestTemplateImmutability(t *testing.T) {
	x := newTfx(t)
	ctx := context.Background()
	sys := SystemTemplateID("project", "viewer")
	for _, q := range []string{
		`UPDATE role_template_versions SET permissions='{}' WHERE template_id=$1`,
		`DELETE FROM role_template_versions WHERE template_id=$1`,
		`UPDATE role_templates SET name='x' WHERE id=$1 AND false OR id=$1 AND name='never'`, // no row: must not error
	} {
		_, err := x.pool.Exec(ctx, q, sys)
		if strings.Contains(q, "never") {
			if err != nil {
				t.Errorf("no-op update errored: %v", err)
			}
			continue
		}
		if pgCode(err) != "23001" {
			t.Errorf("%s: expected restrict_violation, got %v", q, err)
		}
	}
	for _, q := range []string{
		`DELETE FROM role_templates WHERE id=$1`,
		`UPDATE role_templates SET slug='hacked' WHERE id=$1`,
		`UPDATE role_templates SET archived_at=now() WHERE id=$1`,
	} {
		if _, err := x.pool.Exec(ctx, q, sys); pgCode(err) != "23001" {
			t.Errorf("%s: expected restrict_violation, got %v", q, err)
		}
	}
	// system rows must stay org-less and custom ones org-bound
	if _, err := x.pool.Exec(ctx, `INSERT INTO role_templates (org_id,kind,slug,name,system) VALUES ($1,'project','xx','x',true)`, x.org); pgCode(err) != "23514" {
		t.Errorf("system with org: %v", err)
	}
	// a custom template's versions are immutable too, but deleting the organization cascades cleanly
	store := NewAccessStore(x.pool)
	ct, err := store.CreateTemplate(ctx, x.org, NewTemplate{Kind: "project", Slug: "ops", Name: "Ops", Permissions: []string{"project:view", "project:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.pool.Exec(ctx, `UPDATE role_template_versions SET note='x' WHERE template_id=$1`, ct.ID); pgCode(err) != "23001" {
		t.Errorf("custom version update: %v", err)
	}
	if _, err := x.pool.Exec(ctx, `DELETE FROM role_template_versions WHERE template_id=$1`, ct.ID); pgCode(err) != "23001" {
		t.Errorf("custom version delete: %v", err)
	}
	if _, err := store.PublishVersion(ctx, x.org, ct.ID, NewTemplateVersion{Permissions: []string{"project:view"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: x.user, ScopeType: "project", ScopeID: x.p1, TemplateID: ct.ID}); err != nil {
		t.Fatal(err)
	}
	mustExec(t, x.pool, `DELETE FROM org_members WHERE org_id=$1`, x.org)
	mustExec(t, x.pool, `DELETE FROM projects WHERE org_id=$1`, x.org)
	mustExec(t, x.pool, `DELETE FROM organizations WHERE id=$1`, x.org)
	if n := qInt(t, x.pool, `SELECT count(*) FROM role_template_versions WHERE template_id=$1`, ct.ID); n != 0 {
		t.Errorf("versions survived organization delete: %d", n)
	}
	// format constraints
	if _, err := x.pool.Exec(ctx, `INSERT INTO role_template_versions (template_id,version,permissions) VALUES ($1,9,'{Bad Perm}')`, sys); pgCode(err) != "23514" && pgCode(err) != "23001" {
		t.Errorf("perm format: %v", err)
	}
}
