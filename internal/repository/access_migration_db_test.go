//go:build dbtest

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	accessFirst = 66
	accessLast  = 71
)

// accessDB returns a fresh, fully migrated and seeded database.
func accessDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := freshDB(t)
	ctx := context.Background()
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	if _, err := SeedSystemTemplates(ctx, pool); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return pool
}

func qInt(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func qStr(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) string {
	t.Helper()
	var s string
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&s); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return s
}

func tableExists(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	return qInt(t, pool, `SELECT count(*) FROM pg_class WHERE relname = $1 AND relkind = 'r'`, name) == 1
}

func columnExists(t *testing.T, pool *pgxpool.Pool, table, col string) bool {
	t.Helper()
	return qInt(t, pool, `SELECT count(*) FROM information_schema.columns WHERE table_name = $1 AND column_name = $2`, table, col) == 1
}

// runDown executes the .down.sql files (newest first) of versions [lo, hi] and forgets them in schema_migrations.
func runDown(t *testing.T, pool *pgxpool.Pool, hi, lo int) {
	t.Helper()
	ctx := context.Background()
	downs := migrationFiles(t, "down.sql")
	for i := len(downs) - 1; i >= 0; i-- {
		d := downs[i]
		if d.version > hi || d.version < lo {
			continue
		}
		b, err := MigrationsFS.ReadFile("migrations/" + d.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(b)); err != nil {
			t.Fatalf("down %s: %v", d.name, err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = $1`, d.version); err != nil {
			t.Fatal(err)
		}
	}
}

// reapplyUp runs the raw .up.sql files of [lo, hi] again, in order, over an already migrated database (idempotence).
func reapplyUp(t *testing.T, pool *pgxpool.Pool, lo, hi int) {
	t.Helper()
	ctx := context.Background()
	for _, m := range migrationFiles(t, "up.sql") {
		if m.version < lo || m.version > hi {
			continue
		}
		b, err := MigrationsFS.ReadFile("migrations/" + m.name)
		if err != nil {
			t.Fatal(err)
		}
		sql := safeAddIfNotExists(string(b), "CREATE TABLE ")
		sql = safeAddIfNotExists(sql, "CREATE UNIQUE INDEX ")
		sql = safeAddIfNotExists(sql, "CREATE INDEX ")
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatalf("re-applying %s: %v", m.name, err)
		}
	}
}

func TestAccessMigrationRangeIsContiguous(t *testing.T) {
	ups := migrationFiles(t, "up.sql")
	downs := migrationFiles(t, "down.sql")
	have := map[int]bool{}
	for _, u := range ups {
		have[u.version] = true
	}
	for v := accessFirst; v <= accessLast; v++ {
		if !have[v] {
			t.Errorf("migration %06d missing", v)
		}
	}
	if len(ups) != len(downs) {
		t.Errorf("%d up vs %d down files", len(ups), len(downs))
	}
}

// up on an empty database, then down (newest first) leaves the old tables intact, then up again, then up twice more.
func TestAccessMigrationsUpDownUpEmptyDB(t *testing.T) {
	pool := freshDB(t)
	ctx := context.Background()
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("up: %v", err)
	}
	for _, tbl := range []string{"role_templates", "role_template_versions", "groups", "group_members", "access_assignments", "invitations", "ownership_transfers", "access_anomalies"} {
		if !tableExists(t, pool, tbl) {
			t.Errorf("table %s missing after up", tbl)
		}
	}
	// seeded identity rows: 4 org + 3 project + 2 repo templates
	if n := qInt(t, pool, `SELECT count(*) FROM role_templates WHERE system`); n != 9 {
		t.Errorf("system templates after up = %d, want 9", n)
	}

	runDown(t, pool, accessLast, accessFirst)
	for _, tbl := range []string{"role_templates", "role_template_versions", "groups", "group_members", "access_assignments", "invitations", "ownership_transfers", "access_anomalies"} {
		if tableExists(t, pool, tbl) {
			t.Errorf("table %s still exists after down", tbl)
		}
	}
	for _, c := range [][2]string{{"users", "status"}, {"users", "platform_role"}, {"users", "access_epoch"}, {"organizations", "access_epoch"},
		{"organizations", "access_settings"}, {"projects", "access_override"}, {"org_members", "template_id"}, {"org_members", "status"},
		{"api_tokens", "permissions"}, {"api_tokens", "org_id"}} {
		if columnExists(t, pool, c[0], c[1]) {
			t.Errorf("column %s.%s still exists after down", c[0], c[1])
		}
	}
	for _, c := range [][2]string{{"users", "role"}, {"org_members", "role"}, {"project_members", "role"}, {"organizations", "project_access_mode"}, {"api_tokens", "scopes"}} {
		if !columnExists(t, pool, c[0], c[1]) {
			t.Errorf("legacy column %s.%s was touched by down", c[0], c[1])
		}
	}
	// down is idempotent
	runDown(t, pool, accessLast, accessFirst)

	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("up after down: %v", err)
	}
	if _, err := SeedSystemTemplates(ctx, pool); err != nil {
		t.Fatal(err)
	}
	reapplyUp(t, pool, accessFirst, accessLast) // idempotent up (twice)
	reapplyUp(t, pool, accessFirst, accessLast)
	if n := qInt(t, pool, `SELECT count(*) FROM role_templates WHERE system`); n != 9 {
		t.Errorf("system templates after re-up = %d, want 9", n)
	}
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("no-op RunMigrations: %v", err)
	}
}

type populated struct {
	orgOwner, orgBogus                                        uuid.UUID
	uAdmin, uMember, uSusp, uWeird, uReadonly, uOwner, uBogus uuid.UUID
	p1, p2, pDead                                             uuid.UUID
	pmCount                                                   int
}

// seedLegacy builds data as the code before P2 wrote it: users admin/member/suspended/unknown role, organizations with the
// four org roles (+ an unknown one) and project_members in the three project roles (one on a soft-deleted project).
func seedLegacy(t *testing.T, pool *pgxpool.Pool) populated {
	t.Helper()
	ctx := context.Background()
	f := newFx(t, pool)
	now := time.Now().Add(-72 * time.Hour)
	mk := func(role string) uuid.UUID {
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO users (email,password_hash,name,role,created_at) VALUES ($1,'x','U',$2,$3) RETURNING id`,
			uuid.NewString()+"@x.io", role, now).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	var p populated
	p.uOwner, p.uAdmin, p.uMember, p.uSusp, p.uWeird, p.uReadonly, p.uBogus = mk("member"), mk("admin"), mk("member"), mk("suspended"), mk("superuser"), mk("member"), mk("member")
	p.orgOwner = f.org(p.uOwner)
	f.member(p.orgOwner, p.uOwner, "owner")
	f.member(p.orgOwner, p.uAdmin, "admin")
	f.member(p.orgOwner, p.uMember, "member")
	f.member(p.orgOwner, p.uReadonly, "readonly")
	f.member(p.orgOwner, p.uSusp, "member")
	p.orgBogus = f.org(p.uOwner)
	f.member(p.orgBogus, p.uBogus, "godmode")
	f.member(p.orgBogus, p.uOwner, "owner")
	p.p1, p.p2 = f.project(p.orgOwner, "alpha"), f.project(p.orgOwner, "beta")
	if err := pool.QueryRow(ctx, `INSERT INTO projects (org_id,name,slug,deleted_at) VALUES ($1,'D','dead',now()) RETURNING id`, p.orgOwner).Scan(&p.pDead); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		proj uuid.UUID
		user uuid.UUID
		role string
	}{{p.p1, p.uMember, "viewer"}, {p.p1, p.uReadonly, "admin"}, {p.p2, p.uMember, "deployer"}, {p.p2, p.uSusp, "viewer"}, {p.pDead, p.uMember, "admin"}} {
		if _, err := pool.Exec(ctx, `INSERT INTO project_members (project_id,user_id,role,created_by) VALUES ($1,$2,$3,$4)`, r.proj, r.user, r.role, p.uOwner); err != nil {
			t.Fatal(err)
		}
		p.pmCount++
	}
	return p
}

// MIGRATION sec. 2 counts, checked after the backfill.
func checkSec2Counts(t *testing.T, pool *pgxpool.Pool, wantBogusMembers int) {
	t.Helper()
	pm := qInt(t, pool, `SELECT count(*) FROM project_members`)
	if n := qInt(t, pool, `SELECT count(*) FROM access_assignments WHERE source = 'migrated'`); n != pm {
		t.Errorf("count(assignments migrated)=%d, count(project_members)=%d", n, pm)
	}
	om := qInt(t, pool, `SELECT count(*) FROM org_members`)
	withTpl := qInt(t, pool, `SELECT count(*) FROM org_members WHERE template_id IS NOT NULL`)
	unknown := qInt(t, pool, `SELECT count(*) FROM org_members WHERE role NOT IN ('owner','admin','member','readonly')`)
	if withTpl+unknown != om || unknown != wantBogusMembers {
		t.Errorf("org_members: with template %d + unknown role %d != total %d (want %d unknown)", withTpl, unknown, om, wantBogusMembers)
	}
	if a, b := qInt(t, pool, `SELECT count(*) FROM users WHERE status = 'suspended'`), qInt(t, pool, `SELECT count(*) FROM users WHERE role = 'suspended'`); a != b {
		t.Errorf("suspended users %d != role suspended %d", a, b)
	}
	if a, b := qInt(t, pool, `SELECT count(*) FROM users WHERE platform_role = 'admin'`), qInt(t, pool, `SELECT count(*) FROM users WHERE role = 'admin'`); a != b {
		t.Errorf("platform admins %d != role admin %d", a, b)
	}
}

// Database with legacy data: backfill, counts, down/up with data present, and the old data is untouched throughout.
func TestAccessMigrationsPopulatedDB(t *testing.T) {
	pool := freshDB(t)
	ctx := context.Background()
	applyUpTo(t, pool, accessFirst-1)
	p := seedLegacy(t, pool)

	before := map[string]int{
		"users":   qInt(t, pool, `SELECT count(*) FROM users`),
		"members": qInt(t, pool, `SELECT count(*) FROM org_members`),
		"pm":      qInt(t, pool, `SELECT count(*) FROM project_members`),
	}
	roles := qStr(t, pool, `SELECT string_agg(role, ',' ORDER BY email) FROM users`)
	mroles := qStr(t, pool, `SELECT string_agg(role, ',' ORDER BY org_id, user_id) FROM org_members`)
	pmroles := qStr(t, pool, `SELECT string_agg(role, ',' ORDER BY project_id, user_id) FROM project_members`)

	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrating populated database: %v", err)
	}
	checkSec2Counts(t, pool, 1)

	// users
	for _, c := range []struct {
		id            uuid.UUID
		status, platf string
	}{{p.uAdmin, "active", "admin"}, {p.uMember, "active", "user"}, {p.uSusp, "suspended", "user"}, {p.uWeird, "active", "user"}} {
		if s, pr := qStr(t, pool, `SELECT status FROM users WHERE id=$1`, c.id), qStr(t, pool, `SELECT platform_role FROM users WHERE id=$1`, c.id); s != c.status || pr != c.platf {
			t.Errorf("user %s: status=%s platform_role=%s, want %s/%s", c.id, s, pr, c.status, c.platf)
		}
	}
	if n := qInt(t, pool, `SELECT count(*) FROM access_anomalies WHERE kind='users.role.unknown' AND user_id=$1`, p.uWeird); n != 1 {
		t.Errorf("unknown user role anomalies = %d, want 1", n)
	}
	if n := qInt(t, pool, `SELECT count(*) FROM access_anomalies WHERE kind='org_members.role.unknown' AND user_id=$1`, p.uBogus); n != 1 {
		t.Errorf("unknown org role anomalies = %d, want 1", n)
	}
	// org member -> system template with the same slug; the unknown role resolves to nothing
	if n := qInt(t, pool, `SELECT count(*) FROM org_members om JOIN role_templates t ON t.id = om.template_id WHERE t.system AND t.kind='org' AND t.slug = om.role`); n != 6 {
		t.Errorf("members linked to their system template = %d, want 6", n)
	}
	if n := qInt(t, pool, `SELECT count(*) FROM org_members WHERE user_id=$1 AND org_id=$2 AND template_id IS NULL`, p.uBogus, p.orgBogus); n != 1 {
		t.Errorf("member with unknown role must have template_id NULL")
	}
	// migrated assignments keep created_by/created_at and map role -> project template of the same slug
	if n := qInt(t, pool, `
		SELECT count(*) FROM access_assignments a JOIN project_members pm ON pm.project_id=a.scope_id AND pm.user_id=a.subject_id
		  JOIN role_templates t ON t.id=a.template_id
		 WHERE a.source='migrated' AND a.scope_type='project' AND a.subject_type='user' AND t.slug=pm.role AND t.kind='project'
		   AND a.created_by IS NOT DISTINCT FROM pm.created_by AND a.created_at = pm.created_at`); n != p.pmCount {
		t.Errorf("faithful migrated assignments = %d, want %d", n, p.pmCount)
	}
	// legacy columns untouched
	if got := qStr(t, pool, `SELECT string_agg(role, ',' ORDER BY email) FROM users`); got != roles {
		t.Errorf("users.role changed by migration")
	}
	if got := qStr(t, pool, `SELECT string_agg(role, ',' ORDER BY org_id, user_id) FROM org_members`); got != mroles {
		t.Errorf("org_members.role changed by migration")
	}
	if got := qStr(t, pool, `SELECT string_agg(role, ',' ORDER BY project_id, user_id) FROM project_members`); got != pmroles {
		t.Errorf("project_members.role changed by migration")
	}

	// seed content; twice gives the same rows
	n1, err := SeedSystemTemplates(ctx, pool)
	if err != nil || n1 != 9 {
		t.Fatalf("seed: inserted=%d err=%v", n1, err)
	}
	n2, err := SeedSystemTemplates(ctx, pool)
	if err != nil || n2 != 0 {
		t.Fatalf("second seed: inserted=%d err=%v", n2, err)
	}

	// down with data present: old data intact; up again restores the same counts
	runDown(t, pool, accessLast, accessFirst)
	for k, q := range map[string]string{"users": `SELECT count(*) FROM users`, "members": `SELECT count(*) FROM org_members`, "pm": `SELECT count(*) FROM project_members`} {
		if got := qInt(t, pool, q); got != before[k] {
			t.Errorf("%s rows after down = %d, want %d", k, got, before[k])
		}
	}
	if got := qStr(t, pool, `SELECT string_agg(role, ',' ORDER BY org_id, user_id) FROM org_members`); got != mroles {
		t.Errorf("org_members.role changed by down")
	}
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("up after down (with data): %v", err)
	}
	checkSec2Counts(t, pool, 1)
	reapplyUp(t, pool, accessFirst, accessLast)
	checkSec2Counts(t, pool, 1)
	if _, err := SeedSystemTemplates(ctx, pool); err != nil {
		t.Fatal(err)
	}
}

// Header ids written by the SQL migration equal systemtemplates ids, and the seeded content matches the JSON.
func TestSystemTemplateIDsMatchSQL(t *testing.T) {
	pool := accessDB(t)
	ctx := context.Background()
	rows, err := pool.Query(ctx, `SELECT id, kind, slug, access_system_template_id(kind, slug), current_version FROM role_templates WHERE system`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var id, sqlID uuid.UUID
		var kind, slug string
		var cur int
		if err := rows.Scan(&id, &kind, &slug, &sqlID, &cur); err != nil {
			t.Fatal(err)
		}
		n++
		if id != SystemTemplateID(kind, slug) || sqlID != id {
			t.Errorf("%s/%s: stored %s, sql %s, go %s", kind, slug, id, sqlID, SystemTemplateID(kind, slug))
		}
	}
	if n != 9 {
		t.Errorf("system templates = %d, want 9", n)
	}
	// every header has its version row, and readonly carries both ceilings, owner and admin point at project/admin as floor
	if c := qInt(t, pool, `SELECT count(*) FROM role_templates t JOIN role_template_versions v ON v.template_id=t.id AND v.version=t.current_version WHERE t.system`); c != 9 {
		t.Errorf("system templates with current version row = %d, want 9", c)
	}
	if c := qInt(t, pool, `SELECT count(*) FROM role_template_versions v JOIN role_templates t ON t.id=v.template_id
		WHERE t.system AND t.kind='org' AND t.slug='readonly' AND v.ceiling IS NOT NULL AND v.ceiling_project IS NOT NULL AND v.base_template_id = $1`, SystemTemplateID("project", "viewer")); c != 1 {
		t.Errorf("readonly template content not seeded as expected")
	}
	if c := qInt(t, pool, `SELECT count(*) FROM role_template_versions v JOIN role_templates t ON t.id=v.template_id
		WHERE t.system AND t.kind='org' AND t.slug IN ('owner','admin') AND v.floor_template_id = $1`, SystemTemplateID("project", "admin")); c != 2 {
		t.Errorf("owner/admin floor = project/admin expected on 2 templates, got %d", c)
	}
}
