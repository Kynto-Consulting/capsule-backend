//go:build dbtest

package access

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
	"github.com/kynto/capsule/backend/internal/authz/systemtemplates"
	"github.com/kynto/capsule/backend/internal/repository"
)

// These tests need a real Postgres in TEST_DATABASE_URL (local WSL only, never production); they are skipped otherwise.

type testEnv struct {
	pool  *pgxpool.Pool
	store *repository.AccessStore
	eng   *engine.Engine
	svc   *Service
}

func newTestEnv(t testing.TB) *testEnv {
	t.Helper()
	u := os.Getenv("TEST_DATABASE_URL")
	if u == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(u)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 32
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := repository.RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	if _, err := repository.SeedSystemTemplates(ctx, pool); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store := repository.NewAccessStore(pool)
	eng := engine.New(store.EngineStore(), engine.Options{})
	return &testEnv{pool: pool, store: store, eng: eng, svc: New(store, eng, nil)}
}

func (e *testEnv) exec(t testing.TB, sql string, args ...any) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (e *testEnv) user(t testing.TB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := e.pool.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash, name) VALUES ($1,'x','T') RETURNING id`, uuid.NewString()+"@x.io").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// org creates an organization whose owner is a new user (already a member with the owner template) and returns both.
func (e *testEnv) org(t testing.TB, mode string) (org, owner uuid.UUID) {
	t.Helper()
	owner = e.user(t)
	if err := e.pool.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug, owner_id, project_access_mode) VALUES ('O',$2,$1,$3) RETURNING id`, owner, "o-"+uuid.NewString(), mode).Scan(&org); err != nil {
		t.Fatal(err)
	}
	e.member(t, org, owner, "owner")
	return org, owner
}

func (e *testEnv) member(t testing.TB, org, user uuid.UUID, role string) {
	t.Helper()
	e.exec(t, `INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,$3)`, org, user, role)
}

func (e *testEnv) newMember(t testing.TB, org uuid.UUID, role string) uuid.UUID {
	t.Helper()
	u := e.user(t)
	e.member(t, org, u, role)
	return u
}

func (e *testEnv) project(t testing.TB, org uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := e.pool.QueryRow(context.Background(),
		`INSERT INTO projects (org_id, name, slug, repo_url, branch, runtime) VALUES ($1,'P',$2,'https://example.com/r.git','main','node') RETURNING id`, org, "p-"+uuid.NewString()).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *testEnv) environment(t testing.TB, project uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := e.pool.QueryRow(context.Background(),
		`INSERT INTO environments (project_id, name, target_project_id) VALUES ($1,$2,$1) RETURNING id`, project, "e"+uuid.NewString()[:8]).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func sysProject(slug string) uuid.UUID { return systemtemplates.ID(systemtemplates.KindProject, slug) }

// assign inserts a live assignment directly (test setup: no authorization rules).
func (e *testEnv) assign(t testing.TB, org uuid.UUID, subjectType string, subject uuid.UUID, scopeType string, scope uuid.UUID, tpl uuid.UUID, expires *time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := e.pool.QueryRow(context.Background(), `
		INSERT INTO access_assignments (org_id, subject_type, subject_id, scope_type, scope_id, template_id, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`, org, subjectType, subject, scopeType, scope, tpl, expires).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// customOrgTemplate creates an organization template with the given permissions through SQL (setup, no escalation rules) and makes the
// user hold it.
func (e *testEnv) customOrgTemplate(t testing.TB, org uuid.UUID, slug string, perms []string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := e.pool.QueryRow(context.Background(),
		`INSERT INTO role_templates (org_id, kind, slug, name) VALUES ($1,'org',$2,$2) RETURNING id`, org, slug).Scan(&id); err != nil {
		t.Fatal(err)
	}
	e.exec(t, `INSERT INTO role_template_versions (template_id, version, permissions) VALUES ($1,1,$2)`, id, perms)
	return id
}

func (e *testEnv) setOrgTemplate(t testing.TB, org, user, tpl uuid.UUID, label string) {
	t.Helper()
	e.exec(t, `UPDATE org_members SET template_id = $3, template_version = NULL, role = $4 WHERE org_id = $1 AND user_id = $2`, org, user, tpl, label)
}

func act(u uuid.UUID) Actor {
	return Actor{UserID: u, Via: "session", IP: "203.0.113.7", UserAgent: "test", RequestID: "req-" + u.String()[:8]}
}

// closure returns the permission plus everything it needs (SPEC 3.4) so the set validates.
func closure(p string) []string {
	set := catalog.NewSet(p)
	for changed := true; changed; {
		changed = false
		for _, id := range set.IDs() {
			c, _ := catalog.Get(id)
			for _, r := range c.Requires {
				if !set.Has(r) {
					set, changed = set.Add(r), true
				}
			}
		}
	}
	return set.IDs()
}

func asErr(t testing.TB, err error) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *access.Error, got %T %v", err, err)
	}
	return e
}

func wantErr(t testing.TB, err error, status int, detail string) *Error {
	t.Helper()
	if err == nil {
		t.Fatalf("want %d %s, got success", status, detail)
	}
	e := asErr(t, err)
	if e.Status != status || (detail != "" && e.DetailCode() != detail) {
		t.Fatalf("want %d %q, got %d %s %q (%v)", status, detail, e.Status, e.Code, e.DetailCode(), e.Details)
	}
	return e
}

func (e *testEnv) count(t testing.TB, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func ptr[T any](v T) *T { return &v }

var _ = fmt.Sprintf

func repoID(slug string) uuid.UUID { return systemtemplates.ID(systemtemplates.KindRepo, slug) }

// customOrgTemplateCeil is customOrgTemplate with a ceiling (versions are immutable, so it has to be set at creation).
func (e *testEnv) customOrgTemplateCeil(t testing.TB, org uuid.UUID, slug string, perms, ceiling []string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := e.pool.QueryRow(context.Background(),
		`INSERT INTO role_templates (org_id, kind, slug, name) VALUES ($1,'org',$2,$2) RETURNING id`, org, slug).Scan(&id); err != nil {
		t.Fatal(err)
	}
	e.exec(t, `INSERT INTO role_template_versions (template_id, version, permissions, ceiling) VALUES ($1,1,$2,$3)`, id, perms, ceiling)
	return id
}
