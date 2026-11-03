//go:build dbtest

package repository

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Shared helpers for the *_db_test.go integration tests. They need a real,
// throwaway Postgres in TEST_DATABASE_URL and are skipped otherwise.

func dbURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TEST_DATABASE_URL")
	if u == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	return u
}

// sharedPool returns a pool on the shared (fully migrated) test database.
func sharedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return pool
}

// freshDB creates an empty database and returns a pool on it; it is dropped on cleanup.
func freshDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	base := dbURL(t)
	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	name := "dbt_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+name); err != nil {
		admin.Close()
		t.Fatalf("create database: %v", err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
		admin.Close()
	})
	return pool
}

type migFile struct {
	version int
	name    string
}

func migrationFiles(t *testing.T, suffix string) []migFile {
	t.Helper()
	entries, err := MigrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^(\d+)_.*\.` + regexp.QuoteMeta(suffix) + `$`)
	var out []migFile
	for _, e := range entries {
		m := re.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, _ := strconv.Atoi(m[1])
		out = append(out, migFile{v, e.Name()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out
}

// applyUpTo applies the .up.sql files with version <= max exactly like
// RunMigrations does (same IF NOT EXISTS rewriting) and records them.
func applyUpTo(t *testing.T, pool *pgxpool.Pool, max int) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS dirty boolean NOT NULL DEFAULT false`); err != nil {
		t.Fatal(err)
	}
	for _, m := range migrationFiles(t, "up.sql") {
		if m.version > max {
			continue
		}
		b, err := MigrationsFS.ReadFile("migrations/" + m.name)
		if err != nil {
			t.Fatal(err)
		}
		sql := string(b)
		sql = safeAddIfNotExists(sql, "CREATE TABLE ")
		sql = safeAddIfNotExists(sql, "CREATE UNIQUE INDEX ")
		sql = safeAddIfNotExists(sql, "CREATE INDEX ")
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatalf("applying %s: %v", m.name, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version, dirty) VALUES ($1,false) ON CONFLICT DO NOTHING`, m.version); err != nil {
			t.Fatal(err)
		}
	}
}

// ---- fixtures (all unique per call so tests are re-runnable) ----------------

type fx struct {
	t    *testing.T
	pool *pgxpool.Pool
}

func newFx(t *testing.T, pool *pgxpool.Pool) *fx { return &fx{t, pool} }

func (f *fx) user(email string, createdAt time.Time) uuid.UUID {
	f.t.Helper()
	if email == "" {
		email = uuid.NewString() + "@x.io"
	}
	var id uuid.UUID
	err := f.pool.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash, name, created_at) VALUES ($1,'x','T',$2) RETURNING id`, email, createdAt).Scan(&id)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fx) org(owner uuid.UUID) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	err := f.pool.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug, owner_id) VALUES ('O',$2,$1) RETURNING id`, owner, "o-"+uuid.NewString()).Scan(&id)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fx) member(org, user uuid.UUID, role string) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,$3)`, org, user, role); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) project(org uuid.UUID, slug string) uuid.UUID {
	f.t.Helper()
	if slug == "" {
		slug = "p-" + uuid.NewString()
	}
	var id uuid.UUID
	err := f.pool.QueryRow(context.Background(),
		`INSERT INTO projects (org_id, name, slug, repo_url, branch, runtime) VALUES ($1,'P',$2,'https://example.com/r.git','main','node') RETURNING id`, org, slug).Scan(&id)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fx) fail(format string, a ...any) {
	f.t.Helper()
	f.t.Fatalf(format, a...)
}

var _ = fmt.Sprintf
