//go:build dbtest

package api

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/gateway/store"
	"github.com/kynto/capsule/backend/internal/repository"
)

// Deleting a project or a database (soft delete: deleted_at) must remove its gateway services, routes, accesses and leases,
// send the random port to quarantine and bump the revision. Local Postgres only (TEST_DATABASE_URL).
func orphanPool(t *testing.T) *pgxpool.Pool {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	name := "gwor_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+name); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(base)
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
	if err := repository.RunMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

type orphanFx struct {
	t             *testing.T
	pool          *pgxpool.Pool
	st            *store.PgStore
	org, proj, db uuid.UUID
	svc           *store.Service
	route         uuid.UUID
}

func newOrphanFx(t *testing.T, pool *pgxpool.Pool, slug string) *orphanFx {
	ctx := context.Background()
	f := &orphanFx{t: t, pool: pool, st: store.NewPgStore(pool)}
	var owner uuid.UUID
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(pool.QueryRow(ctx, `INSERT INTO users (email, password_hash, name) VALUES ($1,'x','T') RETURNING id`, uuid.NewString()+"@x.io").Scan(&owner))
	must(pool.QueryRow(ctx, `INSERT INTO organizations (name, slug, owner_id) VALUES ('O',$2,$1) RETURNING id`, owner, "o-"+uuid.NewString()).Scan(&f.org))
	must(pool.QueryRow(ctx, `INSERT INTO projects (org_id, name, slug, repo_url, branch, runtime) VALUES ($1,'P',$2,'https://example.com/r.git','main','node') RETURNING id`, f.org, slug).Scan(&f.proj))
	must(pool.QueryRow(ctx, `INSERT INTO databases (org_id, project_id, name, host, port, db_name, credentials_enc) VALUES ($1,$2,'qa-pg','h',40100,'d','\x00') RETURNING id`, f.org, f.proj).Scan(&f.db))
	_, err := f.st.SeedPortPool(ctx, 26000, 26009)
	must(err)
	port := 40100
	f.svc, err = f.st.CreateService(ctx, store.NewService{OrgID: f.org, ProjectID: f.proj, Name: "qa-pg", Protocol: "postgres", DatabaseID: &f.db, DirectPort: &port})
	must(err)
	r, err := f.st.UpsertRoute(ctx, store.NewRoute{ServiceID: f.svc.ID, Host: "qa-pg-" + slug + ".db.example.test", DestHost: "127.0.0.1", DestPort: 40100, Enabled: true})
	must(err)
	f.route = r.ID
	_, err = f.st.LeasePort(ctx, f.svc.ID)
	must(err)
	return f
}

func (f *orphanFx) counts() (services, routes, accesses, leases int) {
	ctx := context.Background()
	f.pool.QueryRow(ctx, `SELECT count(*) FROM gateway_services`).Scan(&services)
	f.pool.QueryRow(ctx, `SELECT count(*) FROM gateway_routes`).Scan(&routes)
	f.pool.QueryRow(ctx, `SELECT count(*) FROM gateway_accesses`).Scan(&accesses)
	f.pool.QueryRow(ctx, `SELECT count(*) FROM gateway_port_leases WHERE state = 'active'`).Scan(&leases)
	return
}

func (f *orphanFx) expectGone(what string, revBefore int64) {
	f.t.Helper()
	ctx := context.Background()
	if s, r, a, l := f.counts(); s+r+a+l != 0 {
		f.t.Fatalf("%s: left services=%d routes=%d accesses=%d leases=%d", what, s, r, a, l)
	}
	snap, err := f.st.Snapshot(ctx, -1)
	if err != nil || len(snap.Routes) != 0 || len(snap.Leases) != 0 || snap.Rev <= revBefore {
		f.t.Fatalf("%s: snapshot %+v err %v (rev before %d)", what, snap, err, revBefore)
	}
	stats, _ := f.st.PoolStats(ctx)
	if stats.Quarantine != 1 || stats.Leased != 0 {
		f.t.Fatalf("%s: the random port must be in quarantine: %+v", what, stats)
	}
	if _, err := f.st.ResolveRoute(ctx, "tcp", "qa-pg-qa-gw.db.example.test"); err == nil {
		f.t.Fatalf("%s: route still resolves", what)
	}
}

func TestDeletingDatabaseThenProjectRemovesGatewayState(t *testing.T) {
	pool := orphanPool(t)
	ctx := context.Background()
	f := newOrphanFx(t, pool, "qa-gw")
	rev, _ := f.st.Revision(ctx)
	// the name is taken while the service exists
	var other uuid.UUID
	pool.QueryRow(ctx, `INSERT INTO projects (org_id, name, slug, repo_url, branch, runtime) VALUES ($1,'P2','qa-gw2','https://example.com/r.git','main','node') RETURNING id`, f.org).Scan(&other)
	o, err := f.st.CreateService(ctx, store.NewService{OrgID: f.org, ProjectID: other, Name: "qa-pg", Protocol: "postgres"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.UpsertRoute(ctx, store.NewRoute{ServiceID: o.ID, Host: "qa-pg-qa-gw.db.example.test", DestHost: "x", DestPort: 1, Enabled: true}); err == nil {
		t.Fatal("setup: the host must be taken by the first project")
	}
	_ = f.st.DeleteService(ctx, o.ID, 0)
	rev, _ = f.st.Revision(ctx)

	// 1) soft-delete the database
	if _, err := pool.Exec(ctx, `UPDATE databases SET deleted_at = now() WHERE id = $1`, f.db); err != nil {
		t.Fatal(err)
	}
	f.expectGone("database delete", rev)
	// 2) the project: nothing left to remove, and it must not fail
	rev, _ = f.st.Revision(ctx)
	if _, err := pool.Exec(ctx, `UPDATE projects SET deleted_at = now(), status = 'archived' WHERE id = $1`, f.proj); err != nil {
		t.Fatal(err)
	}
	// the name is free again for another project
	n, err := f.st.CreateService(ctx, store.NewService{OrgID: f.org, ProjectID: other, Name: "qa-pg", Protocol: "postgres"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.UpsertRoute(ctx, store.NewRoute{ServiceID: n.ID, Host: "qa-pg-qa-gw.db.example.test", DestHost: "x", DestPort: 1, Enabled: true}); err != nil {
		t.Fatalf("the host must be free after the delete: %v", err)
	}
}

func TestDeletingProjectRemovesEverythingIncludingLeases(t *testing.T) {
	pool := orphanPool(t)
	ctx := context.Background()
	f := newOrphanFx(t, pool, "qa-gw")
	rev, _ := f.st.Revision(ctx)
	if _, err := pool.Exec(ctx, `UPDATE projects SET deleted_at = now(), status = 'archived' WHERE id = $1`, f.proj); err != nil {
		t.Fatal(err)
	}
	f.expectGone("project soft delete", rev)
}

func TestHardDeleteAndPortRemovalAlsoClean(t *testing.T) {
	pool := orphanPool(t)
	ctx := context.Background()
	f := newOrphanFx(t, pool, "qa-gw")
	rev, _ := f.st.Revision(ctx)
	if _, err := pool.Exec(ctx, `DELETE FROM databases WHERE id = $1`, f.db); err != nil {
		t.Fatal(err)
	}
	f.expectGone("database hard delete", rev)
}

func TestOrphanSweepCatchesWhatTriggersDidNotSee(t *testing.T) {
	pool := orphanPool(t)
	ctx := context.Background()
	f := newOrphanFx(t, pool, "qa-gw")
	rev, _ := f.st.Revision(ctx)
	// delete behind the triggers' back (session_replication_role = replica), as an old release or a manual SQL would
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Skip("cannot bypass triggers (needs superuser): ", err)
	}
	if _, err := conn.Exec(ctx, `UPDATE projects SET deleted_at = now() WHERE id = $1`, f.proj); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Exec(ctx, `SET session_replication_role = DEFAULT`)
	conn.Release()
	if s, _, _, _ := f.counts(); s != 1 {
		t.Fatalf("setup: the service should still be there, services=%d", s)
	}
	n, err := f.st.PurgeOrphans(ctx)
	if err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	f.expectGone("orphan sweep", rev)
	if n, _ := f.st.PurgeOrphans(ctx); n != 0 {
		t.Fatalf("second purge must find nothing, got %d", n)
	}
}

func TestMigration65DownRemovesTriggers(t *testing.T) {
	pool := orphanPool(t)
	ctx := context.Background()
	sqlDown, err := repository.MigrationsFS.ReadFile("migrations/000065_gateway_orphan_cleanup.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(sqlDown)); err != nil {
		t.Fatal(err)
	}
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'gateway_%'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d gateway triggers left after down", n)
	}
}
