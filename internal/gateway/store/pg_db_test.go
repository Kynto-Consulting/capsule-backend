//go:build dbtest

package store

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/repository"
)

// Needs a throwaway Postgres in TEST_DATABASE_URL (same convention as internal/repository dbtests).

type env struct {
	t    *testing.T
	pool *pgxpool.Pool
	st   *PgStore
	org  uuid.UUID
	proj uuid.UUID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	name := "gwt_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+name); err != nil {
		admin.Close()
		t.Fatalf("create database: %v", err)
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
		t.Fatalf("migrations: %v", err)
	}
	e := &env{t: t, pool: pool, st: NewPgStore(pool)}
	var owner uuid.UUID
	must(t, pool.QueryRow(ctx, `INSERT INTO users (email, password_hash, name) VALUES ($1,'x','T') RETURNING id`, uuid.NewString()+"@x.io").Scan(&owner))
	e.org = e.newOrg(owner)
	e.proj = e.newProject(e.org)
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) newOrg(owner uuid.UUID) uuid.UUID {
	var id uuid.UUID
	must(e.t, e.pool.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug, owner_id) VALUES ('O',$2,$1) RETURNING id`, owner, "o-"+uuid.NewString()).Scan(&id))
	return id
}

func (e *env) newProject(org uuid.UUID) uuid.UUID {
	var id uuid.UUID
	must(e.t, e.pool.QueryRow(context.Background(),
		`INSERT INTO projects (org_id, name, slug, repo_url, branch, runtime) VALUES ($1,'P',$2,'https://example.com/r.git','main','node') RETURNING id`,
		org, "p-"+uuid.NewString()).Scan(&id))
	return id
}

func (e *env) service(name string) *Service {
	e.t.Helper()
	svc, err := e.st.CreateService(context.Background(), NewService{OrgID: e.org, ProjectID: e.proj, Name: name, Protocol: "postgres"})
	must(e.t, err)
	return svc
}

func TestRoutesResolveAndSnapshot(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	svc := e.service("db")
	if _, err := e.st.CreateService(ctx, NewService{OrgID: e.org, ProjectID: e.proj, Name: "db"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name in project must be ErrConflict, got %v", err)
	}
	if _, err := e.st.CreateService(ctx, NewService{OrgID: e.org, ProjectID: e.proj, Name: "Bad_Name"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad name must be ErrInvalid, got %v", err)
	}
	// Same name in another project is fine.
	other := e.newProject(e.org)
	if _, err := e.st.CreateService(ctx, NewService{OrgID: e.org, ProjectID: other, Name: "db"}); err != nil {
		t.Fatal(err)
	}

	rev0, _ := e.st.Revision(ctx)
	r, err := e.st.UpsertRoute(ctx, NewRoute{ServiceID: svc.ID, Host: "DB-P.db.example.com", DestHost: "capsule-db", DestPort: 5432, Enabled: true})
	must(t, err)
	if r.Host != "db-p.db.example.com" || r.Mode != ModePassthrough || r.Protocol != "postgres" || r.Transport != "tcp" {
		t.Fatalf("defaults/normalisation: %+v", r)
	}
	v, err := e.st.ResolveRoute(ctx, "tcp", "Db-P.db.example.com")
	must(t, err)
	if v.ProjectID != e.proj || v.ServiceName != "db" || v.DestPort != 5432 {
		t.Fatalf("resolve: %+v", v)
	}
	if v2, err := e.st.ResolveService(ctx, e.proj, "db", "tcp"); err != nil || v2.ID != r.ID {
		t.Fatalf("resolve service: %v %+v", err, v2)
	}
	if _, err := e.st.ResolveRoute(ctx, "tcp", "nope.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown host: %v", err)
	}
	// A host cannot be stolen by another service.
	if _, err := e.st.UpsertRoute(ctx, NewRoute{ServiceID: e.service("other").ID, Host: "db-p.db.example.com", DestHost: "x", DestPort: 1, Enabled: true}); !errors.Is(err, ErrConflict) {
		t.Fatalf("host theft must be ErrConflict, got %v", err)
	}

	snap, err := e.st.Snapshot(ctx, rev0)
	must(t, err)
	if snap.Unchanged || len(snap.Routes) != 1 || snap.Rev <= rev0 {
		t.Fatalf("snapshot: %+v", snap)
	}
	same, _ := e.st.Snapshot(ctx, snap.Rev)
	if !same.Unchanged || len(same.Routes) != 0 {
		t.Fatalf("unchanged snapshot: %+v", same)
	}

	// Disabling the gateway access hides the route from the data plane (direct_port keeps working).
	if _, err := e.st.SetAccess(ctx, svc.ID, AccessGateway, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.ResolveRoute(ctx, "tcp", "db-p.db.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled access must hide route: %v", err)
	}
	if _, err := e.st.SetAccess(ctx, svc.ID, AccessDirectPort, true, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("direct_port without port must be ErrInvalid: %v", err)
	}
	p := 40123
	if _, err := e.st.SetAccess(ctx, svc.ID, AccessDirectPort, true, &p); err != nil {
		t.Fatal(err)
	}
	must(t, e.st.SetDefaultAccess(ctx, svc.ID, AccessDirectPort))
	got, _ := e.st.GetService(ctx, svc.ID)
	if got.DefaultAccess != AccessDirectPort || len(got.Accesses) != 2 {
		t.Fatalf("service: %+v", got)
	}
	must(t, e.st.DeleteService(ctx, svc.ID, time.Hour))
	if _, err := e.st.GetService(ctx, svc.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
}

func TestPortLeaseLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	n, err := e.st.SeedPortPool(ctx, 20000, 20001)
	must(t, err)
	if n != 2 {
		t.Fatalf("seeded %d", n)
	}
	if again, _ := e.st.SeedPortPool(ctx, 20000, 20001); again != 0 {
		t.Fatalf("seed must be idempotent, added %d", again)
	}
	a, b, c := e.service("a"), e.service("b"), e.service("c")
	la, err := e.st.LeasePort(ctx, a.ID)
	must(t, err)
	if again, _ := e.st.LeasePort(ctx, a.ID); again.Port != la.Port {
		t.Fatal("lease must be idempotent per service")
	}
	lb, err := e.st.LeasePort(ctx, b.ID)
	must(t, err)
	if la.Port == lb.Port {
		t.Fatal("two services got the same port")
	}
	if _, err := e.st.LeasePort(ctx, c.ID); !errors.Is(err, ErrPortPoolExhausted) {
		t.Fatalf("expected ErrPortPoolExhausted, got %v", err)
	}
	st, _ := e.st.PoolStats(ctx)
	if st.Free != 0 || st.Leased != 2 {
		t.Fatalf("stats %+v", st)
	}
	snap, _ := e.st.Snapshot(ctx, -1)
	if len(snap.Leases) != 2 {
		t.Fatalf("snapshot leases: %d", len(snap.Leases))
	}

	// Released port is quarantined: not reusable until the quarantine ends.
	must(t, e.st.ReleaseLease(ctx, a.ID, time.Hour))
	if _, err := e.st.LeasePort(ctx, c.ID); !errors.Is(err, ErrPortPoolExhausted) {
		t.Fatalf("quarantined port must not be leased: %v", err)
	}
	if err := e.st.ReleaseLease(ctx, a.ID, time.Hour); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double release: %v", err)
	}
	// Expire the quarantine.
	_, err = e.pool.Exec(ctx, `UPDATE gateway_port_pool SET quarantine_until = now() - interval '1 second' WHERE state = 'quarantine'`)
	must(t, err)
	if swept, _ := e.st.SweepPool(ctx); swept != 1 {
		t.Fatalf("sweep freed %d", swept)
	}
	lc, err := e.st.LeasePort(ctx, c.ID)
	must(t, err)
	if lc.Port != la.Port {
		t.Fatalf("expected reuse of %d, got %d", la.Port, lc.Port)
	}

	// Deleting a service quarantines its lease (no orphan 'leased' port).
	must(t, e.st.DeleteService(ctx, b.ID, time.Hour))
	st, _ = e.st.PoolStats(ctx)
	if st.Quarantine != 1 || st.Leased != 1 {
		t.Fatalf("after delete: %+v", st)
	}
	// Idle release.
	if n, err := e.st.ReleaseIdle(ctx, time.Now().Add(time.Minute), time.Hour); err != nil || n != 1 {
		t.Fatalf("idle release: %d %v", n, err)
	}
}

func TestPortQuotas(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, err := e.st.SeedPortPool(ctx, 21000, 21050)
	must(t, err)
	must(t, e.st.SetQuotas(ctx, e.org, Quotas{MaxRandomPorts: 3, MaxRandomPortsPerProject: 2}))
	for _, n := range []string{"a", "b"} {
		if _, err := e.st.LeasePort(ctx, e.service(n).ID); err != nil {
			t.Fatal(err)
		}
	}
	var qe *QuotaError
	if _, err := e.st.LeasePort(ctx, e.service("c").ID); !errors.As(err, &qe) || qe.Scope != "project" {
		t.Fatalf("project quota: %v", err)
	}
	other := e.newProject(e.org)
	mk := func(name string) uuid.UUID {
		s, err := e.st.CreateService(ctx, NewService{OrgID: e.org, ProjectID: other, Name: name})
		must(t, err)
		return s.ID
	}
	if _, err := e.st.LeasePort(ctx, mk("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.LeasePort(ctx, mk("y")); !errors.As(err, &qe) || qe.Scope != "org" || !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("org quota: %v", err)
	}
}

func TestConcurrentLeasesAreDistinct(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, err := e.st.SeedPortPool(ctx, 22000, 22029)
	must(t, err)
	must(t, e.st.SetQuotas(ctx, e.org, Quotas{MaxRandomPorts: 100, MaxRandomPortsPerProject: 100}))
	const n = 20
	ids := make([]uuid.UUID, n)
	for i := range ids {
		ids[i] = e.service("s" + strings.Repeat("x", 1) + uuid.NewString()[:8]).ID
	}
	var wg sync.WaitGroup
	ports := make(chan int, n)
	for _, id := range ids {
		wg.Add(1)
		go func(id uuid.UUID) {
			defer wg.Done()
			l, err := e.st.LeasePort(ctx, id)
			if err != nil {
				t.Error(err)
				return
			}
			ports <- l.Port
		}(id)
	}
	wg.Wait()
	close(ports)
	seen := map[int]bool{}
	for p := range ports {
		if seen[p] {
			t.Fatalf("port %d leased twice", p)
		}
		seen[p] = true
	}
}

func TestOrgPolicy(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if p, err := e.st.GetOrgPolicy(ctx, e.org); err != nil || p != PolicyWarn {
		t.Fatalf("default policy: %q %v", p, err)
	}
	must(t, e.st.SetOrgPolicy(ctx, e.org, PolicyError))
	if p, _ := e.st.GetOrgPolicy(ctx, e.org); p != PolicyError {
		t.Fatalf("policy %q", p)
	}
	if err := e.st.SetOrgPolicy(ctx, e.org, "block"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid policy: %v", err)
	}
	if err := e.st.SetOrgPolicy(ctx, uuid.New(), PolicyWarn); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown org: %v", err)
	}
}

// Existing project ports and databases are exposed as services with default_access = direct_port,
// the gateway access off, and the backfill is idempotent.
func TestBackfillKeepsDirectPortDefault(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var pp uuid.UUID
	must(t, e.pool.QueryRow(ctx,
		`INSERT INTO project_ports (project_id, name, container_port, host_port) VALUES ($1,'Web UI!',8080,41001) RETURNING id`, e.proj).Scan(&pp))
	must(t, e.pool.QueryRow(ctx,
		`INSERT INTO project_ports (project_id, name, container_port, host_port) VALUES ($1,'web ui',9090,41002) RETURNING id`, e.proj).Scan(&pp))
	_, err := e.pool.Exec(ctx,
		`INSERT INTO databases (project_id, org_id, name, host, port, db_name, credentials_enc) VALUES ($1,$2,'Main DB','h',40010,'d','\x00')`, e.proj, e.org)
	must(t, err)

	up, err := repository.MigrationsFS.ReadFile("migrations/000062_gateway_policy_backfill.up.sql")
	must(t, err)
	for i := 0; i < 2; i++ { // second run proves idempotency
		if _, err := e.pool.Exec(ctx, string(up)); err != nil {
			t.Fatalf("backfill run %d: %v", i, err)
		}
	}
	svcs, err := e.st.ListServices(ctx, e.proj)
	must(t, err)
	if len(svcs) != 3 {
		t.Fatalf("want 3 services, got %d", len(svcs))
	}
	names := map[string]bool{}
	for _, s := range svcs {
		names[s.Name] = true
		if s.DefaultAccess != AccessDirectPort || len(s.Accesses) != 2 {
			t.Fatalf("service %s: %+v", s.Name, s)
		}
		for _, a := range s.Accesses {
			if a.Kind == AccessGateway && a.Enabled {
				t.Fatalf("gateway access must start disabled: %+v", s)
			}
			if a.Kind == AccessDirectPort && (!a.Enabled || a.Port == nil) {
				t.Fatalf("direct access must be enabled with its port: %+v", s)
			}
		}
	}
	if !names["web-ui"] || !names["web-ui-9090"] || !names["main-db"] {
		t.Fatalf("unexpected names %v", names)
	}
	// Not routable through the gateway until it is enabled explicitly.
	if snap, _ := e.st.Snapshot(ctx, -1); len(snap.Routes) != 0 {
		t.Fatalf("backfill must not create routes: %d", len(snap.Routes))
	}
}

// Every .down.sql of this package's migrations runs and the up files re-apply afterwards.
func TestDownThenUpAgain(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, v := range []string{"000064_project_ports_udp", "000063_gateway_service_tokens", "000062_gateway_policy_backfill", "000061_gateway_port_pool", "000060_gateway_services"} {
		b, err := repository.MigrationsFS.ReadFile("migrations/" + v + ".down.sql")
		must(t, err)
		if _, err := e.pool.Exec(ctx, string(b)); err != nil {
			t.Fatalf("%s down: %v", v, err)
		}
	}
	for _, v := range []string{"000060_gateway_services", "000061_gateway_port_pool", "000062_gateway_policy_backfill", "000063_gateway_service_tokens", "000064_project_ports_udp"} {
		b, err := repository.MigrationsFS.ReadFile("migrations/" + v + ".up.sql")
		must(t, err)
		if _, err := e.pool.Exec(ctx, string(b)); err != nil {
			t.Fatalf("%s up again: %v", v, err)
		}
	}
}
