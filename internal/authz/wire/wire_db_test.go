//go:build dbtest

package wire

import (
	"context"
	"log/slog"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
	"github.com/kynto/capsule/backend/internal/authz/systemtemplates"
	"github.com/kynto/capsule/backend/internal/repository"
)

// These tests need a real Postgres in TEST_DATABASE_URL (local WSL only, never production) and are skipped otherwise.

func dbPool(t *testing.T) *pgxpool.Pool {
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
	cfg.MaxConns = 24
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
	return pool
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func newUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash, name) VALUES ($1,'x','T') RETURNING id`, uuid.NewString()+"@x.io").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func newOrg(t *testing.T, pool *pgxpool.Pool, owner uuid.UUID, mode string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug, owner_id, project_access_mode) VALUES ('O',$2,$1,$3) RETURNING id`, owner, "o-"+uuid.NewString(), mode).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func newProject(t *testing.T, pool *pgxpool.Pool, org uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO projects (org_id, name, slug, repo_url, branch, runtime) VALUES ($1,'P',$2,'https://example.com/r.git','main','node') RETURNING id`, org, "p-"+uuid.NewString()).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

type world struct {
	orgs     []uuid.UUID
	projects map[uuid.UUID][]uuid.UUID // org -> projects
	users    []uuid.UUID               // members and strangers
	roles    map[[2]uuid.UUID]string   // (org,user) -> org role ("" not a member)
}

// buildWorld creates `orgs` organizations, each with 6 projects, mixed open/restricted policy, 24 members with the four roles (and an unknown
// one), random explicit project roles, plus users that belong to no organization.
func buildWorld(t *testing.T, pool *pgxpool.Pool, rng *rand.Rand, orgs int) *world {
	t.Helper()
	w := &world{projects: map[uuid.UUID][]uuid.UUID{}, roles: map[[2]uuid.UUID]string{}}
	owner := newUser(t, pool)
	w.users = append(w.users, owner)
	orgRoles := []string{"owner", "admin", "member", "member", "member", "readonly", "readonly", "bogus"}
	pRoles := []string{"viewer", "deployer", "admin"}
	for i := 0; i < orgs; i++ {
		mode := []string{"open", "restricted"}[rng.Intn(2)]
		o := newOrg(t, pool, owner, mode)
		w.orgs = append(w.orgs, o)
		for p := 0; p < 6; p++ {
			w.projects[o] = append(w.projects[o], newProject(t, pool, o))
		}
		for m := 0; m < 24; m++ {
			u := newUser(t, pool)
			w.users = append(w.users, u)
			role := orgRoles[rng.Intn(len(orgRoles))]
			mustExec(t, pool, `INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,$3)`, o, u, role)
			w.roles[[2]uuid.UUID{o, u}] = role
			for _, p := range w.projects[o] {
				if rng.Intn(5) == 0 {
					mustExec(t, pool, `INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,$3)`, p, u, pRoles[rng.Intn(3)])
				}
			}
		}
	}
	return w
}

type countObs struct{ total, mismatch, skipped atomic.Int64 }

func (c *countObs) ObserveShadow(_ string, _ time.Duration, mm bool) {
	c.total.Add(1)
	if mm {
		c.mismatch.Add(1)
	}
}
func (c *countObs) ObserveShadowSkipped(string, string) { c.skipped.Add(1) }

func realRuntime(t *testing.T, pool *pgxpool.Pool) *Runtime {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rt, err := Start(ctx, slog.New(slog.NewTextHandler(discard{}, nil)), pool)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// (c) Shadow mode against the real AccessStore: 100 000 random decisions (organization, member or stranger, project, old action or
// atom) answered by the legacy path over project_members and compared with the engine over the real access_* tables: 0 differences.
func TestShadowZeroDifferencesAgainstPostgres(t *testing.T) {
	pool := dbPool(t)
	rng := rand.New(rand.NewSource(20261104))
	w := buildWorld(t, pool, rng, 30)
	rt := realRuntime(t, pool)
	obs := &countObs{}
	svc := authz.New(repository.NewProjectMemberRepository(pool))
	svc.EnableEngine(authz.EngineConfig{V2: rt.V2, Global: authz.ModeShadow, Observer: obs, Log: slog.New(slog.NewTextHandler(os_stderr{t}, nil)), MaxInFlight: 4096, Timeout: 5 * time.Second})

	var actions []authz.Action
	actions = append(actions, authz.AllActions...)
	actions = append(actions, authz.GitActions...)
	actions = append(actions, authz.ProjectConnect)
	for _, p := range catalog.All() {
		if hasScope(p, "project") {
			actions = append(actions, authz.Action(p.ID))
		}
	}
	const total = 100000
	const workers = 16
	var next atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed))
			ctx := authz.WithRoute(context.Background(), "test")
			for next.Add(1) <= total {
				o := w.orgs[r.Intn(len(w.orgs))]
				u := w.users[r.Intn(len(w.users))] // members of other orgs and the owner act as strangers
				p := w.projects[o][r.Intn(6)]
				a := actions[r.Intn(len(actions))]
				if _, err := svc.Check(ctx, u, o, p, a); err != nil {
					t.Error(err)
					return
				}
			}
		}(int64(g) + 1)
	}
	wg.Wait()
	deadline := time.Now().Add(120 * time.Second)
	for obs.total.Load()+obs.skipped.Load() < total && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("100 000 decisions in %v; compared=%d mismatches=%d skipped=%d (30 orgs x 24 members x 6 projects, seed 20261104)",
		time.Since(start).Round(time.Millisecond), obs.total.Load(), obs.mismatch.Load(), obs.skipped.Load())
	if obs.total.Load() != total || obs.mismatch.Load() != 0 || obs.skipped.Load() != 0 {
		t.Fatalf("compared=%d mismatches=%d skipped=%d", obs.total.Load(), obs.mismatch.Load(), obs.skipped.Load())
	}
}

type os_stderr struct{ t *testing.T }

func (o os_stderr) Write(p []byte) (int, error) {
	o.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

func hasScope(p catalog.Perm, s string) bool {
	for _, x := range p.Scopes {
		if string(x) == s {
			return true
		}
	}
	return false
}

func pct(d []time.Duration, q float64) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[int(float64(len(d)-1)*q)]
}

// (d) Timings with the real database: end-to-end decision with the snapshot in cache (p99 < 5 ms), the extra cost of the strict path
// (< 1.5 ms), and the cold snapshot load for a typical user and for one with 500 project assignments.
func TestDecisionTimingsAgainstPostgres(t *testing.T) {
	pool := dbPool(t)
	rng := rand.New(rand.NewSource(7))
	w := buildWorld(t, pool, rng, 3)
	rt := realRuntime(t, pool)
	time.Sleep(2 * time.Second) // let the listener drain the NOTIFY backlog of the fixtures: each one evicts a snapshot
	svc := authz.New(repository.NewProjectMemberRepository(pool))
	svc.EnableEngine(authz.EngineConfig{V2: rt.V2, Global: authz.ModeV2})
	ctx := context.Background()
	org := w.orgs[0]
	var user uuid.UUID
	for k, role := range w.roles {
		if k[0] == org && role == "member" {
			user = k[1]
			break
		}
	}
	proj := w.projects[org][0]

	// cold load, typical user
	var cold []time.Duration
	for i := 0; i < 50; i++ {
		rt.Engine.Invalidate(engine.Target{Org: org})
		s := time.Now()
		if _, err := svc.Check(ctx, user, org, proj, authz.ProjectRead); err != nil {
			t.Fatal(err)
		}
		cold = append(cold, time.Since(s))
	}
	t.Logf("cold snapshot load (typical user, real store): p50=%v p99=%v max=%v", pct(cold, .5), pct(cold, .99), pct(cold, 1))

	// warm decisions
	measure := func(a authz.Action, n int) []time.Duration {
		var d []time.Duration
		for i := 0; i < n; i++ {
			s := time.Now()
			if _, err := svc.Check(ctx, user, org, proj, a); err != nil {
				t.Fatal(err)
			}
			d = append(d, time.Since(s))
		}
		return d
	}
	measure(authz.ProjectRead, 50)
	warm := measure(authz.ProjectRead, 1000)
	strict := measure(authz.Action(sensitiveProjectAtom(t)), 1000) // sensitive: epoch comparison by primary key every time
	t.Logf("warm decision (1000 calls): p50=%v p99=%v max=%v", pct(warm, .5), pct(warm, .99), pct(warm, 1))
	t.Logf("strict decision (sensitive permission, 1000 calls): p50=%v p99=%v max=%v", pct(strict, .5), pct(strict, .99), pct(strict, 1))
	if p := pct(warm, .99); p > 5*time.Millisecond {
		t.Errorf("warm p99 %v > 5 ms", p)
	}
	if extra := pct(strict, .99) - pct(warm, .99); extra > 1500*time.Microsecond {
		t.Errorf("strict path adds %v > 1.5 ms", extra)
	}

	// heavy user: 500 project assignments
	heavyOrg := newOrg(t, pool, user, "restricted")
	heavy := newUser(t, pool)
	mustExec(t, pool, `INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,'member')`, heavyOrg, heavy)
	for i := 0; i < 500; i++ {
		p := newProject(t, pool, heavyOrg)
		mustExec(t, pool, `INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,'deployer')`, p, heavy)
	}
	var hc []time.Duration
	for i := 0; i < 30; i++ {
		rt.Engine.Invalidate(engine.Target{Org: heavyOrg})
		s := time.Now()
		if _, _, err := rt.Engine.Effective(ctx, heavy, heavyOrg, engine.OrgScope()); err != nil {
			t.Fatal(err)
		}
		hc = append(hc, time.Since(s))
	}
	t.Logf("cold snapshot load, user with 500 assignments (real store): p50=%v p99=%v max=%v", pct(hc, .5), pct(hc, .99), pct(hc, 1))
	if p := pct(hc, .95); p > 50*time.Millisecond { // p95: the p99 of 30 samples is the maximum
		t.Errorf("cold load with 500 assignments p95 %v > 50 ms", p)
	}
}

// (e) Revocation: the same process sees it on the next sensitive decision and after Invalidate; ANOTHER connection (a different pool,
// i.e. a different process as far as Postgres is concerned) is seen through the real LISTEN/NOTIFY in < 1 s.
func TestRevocationAcrossConnections(t *testing.T) {
	pool := dbPool(t)
	rng := rand.New(rand.NewSource(11))
	w := buildWorld(t, pool, rng, 1)
	rt := realRuntime(t, pool)
	time.Sleep(300 * time.Millisecond) // listener connected
	ctx := context.Background()
	org := w.orgs[0]
	proj := w.projects[org][0]

	// the writer: an independent pool
	writer, err := pgxpool.New(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	var lat []time.Duration
	probe := adminOnlyAtom(t, false)
	for i := 0; i < 20; i++ {
		u := newUser(t, pool)
		mustExec(t, pool, `INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,'member')`, org, u)
		mustExec(t, pool, `INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,'admin')`, proj, u)
		time.Sleep(150 * time.Millisecond) // let the NOTIFY of the setup arrive so the cache is stable
		ok, err := rt.Engine.Can(ctx, u, org, engine.ProjectScope(proj), probe)
		if err != nil || !ok {
			t.Fatalf("setup: %v %v", ok, err)
		}
		// revoke through the other connection (old path: the project_members trigger bumps the epoch and NOTIFYs)
		start := time.Now()
		if _, err := writer.Exec(ctx, `DELETE FROM project_members WHERE project_id=$1 AND user_id=$2`, proj, u); err != nil {
			t.Fatal(err)
		}
		var seen time.Duration
		for {
			ok, _ := rt.Engine.Can(ctx, u, org, engine.ProjectScope(proj), probe) // non sensitive: relies on NOTIFY
			if !ok {
				seen = time.Since(start)
				break
			}
			if time.Since(start) > 5*time.Second {
				t.Fatal("revocation not seen in 5 s")
			}
			time.Sleep(time.Millisecond)
		}
		lat = append(lat, seen)
		// the strict path never needs the NOTIFY
		u2 := newUser(t, pool)
		mustExec(t, pool, `INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,'member')`, org, u2)
		mustExec(t, pool, `INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,'admin')`, proj, u2)
		if ok, _ := rt.Engine.Can(ctx, u2, org, engine.ProjectScope(proj), sensitiveProjectAtom(t)); !ok {
			t.Fatal("admin must query")
		}
		if _, err := writer.Exec(ctx, `DELETE FROM project_members WHERE project_id=$1 AND user_id=$2`, proj, u2); err != nil {
			t.Fatal(err)
		}
		if ok, _ := rt.Engine.Can(ctx, u2, org, engine.ProjectScope(proj), sensitiveProjectAtom(t)); ok {
			t.Fatal("strict path still allowed right after the revocation")
		}
	}
	t.Logf("revocation seen through NOTIFY by another connection (20 runs): p50=%v p99=%v max=%v", pct(lat, .5), pct(lat, .99), pct(lat, 1))
	if pct(lat, 1) > time.Second {
		t.Errorf("max %v >= 1 s", pct(lat, 1))
	}
}

// adminOnlyAtom returns a project-level permission of the system role admin that deployer does not hold (so revoking an explicit admin
// row removes it whatever the organization policy is), sensitive or not.
func adminOnlyAtom(t *testing.T, sensitive bool) string {
	t.Helper()
	adm, _ := systemtemplates.Project("admin")
	dep, _ := systemtemplates.Project("deployer")
	for _, p := range catalog.All() {
		if p.Sensitive == sensitive && hasScope(p, "project") && adm.Permissions.Has(p.ID) && !dep.Permissions.Has(p.ID) {
			return p.ID
		}
	}
	t.Fatalf("no admin-only project permission with sensitive=%t", sensitive)
	return ""
}

func sensitiveProjectAtom(t *testing.T) string { return adminOnlyAtom(t, true) }
