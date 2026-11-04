//go:build dbtest

package server

import (
	"context"
	"math/rand"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
	"github.com/kynto/capsule/backend/internal/authz/wire"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"log/slog"
)

type tokUser struct {
	name string
	id   uuid.UUID
}

func tokPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	u := os.Getenv("TEST_DATABASE_URL")
	if u == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := repository.RunMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.SeedSystemTemplates(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func q1(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&id); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return id
}

func ex(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// (f) A token never exceeds its user. For every route of the table, every user shape and every token kind (legacy deploy,
// security:write, both, "*", and 10 000 random explicit subsets): decision(token) = gate AND DecideToken (Effective(user) ∩ token) implies
// the user holds every atom of the route.
func TestTokenNeverExceedsUser(t *testing.T) {
	pool := tokPool(t)
	ctx := context.Background()
	owner := q1(t, pool, `INSERT INTO users (email, password_hash, name) VALUES ($1,'x','T') RETURNING id`, uuid.NewString()+"@x.io")
	org := q1(t, pool, `INSERT INTO organizations (name, slug, owner_id, project_access_mode) VALUES ('O',$2,$1,'restricted') RETURNING id`, owner, "o-"+uuid.NewString())
	var projects []uuid.UUID
	for i := 0; i < 4; i++ {
		projects = append(projects, q1(t, pool, `INSERT INTO projects (org_id, name, slug, repo_url, branch, runtime) VALUES ($1,'P',$2,'https://e.com/r.git','main','node') RETURNING id`, org, "p-"+uuid.NewString()))
	}
	mk := func(name, role string, rows map[int]string) tokUser {
		u := q1(t, pool, `INSERT INTO users (email, password_hash, name) VALUES ($1,'x','T') RETURNING id`, uuid.NewString()+"@x.io")
		ex(t, pool, `INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,$3)`, org, u, role)
		for i, r := range rows {
			ex(t, pool, `INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,$3)`, projects[i], u, r)
		}
		return tokUser{name, u}
	}
	users := []tokUser{
		mk("owner", "owner", nil), mk("admin", "admin", nil),
		mk("member-none", "member", nil),
		mk("member-viewer-p0", "member", map[int]string{0: "viewer"}),
		mk("member-deployer-p0", "member", map[int]string{0: "deployer"}),
		mk("member-admin-p0", "member", map[int]string{0: "admin", 1: "viewer"}),
		mk("readonly-admin-row", "readonly", map[int]string{0: "admin"}),
		mk("readonly-none", "readonly", nil),
		{"stranger", q1(t, pool, `INSERT INTO users (email, password_hash, name) VALUES ($1,'x','T') RETURNING id`, uuid.NewString()+"@x.io")},
	}
	rt, err := wire.Start(ctx, slog.Default(), pool)
	if err != nil {
		t.Fatal(err)
	}
	gate := &middleware.TokenGate{Routes: newRouteTable(), Mode: func(context.Context, uuid.UUID) string { return "v2" }}

	userHas := func(u uuid.UUID, p uuid.UUID, perms []string) bool {
		acc, set, err := rt.Engine.EffectiveStrict(ctx, u, org, engine.ProjectScope(p))
		if err != nil || !acc.Member || acc.Hidden {
			return false
		}
		want, unknown := catalog.ParseSet(perms)
		return len(unknown) == 0 && set.ContainsAll(want)
	}

	type route struct {
		method, pattern string
		perms           []string
	}
	var routes []route
	for k, v := range routePermissions {
		method, pattern, _ := strings.Cut(k, " ")
		if v.Planned || v.Kind != middleware.KindPerm || !strings.Contains(pattern, "{projectID}") || method == "ANY" {
			continue
		}
		routes = append(routes, route{method, pattern, v.Perms})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].method+routes[i].pattern < routes[j].method+routes[j].pattern })

	decide := func(u tokUser, tok *domain.APIToken, r route, project uuid.UUID) (tokenOK, userOK bool) {
		path := concreteOrg(r.pattern, org, project)
		req := httptest.NewRequest(r.method, path, nil)
		userOK = userHas(u.id, project, r.perms)
		if !gate.Allow(req, tok) {
			return false, userOK
		}
		okd, err := wire.DecideToken(ctx, rt.Engine, middleware.TokenInfoFor(tok), u.id, org, project, r.perms...)
		if err != nil {
			t.Fatal(err)
		}
		return okd, userOK
	}

	// 1. legacy tokens, by route
	type kind struct {
		name   string
		scopes string
	}
	kinds := []kind{{"deploy", "deploy"}, {"security:write", "security:write"}, {"deploy+security:write", "deploy,security:write"}, {"*", "*"}}
	cases, allowed := 0, 0
	for _, u := range users {
		for _, kd := range kinds {
			for _, pi := range []int{0, 1, 2} {
				p := projects[pi]
				tok := &domain.APIToken{ID: uuid.New(), UserID: u.id, Scopes: kd.scopes, ProjectID: &p}
				if kd.scopes == "*" {
					tok.ProjectID = nil
				}
				for _, r := range routes {
					tokenOK, userOK := decide(u, tok, r, p)
					cases++
					if tokenOK {
						allowed++
					}
					if tokenOK && !userOK {
						t.Fatalf("token exceeds user: user=%s token=%s project=p%d %s %s needs %v", u.name, kd.name, pi, r.method, r.pattern, r.perms)
					}
					// the legacy "deploy" and "security:write" tokens never pass a route the old middleware denies
					if kd.scopes != "*" && tokenOK && !middleware.TokenAllows(tok, r.method, concreteOrg(r.pattern, org, p)) {
						t.Fatalf("token passes a route TokenAllows denies: %s %s (%s)", r.method, r.pattern, kd.name)
					}
				}
			}
		}
	}
	t.Logf("legacy tokens: %d (user x token x project x route) cases, %d allowed, 0 exceed the user", cases, allowed)

	// 2. targeted expectations
	find := func(method, suffix string) route {
		for _, r := range routes {
			if r.method == method && strings.HasSuffix(r.pattern, suffix) {
				return r
			}
		}
		t.Fatalf("route %s %s not in table", method, suffix)
		return route{}
	}
	byName := map[string]tokUser{}
	for _, u := range users {
		byName[u.name] = u
	}
	p0 := projects[0]
	deployTok := func(u tokUser) *domain.APIToken {
		return &domain.APIToken{ID: uuid.New(), UserID: u.id, Scopes: "deploy", ProjectID: &p0}
	}
	secTok := func(u tokUser) *domain.APIToken {
		return &domain.APIToken{ID: uuid.New(), UserID: u.id, Scopes: "security:write", ProjectID: &p0}
	}
	expect := func(name string, u tokUser, tok *domain.APIToken, method, suffix string, want bool) {
		got, _ := decide(u, tok, find(method, suffix), p0)
		if got != want {
			t.Errorf("%s: %s %s = %t, want %t", name, method, suffix, got, want)
		}
	}
	expect("viewer + deploy token cannot create a deployment", byName["member-viewer-p0"], deployTok(byName["member-viewer-p0"]), "POST", "/deployments", false)
	expect("viewer + deploy token can read deployments", byName["member-viewer-p0"], deployTok(byName["member-viewer-p0"]), "GET", "/deployments", true)
	expect("deployer + deploy token creates a deployment", byName["member-deployer-p0"], deployTok(byName["member-deployer-p0"]), "POST", "/deployments", true)
	expect("admin + deploy token cannot write env", byName["member-admin-p0"], deployTok(byName["member-admin-p0"]), "PUT", "/env", false)
	expect("admin + deploy token cannot delete the project", byName["member-admin-p0"], deployTok(byName["member-admin-p0"]), "DELETE", "/projects/{projectID}", false)
	expect("admin + security:write uploads SARIF", byName["member-admin-p0"], secTok(byName["member-admin-p0"]), "POST", "/security/sarif", true)
	expect("admin + security:write cannot deploy", byName["member-admin-p0"], secTok(byName["member-admin-p0"]), "POST", "/deployments", false)
	expect("viewer + security:write cannot upload SARIF", byName["member-viewer-p0"], secTok(byName["member-viewer-p0"]), "POST", "/security/sarif", false)
	expect("stranger + deploy token gets nothing", byName["stranger"], deployTok(byName["stranger"]), "GET", "/deployments", false)
	other := projects[1]
	wrong := &domain.APIToken{ID: uuid.New(), UserID: byName["member-admin-p0"].id, Scopes: "deploy", ProjectID: &other}
	if got, _ := decide(byName["member-admin-p0"], wrong, find("GET", "/deployments"), p0); got {
		t.Error("a deploy token of another project passed")
	}

	// 3. 10 000 random explicit tokens
	var tokenable []string
	for _, p := range catalog.All() {
		if p.Tokenable {
			tokenable = append(tokenable, p.ID)
		}
	}
	rng := rand.New(rand.NewSource(20261104))
	rc, ra := 0, 0
	for i := 0; i < 10000; i++ {
		u := users[rng.Intn(len(users))]
		var perms []string
		for j, n := 0, 1+rng.Intn(30); j < n; j++ {
			perms = append(perms, tokenable[rng.Intn(len(tokenable))])
		}
		tok := &domain.APIToken{ID: uuid.New(), UserID: u.id, Permissions: perms, OrgID: &org}
		if rng.Intn(3) == 0 {
			p := projects[rng.Intn(4)]
			tok.ProjectID = &p
		}
		r := routes[rng.Intn(len(routes))]
		project := projects[rng.Intn(4)]
		if tok.ProjectID != nil && rng.Intn(2) == 0 {
			project = *tok.ProjectID
		}
		tokenOK, userOK := decide(u, tok, r, project)
		rc++
		if tokenOK {
			ra++
			if !userOK {
				t.Fatalf("explicit token exceeds user %s on %s %s (%v)", u.name, r.method, r.pattern, r.perms)
			}
			// and it holds every atom of the route
			if !middleware.TokenInfoFor(tok).Set.ContainsAll(catalog.NewSet(r.perms...)) {
				t.Fatalf("token passed a route whose atoms it does not hold: %s %s", r.method, r.pattern)
			}
		}
	}
	t.Logf("explicit tokens: %d random cases, %d allowed, 0 exceed the user or the token", rc, ra)
}
