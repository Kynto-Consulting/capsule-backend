package server

import (
	"bufio"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

func tableEntry(method, route string) (routePerm, bool) {
	if e, ok := routePermissions[method+" "+route]; ok {
		return e, true
	}
	e, ok := routePermissions["ANY "+route]
	return e, ok
}

// Every route the router mounts has a row in routePermissions (a route without one would be closed to scoped tokens but is a
// hole in the contract: CI must stop it).
func TestEveryMountedRouteHasARoutePermissionsRow(t *testing.T) {
	r := newRouter(&config.Config{}, slog.Default(), "test", Deps{})
	n := 0
	_ = chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		n++
		if _, ok := tableEntry(method, route); !ok {
			t.Errorf("mounted route without a routePermissions row: %s %s", method, route)
		}
		return nil
	})
	if n < 200 {
		t.Fatalf("only %d routes mounted", n)
	}
	t.Logf("%d mounted route/method pairs, all with a row (%d rows in the table)", n, len(routePermissions))
}

type goldenRow struct{ method, path, class, old string }

func readGolden(t *testing.T) []goldenRow {
	t.Helper()
	f, err := os.Open("../authz/routes_authz.golden")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []goldenRow
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		c := strings.Split(l, "\t")
		out = append(out, goldenRow{c[0], c[1], c[4], c[5]})
	}
	return out
}

// Every golden row has a row; action rows need atoms of the catalog that come from the old actions the handler checks (never more
// than the old action granted, for every system role), except the approver routes whose decision is the approver list.
func TestRoutePermissionsCoverGolden(t *testing.T) {
	roleSet := func(r authz.Role) catalog.Set {
		var s catalog.Set
		for _, old := range catalog.OldActions() {
			if authz.RoleAllows(r, authz.Action(old)) {
				s = s.Union(catalog.ExpandSet(authz.Action(old)))
			}
		}
		return s
	}
	roles := []authz.Role{authz.RoleViewer, authz.RoleDeployer, authz.RoleAdmin}
	for _, g := range readGolden(t) {
		e, ok := routePermissions[g.method+" "+g.path]
		if !ok {
			t.Errorf("golden row without table row: %s %s", g.method, g.path)
			continue
		}
		for _, p := range e.Perms {
			if !catalog.Has(p) {
				t.Errorf("%s %s: unknown atom %q", g.method, g.path, p)
			}
		}
		if g.class != "action" {
			continue
		}
		if e.Kind == middleware.KindPerm && len(e.Perms) == 0 {
			t.Errorf("%s %s: perm row without atoms", g.method, g.path)
		}
		if e.Kind != middleware.KindPerm {
			continue // session-only rows (POST /user/tokens, git credentials) and shared-secret internals
		}
		olds := strings.Split(g.old, ",")
		var oldSet catalog.Set
		for _, o := range olds {
			oldSet = oldSet.Union(catalog.ExpandSet(authz.Action(o)))
		}
		want := catalog.NewSet(e.Perms...)
		if strings.HasSuffix(g.path, "/approve") || strings.HasSuffix(g.path, "/reject") || strings.Contains(g.path, "/security/sarif/") {
			// approvers are decided by the approver list; the status of an upload is the uploader's own (SPEC 9.2: security:upload)
			continue
		}
		if !oldSet.ContainsAll(want) {
			t.Errorf("%s %s: atoms %v are not in the expansion of the old actions %v", g.method, g.path, e.Perms, olds)
		}
		// never grants a system role more than the handler's old actions did
		for _, r := range roles {
			if roleSet(r).ContainsAll(want) {
				any := false
				for _, o := range olds {
					any = any || authz.RoleAllows(r, authz.Action(o))
				}
				if !any {
					t.Errorf("%s %s: role %s holds the atoms %v but none of the old actions %v", g.method, g.path, r, e.Perms, olds)
				}
			}
		}
	}
}

var phaseP = regexp.MustCompile(`public-repos|git/visibility|git/contributions|^/api/v1/public/|git-public-auth`)

// The table agrees with the x-permission of API.openapi.yaml: same atoms for every operation that has a row; operations without a
// row are exactly those of phase P (atoms outside catalog 99, public API); Planned rows exist in the API.
func TestRoutePermissionsMatchOpenAPI(t *testing.T) {
	b, err := os.ReadFile("../../../docs/permissions/API.openapi.yaml")
	if err != nil {
		t.Skipf("API.openapi.yaml not reachable (backend-only checkout): %v", err)
	}
	type op struct {
		method, path, scope string
		perms               []string
	}
	var ops []op
	var path, method string
	rePath := regexp.MustCompile(`^  (/[^ ]*):$`)
	reMeth := regexp.MustCompile(`^    (get|post|put|patch|delete):`)
	rePerm := regexp.MustCompile(`x-permission: \{ permissions: \[([^\]]*)\], scope: ([a-z]+)`)
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimRight(l, "\r")
		if m := rePath.FindStringSubmatch(l); m != nil {
			path = m[1]
		} else if m := reMeth.FindStringSubmatch(l); m != nil {
			method = strings.ToUpper(m[1])
		} else if m := rePerm.FindStringSubmatch(l); m != nil && path != "" && method != "" {
			var ps []string
			for _, p := range strings.Split(m[1], ",") {
				if p = strings.Trim(strings.TrimSpace(p), `"`); p != "" {
					ps = append(ps, p)
				}
			}
			ops = append(ops, op{method, "/api/v1" + path, m[2], ps})
		}
	}
	if len(ops) < 60 {
		t.Fatalf("parsed only %d operations", len(ops))
	}
	inAPI := map[string]bool{}
	matched, skipped := 0, 0
	for _, o := range ops {
		key := o.method + " " + o.path
		inAPI[key] = true
		e, ok := routePermissions[key]
		if !ok {
			if !phaseP.MatchString(o.path) && !(len(o.perms) > 0 && !allKnown(o.perms)) {
				t.Errorf("API operation without a table row: %s", key)
			}
			skipped++
			continue
		}
		matched++
		got := append([]string(nil), e.Perms...)
		want := append([]string(nil), o.perms...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: table %v, x-permission %v", key, got, want)
		}
		if (o.scope == "self" || o.scope == "public") && e.Kind == middleware.KindPerm {
			t.Errorf("%s: scope %s but the table requires permissions", key, o.scope)
		}
	}
	for k, e := range routePermissions {
		if e.Planned && !inAPI[k] {
			t.Errorf("planned row not in API.openapi.yaml: %s", k)
		}
	}
	t.Logf("%d operations compared, %d left to phase P / not in catalog 99", matched, skipped)
}

func allKnown(ps []string) bool {
	for _, p := range ps {
		if !catalog.Has(p) {
			return false
		}
	}
	return true
}

var paramRe = regexp.MustCompile(`\{[^}]*\}`)

func concrete(pattern string, project uuid.UUID) string {
	return concreteOrg(pattern, uuid.MustParse("00000000-0000-0000-0000-0000000000a1"), project)
}

func concreteOrg(pattern string, org, project uuid.UUID) string {
	p := strings.Replace(pattern, "{orgID}", org.String(), 1)
	p = strings.Replace(p, "{projectID}", project.String(), 1)
	p = paramRe.ReplaceAllString(p, "x1")
	return strings.Replace(p, "/*", "/s/t", 1)
}

// The pattern matcher of the gate resolves every concrete path to the row of its pattern.
func TestRouteTableMatchesConcretePaths(t *testing.T) {
	rt := newRouteTable()
	pid := uuid.New()
	for k, v := range routePermissions {
		method, pattern, _ := strings.Cut(k, " ")
		if method == "ANY" {
			method = "GET"
		}
		got, ok := rt.Lookup(method, concrete(pattern, pid))
		if !ok {
			t.Errorf("no match for %s", k)
			continue
		}
		if got.Kind != v.Kind || strings.Join(got.Perms, ",") != strings.Join(v.Perms, ",") {
			t.Errorf("%s resolves to %+v, want %+v", k, got, v)
		}
	}
}

// Route by route (MIGRATION 5.4): the table gate in v2 decides exactly like middleware.TokenAllows for every route, token scope
// and project relation.
func TestTokenGateV2EqualsTokenAllows(t *testing.T) {
	gate := &middleware.TokenGate{Routes: newRouteTable(), Mode: func(_ context.Context, _ uuid.UUID) string { return "v2" }}
	proj, other := uuid.New(), uuid.New()
	scopeSets := []string{"*", "", "deploy", "security:write", "deploy,security:write", "deploy, security:write", "bogus", "deploy,bogus"}
	type rel struct {
		name string
		tok  *uuid.UUID
		path uuid.UUID
	}
	rels := []rel{{"match", &proj, proj}, {"other", &other, proj}, {"noproject", nil, proj}}
	checked, allowed := 0, 0
	for k := range routePermissions {
		method, pattern, _ := strings.Cut(k, " ")
		if method == "ANY" {
			method = "GET"
		}
		for _, sc := range scopeSets {
			for _, rl := range rels {
				tok := &domain.APIToken{ID: uuid.New(), UserID: uuid.New(), Scopes: sc, ProjectID: rl.tok}
				path := concrete(pattern, rl.path)
				req := httptest.NewRequest(method, path, nil)
				old := middleware.TokenAllows(tok, method, path)
				nw := gate.Allow(req, tok)
				checked++
				if old {
					allowed++
				}
				if old != nw {
					t.Errorf("%s %s scopes=%q project=%s: TokenAllows=%t gate=%t", method, path, sc, rl.name, old, nw)
				}
			}
		}
	}
	t.Logf("%d (route x scope x project) cases equal; %d of them allowed", checked, allowed)
}

// Scoped tokens are closed on rows that are not "perm" rows and on unknown routes.
func TestTokenGateClosedByDefault(t *testing.T) {
	gate := &middleware.TokenGate{Routes: newRouteTable(), Mode: func(_ context.Context, _ uuid.UUID) string { return "v2" }}
	proj := uuid.New()
	tok := &domain.APIToken{ID: uuid.New(), Scopes: "deploy", ProjectID: &proj}
	for _, p := range []string{"/api/v1/user/tokens", "/api/v1/orgs", "/api/v1/this/route/does/not/exist", "/api/v1/auth/me"} {
		if gate.Allow(httptest.NewRequest("GET", p, nil), tok) {
			t.Errorf("scoped token passed %s", p)
		}
	}
	// a token with explicit permissions and a route without a row: 403 (closed)
	ex := &domain.APIToken{ID: uuid.New(), Permissions: []string{"deployment:read"}}
	if gate.Allow(httptest.NewRequest("GET", "/api/v1/orgs/"+uuid.NewString()+"/nothing", nil), ex) {
		t.Error("explicit token passed a route without a row")
	}
	// explicit permissions: only the atoms it holds, in any project of its organization
	org := uuid.New()
	ex.OrgID = &org
	okPath := "/api/v1/orgs/" + org.String() + "/projects/" + proj.String() + "/deployments"
	if !gate.Allow(httptest.NewRequest("GET", okPath, nil), ex) {
		t.Error("explicit token denied a route it holds")
	}
	if gate.Allow(httptest.NewRequest("POST", okPath, nil), ex) {
		t.Error("explicit token passed deployment:create it does not hold")
	}
	if gate.Allow(httptest.NewRequest("GET", "/api/v1/orgs/"+uuid.NewString()+"/projects/"+proj.String()+"/deployments", nil), ex) {
		t.Error("explicit token crossed to another organization")
	}
}
