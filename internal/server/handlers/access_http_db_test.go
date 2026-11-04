//go:build dbtest

package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/access"
	"github.com/kynto/capsule/backend/internal/authz/engine"
	"github.com/kynto/capsule/backend/internal/authz/systemtemplates"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server"
	"github.com/kynto/capsule/backend/internal/server/handlers"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// HTTP-level tests of the permission-management API against a real Postgres (TEST_DATABASE_URL, local only).

type httpEnv struct {
	t      *testing.T
	pool   *pgxpool.Pool
	router *chi.Mux
}

func newHTTPEnv(t *testing.T) *httpEnv {
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
	store := repository.NewAccessStore(pool)
	eng := engine.New(store.EngineStore(), engine.Options{})
	handlers.WireAccess(access.New(store, eng, nil), nil)
	t.Cleanup(func() { handlers.WireAccess(nil, nil) })
	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if id, err := uuid.Parse(req.Header.Get("X-Test-User")); err == nil {
					req = req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: id}))
				}
				next.ServeHTTP(w, req)
			})
		})
		handlers.MountAccess(r)
	})
	return &httpEnv{t: t, pool: pool, router: r}
}

func (h *httpEnv) exec(sql string, args ...any) {
	h.t.Helper()
	if _, err := h.pool.Exec(context.Background(), sql, args...); err != nil {
		h.t.Fatalf("%s: %v", sql, err)
	}
}

func (h *httpEnv) one(sql string, args ...any) uuid.UUID {
	h.t.Helper()
	var id uuid.UUID
	if err := h.pool.QueryRow(context.Background(), sql, args...).Scan(&id); err != nil {
		h.t.Fatalf("%s: %v", sql, err)
	}
	return id
}

func (h *httpEnv) user() uuid.UUID {
	return h.one(`INSERT INTO users (email, password_hash, name) VALUES ($1,'x','T') RETURNING id`, uuid.NewString()+"@x.io")
}

func (h *httpEnv) member(org uuid.UUID, role string) uuid.UUID {
	u := h.user()
	h.exec(`INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,$3)`, org, u, role)
	return u
}

func (h *httpEnv) project(org uuid.UUID) uuid.UUID {
	return h.one(`INSERT INTO projects (org_id, name, slug, repo_url, branch, runtime) VALUES ($1,'P',$2,'https://example.com/r.git','main','node') RETURNING id`, org, "p-"+uuid.NewString())
}

type reply struct {
	*httptest.ResponseRecorder
}

func (r reply) json() map[string]any {
	var m map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &m)
	return m
}

func (r reply) errBody() (code, detail string, details map[string]any) {
	e, _ := r.json()["error"].(map[string]any)
	code, _ = e["code"].(string)
	details, _ = e["details"].(map[string]any)
	detail, _ = details["code"].(string)
	return
}

func (h *httpEnv) do(method, path string, user uuid.UUID, body any, hdr ...string) reply {
	h.t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = bytes.NewReader([]byte(b))
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			h.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "/api/v1"+path, rd)
	req.RemoteAddr = "198.51.100.9:4455"
	if user != uuid.Nil {
		req.Header.Set("X-Test-User", user.String())
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return reply{rec}
}

func want(t *testing.T, r reply, status int) {
	t.Helper()
	if r.Code != status {
		t.Fatalf("status %d, want %d: %s", r.Code, status, r.Body.String())
	}
}

func TestAccessAPIEndToEnd(t *testing.T) {
	h := newHTTPEnv(t)
	org := h.one(`INSERT INTO organizations (name, slug, owner_id, project_access_mode) VALUES ('O',$1,$2,'open') RETURNING id`, "o-"+uuid.NewString(), h.user())
	owner := h.one(`SELECT owner_id FROM organizations WHERE id = $1`, org)
	h.exec(`INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,'owner')`, org, owner)
	proj := h.project(org)
	member := h.member(org, "member")
	h.member(org, "member") // relies on the open base: the restricted preview must name them
	o := "/orgs/" + org.String()

	// unauthenticated, bad ids, bad bodies
	want(t, h.do("GET", o+"/templates", uuid.Nil, nil), 401)
	want(t, h.do("GET", "/orgs/not-a-uuid/templates", owner, nil), 400)
	want(t, h.do("POST", o+"/templates", owner, "{not json"), 400)
	want(t, h.do("POST", o+"/templates", owner, ""), 400)
	big := `{"kind":"project","slug":"big","name":"` + strings.Repeat("x", 2<<20) + `","permissions":["project:view"]}`
	r := h.do("POST", o+"/templates", owner, big)
	want(t, r, 413)
	if c, _, _ := r.errBody(); c != "PAYLOAD_TOO_LARGE" {
		t.Fatalf("413 code %s", c)
	}

	// catalog: ETag and 304
	r = h.do("GET", "/permissions/catalog", member, nil)
	want(t, r, 200)
	var cat struct {
		CatalogVersion int              `json:"catalog_version"`
		Permissions    []map[string]any `json:"permissions"`
		Groups         []map[string]any `json:"groups"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &cat)
	if cat.CatalogVersion != 1 || len(cat.Permissions) != 99 || len(cat.Groups) == 0 {
		t.Fatalf("catalog: version %d, %d permissions", cat.CatalogVersion, len(cat.Permissions))
	}
	want(t, h.do("GET", "/permissions/catalog", member, nil, "If-None-Match", r.Header().Get("ETag")), 304)

	// templates: create with a key, replay, conflict, 422 shape, publish dry run and real, versions, diff
	body := map[string]any{"kind": "project", "slug": "readers", "name": "Readers", "permissions": []string{"project:view", "log:read"}}
	r1 := h.do("POST", o+"/templates", owner, body, "Idempotency-Key", "tpl-1")
	want(t, r1, 201)
	r2 := h.do("POST", o+"/templates", owner, body, "Idempotency-Key", "tpl-1")
	want(t, r2, 201)
	if r2.Header().Get("Idempotency-Replayed") != "true" || r1.json()["id"] != r2.json()["id"] {
		t.Fatalf("replay: %s vs %s", r1.Body.String(), r2.Body.String())
	}
	body2 := map[string]any{"kind": "project", "slug": "readers2", "name": "Readers", "permissions": []string{"project:view"}}
	r3 := h.do("POST", o+"/templates", owner, body2, "Idempotency-Key", "tpl-1")
	want(t, r3, 409)
	if c, _, _ := r3.errBody(); c != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("code %s", c)
	}
	r = h.do("POST", o+"/templates", owner, map[string]any{"kind": "project", "slug": "bad", "name": "Bad", "permissions": []string{"*"}})
	want(t, r, 422)
	if c, _, d := r.errBody(); c != "VALIDATION_ERROR" || d["fields"] == nil {
		t.Fatalf("422 shape: %s", r.Body.String())
	}
	tplID := r1.json()["id"].(string)
	pub := map[string]any{"name": "Readers", "permissions": []string{"project:view", "log:read", "deployment:read"}}
	r = h.do("PUT", o+"/templates/"+tplID+"?dry_run=true", owner, pub)
	want(t, r, 200)
	if r.json()["published"] != false || r.json()["impact"] == nil {
		t.Fatalf("dry run: %s", r.Body.String())
	}
	r = h.do("PUT", o+"/templates/"+tplID, owner, pub)
	want(t, r, 200)
	if r.json()["published"] != true {
		t.Fatalf("publish: %s", r.Body.String())
	}
	r = h.do("GET", o+"/templates/"+tplID+"/versions", owner, nil)
	want(t, r, 200)
	r = h.do("GET", o+"/templates/"+tplID+"/versions/1/diff/2", owner, nil)
	want(t, r, 200)
	if d, _ := r.json()["added"].([]any); len(d) != 1 || d[0] != "deployment:read" {
		t.Fatalf("diff: %s", r.Body.String())
	}
	want(t, h.do("GET", o+"/templates/"+tplID+"/versions/1/diff/x", owner, nil), 400)
	r = h.do("GET", o+"/templates?kind=project", owner, nil)
	want(t, r, 200)
	sysID := systemtemplates.ID(systemtemplates.KindProject, "viewer").String()
	r = h.do("PUT", o+"/templates/"+sysID, owner, pub)
	want(t, r, 409)
	if _, d, _ := r.errBody(); d != "SYSTEM_TEMPLATE" {
		t.Fatalf("detail %s", d)
	}
	want(t, h.do("GET", o+"/templates/"+uuid.NewString(), owner, nil), 404)

	// groups
	r = h.do("POST", o+"/groups", owner, map[string]any{"slug": "ops", "name": "Ops"})
	want(t, r, 201)
	gid := r.json()["id"].(string)
	want(t, h.do("POST", o+"/groups", owner, map[string]any{"slug": "ops", "name": "Ops"}), 409)
	want(t, h.do("PATCH", o+"/groups/"+gid, owner, map[string]any{"name": "Operations"}), 200)
	want(t, h.do("PATCH", o+"/groups/"+gid, owner, map[string]any{"slug": "other"}), 422)
	r = h.do("POST", o+"/groups/"+gid+"/members", owner, map[string]any{"user_ids": []string{member.String()}})
	want(t, r, 200)
	r = h.do("GET", o+"/groups/"+gid+"/members", owner, nil)
	want(t, r, 200)
	if d, _ := r.json()["data"].([]any); len(d) != 1 {
		t.Fatalf("members: %s", r.Body.String())
	}
	want(t, h.do("POST", o+"/groups/"+gid+"/members", owner, map[string]any{"user_ids": []string{uuid.NewString()}}), 422)
	r = h.do("GET", o+"/groups", owner, nil)
	want(t, r, 200)
	r = h.do("GET", o+"/groups/"+gid, owner, nil)
	want(t, r, 200)

	// assignments
	ai := map[string]any{"subject_type": "group", "subject_id": gid, "scope": map[string]any{"type": "project", "id": proj.String()}, "template_id": tplID, "reason": "qa"}
	r = h.do("POST", o+"/assignments", owner, ai, "Idempotency-Key", "asg-1")
	want(t, r, 201)
	aid := r.json()["id"].(string)
	want(t, h.do("POST", o+"/assignments", owner, ai, "Idempotency-Key", "asg-1"), 201)
	r = h.do("GET", o+"/assignments?scope_type=project&scope_id="+proj.String(), owner, nil)
	want(t, r, 200)
	if d, _ := r.json()["data"].([]any); len(d) != 1 {
		t.Fatalf("assignments: %s", r.Body.String())
	}
	want(t, h.do("GET", o+"/assignments?expiring_within=7x", owner, nil), 422)
	want(t, h.do("GET", o+"/assignments/"+aid, owner, nil), 200)
	exp := time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
	r = h.do("PATCH", o+"/assignments/"+aid, owner, map[string]any{"expires_at": exp, "reason": "temporary"})
	want(t, r, 200)
	if r.json()["status"] != "active" || r.json()["reason"] != "temporary" {
		t.Fatalf("patch: %s", r.Body.String())
	}
	want(t, h.do("PATCH", o+"/assignments/"+aid, owner, map[string]any{"nope": 1}), 400)
	r = h.do("GET", o+"/projects/"+proj.String()+"/access", owner, nil)
	want(t, r, 200)
	r = h.do("GET", o+"/users/"+member.String()+"/permissions?expand=projects", owner, nil)
	want(t, r, 200)
	r = h.do("POST", o+"/access/simulate", owner, map[string]any{"user_id": member, "permission": "log:read", "scope": map[string]any{"type": "project", "id": proj}})
	want(t, r, 200)
	if r.json()["allowed"] != true || r.json()["reason"] != "granted" {
		t.Fatalf("simulate: %s", r.Body.String())
	}
	want(t, h.do("POST", o+"/access/simulate", owner, map[string]any{"user_id": member, "permission": "not:real"}), 422)
	r = h.do("PUT", o+"/projects/"+proj.String()+"/access-override", owner, map[string]any{"mode": "restricted"})
	want(t, r, 409)
	if _, d, det := r.errBody(); d != "WOULD_HIDE" || det["would_hide"] == nil {
		t.Fatalf("WOULD_HIDE: %s", r.Body.String())
	}
	want(t, h.do("PUT", o+"/projects/"+proj.String()+"/access-override?confirm=true", owner, map[string]any{"mode": "restricted"}), 200)
	want(t, h.do("PUT", o+"/projects/"+proj.String()+"/access-override", owner, map[string]any{"mode": nil}), 200)
	want(t, h.do("PUT", o+"/members/"+member.String()+"/template", owner, map[string]any{"template": "admin"}), 200)
	r = h.do("PUT", o+"/members/"+member.String()+"/template", owner, map[string]any{"template": "nope"})
	want(t, r, 422)
	want(t, h.do("DELETE", o+"/assignments/"+aid, owner, nil), 204)
	want(t, h.do("DELETE", o+"/assignments/"+aid, owner, nil), 404)
	want(t, h.do("DELETE", o+"/groups/"+gid+"/members/"+member.String(), owner, nil), 204)
	want(t, h.do("DELETE", o+"/groups/"+gid, owner, nil), 204)
	want(t, h.do("DELETE", o+"/templates/"+tplID, owner, nil), 204)

	// audit: json and csv (csv also needs audit:export, which the owner has)
	r = h.do("GET", o+"/access-audit?action=access.assignment.*", owner, nil)
	want(t, r, 200)
	rows, _ := r.json()["data"].([]any)
	if len(rows) < 3 {
		t.Fatalf("audit rows: %d", len(rows))
	}
	r = h.do("GET", o+"/access-audit?format=csv&action=access.template.*", owner, nil)
	want(t, r, 200)
	if !strings.HasPrefix(r.Body.String(), "id,created_at,action") || r.Header().Get("Content-Type") != "text/csv; charset=utf-8" {
		t.Fatalf("csv: %s", r.Body.String()[:80])
	}
	want(t, h.do("GET", o+"/access-audit?format=xml", owner, nil), 422)
	r = h.do("GET", o+"/access-audit?limit=1", owner, nil)
	if r.json()["next_cursor"] == nil {
		t.Fatalf("pagination cursor missing: %s", r.Body.String())
	}

	// /me/permissions: ETag, 304, epoch header, explain
	r = h.do("GET", "/me/permissions?org="+org.String(), member, nil)
	want(t, r, 200)
	etag := r.Header().Get("ETag")
	if etag == "" || r.Header().Get("X-Access-Epoch") == "" || !strings.Contains(r.Header().Get("Cache-Control"), "must-revalidate") {
		t.Fatalf("headers: %v", r.Header())
	}
	want(t, h.do("GET", "/me/permissions?org="+org.String(), member, nil, "If-None-Match", etag), 304)
	want(t, h.do("GET", "/me/permissions?org="+uuid.NewString(), member, nil), 404)
	want(t, h.do("GET", "/me/permissions?org="+org.String()+"&project="+uuid.NewString(), member, nil), 404)
	r = h.do("GET", "/me/permissions/explain?org="+org.String()+"&permission=log:read&scope_type=project&scope_id="+proj.String(), member, nil)
	want(t, r, 200)
	if _, ok := r.json()["trace"].([]any); !ok {
		t.Fatalf("explain: %s", r.Body.String())
	}
	want(t, h.do("GET", "/me/permissions/explain?org="+org.String()+"&permission=log:read&scope_type=project&scope_id="+uuid.NewString(), member, nil), 404)
}

// For every mounted route: it has a row in routePermissions, a person without the permission gets the 403 PERMISSION_DENIED naming
// that permission, a stranger gets "not a member", and a non-visible resource does not change the shape of the answer.
func TestAccessRoutesEnforceTheirTableRow(t *testing.T) {
	h := newHTTPEnv(t)
	owner := h.user()
	org := h.one(`INSERT INTO organizations (name, slug, owner_id, project_access_mode) VALUES ('O',$1,$2,'open') RETURNING id`, "o-"+uuid.NewString(), owner)
	h.exec(`INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,'owner')`, org, owner)
	proj := h.project(org)
	readonly := h.member(org, "readonly")
	stranger := h.user()
	target := h.member(org, "member") // the {userID} of the routes: never the actor
	tpl := h.one(`INSERT INTO role_templates (org_id, kind, slug, name) VALUES ($1,'project','tt','tt') RETURNING id`, org)
	h.exec(`INSERT INTO role_template_versions (template_id, version, permissions) VALUES ($1,1,'{project:view}')`, tpl)
	grp := h.one(`INSERT INTO groups (org_id, slug, name) VALUES ($1,'gg','gg') RETURNING id`, org)
	asg := h.one(`INSERT INTO access_assignments (org_id, subject_type, subject_id, scope_type, scope_id, template_id) VALUES ($1,'group',$2,'project',$3,$4) RETURNING id`, org, grp, proj, tpl)

	sub := strings.NewReplacer("{orgID}", org.String(), "{templateID}", tpl.String(), "{groupID}", grp.String(), "{userID}", target.String(),
		"{assignmentID}", asg.String(), "{projectID}", proj.String(), "{from}", "1", "{to}", "1")
	bodies := map[string]any{
		"POST /orgs/{orgID}/templates":                           map[string]any{"kind": "project", "slug": "zz", "name": "zz", "permissions": []string{"project:view"}},
		"PUT /orgs/{orgID}/templates/{templateID}":               map[string]any{"name": "tt", "permissions": []string{"project:view", "log:read"}},
		"POST /orgs/{orgID}/groups":                              map[string]any{"slug": "zz", "name": "zz"},
		"PATCH /orgs/{orgID}/groups/{groupID}":                   map[string]any{"name": "zz"},
		"POST /orgs/{orgID}/groups/{groupID}/members":            map[string]any{"user_ids": []string{readonly.String()}},
		"POST /orgs/{orgID}/assignments":                         map[string]any{"subject_type": "user", "subject_id": readonly.String(), "scope": map[string]any{"type": "project", "id": proj.String()}, "template_id": tpl.String()},
		"PATCH /orgs/{orgID}/assignments/{assignmentID}":         map[string]any{"reason": "x"},
		"PUT /orgs/{orgID}/projects/{projectID}/access-override": map[string]any{"mode": "open"},
		"POST /orgs/{orgID}/access/simulate":                     map[string]any{"user_id": readonly.String(), "permission": "project:view"},
		"PUT /orgs/{orgID}/members/{userID}/template":            map[string]any{"template": "admin"},
	}
	table := server.RouteTable()
	var routes [][2]string
	_ = chi.Walk(h.router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, [2]string{method, strings.TrimPrefix(route, "/api/v1")})
		return nil
	})
	sort.Slice(routes, func(i, j int) bool { return routes[i][1]+routes[i][0] < routes[j][1]+routes[j][0] })
	if len(routes) < 29 {
		t.Fatalf("only %d routes mounted", len(routes))
	}
	checked := 0
	var ownerCalls []func()
	var deletes []bool
	for _, rt := range routes {
		method, pattern := rt[0], rt[1]
		entry, ok := table.Lookup(method, "/api/v1"+sub.Replace(pattern))
		if !ok {
			t.Errorf("%s %s has no row in routePermissions", method, pattern)
			continue
		}
		var body any
		if b, ok := bodies[method+" "+pattern]; ok {
			body = b
		}
		path := sub.Replace(pattern)
		if !strings.Contains(pattern, "{orgID}") {
			continue // /permissions/catalog and /me/* are self-scope; covered by the end-to-end test
		}
		// a stranger is not a member
		r := h.do(method, path, stranger, body)
		if r.Code != 403 {
			t.Errorf("%s %s: stranger got %d: %s", method, pattern, r.Code, r.Body.String())
		}
		if c, _, _ := r.errBody(); c != "FORBIDDEN" {
			t.Errorf("%s %s: stranger code %s", method, pattern, c)
		}
		// a read-only member lacks every permission of these routes
		r = h.do(method, path, readonly, body)
		if r.Code != 403 {
			t.Errorf("%s %s: readonly got %d: %s", method, pattern, r.Code, r.Body.String())
			continue
		}
		_, detail, details := r.errBody()
		if detail != "PERMISSION_DENIED" {
			t.Errorf("%s %s: detail code %q", method, pattern, detail)
			continue
		}
		if len(entry.Perms) > 0 && details["permission"] != entry.Perms[0] {
			t.Errorf("%s %s: handler asked %v, routePermissions says %v", method, pattern, details["permission"], entry.Perms)
		}
		// the owner is tried after every denial check (the calls change the world, deletions last): never 401/403
		m, pat, pth, bdy := method, pattern, path, body
		ownerCalls = append(ownerCalls, func() {
			if r := h.do(m, pth, owner, bdy); r.Code == 401 || r.Code == 403 {
				t.Errorf("%s %s: owner got %d: %s", m, pat, r.Code, r.Body.String())
			}
		})
		deletes = append(deletes, m == "DELETE")
		checked++
	}
	for pass := 0; pass < 2; pass++ {
		for i, call := range ownerCalls {
			if deletes[i] == (pass == 1) {
				call()
			}
		}
	}
	t.Logf("%d routes mounted; %d organization routes checked against routePermissions (stranger 403, member 403 with the table's permission, owner allowed)", len(routes), checked)
}

func TestMePermissionsHTTPLatency(t *testing.T) {
	h := newHTTPEnv(t)
	owner := h.user()
	org := h.one(`INSERT INTO organizations (name, slug, owner_id) VALUES ('O',$1,$2) RETURNING id`, "o-"+uuid.NewString(), owner)
	h.exec(`INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,'owner')`, org, owner)
	h.exec(`INSERT INTO projects (org_id, name, slug, repo_url, branch, runtime) SELECT $1, 'P', 'p-' || g || '-' || substr(md5(random()::text),1,8), 'https://example.com/r.git', 'main', 'node' FROM generate_series(1, 500) g`, org)
	r := h.do("GET", "/me/permissions?expand=projects", owner, nil)
	want(t, r, 200)
	etag := r.Header().Get("ETag")
	var ds, ds304 []time.Duration
	for i := 0; i < 1500; i++ {
		t0 := time.Now()
		rr := h.do("GET", "/me/permissions?expand=projects", owner, nil)
		ds = append(ds, time.Since(t0))
		if rr.Code != 200 {
			t.Fatal(rr.Code)
		}
		t0 = time.Now()
		rr = h.do("GET", "/me/permissions?expand=projects", owner, nil, "If-None-Match", etag)
		ds304 = append(ds304, time.Since(t0))
		if rr.Code != 304 {
			t.Fatal(rr.Code)
		}
	}
	p := func(ds []time.Duration, q int) time.Duration {
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[len(ds)*q/100]
	}
	t.Logf("GET /me/permissions (cached, 500 projects, in-process HTTP): 200 p50 %v p99 %v; 304 p50 %v p99 %v", p(ds, 50), p(ds, 99), p(ds304, 50), p(ds304, 99))
	if p(ds, 99) > 20*time.Millisecond || p(ds304, 99) > 20*time.Millisecond {
		t.Fatalf("p99 over 20 ms")
	}
}
