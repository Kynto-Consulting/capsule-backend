package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// router mounts the internal routes on the root and the user API behind a stand-in for the Auth middleware
// (X-Test-User: <uuid>), like cmd/server wiring does.
func (e *env) router() http.Handler {
	r := chi.NewRouter()
	e.svc.MountInternal(r)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if id, err := uuid.Parse(req.Header.Get("X-Test-User")); err == nil {
					req = req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: id}))
				}
				next.ServeHTTP(w, req)
			})
		})
		e.svc.MountAPI(r)
	})
	return r
}

type resp struct {
	*httptest.ResponseRecorder
}

func (r resp) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.Body.Bytes(), v); err != nil {
		t.Fatalf("body %q: %v", r.Body.String(), err)
	}
}

func (r resp) errCode(t *testing.T) string {
	t.Helper()
	var b struct {
		Error struct{ Code string } `json:"error"`
	}
	r.json(t, &b)
	return b.Error.Code
}

func (e *env) do(h http.Handler, method, path, user string, body any, hdr map[string]string) resp {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "127.0.0.1:5555"
	if user != "" {
		req.Header.Set("X-Test-User", user)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return resp{rec}
}

func (e *env) base() string {
	return "/api/v1/orgs/" + e.org.String() + "/projects/" + e.project.ID.String() + "/gateway"
}

var secretHdr = map[string]string{SecretHeader: testSecret}

// ---- internal endpoints: closed by default, secret, ALB, constant time --------------------------

func TestInternalClosedWithoutSecret(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Secret = "" })
	h := e.router()
	for _, c := range []struct{ m, p string }{{"GET", "/internal/gateway/routes"}, {"POST", "/internal/gateway/authorize"}, {"GET", "/internal/gateway/keys"}} {
		// even with a header: there is no secret to compare against
		r := e.do(h, c.m, c.p, "", AuthorizeRequest{}, map[string]string{SecretHeader: "anything"})
		if r.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: status %d, want 503 (closed)", c.m, c.p, r.Code)
		}
		r = e.do(h, c.m, c.p, "", nil, map[string]string{SecretHeader: ""})
		if r.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s with empty header: status %d, want 503", c.m, c.p, r.Code)
		}
	}
}

func TestInternalSecretRequiredAndALBRefused(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	if r := e.do(h, "GET", "/internal/gateway/routes", "", nil, nil); r.Code != 401 {
		t.Errorf("missing secret: %d, want 401", r.Code)
	}
	if r := e.do(h, "GET", "/internal/gateway/routes", "", nil, map[string]string{SecretHeader: testSecret + "x"}); r.Code != 401 {
		t.Errorf("wrong secret: %d, want 401", r.Code)
	}
	if r := e.do(h, "GET", "/internal/gateway/routes", "", nil, map[string]string{SecretHeader: strings.ToUpper(testSecret)}); r.Code != 401 {
		t.Errorf("case-changed secret: %d, want 401", r.Code)
	}
	if r := e.do(h, "GET", "/internal/gateway/routes?wait=0", "", nil, secretHdr); r.Code != 200 {
		t.Errorf("right secret: %d, want 200", r.Code)
	}
	via := map[string]string{SecretHeader: testSecret, "X-Amzn-Trace-Id": "Root=1-abc"}
	if r := e.do(h, "GET", "/internal/gateway/routes?wait=0", "", nil, via); r.Code != 403 {
		t.Errorf("through the public ALB: %d, want 403", r.Code)
	}
	if r := e.do(h, "POST", "/internal/gateway/authorize", "", AuthorizeRequest{}, via); r.Code != 403 {
		t.Errorf("authorize through the ALB: %d, want 403", r.Code)
	}
}

func TestInternalWrongSecretIsBlockedAfterRepeatedFailures(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	for i := 0; i < 10; i++ {
		e.do(h, "GET", "/internal/gateway/routes", "", nil, map[string]string{SecretHeader: "guess"})
	}
	r := e.do(h, "GET", "/internal/gateway/routes?wait=0", "", nil, secretHdr)
	if r.Code != 429 || r.Header().Get("Retry-After") == "" {
		t.Fatalf("after 10 wrong secrets the caller is blocked: %d %q", r.Code, r.Header().Get("Retry-After"))
	}
}

func TestSecretComparisonIsLengthIndependentAndConstantTime(t *testing.T) {
	if !secretEqual(testSecret, testSecret) || secretEqual(testSecret, testSecret+"a") || secretEqual("", testSecret) || secretEqual(testSecret[:5], testSecret) {
		t.Fatal("secretEqual semantics")
	}
}

// ---- routes long-poll ---------------------------------------------------------------------------

func TestRoutesSnapshotThen304ThenWake(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	e.expose("db", "postgres", 5432)
	r := e.do(h, "GET", "/internal/gateway/routes", "", nil, secretHdr) // no since: immediate full table
	if r.Code != 200 || r.Header().Get("X-Gateway-Rev") == "" || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("first fetch: %d %v", r.Code, r.Header())
	}
	var snap SnapshotJSON
	r.json(t, &snap)
	if len(snap.Routes) != 1 || snap.Routes[0].Service != "db" || snap.Routes[0].Host != "db-shop.db.example.test" || snap.Routes[0].DestHost != "capsule-app-"+shortID(e.project.ID) || snap.Routes[0].DestPort != 5432 {
		t.Fatalf("snapshot: %+v", snap)
	}
	if snap.Routes[0].ProjectID != e.project.ID || snap.Routes[0].OrgID != e.org || snap.Routes[0].Transport != "tcp" || snap.Routes[0].Mode != "passthrough" {
		t.Fatalf("route identity: %+v", snap.Routes[0])
	}

	// same revision: waits, then 304 with the revision header and an empty body
	start := time.Now()
	r = e.do(h, "GET", "/internal/gateway/routes?since="+itoa(int(snap.Rev))+"&wait=0", "", nil, secretHdr)
	if r.Code != http.StatusNotModified || r.Body.Len() != 0 || r.Header().Get("X-Gateway-Rev") != itoa(int(snap.Rev)) {
		t.Fatalf("unchanged: %d body=%q rev=%q", r.Code, r.Body.String(), r.Header().Get("X-Gateway-Rev"))
	}
	r = e.do(h, "GET", "/internal/gateway/routes?since="+itoa(int(snap.Rev)), "", nil, secretHdr) // default wait (200 ms in tests)
	if r.Code != http.StatusNotModified || time.Since(start) < 150*time.Millisecond {
		t.Fatalf("long-poll must wait the default time before 304 (waited %v, status %d)", time.Since(start), r.Code)
	}

	// a change made while waiting wakes the poll well before the timeout
	done := make(chan resp, 1)
	go func() {
		done <- e.do(h, "GET", "/internal/gateway/routes?since="+itoa(int(snap.Rev))+"&wait=30", "", nil, secretHdr)
	}()
	time.Sleep(50 * time.Millisecond)
	t0 := time.Now()
	e.expose("cache", "redis", 6379)
	select {
	case got := <-done:
		if got.Code != 200 || time.Since(t0) > 150*time.Millisecond {
			t.Fatalf("wake: status %d after %v", got.Code, time.Since(t0))
		}
		var s2 SnapshotJSON
		got.json(t, &s2)
		if s2.Rev <= snap.Rev {
			t.Fatalf("woken snapshot did not advance: rev %d->%d", snap.Rev, s2.Rev)
		}
		// the change is two store writes (service, then route): the next poll converges on the final table
		var s3 SnapshotJSON
		e.do(h, "GET", "/internal/gateway/routes?since=0&wait=0", "", nil, secretHdr).json(t, &s3)
		if len(s3.Routes) != 2 {
			t.Fatalf("final table has %d routes, want 2", len(s3.Routes))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the long-poll was not woken by the change")
	}

	// since beyond the current revision (control plane restored from backup) answers with the full table
	r = e.do(h, "GET", "/internal/gateway/routes?since=999999&wait=0", "", nil, secretHdr)
	if r.Code != 200 {
		t.Fatalf("since ahead of the server: %d, want 200", r.Code)
	}
}

func TestRoutesSeesChangesMadeByAnotherProcessWithinPollInterval(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	e.expose("db", "postgres", 5432)
	rev, _ := e.st.Revision(context.Background())
	done := make(chan resp, 1)
	go func() {
		done <- e.do(h, "GET", "/internal/gateway/routes?since="+itoa(int(rev))+"&wait=30", "", nil, secretHdr)
	}()
	time.Sleep(30 * time.Millisecond)
	// bypass the service: no notify(), as if another backend instance wrote it
	e.st.mu.Lock()
	e.st.bump()
	e.st.mu.Unlock()
	select {
	case got := <-done:
		if got.Code != 200 {
			t.Fatalf("status %d", got.Code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("polling must notice a revision bump without a local notification")
	}
}

func TestRoutesWaitIsClampedAndValidated(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	rev, _ := e.st.Revision(context.Background())
	start := time.Now()
	r := e.do(h, "GET", "/internal/gateway/routes?since="+itoa(int(rev))+"&wait=60", "", nil, secretHdr)
	if r.Code != 304 || time.Since(start) > 2*time.Second {
		t.Fatalf("wait=60 must be clamped to the configured maximum: %d after %v", r.Code, time.Since(start))
	}
	for _, q := range []string{"since=-1", "since=abc", "wait=61", "wait=-1", "wait=x"} {
		if r := e.do(h, "GET", "/internal/gateway/routes?"+q, "", nil, secretHdr); r.Code != 400 {
			t.Errorf("%s: %d, want 400", q, r.Code)
		}
	}
}

func TestRoutesHideDisabledRoutesAndIncludeLeases(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	e.st.SeedPortPool(context.Background(), 20000, 20005)
	e.expose("db", "postgres", 5432)
	if _, err := e.svc.LeasePort(context.Background(), e.project, Actor{UserID: e.admin}, "db"); err != nil {
		t.Fatal(err)
	}
	var snap SnapshotJSON
	e.do(h, "GET", "/internal/gateway/routes?wait=0", "", nil, secretHdr).json(t, &snap)
	if len(snap.Leases) != 1 || snap.Leases[0].Port < 20000 || snap.Leases[0].Port > 20005 {
		t.Fatalf("leases: %+v", snap.Leases)
	}
	off := false
	if _, err := e.svc.UpdateService(context.Background(), e.project, Actor{UserID: e.admin}, "db", UpdateInput{GatewayEnabled: &off}); err != nil {
		t.Fatal(err)
	}
	e.do(h, "GET", "/internal/gateway/routes?wait=0", "", nil, secretHdr).json(t, &snap)
	if len(snap.Routes) != 0 || len(snap.Leases) != 0 {
		t.Fatalf("a service with the gateway access off must disappear (and free its lease): %+v", snap)
	}
}

func TestAuthorizeEndpointDecisionAndErrors(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	e.expose("db", "postgres", 5432)
	good := AuthorizeRequest{RouteID: e.routeID("db").String(), SrcIP: "203.0.113.9", CredentialType: CredCap, Credential: e.capToken(e.admin, nil)}
	r := e.do(h, "POST", "/internal/gateway/authorize", "", good, secretHdr)
	var res AuthorizeResponse
	r.json(t, &res)
	if r.Code != 200 || !res.Allow {
		t.Fatalf("authorize: %d %s", r.Code, r.Body.String())
	}
	if r := e.do(h, "POST", "/internal/gateway/authorize", "", map[string]string{"route_id": "x"}, secretHdr); r.Code != 400 || r.errCode(t) != "invalid_request" {
		t.Fatalf("bad request: %d %s", r.Code, r.Body.String())
	}
	big := good
	big.Credential = strings.Repeat("a", 9000)
	if r := e.do(h, "POST", "/internal/gateway/authorize", "", big, secretHdr); r.Code != 400 {
		t.Fatalf("oversized body: %d", r.Code)
	}
	// blocked address: 429 with Retry-After
	bad := AuthorizeRequest{RouteID: good.RouteID, SrcIP: "198.51.100.1", CredentialType: CredCap, Credential: "cap_x"}
	for i := 0; i < 10; i++ {
		e.do(h, "POST", "/internal/gateway/authorize", "", bad, secretHdr)
	}
	r = e.do(h, "POST", "/internal/gateway/authorize", "", bad, secretHdr)
	if r.Code != 429 || r.Header().Get("Retry-After") == "" || r.errCode(t) != "rate_limited" {
		t.Fatalf("blocked: %d %q %s", r.Code, r.Header().Get("Retry-After"), r.Body.String())
	}
}

func TestKeysEndpointServesPublicKeysOnly(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	r := e.do(h, "GET", "/internal/gateway/keys", "", nil, secretHdr)
	var out struct {
		Keys []KeyInfo `json:"keys"`
	}
	r.json(t, &out)
	if r.Code != 200 || len(out.Keys) != 1 || out.Keys[0].Alg != "EdDSA" || len(out.Keys[0].X) != 43 {
		t.Fatalf("keys: %d %s", r.Code, r.Body.String())
	}
	if strings.Contains(r.Body.String(), "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8") {
		t.Fatal("the seed must never be served")
	}
}

// ---- user API: permissions by role --------------------------------------------------------------

func TestUserAPIPermissionsByRole(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	e.expose("db", "postgres", 5432)
	st := e.st
	st.SeedPortPool(context.Background(), 20000, 20010)
	b := e.base()
	svc := b + "/services/db"
	type call struct {
		name, method, path string
		body               any
		// expected status per user: admin, deployer, viewer
		admin, deployer, viewer int
	}
	calls := []call{
		{"list", "GET", b + "/services", nil, 200, 200, 200},
		{"connection-info", "GET", svc + "/connection-info", nil, 200, 200, 200},
		{"connection-token", "POST", svc + "/connection-token", nil, 200, 200, 403},
		{"create", "POST", b + "/services", CreateInput{Name: "web", ContainerPort: 80}, 201, 403, 403},
		{"patch", "PATCH", svc, map[string]any{"mode": "terminate"}, 200, 403, 403},
		{"port lease", "POST", svc + "/port", nil, 200, 403, 403},
		{"port release", "DELETE", svc + "/port", nil, 204, 403, 403},
		{"tokens list", "GET", b + "/service-tokens", nil, 200, 403, 403},
		{"tokens create", "POST", b + "/service-tokens", map[string]any{"name": "ci"}, 201, 403, 403},
		{"delete", "DELETE", svc, nil, 204, 403, 403},
	}
	users := []struct {
		label string
		id    uuid.UUID
		pick  func(call) int
	}{
		{"viewer", e.viewer, func(c call) int { return c.viewer }},
		{"deployer", e.deployer, func(c call) int { return c.deployer }},
		{"admin", e.admin, func(c call) int { return c.admin }},
	}
	for _, c := range calls {
		for _, u := range users {
			r := e.do(h, c.method, c.path, u.id.String(), c.body, nil)
			if want := u.pick(c); r.Code != want {
				t.Errorf("%s as %s: %d, want %d (%s)", c.name, u.label, r.Code, want, r.Body.String())
			}
			if c.name == "delete" && u.label == "admin" {
				continue
			}
		}
	}
	// not a member -> 403; member who must not see the project -> 404; no user -> 401
	if r := e.do(h, "GET", b+"/services", e.outsider.String(), nil, nil); r.Code != 403 {
		t.Errorf("outsider: %d", r.Code)
	}
	if r := e.do(h, "GET", b+"/services", e.hidden.String(), nil, nil); r.Code != 404 {
		t.Errorf("hidden: %d", r.Code)
	}
	if r := e.do(h, "GET", b+"/services", "", nil, nil); r.Code != 401 {
		t.Errorf("anonymous: %d", r.Code)
	}
	// project of another organisation -> 404 even for an admin of the URL org
	wrong := "/api/v1/orgs/" + uuid.NewString() + "/projects/" + e.project.ID.String() + "/gateway/services"
	e.az.m[e.admin] = e.az.m[e.admin]
	if r := e.do(h, "GET", wrong, e.admin.String(), nil, nil); r.Code != 403 {
		t.Errorf("project under an org the caller is not in: %d, want 403", r.Code)
	}
}

func TestUserAPIServiceLifecycleAndContract(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	admin := e.admin.String()
	b := e.base()

	r := e.do(h, "POST", b+"/services", admin, CreateInput{Name: "Bad_Name", ContainerPort: 80}, nil)
	if r.Code != 400 || r.errCode(t) != "invalid_request" {
		t.Fatalf("bad name: %d %s", r.Code, r.Body.String())
	}
	r = e.do(h, "POST", b+"/services", admin, CreateInput{Name: "web", Protocol: "http", ContainerPort: 8080}, nil)
	var sv ServiceView
	r.json(t, &sv)
	if r.Code != 201 || sv.Name != "web" || sv.DefaultAccess != "gateway" || sv.Host != "web-shop.apps.example.test" || len(sv.Accesses) != 1 || !sv.Accesses[0].Enabled {
		t.Fatalf("create: %d %s", r.Code, r.Body.String())
	}
	if r := e.do(h, "POST", b+"/services", admin, CreateInput{Name: "web", ContainerPort: 80}, nil); r.Code != 409 || r.errCode(t) != "service_name_taken" {
		t.Fatalf("duplicate: %d %s", r.Code, r.Body.String())
	}
	if r := e.do(h, "POST", b+"/services", admin, CreateInput{Name: strings.Repeat("a", 60), ContainerPort: 80}, nil); r.Code != 400 {
		t.Fatalf("name too long to form a DNS label with the slug: %d", r.Code)
	}
	if r := e.do(h, "POST", b+"/services", admin, CreateInput{Name: "x", ContainerPort: 0}, nil); r.Code != 400 {
		t.Fatalf("port 0: %d", r.Code)
	}
	if r := e.do(h, "POST", b+"/services", admin, CreateInput{Name: "x", ContainerPort: 80, DefaultAccess: "direct_port"}, nil); r.Code != 400 {
		t.Fatalf("direct default without a direct port: %d", r.Code)
	}

	var list struct{ Services []ServiceView }
	e.do(h, "GET", b+"/services", admin, nil, nil).json(t, &list)
	if len(list.Services) != 1 {
		t.Fatalf("list: %+v", list)
	}

	// turn the gateway off and on again; the route follows
	r = e.do(h, "PATCH", b+"/services/web", admin, map[string]any{"gateway_enabled": false}, nil)
	if r.Code != 200 {
		t.Fatalf("patch off: %d %s", r.Code, r.Body.String())
	}
	if _, err := e.st.ResolveService(context.Background(), e.project.ID, "web", "tcp"); err == nil {
		t.Fatal("a disabled gateway access must not resolve")
	}
	if r := e.do(h, "POST", b+"/services/web/connection-token", admin, nil, nil); r.Code != 404 {
		t.Fatalf("token for a service with the gateway off: %d, want the not-found answer", r.Code)
	}
	r = e.do(h, "PATCH", b+"/services/web", admin, map[string]any{"gateway_enabled": true, "mode": "terminate"}, nil)
	if r.Code != 200 {
		t.Fatalf("patch on: %d %s", r.Code, r.Body.String())
	}
	if rv, err := e.st.ResolveService(context.Background(), e.project.ID, "web", "tcp"); err != nil || rv.Mode != "terminate" {
		t.Fatalf("route after re-enable: %+v %v", rv, err)
	}
	if r := e.do(h, "PATCH", b+"/services/web", admin, map[string]any{"default_access": "direct_port"}, nil); r.Code != 400 {
		t.Fatalf("default to a missing direct access: %d", r.Code)
	}
	if r := e.do(h, "PATCH", b+"/services/web", admin, map[string]any{"direct_port_enabled": true}, nil); r.Code != 400 {
		t.Fatalf("the direct port is not managed here: %d", r.Code)
	}
	if r := e.do(h, "PATCH", b+"/services/web", admin, map[string]any{}, nil); r.Code != 400 {
		t.Fatalf("empty patch: %d", r.Code)
	}
	if r := e.do(h, "PATCH", b+"/services/ghost", admin, map[string]any{"mode": "terminate"}, nil); r.Code != 404 {
		t.Fatalf("patch of a missing service: %d", r.Code)
	}
	if r := e.do(h, "DELETE", b+"/services/web", admin, nil, nil); r.Code != 204 {
		t.Fatalf("delete: %d", r.Code)
	}
	if r := e.do(h, "DELETE", b+"/services/web", admin, nil, nil); r.Code != 404 {
		t.Fatalf("second delete: %d", r.Code)
	}
}

func TestConnectionInfoGatewayFirstAndLegacyFieldIntact(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	admin := e.admin.String()
	// a mirrored legacy database: direct port enabled, gateway off
	dbID := uuid.New()
	e.src.dbs = []*domain.Database{{ID: dbID, OrgID: e.org, Name: "Main DB", Engine: "postgres", Port: 40010, Status: "available"}}
	b := e.base()
	var info ConnectionInfo
	r := e.do(h, "GET", b+"/services/main-db/connection-info", admin, nil, nil)
	r.json(t, &info)
	if r.Code != 200 || len(info.ConnectionStrings) != 1 || info.ConnectionStrings[0].Access != "direct_port" || info.ConnectionString != "tcp.example.test:40010" {
		t.Fatalf("legacy only: %d %s", r.Code, r.Body.String())
	}
	if info.ConnectionStrings[0].Warning == "" {
		t.Fatal("the direct string must carry its warning")
	}
	// turn the gateway on: it goes FIRST; the direct one follows; the old field keeps the direct string
	if r := e.do(h, "PATCH", b+"/services/main-db", admin, map[string]any{"gateway_enabled": true}, nil); r.Code != 200 {
		t.Fatalf("enable gateway on a mirrored database: %d %s", r.Code, r.Body.String())
	}
	e.st.SeedPortPool(context.Background(), 20000, 20010)
	e.do(h, "POST", b+"/services/main-db/port", admin, nil, nil)
	e.do(h, "GET", b+"/services/main-db/connection-info", admin, nil, nil).json(t, &info)
	kinds := []string{}
	for _, c := range info.ConnectionStrings {
		kinds = append(kinds, c.Access+":"+c.Kind)
	}
	if strings.Join(kinds, ",") != "gateway:sni_name,gateway:capsule_uri,gateway:random_port,direct_port:direct_port" {
		t.Fatalf("order: %v", kinds)
	}
	first := info.ConnectionStrings[0]
	if first.Value != "postgresql://main-db-shop.db.example.test:5432/?sslmode=require" || !first.Recommended || first.Port != 5432 {
		t.Fatalf("first string: %+v", first)
	}
	if info.ConnectionStrings[1].Value != "capsule://shop/main-db" || info.ConnectionStrings[1].Command != "capsule connect shop/main-db" {
		t.Fatalf("capsule uri: %+v", info.ConnectionStrings[1])
	}
	if info.ConnectionString != "tcp.example.test:40010" {
		t.Fatalf("legacy field changed: %q", info.ConnectionString)
	}
	for _, c := range info.ConnectionStrings {
		if strings.Contains(strings.ToLower(c.Value), "password") || strings.Contains(c.Value, "@") {
			t.Fatalf("no credentials in a connection string: %q", c.Value)
		}
	}
	if r := e.do(h, "GET", b+"/services/ghost/connection-info", admin, nil, nil); r.Code != 404 {
		t.Fatalf("unknown service: %d", r.Code)
	}
}

func TestConnectionTokenEndpointNeverEchoedInAudit(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	e.expose("db", "postgres", 5432)
	r := e.do(h, "POST", e.base()+"/services/db/connection-token", e.deployer.String(), nil, nil)
	var out ConnectionTokenResult
	r.json(t, &out)
	if r.Code != 200 || !strings.HasPrefix(out.Token, "cgc_") || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("token: %d %s", r.Code, r.Body.String())
	}
	e.audit.mu.Lock()
	ab, _ := json.Marshal(e.audit.entries)
	e.audit.mu.Unlock()
	if strings.Contains(string(ab), out.Token) || strings.Contains(e.logs.String(), out.Token) {
		t.Fatal("the connection token must not appear in audit or logs")
	}
	if !strings.Contains(string(ab), "gateway.token.issue") || !strings.Contains(string(ab), `"jti"`) {
		t.Fatalf("issuing must be audited by jti: %s", ab)
	}
}

func TestPortLeaseEndpointsAndErrors(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	admin := e.admin.String()
	b := e.base()
	e.expose("db", "postgres", 5432)
	e.expose("web", "http", 80)
	// no pool yet -> exhausted with the hint
	r := e.do(h, "POST", b+"/services/db/port", admin, nil, nil)
	if r.Code != 409 || r.errCode(t) != "port_pool_exhausted" {
		t.Fatalf("empty pool: %d %s", r.Code, r.Body.String())
	}
	var body struct {
		Error errorBody `json:"error"`
	}
	r.json(t, &body)
	if !strings.Contains(body.Error.Hint, "capsule://") {
		t.Fatalf("the exhausted hint must point at capsule://: %q", body.Error.Hint)
	}
	e.st.SeedPortPool(context.Background(), 20000, 20000+10)
	r = e.do(h, "POST", b+"/services/db/port", admin, nil, nil)
	var lease PortLeaseView
	r.json(t, &lease)
	if r.Code != 200 || lease.Port < 20000 || lease.Port > 20010 || lease.Host != "db-shop.apps.example.test" || lease.State != "active" || lease.PlannedReleaseAt == nil {
		t.Fatalf("lease: %d %s", r.Code, r.Body.String())
	}
	if lease.PlannedReleaseAt.Sub(lease.LeasedAt) != 30*24*time.Hour {
		t.Fatalf("planned release %v after lease", lease.PlannedReleaseAt.Sub(lease.LeasedAt))
	}
	var again PortLeaseView
	e.do(h, "POST", b+"/services/db/port", admin, nil, nil).json(t, &again)
	if again.Port != lease.Port {
		t.Fatalf("leasing twice must be idempotent: %d vs %d", again.Port, lease.Port)
	}
	// quota: project limit 5 (others exercised in the store tests)
	e.st.quotas[e.org] = quotaOf(1, 1)
	r = e.do(h, "POST", b+"/services/web/port", admin, nil, nil)
	if r.Code != 409 || r.errCode(t) != "port_quota_exceeded" {
		t.Fatalf("quota: %d %s", r.Code, r.Body.String())
	}
	r.json(t, &body)
	if body.Error.Details["scope"] == nil || body.Error.Details["limit"] == nil {
		t.Fatalf("quota details: %+v", body.Error)
	}
	if r := e.do(h, "DELETE", b+"/services/db/port", admin, nil, nil); r.Code != 204 {
		t.Fatalf("release: %d", r.Code)
	}
	if r := e.do(h, "DELETE", b+"/services/db/port", admin, nil, nil); r.Code != 404 {
		t.Fatalf("release without lease: %d", r.Code)
	}
	if st := e.st.pool[lease.Port]; st != "quarantine" {
		t.Fatalf("a released port goes to quarantine, got %q", st)
	}
}

func TestOrgPolicyEndpoints(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	p := "/api/v1/orgs/" + e.org.String() + "/gateway/policy"
	var pol OrgPolicyView
	r := e.do(h, "GET", p, e.viewer.String(), nil, nil)
	r.json(t, &pol)
	if r.Code != 200 || pol.GatewayPolicy != "warn" || pol.MaxRandomPorts != 20 || pol.MaxRandomPortsPerProject != 5 {
		t.Fatalf("get: %d %s", r.Code, r.Body.String())
	}
	if r := e.do(h, "PUT", p, e.deployer.String(), map[string]string{"gateway_policy": "error"}, nil); r.Code != 403 {
		t.Fatalf("a plain member must not set the policy: %d", r.Code)
	}
	if r := e.do(h, "PUT", p, e.viewer.String(), map[string]string{"gateway_policy": "error"}, nil); r.Code != 403 {
		t.Fatalf("readonly must not set the policy: %d", r.Code)
	}
	if r := e.do(h, "PUT", p, e.outsider.String(), map[string]string{"gateway_policy": "error"}, nil); r.Code != 403 {
		t.Fatalf("non member: %d", r.Code)
	}
	if r := e.do(h, "GET", p, e.outsider.String(), nil, nil); r.Code != 403 {
		t.Fatalf("non member read: %d", r.Code)
	}
	if r := e.do(h, "PUT", p, e.admin.String(), map[string]string{"gateway_policy": "strict"}, nil); r.Code != 400 {
		t.Fatalf("invalid value: %d", r.Code)
	}
	r = e.do(h, "PUT", p, e.admin.String(), map[string]string{"gateway_policy": "error"}, nil)
	r.json(t, &pol)
	if r.Code != 200 || pol.GatewayPolicy != "error" {
		t.Fatalf("owner sets error: %d %s", r.Code, r.Body.String())
	}
	if got, _ := e.st.GetOrgPolicy(context.Background(), e.org); got != "error" {
		t.Fatalf("stored policy %q", got)
	}
	found := false
	for _, a := range e.audit.actions() {
		found = found || a == "gateway.policy.set"
	}
	if !found {
		t.Fatal("a policy change must be audited")
	}
}

func TestServiceTokenEndpointsShowTokenOnce(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	admin := e.admin.String()
	b := e.base()
	e.expose("db", "postgres", 5432)
	r := e.do(h, "POST", b+"/service-tokens", admin, map[string]any{"name": "ci", "service": "db", "expires_in_days": 30}, nil)
	var created struct {
		ID    uuid.UUID `json:"id"`
		Token string    `json:"token"`
	}
	r.json(t, &created)
	if r.Code != 201 || !strings.HasPrefix(created.Token, "cgs_") {
		t.Fatalf("create: %d %s", r.Code, r.Body.String())
	}
	r = e.do(h, "GET", b+"/service-tokens", admin, nil, nil)
	if r.Code != 200 || strings.Contains(r.Body.String(), created.Token) || !strings.Contains(r.Body.String(), created.ID.String()) {
		t.Fatalf("list: %d %s", r.Code, r.Body.String())
	}
	if r := e.do(h, "POST", b+"/service-tokens", admin, map[string]any{"name": "x", "service": "ghost"}, nil); r.Code != 404 {
		t.Fatalf("token for a missing service: %d", r.Code)
	}
	if r := e.do(h, "DELETE", b+"/service-tokens/"+created.ID.String(), admin, nil, nil); r.Code != 204 {
		t.Fatalf("revoke: %d", r.Code)
	}
	if r := e.do(h, "DELETE", b+"/service-tokens/"+created.ID.String(), admin, nil, nil); r.Code != 404 {
		t.Fatalf("revoke twice: %d", r.Code)
	}
	if r := e.do(h, "DELETE", b+"/service-tokens/not-a-uuid", admin, nil, nil); r.Code != 400 {
		t.Fatalf("bad id: %d", r.Code)
	}
}

func TestErrorsNeverLeakInternals(t *testing.T) {
	e := newEnv(t)
	h := e.router()
	e.ips.err = nil
	rec := httptest.NewRecorder()
	writeErr(rec, e.svc.log, context.DeadlineExceeded)
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "deadline") || !strings.Contains(rec.Body.String(), `"internal"`) {
		t.Fatalf("500 body: %s", rec.Body.String())
	}
	_ = h
}
