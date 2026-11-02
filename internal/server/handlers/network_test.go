package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type fakeNetRepo struct {
	lists map[uuid.UUID][]string
	err   error
	gets  int
}

func (f *fakeNetRepo) GetIPAllowlist(_ context.Context, id uuid.UUID) ([]string, error) {
	f.gets++
	if f.err != nil {
		return nil, f.err
	}
	return f.lists[id], nil
}
func (f *fakeNetRepo) SetIPAllowlist(_ context.Context, id uuid.UUID, c []string) error {
	if f.lists == nil {
		f.lists = map[uuid.UUID][]string{}
	}
	f.lists[id] = c
	return nil
}

// stack mirrors the production order: CaptureRemoteAddr, then chi RealIP (which trusts client headers).
func stack(h http.Handler) http.Handler {
	return middleware.CaptureRemoteAddr(chiMiddleware.RealIP(h))
}

func TestMyIPIgnoresSpoofedHeaders(t *testing.T) {
	h := NewNetworkHandler(nil, nil, nil, nil)
	srv := stack(http.HandlerFunc(h.MyIP))

	cases := []struct {
		name, remote string
		headers      map[string]string
		want         string
	}{
		{"alb appends client", "10.0.1.5:1234", map[string]string{"X-Forwarded-For": "203.0.113.7"}, "203.0.113.7"},
		{"client spoofs xff", "10.0.1.5:1234", map[string]string{"X-Forwarded-For": "1.1.1.1, 203.0.113.7"}, "203.0.113.7"},
		{"client spoofs x-real-ip and true-client-ip", "10.0.1.5:1234", map[string]string{
			"X-Forwarded-For": "203.0.113.7", "X-Real-IP": "9.9.9.9", "True-Client-IP": "8.8.8.8"}, "203.0.113.7"},
		{"no proxy header", "198.51.100.4:9999", nil, "198.51.100.4"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/network/my-ip", nil)
		req.RemoteAddr = c.remote
		for k, v := range c.headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		var out map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != 200 || out["ip"] != c.want {
			t.Errorf("%s: %d %v want %s", c.name, rec.Code, out, c.want)
		}
	}
}

func TestAllowlistCacheTTLAndInvalidation(t *testing.T) {
	pid := uuid.New()
	repo := &fakeNetRepo{lists: map[uuid.UUID][]string{pid: {"203.0.113.0/24"}}}
	c := NewAllowlistCache(repo, 10*time.Second)
	now := time.Now()
	c.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		if ok, err := c.Allowed(context.Background(), pid, "203.0.113.9"); err != nil || !ok {
			t.Fatalf("allowed: %v %v", ok, err)
		}
	}
	if repo.gets != 1 {
		t.Fatalf("expected one DB hit within TTL, got %d", repo.gets)
	}
	repo.lists[pid] = []string{"198.51.100.0/24"}
	if ok, _ := c.Allowed(context.Background(), pid, "203.0.113.9"); !ok {
		t.Fatal("cached value should still apply within TTL")
	}
	c.Invalidate(pid)
	if ok, _ := c.Allowed(context.Background(), pid, "203.0.113.9"); ok {
		t.Fatal("after invalidation the new list must apply")
	}
	now = now.Add(11 * time.Second)
	repo.lists[pid] = nil
	if ok, _ := c.Allowed(context.Background(), pid, "203.0.113.9"); !ok {
		t.Fatal("empty list means public after TTL expiry")
	}
	// stale entry is served when the DB fails, but unknown projects fail closed
	repo.err = errors.New("db down")
	now = now.Add(time.Minute)
	if _, err := c.Allowed(context.Background(), pid, "1.2.3.4"); err != nil {
		t.Fatalf("stale entry should be served: %v", err)
	}
	if _, err := c.Allowed(context.Background(), uuid.New(), "1.2.3.4"); err == nil {
		t.Fatal("no cached value + DB error must surface an error")
	}
}

func proxyWith(repo domain.ProjectNetworkRepository) *ProxyHandler {
	h := &ProxyHandler{}
	h.SetAllowlist(NewAllowlistCache(repo, time.Minute))
	return h
}

func TestProxyAllowlistEnforcement(t *testing.T) {
	pid := uuid.New()
	project := &domain.Project{ID: pid}
	repo := &fakeNetRepo{lists: map[uuid.UUID][]string{pid: {"203.0.113.0/24"}}}
	h := proxyWith(repo)

	do := func(remote, xff string) *httptest.ResponseRecorder {
		var rec *httptest.ResponseRecorder
		srv := stack(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.ipAllowed(w, r, project) {
				w.WriteHeader(http.StatusTeapot) // reached the upstream
			}
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rec = httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	if rec := do("10.0.1.5:1", "203.0.113.50"); rec.Code != http.StatusTeapot {
		t.Fatalf("allowed IP blocked: %d", rec.Code)
	}
	rec := do("10.0.1.5:1", "8.8.8.8")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Access Restricted") || !strings.Contains(rec.Body.String(), "403 Forbidden") {
		t.Fatalf("outsider must get the 403 error page: %d %s", rec.Code, rec.Body.String())
	}
	// spoofing an allowed address in the first XFF slot must not help
	if rec := do("10.0.1.5:1", "203.0.113.50, 8.8.8.8"); rec.Code != http.StatusForbidden {
		t.Fatalf("spoofed XFF bypassed the allowlist: %d", rec.Code)
	}
	// spoofing via X-Real-IP (RealIP rewrites RemoteAddr) must not help either
	srv := stack(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.ipAllowed(w, r, project) {
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:5"
	req.Header.Set("X-Real-IP", "203.0.113.50")
	r2 := httptest.NewRecorder()
	srv.ServeHTTP(r2, req)
	if r2.Code != http.StatusForbidden {
		t.Fatalf("spoofed X-Real-IP bypassed the allowlist: %d", r2.Code)
	}
	// empty list = public
	repo.lists[pid] = nil
	h = proxyWith(repo)
	if rec := do("10.0.1.5:1", "8.8.8.8"); rec.Code != http.StatusTeapot {
		t.Fatalf("public project blocked: %d", rec.Code)
	}
	// backend failure fails closed
	repo.err = errors.New("db down")
	h = proxyWith(repo)
	if rec := do("10.0.1.5:1", "203.0.113.50"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("lookup failure must fail closed: %d", rec.Code)
	}
	// enforcement disabled when no cache is wired
	if !(&ProxyHandler{}).ipAllowed(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), project) {
		t.Fatal("nil allowlist must allow")
	}
}

func TestNetworkSettingsEndpoints(t *testing.T) {
	org, pid := uuid.New(), uuid.New()
	repo := &fakeNetRepo{}
	cache := NewAllowlistCache(repo, time.Minute)
	mk := func(role string) http.Handler {
		h := NewNetworkHandler(fakeOrgRepo{role: role}, fakeAccessProjects{p: &domain.Project{ID: pid, OrgID: org}}, repo, cache)
		r := chi.NewRouter()
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: uuid.New()})))
			})
		})
		r.Get("/orgs/{orgID}/projects/{projectID}/network", h.Get)
		r.Put("/orgs/{orgID}/projects/{projectID}/network", h.Put)
		return r
	}
	url := "/orgs/" + org.String() + "/projects/" + pid.String() + "/network"
	call := func(h http.Handler, method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	owner := mk("member")
	rec := call(owner, http.MethodPut, `{"ip_allowlist":["203.0.113.9","203.0.113.0/24","203.0.113.9/32"]}`)
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `{"ip_allowlist":["203.0.113.9/32","203.0.113.0/24"]}` {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	if rec := call(owner, http.MethodGet, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "203.0.113.0/24") {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	if rec := call(owner, http.MethodPut, `{"ip_allowlist":[]}`); rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `{"ip_allowlist":[]}` {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{`{"ip_allowlist":["0.0.0.0/0"]}`, `{"ip_allowlist":["10.0.0.0/4"]}`, `{"ip_allowlist":["x"]}`, `{"ip_allowlist":["::1"]}`} {
		if rec := call(owner, http.MethodPut, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, rec.Code)
		}
	}
	ro := mk("readonly")
	if rec := call(ro, http.MethodGet, ""); rec.Code != 200 {
		t.Fatalf("readonly read: %d", rec.Code)
	}
	if rec := call(ro, http.MethodPut, `{"ip_allowlist":[]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("readonly write: %d", rec.Code)
	}
	if rec := call(mk(""), http.MethodGet, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("non-member: %d", rec.Code)
	}
}
