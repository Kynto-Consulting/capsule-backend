package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/netaccess"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// ── fakes ────────────────────────────────────────────────────────────────────

type fakeAccessProjects struct {
	domain.ProjectRepository
	p *domain.Project
}

func (f fakeAccessProjects) GetByID(context.Context, uuid.UUID) (*domain.Project, error) {
	if f.p == nil {
		return nil, domain.ErrNotFound
	}
	return f.p, nil
}

type fakeAccessDBs struct {
	domain.DatabaseRepository
	db *domain.Database
}

func (f fakeAccessDBs) GetByID(context.Context, uuid.UUID) (*domain.Database, error) {
	if f.db == nil {
		return nil, domain.ErrNotFound
	}
	return f.db, nil
}

type fakeRuleRepo struct {
	mu    sync.Mutex
	rules []*domain.DatabaseAccessRule
}

func (f *fakeRuleRepo) List(_ context.Context, dbID uuid.UUID) ([]*domain.DatabaseAccessRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []*domain.DatabaseAccessRule{}
	for _, r := range f.rules {
		if r.DatabaseID == dbID {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *fakeRuleRepo) ListDesired(context.Context) ([]domain.DesiredAccess, error) { return nil, nil }
func (f *fakeRuleRepo) Replace(_ context.Context, dbID uuid.UUID, rules []*domain.DatabaseAccessRule, by uuid.UUID) ([]*domain.DatabaseAccessRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = nil
	for _, r := range rules {
		c := *r
		c.ID, c.CreatedBy, c.CreatedAt = uuid.New(), &by, time.Now()
		f.rules = append(f.rules, &c)
	}
	return append([]*domain.DatabaseAccessRule(nil), f.rules...), nil
}
func (f *fakeRuleRepo) Add(_ context.Context, rule *domain.DatabaseAccessRule, max int) (*domain.DatabaseAccessRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.rules) >= max {
		return nil, domain.ErrRuleLimit
	}
	for _, r := range f.rules {
		if r.CIDR == rule.CIDR {
			return nil, domain.ErrConflict
		}
	}
	c := *rule
	c.ID, c.CreatedAt = uuid.New(), time.Now()
	f.rules = append(f.rules, &c)
	return &c, nil
}
func (f *fakeRuleRepo) Delete(_ context.Context, _, ruleID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.rules {
		if r.ID == ruleID {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			return nil
		}
	}
	return domain.ErrNotFound
}
func (f *fakeRuleRepo) DeleteAll(context.Context, uuid.UUID) error { f.rules = nil; return nil }

type fakeApplier struct {
	calls [][]string
	ports []int
	err   error
}

func (f *fakeApplier) ReconcileDB(_ context.Context, _ uuid.UUID, port int, cidrs []string) error {
	if f.err != nil {
		return f.err
	}
	c := append([]string(nil), cidrs...)
	sort.Strings(c)
	f.calls = append(f.calls, c)
	f.ports = append(f.ports, port)
	return nil
}

// ── harness ──────────────────────────────────────────────────────────────────

type accessEnv struct {
	h       *DatabaseAccessHandler
	rules   *fakeRuleRepo
	applier *fakeApplier
	router  http.Handler
	org     uuid.UUID
	project uuid.UUID
	db      *domain.Database
}

func newAccessEnv(t *testing.T, role string, withApplier bool) *accessEnv {
	t.Helper()
	org, proj := uuid.New(), uuid.New()
	db := &domain.Database{ID: uuid.New(), OrgID: org, ProjectID: &proj, Engine: "postgres", Tier: "dev", Port: 40123, Host: "h", DBName: "app", Status: "available"}
	rules := &fakeRuleRepo{}
	applier := &fakeApplier{}
	var ap AccessApplier
	if withApplier {
		ap = applier
	}
	h := NewDatabaseAccessHandler(
		fakeAccessDBs{db: db},
		fakeOrgRepo{role: role},
		fakeAccessProjects{p: &domain.Project{ID: proj, OrgID: org}},
		rules, ap, "db.example.test", "", "secret", slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: uuid.New()})))
		})
	})
	base := "/orgs/{orgID}/projects/{projectID}/databases/{dbID}/access"
	r.Get(base, h.List)
	r.Put(base, h.Replace)
	r.Post(base, h.Add)
	r.Delete(base+"/{ruleID}", h.Remove)
	return &accessEnv{h: h, rules: rules, applier: applier, router: r, org: org, project: proj, db: db}
}

func (e *accessEnv) url(suffix string) string {
	return fmt.Sprintf("/orgs/%s/projects/%s/databases/%s/access%s", e.org, e.project, e.db.ID, suffix)
}

func (e *accessEnv) do(method, url string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, url, &buf)
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env errorEnvelope
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	return env.Error.Code
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestAccess501WhenNotConfigured(t *testing.T) {
	e := newAccessEnv(t, "owner", false)
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodPost} {
		rec := e.do(m, e.url(""), map[string]any{"cidr": "203.0.113.5/32"})
		if rec.Code != http.StatusNotImplemented || errCode(t, rec) != "NOT_CONFIGURED" {
			t.Fatalf("%s: %d %s", m, rec.Code, rec.Body)
		}
	}
	if rec := e.do(http.MethodDelete, e.url("/"+uuid.NewString()), nil); rec.Code != http.StatusNotImplemented {
		t.Fatalf("delete: %d", rec.Code)
	}
}

func TestAccessReplaceAppliesAndIsIdempotent(t *testing.T) {
	// Changing network rules needs ProjectNetwork: a plain org member (deployer) no longer has it.
	e := newAccessEnv(t, "admin", true)
	body := map[string]any{"rules": []map[string]string{{"cidr": "203.0.113.5", "description": "office"}}, "cidrs": []string{"198.51.100.0/24", "203.0.113.5/32"}}
	for i := 0; i < 2; i++ {
		rec := e.do(http.MethodPut, e.url(""), body)
		if rec.Code != http.StatusOK {
			t.Fatalf("put %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	last := e.applier.calls[len(e.applier.calls)-1]
	if len(last) != 2 || last[0] != "198.51.100.0/24" || last[1] != "203.0.113.5/32" {
		t.Fatalf("applied %v", last)
	}
	if e.applier.ports[0] != 40123 {
		t.Fatalf("must apply on the database's host port, got %d", e.applier.ports[0])
	}
	var resp accessResponse
	rec := e.do(http.MethodGet, e.url(""), nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != 200 || len(resp.Rules) != 2 || resp.Port != 40123 || resp.Host != "db.example.test" || resp.MaxRules != 25 {
		t.Fatalf("get: %d %+v", rec.Code, resp)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("secret")) || resp.Connection.URLTemplate != "postgres://capsuleadmin:<password>@db.example.test:40123/app" {
		t.Fatalf("connection info leaks or is wrong: %s", rec.Body)
	}
}

func TestAccessValidation(t *testing.T) {
	e := newAccessEnv(t, "owner", true)
	bad := map[string]string{
		"0.0.0.0/0":     "PUBLIC_NOT_ALLOWED",
		"10.0.0.0/7":    "INVALID_CIDR",
		"::/0":          "PUBLIC_NOT_ALLOWED",
		"2001:db8::/31": "INVALID_CIDR",
		"fe80::1%eth0":  "INVALID_CIDR",
		"not-a-cidr":    "INVALID_CIDR",
		"1.2.3.4/33":    "INVALID_CIDR",
		"":              "INVALID_CIDR",
	}
	for cidr, code := range bad {
		rec := e.do(http.MethodPost, e.url(""), map[string]any{"cidr": cidr})
		if rec.Code != http.StatusBadRequest || errCode(t, rec) != code {
			t.Errorf("%q: %d %s (want %s)", cidr, rec.Code, rec.Body, code)
		}
	}
	if len(e.applier.calls) != 0 {
		t.Fatal("invalid input must never reach the firewall")
	}
	// private ranges are fine
	if rec := e.do(http.MethodPost, e.url(""), map[string]any{"cidr": "10.1.0.0/16"}); rec.Code != http.StatusCreated {
		t.Fatalf("private cidr: %d %s", rec.Code, rec.Body)
	}
}

func TestAccessAllowPublicNeedsFlagAndAdmin(t *testing.T) {
	owner := newAccessEnv(t, "owner", true)
	if rec := owner.do(http.MethodPost, owner.url(""), map[string]any{"cidr": "0.0.0.0/0", "allow_public": true}); rec.Code != http.StatusCreated {
		t.Fatalf("owner with flag: %d %s", rec.Code, rec.Body)
	}
	admin := newAccessEnv(t, "admin", true)
	if rec := admin.do(http.MethodPut, admin.url(""), map[string]any{"cidrs": []string{"0.0.0.0/0"}, "allow_public": true}); rec.Code != http.StatusOK {
		t.Fatalf("admin with flag: %d %s", rec.Code, rec.Body)
	}
	member := newAccessEnv(t, "member", true)
	rec := member.do(http.MethodPost, member.url(""), map[string]any{"cidr": "0.0.0.0/0", "allow_public": true})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member must not open to the world: %d %s", rec.Code, rec.Body)
	}
	if len(member.applier.calls) != 0 {
		t.Fatal("firewall touched for a forbidden request")
	}
}

func TestAccessRolePermissions(t *testing.T) {
	ro := newAccessEnv(t, "readonly", true)
	if rec := ro.do(http.MethodGet, ro.url(""), nil); rec.Code != http.StatusOK {
		t.Fatalf("readonly may read: %d", rec.Code)
	}
	for _, m := range []string{http.MethodPut, http.MethodPost} {
		if rec := ro.do(m, ro.url(""), map[string]any{"cidr": "203.0.113.5/32"}); rec.Code != http.StatusForbidden {
			t.Fatalf("readonly %s: %d", m, rec.Code)
		}
	}
	if rec := ro.do(http.MethodDelete, ro.url("/"+uuid.NewString()), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("readonly delete: %d", rec.Code)
	}
	stranger := newAccessEnv(t, "", true)
	if rec := stranger.do(http.MethodGet, stranger.url(""), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("non-member: %d", rec.Code)
	}
}

func TestAccessMaxTwentyFiveRules(t *testing.T) {
	e := newAccessEnv(t, "owner", true)
	var cidrs []string
	for i := 0; i < 26; i++ {
		cidrs = append(cidrs, fmt.Sprintf("203.0.113.%d/32", i+1))
	}
	if rec := e.do(http.MethodPut, e.url(""), map[string]any{"cidrs": cidrs}); rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "LIMIT_EXCEEDED" {
		t.Fatalf("26 via PUT: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(http.MethodPut, e.url(""), map[string]any{"cidrs": cidrs[:25]}); rec.Code != http.StatusOK {
		t.Fatalf("25 via PUT: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(http.MethodPost, e.url(""), map[string]any{"cidr": "198.51.100.1/32"}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("26th via POST: %d %s", rec.Code, rec.Body)
	}
}

func TestAccessAddDuplicateAndDelete(t *testing.T) {
	e := newAccessEnv(t, "owner", true)
	rec := e.do(http.MethodPost, e.url(""), map[string]any{"cidr": "203.0.113.5/32", "description": "ci"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	var rule domain.DatabaseAccessRule
	_ = json.Unmarshal(rec.Body.Bytes(), &rule)
	if rec := e.do(http.MethodPost, e.url(""), map[string]any{"cidr": "203.0.113.5"}); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", rec.Code)
	}
	if rec := e.do(http.MethodDelete, e.url("/"+rule.ID.String()), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if last := e.applier.calls[len(e.applier.calls)-1]; len(last) != 0 {
		t.Fatalf("delete must revoke, desired=%v", last)
	}
	if rec := e.do(http.MethodDelete, e.url("/"+rule.ID.String()), nil); rec.Code != http.StatusNotFound {
		t.Fatalf("delete twice: %d", rec.Code)
	}
}

func TestAccessFirewallErrorChangesNothing(t *testing.T) {
	e := newAccessEnv(t, "owner", true)
	e.applier.err = netaccess.ErrRuleLimit
	rec := e.do(http.MethodPost, e.url(""), map[string]any{"cidr": "203.0.113.5/32"})
	if rec.Code != http.StatusConflict || errCode(t, rec) != "SG_RULE_LIMIT" {
		t.Fatalf("limit: %d %s", rec.Code, rec.Body)
	}
	e.applier.err = fmt.Errorf("aws down")
	rec = e.do(http.MethodPut, e.url(""), map[string]any{"cidrs": []string{"203.0.113.5/32"}})
	if rec.Code != http.StatusBadGateway || errCode(t, rec) != "FIREWALL_ERROR" {
		t.Fatalf("aws error: %d %s", rec.Code, rec.Body)
	}
	if len(e.rules.rules) != 0 {
		t.Fatal("rules persisted although the firewall rejected them")
	}
}

func TestAccessWrongProjectOrUnsupportedDB(t *testing.T) {
	e := newAccessEnv(t, "owner", true)
	other := uuid.New()
	e.db.ProjectID = &other
	if rec := e.do(http.MethodGet, e.url(""), nil); rec.Code != http.StatusNotFound {
		t.Fatalf("db of another project: %d", rec.Code)
	}
	e = newAccessEnv(t, "owner", true)
	e.db.Tier = "prod"
	if rec := e.do(http.MethodGet, e.url(""), nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("rds-backed db: %d", rec.Code)
	}
	e = newAccessEnv(t, "owner", true)
	e.db.Port = 0
	if rec := e.do(http.MethodPost, e.url(""), map[string]any{"cidr": "203.0.113.5/32"}); rec.Code != http.StatusConflict {
		t.Fatalf("db without port: %d", rec.Code)
	}
}

func TestAccessCleanupRevokesAllRules(t *testing.T) {
	e := newAccessEnv(t, "owner", true)
	e.rules.rules = []*domain.DatabaseAccessRule{{ID: uuid.New(), DatabaseID: e.db.ID, CIDR: "203.0.113.5/32"}}
	e.h.Cleanup(e.db)
	if len(e.applier.calls) != 1 || len(e.applier.calls[0]) != 0 || e.applier.ports[0] != 0 {
		t.Fatalf("cleanup calls=%v ports=%v", e.applier.calls, e.applier.ports)
	}
	if len(e.rules.rules) != 0 {
		t.Fatal("stored rules must be deleted")
	}
}
