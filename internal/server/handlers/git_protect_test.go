package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitcore/fake"
	"github.com/kynto/capsule/backend/internal/gitprotect"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// ---- doubles (names prefixed gp to avoid clashing with the other handler tests) ---------------

type gpAuthzStore struct{ access *authz.OrgAccess }

func (s gpAuthzStore) LoadOrgAccess(context.Context, uuid.UUID, uuid.UUID) (*authz.OrgAccess, error) {
	return s.access, nil
}
func (gpAuthzStore) UserGrants(context.Context, uuid.UUID) ([]authz.Grant, error) { return nil, nil }

type gpOrgs struct {
	domain.OrganizationRepository
	org *domain.Organization
}

func (o gpOrgs) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	if id != o.org.ID {
		return nil, domain.ErrNotFound
	}
	return o.org, nil
}

type gpProjects struct {
	domain.ProjectRepository
	p *domain.Project
}

func (p gpProjects) GetByID(_ context.Context, id uuid.UUID) (*domain.Project, error) {
	if id != p.p.ID {
		return nil, domain.ErrNotFound
	}
	return p.p, nil
}

type gpStore struct {
	mu     sync.Mutex
	rules  map[uuid.UUID]gitprotect.Rule
	syncs  map[uuid.UUID]gitprotect.SyncState
	audits []gitprotect.AuditEntry
	tick   int
}

func (s *gpStore) ListRules(_ context.Context, p uuid.UUID) ([]gitprotect.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []gitprotect.Rule
	for _, r := range s.rules {
		if r.ProjectID == p {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (s *gpStore) GetRule(_ context.Context, p, id uuid.UUID) (*gitprotect.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rules[id]; ok && r.ProjectID == p {
		return &r, nil
	}
	return nil, gitprotect.ErrNotFound
}
func (s *gpStore) CreateRule(_ context.Context, r *gitprotect.Rule, a gitprotect.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, o := range s.rules {
		if o.ProjectID == r.ProjectID && o.Pattern == r.Pattern {
			return gitprotect.ErrDuplicate
		}
	}
	s.tick++
	r.CreatedAt = time.Date(2026, 11, 1, 0, 0, s.tick, 0, time.UTC)
	r.UpdatedAt = r.CreatedAt
	s.rules[r.ID] = *r
	s.syncs[r.ID] = gitprotect.SyncState{RuleID: r.ID, ProjectID: r.ProjectID, Status: gitprotect.SyncPending}
	s.audits = append(s.audits, a)
	return nil
}
func (s *gpStore) UpdateRule(_ context.Context, r *gitprotect.Rule, a gitprotect.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.rules[r.ID]
	if !ok {
		return gitprotect.ErrNotFound
	}
	r.CreatedAt = old.CreatedAt
	s.rules[r.ID] = *r
	s.audits = append(s.audits, a)
	return nil
}
func (s *gpStore) DeleteRule(_ context.Context, _, id uuid.UUID, a gitprotect.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rules[id]; !ok {
		return gitprotect.ErrNotFound
	}
	delete(s.rules, id)
	delete(s.syncs, id)
	s.audits = append(s.audits, a)
	return nil
}
func (s *gpStore) ListSync(_ context.Context, p uuid.UUID) (map[uuid.UUID]gitprotect.SyncState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[uuid.UUID]gitprotect.SyncState{}
	for id, st := range s.syncs {
		if st.ProjectID == p {
			out[id] = st
		}
	}
	return out, nil
}
func (s *gpStore) PutSync(_ context.Context, st gitprotect.SyncState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncs[st.RuleID] = st
	return nil
}
func (s *gpStore) ProjectsWithRules(context.Context) ([]gitprotect.Target, error) { return nil, nil }
func (s *gpStore) WriteAudit(_ context.Context, a gitprotect.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audits = append(s.audits, a)
	return nil
}

// ---- rig --------------------------------------------------------------------------------------

type gpRig struct {
	t       *testing.T
	fs      *fake.Server
	store   *gpStore
	router  chi.Router
	org     *domain.Organization
	project *domain.Project
	user    uuid.UUID
}

func newGPRig(t *testing.T, access *authz.OrgAccess) *gpRig {
	t.Helper()
	fs := fake.New()
	t.Cleanup(fs.Close)
	fs.AddRepo("acme", "web")
	core := gitcore.New(gitcore.Config{URL: fs.URL, Token: fake.Token, Timeout: 2 * time.Second, BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond, BreakerOpenFor: 20 * time.Millisecond}, nil, nil)
	st := &gpStore{rules: map[uuid.UUID]gitprotect.Rule{}, syncs: map[uuid.UUID]gitprotect.SyncState{}}
	svc := gitprotect.New(st, core, gitprotect.DefaultConfig(), nil)

	org := &domain.Organization{ID: uuid.New(), Slug: "acme"}
	project := &domain.Project{ID: uuid.New(), OrgID: org.ID, Slug: "web"}
	gitprotect.SetShared(svc)
	t.Cleanup(func() { gitprotect.SetShared(nil) })

	g := &gpRig{t: t, fs: fs, store: st, org: org, project: project, user: uuid.New()}
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: g.user})))
		})
	})
	MountGitProtect(r, authz.New(gpAuthzStore{access: access}), gpOrgs{org: org}, gpProjects{p: project})
	g.router = r
	return g
}

func (g *gpRig) url(suffix string) string {
	return "/orgs/" + g.org.ID.String() + "/projects/" + g.project.ID.String() + "/git/protections" + suffix
}

func (g *gpRig) do(method, url, body string) *httptest.ResponseRecorder {
	g.t.Helper()
	req := httptest.NewRequest(method, url, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.router.ServeHTTP(w, req)
	return w
}

func gpJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON: %q", w.Body.String())
	}
	return m
}

func gpErr(t *testing.T, w *httptest.ResponseRecorder) (code string, fields []any) {
	t.Helper()
	e, _ := gpJSON(t, w)["error"].(map[string]any)
	if e == nil {
		t.Fatalf("no error envelope: %s", w.Body.String())
	}
	f, _ := e["fields"].([]any)
	return e["code"].(string), f
}

var gpOwner = &authz.OrgAccess{OrgRole: "owner", Mode: authz.ModeOpen}

// ---- tests ------------------------------------------------------------------------------------

func TestGitProtectCRUDHappyPath(t *testing.T) {
	g := newGPRig(t, gpOwner)
	w := g.do(http.MethodPost, g.url(""), `{"pattern":"main","required_approvals":1,"required_checks":["ci/build"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	c := gpJSON(t, w)
	id, _ := c["id"].(string)
	if id == "" || c["pattern"] != "main" || c["forgejo_synced"] != true || c["sync_status"] != "synced" || c["created_at"] == nil ||
		c["require_pull_request"] != true || c["block_force_push"] != true || c["block_deletion"] != true || c["enforce_for_admins"] != true || c["required_approvals"] != float64(1) {
		t.Fatalf("create body: %v", c)
	}
	if !g.fs.HasProtection("acme", "web", "main") {
		t.Fatal("rule not projected to Forgejo")
	}

	w = g.do(http.MethodGet, g.url(""), "")
	l := gpJSON(t, w)
	items, _ := l["items"].([]any)
	if w.Code != 200 || len(items) != 1 || items[0].(map[string]any)["id"] != id {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if _, ok := l["next_cursor"]; !ok {
		t.Fatal("list must carry next_cursor")
	}

	// PUT accepts the response of GET echoed back (response-only fields are tolerated)
	echo := items[0].(map[string]any)
	echo["required_approvals"] = 2
	b, _ := json.Marshal(echo)
	w = g.do(http.MethodPut, g.url("/"+id), string(b))
	if w.Code != 200 || gpJSON(t, w)["required_approvals"] != float64(2) {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}

	w = g.do(http.MethodGet, g.url("/evaluate?branch=main"), "")
	ev := gpJSON(t, w)
	if w.Code != 200 || ev["branch"] != "main" || ev["rule"] == nil || !strings.Contains(ev["reason"].(string), "main") || ev["matches"] == nil {
		t.Fatalf("evaluate: %d %s", w.Code, w.Body)
	}
	w = g.do(http.MethodGet, g.url("/evaluate?branch=feature%2Fx"), "")
	if ev := gpJSON(t, w); w.Code != 200 || ev["rule"] != nil || !strings.Contains(ev["reason"].(string), "no está protegida") {
		t.Fatalf("evaluate unprotected: %d %s", w.Code, w.Body)
	}

	w = g.do(http.MethodDelete, g.url("/"+id), "")
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Header().Get("X-Capsule-Warnings"), "DEFAULT_BRANCH_UNPROTECTED") {
		t.Fatalf("delete of the default branch rule must warn: %v", w.Header())
	}
	if g.fs.HasProtection("acme", "web", "main") {
		t.Fatal("Forgejo rule must be gone")
	}
	if w = g.do(http.MethodDelete, g.url("/"+id), ""); w.Code != http.StatusNotFound {
		t.Fatalf("second delete: %d", w.Code)
	}
}

func TestGitProtectPermissions(t *testing.T) {
	cases := []struct {
		name                 string
		access               *authz.OrgAccess
		list, create, delete int
	}{
		{"owner", &authz.OrgAccess{OrgRole: "owner", Mode: authz.ModeOpen}, 200, 201, 204},
		{"org admin", &authz.OrgAccess{OrgRole: "admin", Mode: authz.ModeOpen}, 200, 201, 204},
		{"member = deployer cannot administer", &authz.OrgAccess{OrgRole: "member", Mode: authz.ModeOpen}, 200, 403, 403},
		{"readonly = viewer reads only", &authz.OrgAccess{OrgRole: "readonly", Mode: authz.ModeOpen}, 200, 403, 403},
		{"not a member", nil, 403, 403, 403},
		{"restricted mode hides the project", &authz.OrgAccess{OrgRole: "member", Mode: authz.ModeRestricted}, 404, 404, 404},
	}
	for _, c := range cases {
		g := newGPRig(t, c.access)
		// a rule created straight in the store so deletion can be tried by everyone
		rule := gitprotect.Rule{ID: uuid.New(), ProjectID: g.project.ID, Pattern: "seed", BlockForcePush: true, BlockDeletion: true}
		_ = g.store.CreateRule(context.Background(), &rule, gitprotect.AuditEntry{})
		if w := g.do(http.MethodGet, g.url(""), ""); w.Code != c.list {
			t.Errorf("%s: list %d, want %d", c.name, w.Code, c.list)
		}
		if w := g.do(http.MethodGet, g.url("/evaluate?branch=main"), ""); w.Code != c.list {
			t.Errorf("%s: evaluate %d, want %d", c.name, w.Code, c.list)
		}
		if w := g.do(http.MethodPost, g.url(""), `{"pattern":"main"}`); w.Code != c.create {
			t.Errorf("%s: create %d, want %d", c.name, w.Code, c.create)
		}
		wantPut := http.StatusOK
		if c.create != http.StatusCreated {
			wantPut = c.create
		}
		if w := g.do(http.MethodPut, g.url("/"+rule.ID.String()), `{"pattern":"seed2"}`); w.Code != wantPut {
			t.Errorf("%s: put %d, want %d", c.name, w.Code, wantPut)
		}
		if w := g.do(http.MethodDelete, g.url("/"+rule.ID.String()), ""); w.Code != c.delete {
			t.Errorf("%s: delete %d, want %d", c.name, w.Code, c.delete)
		}
		if c.create != 201 && g.fs.HasProtection("acme", "web", "main") {
			t.Errorf("%s: a forbidden create must not reach Forgejo", c.name)
		}
	}
}

func TestGitProtectErrorMapping(t *testing.T) {
	g := newGPRig(t, gpOwner)

	// validation: 422 with the offending fields
	w := g.do(http.MethodPost, g.url(""), `{"pattern":"a[","required_approvals":11,"block_force_push":false}`)
	code, fields := gpErr(t, w)
	if w.Code != http.StatusUnprocessableEntity || code != "VALIDATION_ERROR" || len(fields) != 3 {
		t.Fatalf("validation: %d %s", w.Code, w.Body)
	}
	// unknown field and bad JSON: 400
	for _, body := range []string{`{"pattern":"main","required_aprovals":1}`, `{"pattern":`, `{"pattern":5}`, `[]`} {
		if w := g.do(http.MethodPost, g.url(""), body); w.Code != http.StatusBadRequest {
			t.Errorf("body %q: %d %s", body, w.Code, w.Body)
		} else if c, _ := gpErr(t, w); c != "INVALID_BODY" {
			t.Errorf("code %s", c)
		}
	}
	// oversized body
	if w := g.do(http.MethodPost, g.url(""), `{"pattern":"`+strings.Repeat("a", 70<<10)+`"}`); w.Code != http.StatusBadRequest {
		t.Errorf("oversized body: %d", w.Code)
	}
	// conflict
	if w := g.do(http.MethodPost, g.url(""), `{"pattern":"main"}`); w.Code != 201 {
		t.Fatalf("create: %d", w.Code)
	}
	w = g.do(http.MethodPost, g.url(""), `{"pattern":"main"}`)
	if c, _ := gpErr(t, w); w.Code != http.StatusConflict || c != "DUPLICATE_PATTERN" {
		t.Fatalf("duplicate: %d %s", w.Code, w.Body)
	}
	// ids
	if w := g.do(http.MethodPut, g.url("/not-a-uuid"), `{"pattern":"x"}`); w.Code != http.StatusBadRequest {
		t.Errorf("bad rule id: %d", w.Code)
	}
	w = g.do(http.MethodPut, g.url("/"+uuid.NewString()), `{"pattern":"x"}`)
	if c, _ := gpErr(t, w); w.Code != http.StatusNotFound || c != "NOT_FOUND" {
		t.Errorf("unknown rule: %d %s", w.Code, w.Body)
	}
	// evaluate input
	for _, q := range []string{"", "?branch=", "?branch=a..b"} {
		w := g.do(http.MethodGet, g.url("/evaluate"+q), "")
		if c, _ := gpErr(t, w); w.Code != http.StatusUnprocessableEntity || c != "VALIDATION_ERROR" {
			t.Errorf("evaluate %q: %d %s", q, w.Code, w.Body)
		}
	}
	// Forgejo down: a create still answers 201 (rule kept) but flags the sync error; a delete answers 502
	g.fs.Fail = func(fake.Request) int { return 500 }
	w = g.do(http.MethodPost, g.url(""), `{"pattern":"develop"}`)
	c := gpJSON(t, w)
	if w.Code != 201 || c["forgejo_synced"] != false || c["sync_status"] != "error" || c["sync_error"] == "" {
		t.Fatalf("create with Forgejo down: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), fake.Token) {
		t.Fatal("the response leaks the service token")
	}
	for id := range g.store.rules {
		if g.store.rules[id].Pattern == "main" {
			time.Sleep(30 * time.Millisecond)
			w = g.do(http.MethodDelete, g.url("/"+id.String()), "")
			if code, _ := gpErr(t, w); w.Code != http.StatusBadGateway || code != "UPSTREAM_GIT_ERROR" {
				t.Fatalf("delete with Forgejo down: %d %s", w.Code, w.Body)
			}
		}
	}
}

func TestGitProtectProjectOfAnotherOrgIs404(t *testing.T) {
	g := newGPRig(t, gpOwner)
	url := "/orgs/" + uuid.NewString() + "/projects/" + g.project.ID.String() + "/git/protections"
	if w := g.do(http.MethodGet, url, ""); w.Code != http.StatusNotFound {
		t.Fatalf("foreign org: %d %s", w.Code, w.Body)
	}
	url = "/orgs/" + g.org.ID.String() + "/projects/" + uuid.NewString() + "/git/protections"
	if w := g.do(http.MethodGet, url, ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown project: %d %s", w.Code, w.Body)
	}
	if w := g.do(http.MethodGet, "/orgs/x/projects/y/git/protections", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("bad ids: %d", w.Code)
	}
}

func TestGitProtectNotConfiguredAnswers501(t *testing.T) {
	gitprotect.SetShared(nil)
	r := chi.NewRouter()
	MountGitProtect(r, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/orgs/"+uuid.NewString()+"/projects/"+uuid.NewString()+"/git/protections", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestGitProtectEvaluateRouteDoesNotCollideWithRuleID(t *testing.T) {
	g := newGPRig(t, gpOwner)
	// GET .../protections/evaluate is the evaluator, never a rule lookup
	if w := g.do(http.MethodGet, g.url("/evaluate?branch=main"), ""); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// DELETE .../protections/evaluate would be a rule id "evaluate": invalid id
	if w := g.do(http.MethodDelete, g.url("/evaluate"), ""); w.Code != http.StatusBadRequest {
		t.Fatalf("%d", w.Code)
	}
}
