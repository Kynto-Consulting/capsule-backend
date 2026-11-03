package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

func sp(s string) *string { return &s }
func ip(i int) *int       { return &i }

func TestMergeHealthValidation(t *testing.T) {
	cur := domain.DefaultProjectHealthConfig()
	bad := []healthPatch{
		{Path: sp("healthz")},                      // no leading slash
		{Path: sp("http://evil.test/x")},           // scheme
		{Path: sp("//evil.test/x")},                // host
		{Path: sp("/a b")},                         // whitespace
		{Path: sp("/x#frag")},                      // fragment
		{Path: sp("/" + strings.Repeat("a", 250))}, // too long
		{Timeout: ip(4)}, {Timeout: ip(601)}, {Timeout: ip(0)}, // timeout range
		{Expected: sp("abc")}, {Expected: sp("99")}, {Expected: sp("200-700")}, {Expected: sp("")}, {Expected: sp("399-200")},
		{Interval: ip(0)}, {Interval: ip(31)},
		{Interval: ip(30), Timeout: ip(10)}, // interval > timeout
	}
	for i, p := range bad {
		if _, err := mergeHealth(cur, p); err == nil {
			t.Errorf("case %d should be rejected: %+v", i, p)
		}
	}
	good, err := mergeHealth(cur, healthPatch{Path: sp("/healthz?full=1"), Timeout: ip(5), Expected: sp("200,204,301-302")})
	if err != nil || good.Path != "/healthz?full=1" || good.TimeoutSeconds != 5 || good.ExpectedStatus != "200,204,301-302" {
		t.Fatalf("good patch: %+v %v", good, err)
	}
	off, err := mergeHealth(good, healthPatch{Path: sp("")})
	if err != nil || off.Path != "" {
		t.Fatalf("empty path must disable the check: %+v %v", off, err)
	}
}

type memHealthStore struct{ cfg domain.ProjectHealthConfig }

func (m *memHealthStore) GetHealthConfig(context.Context, uuid.UUID) (domain.ProjectHealthConfig, error) {
	return m.cfg, nil
}
func (m *memHealthStore) SetHealthConfig(_ context.Context, _ uuid.UUID, c domain.ProjectHealthConfig) error {
	m.cfg = c
	return nil
}

type patchProjects struct {
	domain.ProjectRepository
	p *domain.Project
}

func (f patchProjects) GetByID(context.Context, uuid.UUID) (*domain.Project, error) {
	c := *f.p
	return &c, nil
}
func (f patchProjects) Update(_ context.Context, p *domain.Project) (*domain.Project, error) {
	c := *p
	return &c, nil
}

func withTestUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: uuid.New()})))
	})
}

func projectPatchRouter(role string, store domain.ProjectHealthStore, p *domain.Project) http.Handler {
	h := NewProjectHandler(patchProjects{p: p}, fakeOrgRepo{role: role})
	if store != nil {
		h.SetHealthStore(store)
	}
	r := chi.NewRouter()
	r.Use(withTestUser)
	r.Get("/orgs/{orgID}/projects/{projectID}", h.Get)
	r.Patch("/orgs/{orgID}/projects/{projectID}", h.Update)
	return r
}

func doJSON(r http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, path, &buf))
	return rec
}

func TestProjectPatchHealthFields(t *testing.T) {
	org, pid := uuid.New(), uuid.New()
	proj := &domain.Project{ID: pid, OrgID: org, Name: "x", Slug: "x"}
	store := &memHealthStore{cfg: domain.DefaultProjectHealthConfig()}
	r := projectPatchRouter("owner", store, proj)
	path := "/orgs/" + org.String() + "/projects/" + pid.String()

	// defaults on GET
	rec := doJSON(r, http.MethodGet, path, nil)
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != 200 || got["health_path"] != "" || got["health_timeout_seconds"] != float64(60) || got["health_expected_status"] != "200-399" {
		t.Fatalf("defaults: %d %s", rec.Code, rec.Body)
	}

	// valid patch is stored and echoed
	rec = doJSON(r, http.MethodPatch, path, map[string]any{"health_path": "/healthz", "health_timeout_seconds": 30, "health_expected_status": "200"})
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != 200 || got["health_path"] != "/healthz" || got["health_timeout_seconds"] != float64(30) || got["health_expected_status"] != "200" {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	if store.cfg.Path != "/healthz" || store.cfg.TimeoutSeconds != 30 {
		t.Fatalf("not stored: %+v", store.cfg)
	}

	// invalid patches -> 422 and nothing changes
	for _, body := range []map[string]any{
		{"health_path": "http://x/y"}, {"health_path": "nope"}, {"health_timeout_seconds": 3}, {"health_timeout_seconds": 601}, {"health_expected_status": "ok"},
	} {
		rec = doJSON(r, http.MethodPatch, path, body)
		if rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "VALIDATION_ERROR" {
			t.Errorf("%v: %d %s", body, rec.Code, rec.Body)
		}
	}
	if store.cfg.Path != "/healthz" || store.cfg.TimeoutSeconds != 30 {
		t.Fatalf("invalid patch changed settings: %+v", store.cfg)
	}

	// without a store the health fields are refused, other fields still work
	r2 := projectPatchRouter("owner", nil, proj)
	if rec = doJSON(r2, http.MethodPatch, path, map[string]any{"health_path": "/x"}); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no store: %d", rec.Code)
	}
	if rec = doJSON(r2, http.MethodPatch, path, map[string]any{"name": "y"}); rec.Code != 200 {
		t.Fatalf("plain patch: %d %s", rec.Code, rec.Body)
	}
}

// ── rollback ─────────────────────────────────────────────────────────────────

type rollbackDeploys struct {
	domain.DeploymentRepository
	byID    map[uuid.UUID]*domain.Deployment
	created []*domain.Deployment
}

func (f *rollbackDeploys) GetByID(_ context.Context, id uuid.UUID) (*domain.Deployment, error) {
	if d, ok := f.byID[id]; ok {
		return d, nil
	}
	return nil, domain.ErrNotFound
}
func (f *rollbackDeploys) Create(_ context.Context, d *domain.Deployment) (*domain.Deployment, error) {
	c := *d
	c.ID = uuid.New()
	c.Status = "queued"
	f.created = append(f.created, &c)
	return &c, nil
}

func rollbackRouter(role string, repo *rollbackDeploys, org, proj uuid.UUID) http.Handler {
	h := NewDeploymentHandler(repo, fakeOrgRepo{role: role},
		fakeAccessProjects{p: &domain.Project{ID: proj, OrgID: org, BuildStrategy: "docker"}}, nil, "")
	r := chi.NewRouter()
	r.Use(withTestUser)
	r.Post("/orgs/{orgID}/projects/{projectID}/deployments/{deploymentID}/rollback", h.Rollback)
	return r
}

func TestRollbackEndpoint(t *testing.T) {
	org, proj := uuid.New(), uuid.New()
	key := "deployments/x/src.tar.gz"
	ok := &domain.Deployment{ID: uuid.New(), ProjectID: proj, Status: "success", SourceKey: &key, GitSHA: "abc", BuildStrategy: "docker", ContainerPort: 3000}
	failed := &domain.Deployment{ID: uuid.New(), ProjectID: proj, Status: "failed", SourceKey: &key}
	nosrc := &domain.Deployment{ID: uuid.New(), ProjectID: proj, Status: "success"}
	foreign := &domain.Deployment{ID: uuid.New(), ProjectID: uuid.New(), Status: "success", SourceKey: &key}
	repo := &rollbackDeploys{byID: map[uuid.UUID]*domain.Deployment{ok.ID: ok, failed.ID: failed, nosrc.ID: nosrc, foreign.ID: foreign}}
	url := func(d *domain.Deployment) string {
		return "/orgs/" + org.String() + "/projects/" + proj.String() + "/deployments/" + d.ID.String() + "/rollback"
	}

	r := rollbackRouter("member", repo, org, proj) // org member => deployer
	rec := doJSON(r, http.MethodPost, url(ok), nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("rollback: %d %s", rec.Code, rec.Body)
	}
	if len(repo.created) != 1 {
		t.Fatalf("expected one new deployment, got %d", len(repo.created))
	}
	c := repo.created[0]
	if c.Trigger != "rollback" || c.SourceKey == nil || *c.SourceKey != key || c.GitSHA != "abc" || c.Meta["rollback_to"] != ok.ID.String() || c.ProjectID != proj {
		t.Fatalf("bad rollback deployment: %+v", c)
	}

	for name, d := range map[string]*domain.Deployment{"failed": failed, "no source": nosrc} {
		if rec := doJSON(r, http.MethodPost, url(d), nil); rec.Code != http.StatusConflict {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := doJSON(r, http.MethodPost, url(foreign), nil); rec.Code != http.StatusNotFound {
		t.Errorf("other project's deployment: %d", rec.Code)
	}
	if len(repo.created) != 1 {
		t.Fatalf("rejected rollbacks created deployments: %d", len(repo.created))
	}

	// read-only members cannot roll back (authz project.deploy)
	ro := rollbackRouter("readonly", repo, org, proj)
	if rec := doJSON(ro, http.MethodPost, url(ok), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("readonly: %d %s", rec.Code, rec.Body)
	}
}
