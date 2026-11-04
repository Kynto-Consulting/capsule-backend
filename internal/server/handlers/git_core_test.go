package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/forgejo"
	"github.com/kynto/capsule/backend/internal/gitsource"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/internal/service"
)

// previewStore adds preview persistence to memGit.
type previewStore struct {
	memGit
	mu        sync.Mutex
	pvs       map[int]*domain.Preview
	destroyed []uuid.UUID
}

func (p *previewStore) GetPreview(_ context.Context, _ uuid.UUID, pr int) (*domain.Preview, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pv, ok := p.pvs[pr]; ok {
		return pv, nil
	}
	return nil, domain.ErrNotFound
}

func (p *previewStore) ListPreviews(context.Context, uuid.UUID) ([]*domain.Preview, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []*domain.Preview
	for _, pv := range p.pvs {
		out = append(out, pv)
	}
	return out, nil
}

func (p *previewStore) DestroyPreview(_ context.Context, id uuid.UUID) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.destroyed = append(p.destroyed, id)
	for k, pv := range p.pvs {
		if pv.ProjectID == id {
			delete(p.pvs, k)
		}
	}
	return nil
}

type fakeDeployments struct {
	domain.DeploymentRepository
	list []*domain.Deployment
}

func (f fakeDeployments) ListByProject(context.Context, uuid.UUID, int, int) ([]*domain.Deployment, int, error) {
	return f.list, len(f.list), nil
}

type fakeAuthzStore struct{ access *authz.OrgAccess }

func (f fakeAuthzStore) LoadOrgAccess(context.Context, uuid.UUID, uuid.UUID) (*authz.OrgAccess, error) {
	return f.access, nil
}
func (f fakeAuthzStore) UserGrants(context.Context, uuid.UUID) ([]authz.Grant, error) {
	return nil, nil
}

type coreRig struct {
	h       *GitCoreHandler
	store   *previewStore
	project *domain.Project
	router  chi.Router
	api     *httptest.Server // fake provider API
	hits    int
	mu      sync.Mutex
	deps    *fakeDeployments
	ran     []*gitsource.Event
}

func newCoreRig(t *testing.T, access *authz.OrgAccess) *coreRig {
	t.Helper()
	p := &domain.Project{ID: uuid.New(), OrgID: uuid.New(), Slug: "shop"}
	store := &previewStore{pvs: map[int]*domain.Preview{}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &service.GitService{Git: store, Fetcher: fakeFetch{}, Logger: logger, AppsDomain: "apps.example.com"}
	gh := NewGitHandler(GitDeps{Git: store, Projects: onlyProject{p: p}, Orgs: fakeOrgRepo{role: "owner"}, Policy: publicPolicy(), Fetcher: fakeFetch{}, Service: svc, Logger: logger})
	deps := &fakeDeployments{}
	core := &forgejo.Core{Client: forgejo.NewClient(forgejo.Config{})}
	h := NewGitCoreHandler(gh, core, deps)
	h.SetAuthz(authz.New(fakeAuthzStore{access: access}))
	h.previewWait = 2 * time.Second

	rg := &coreRig{h: h, store: store, project: p, deps: deps}
	rg.api = httptest.NewServer(http.HandlerFunc(rg.provider))
	t.Cleanup(rg.api.Close)
	h.clientFor = func(*domain.ProjectGit) (*gitsource.ProviderClient, error) {
		return &gitsource.ProviderClient{Kind: "forgejo", APIBase: rg.api.URL + "/api/v1", Owner: "acme", Repo: "shop", Token: "t", HTTP: rg.api.Client()}, nil
	}
	h.runPreview = func(_ context.Context, _ *domain.ProjectGit, parent *domain.Project, ev *gitsource.Event) error {
		rg.mu.Lock()
		rg.ran = append(rg.ran, ev)
		rg.mu.Unlock()
		dep := uuid.New()
		store.mu.Lock()
		store.pvs[ev.PR] = &domain.Preview{ProjectID: uuid.New(), ParentProjectID: parent.ID, Slug: "shop-pr-" + string(rune('0'+ev.PR%10)), PR: ev.PR, Status: "active", LatestDeployment: &dep, DeploymentStatus: "building"}
		store.mu.Unlock()
		return nil
	}

	user := &domain.User{ID: uuid.New(), Name: "Ana"}
	r := chi.NewRouter()
	r.Route("/orgs/{orgID}/projects/{projectID}", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), user)))
			})
		})
		r.Get("/git", gh.Get)
		r.Post("/git/repo", h.CreateRepo)
		r.Get("/git/repo", h.RepoStatus)
		r.Get("/git/branches", h.Branches)
		r.Get("/git/commits", h.Commits)
		r.Get("/git/pulls", h.Pulls)
		r.Post("/previews", h.CreatePreview)
		r.Delete("/previews/{pr}", h.DeletePreview)
	})
	rg.router = r
	return rg
}

// provider is a fake Forgejo repository API.
func (rg *coreRig) provider(w http.ResponseWriter, r *http.Request) {
	rg.mu.Lock()
	rg.hits++
	rg.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/v1/repos/acme/shop":
		w.Write([]byte(`{"default_branch":"main"}`))
	case "/api/v1/repos/acme/shop/branches":
		w.Write([]byte(`[{"name":"main","commit":{"id":"aaaaaaaa11111111"},"protected":true},{"name":"dev","commit":{"id":"bbbbbbbb22222222"},"protected":false}]`))
	case "/api/v1/repos/acme/shop/commits":
		if r.URL.Query().Get("sha") != "main" {
			http.Error(w, "unexpected branch "+r.URL.Query().Get("sha"), 400)
			return
		}
		if r.URL.Query().Get("page") == "2" {
			w.Header().Set("X-HasMore", "false")
			w.Write([]byte(`[{"sha":"cccccccc33333333","html_url":"https://git/c3","commit":{"message":"old\n\nbody","author":{"name":"Bo","date":"2026-10-01T10:00:00Z"}}}]`))
			return
		}
		w.Header().Set("X-HasMore", "true")
		w.Write([]byte(`[
		 {"sha":"aaaaaaaa11111111","html_url":"https://git/c1","commit":{"message":"feat: one\n\nlong body","author":{"name":"Ana","date":"2026-11-01T10:00:00Z"}},"author":{"login":"ana"}},
		 {"sha":"dddddddd44444444","html_url":"https://git/c2","commit":{"message":"fix: two","author":{"name":"","date":"2026-10-31T10:00:00Z"}},"author":{"login":"bo"}}]`))
	case "/api/v1/repos/acme/shop/pulls":
		w.Write([]byte(`[
		 {"number":7,"title":"Add cart","state":"open","html_url":"https://git/pr/7","user":{"login":"ana"},"head":{"ref":"feat/cart","sha":"x"},"base":{"ref":"main"}},
		 {"number":8,"title":"Docs","state":"open","html_url":"https://git/pr/8","user":{"login":"bo"},"head":{"ref":"docs","sha":"y"},"base":{"ref":"main"}}]`))
	default:
		http.NotFound(w, r)
	}
}

func (rg *coreRig) do(method, path string, body any) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, "/orgs/"+rg.project.OrgID.String()+"/projects/"+rg.project.ID.String()+path, rd)
	rec := httptest.NewRecorder()
	rg.router.ServeHTTP(rec, req)
	return rec
}

func (rg *coreRig) link(provider string) {
	rg.store.link = &domain.ProjectGit{ProjectID: rg.project.ID, Provider: provider, RepoURL: "https://git.example.com/acme/shop.git", Branch: "main", AuthKind: "token", Credential: "t", PreviewEnabled: true}
}

var coreOwnerAccess = &authz.OrgAccess{OrgRole: "owner", Mode: authz.ModeOpen}

func TestBranchesView(t *testing.T) {
	rg := newCoreRig(t, coreOwnerAccess)
	rg.link("forgejo")
	rec := rg.do("GET", "/git/branches", nil)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	want := `{"data":[{"name":"main","sha":"aaaaaaaa11111111","default":true,"protected":true},{"name":"dev","sha":"bbbbbbbb22222222","default":false,"protected":false}]}`
	if strings.TrimSpace(rec.Body.String()) != want {
		t.Fatalf("got %s", rec.Body)
	}
	// cached: a second call does not hit the provider again
	hits := rg.hits
	rg.do("GET", "/git/branches", nil)
	if rg.hits != hits {
		t.Fatalf("branches must be cached (%d -> %d provider calls)", hits, rg.hits)
	}
}

func TestCommitsViewJoinsDeploymentsBySHA(t *testing.T) {
	rg := newCoreRig(t, coreOwnerAccess)
	rg.link("forgejo")
	depID := uuid.New()
	rg.deps.list = []*domain.Deployment{{ID: depID, GitSHA: "AAAAAAAA11111111", Status: "running"}, {ID: uuid.New(), GitSHA: "", Status: "queued"}}

	rec := rg.do("GET", "/git/commits?branch=main", nil)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var got struct {
		Data []struct {
			SHA        string         `json:"sha"`
			ShortSHA   string         `json:"short_sha"`
			Message    string         `json:"message"`
			Author     string         `json:"author"`
			AuthoredAt string         `json:"authored_at"`
			URL        string         `json:"url"`
			Deployment map[string]any `json:"deployment"`
		} `json:"data"`
		Page    int  `json:"page"`
		HasMore bool `json:"has_more"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Page != 1 || !got.HasMore || len(got.Data) != 2 {
		t.Fatalf("%+v", got)
	}
	c1, c2 := got.Data[0], got.Data[1]
	if c1.ShortSHA != "aaaaaaa" || c1.Message != "feat: one" || c1.Author != "Ana" || c1.URL != "https://git/c1" || c1.AuthoredAt != "2026-11-01T10:00:00Z" {
		t.Fatalf("c1 %+v", c1)
	}
	if c1.Deployment == nil || c1.Deployment["id"] != depID.String() || c1.Deployment["status"] != "running" {
		t.Fatalf("c1 deployment %v", c1.Deployment)
	}
	if c2.Deployment != nil || c2.Author != "bo" {
		t.Fatalf("c2 must have a null deployment and fall back to the login: %+v", c2)
	}
	if !strings.Contains(rec.Body.String(), `"deployment":null`) {
		t.Fatalf("deployment must serialize as null: %s", rec.Body)
	}

	// no deployments at all
	rg.deps.list = nil
	rec = rg.do("GET", "/git/commits?branch=main&page=2", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"page":2`) || !strings.Contains(rec.Body.String(), `"has_more":false`) || strings.Contains(rec.Body.String(), `"deployment":{`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// default branch comes from the link; bad branch and page are rejected
	if rec = rg.do("GET", "/git/commits", nil); rec.Code != 200 {
		t.Fatalf("default branch: %d %s", rec.Code, rec.Body)
	}
	if rec = rg.do("GET", "/git/commits?branch=--upload-pack", nil); rec.Code != 422 {
		t.Fatalf("bad branch: %d", rec.Code)
	}
	if rec = rg.do("GET", "/git/commits?page=0", nil); rec.Code != 422 {
		t.Fatalf("bad page: %d", rec.Code)
	}
}

func TestPullsViewJoinsPreviews(t *testing.T) {
	rg := newCoreRig(t, coreOwnerAccess)
	rg.link("forgejo")
	exp := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	rg.store.pvs[7] = &domain.Preview{ProjectID: uuid.New(), PR: 7, Slug: "shop-pr-7", Status: "active", DeploymentStatus: "running", ExpiresAt: &exp}

	rec := rg.do("GET", "/git/pulls", nil)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	want := `{"data":[` +
		`{"number":7,"title":"Add cart","author":"ana","state":"open","head_ref":"feat/cart","base_ref":"main","url":"https://git/pr/7","preview":{"url":"https://shop-pr-7.apps.example.com","status":"running","expires_at":"2026-11-09T00:00:00Z"}},` +
		`{"number":8,"title":"Docs","author":"bo","state":"open","head_ref":"docs","base_ref":"main","url":"https://git/pr/8","preview":null}]}`
	if strings.TrimSpace(rec.Body.String()) != want {
		t.Fatalf("got  %s\nwant %s", rec.Body, want)
	}
	if rec = rg.do("GET", "/git/pulls?state=merged", nil); rec.Code != 422 {
		t.Fatalf("bad state: %d", rec.Code)
	}
}

func TestViewsRequireReadAccessAndSupportedProvider(t *testing.T) {
	// not a member of the org
	rg := newCoreRig(t, nil)
	rg.link("forgejo")
	for _, p := range []string{"/git/branches", "/git/commits", "/git/pulls"} {
		if rec := rg.do("GET", p, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("%s as outsider: %d", p, rec.Code)
		}
	}
	// restricted org, no explicit role: the project looks absent
	rg = newCoreRig(t, &authz.OrgAccess{OrgRole: "member", Mode: authz.ModeRestricted, Explicit: nil})
	rg.link("forgejo")
	if rec := rg.do("GET", "/git/branches", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("hidden project must look absent: %d", rec.Code)
	}
	// generic provider has no API
	rg = newCoreRig(t, coreOwnerAccess)
	rg.link("generic")
	rg.h.clientFor = nil
	if rec := rg.do("GET", "/git/branches", nil); rec.Code != 422 {
		t.Fatalf("generic: %d %s", rec.Code, rec.Body)
	}
	// no link
	rg = newCoreRig(t, coreOwnerAccess)
	if rec := rg.do("GET", "/git/commits", nil); rec.Code != 404 {
		t.Fatalf("no link: %d", rec.Code)
	}
}

func TestViewClientUsesServiceTokenForForgejoLinksWithoutCredential(t *testing.T) {
	rg := newCoreRig(t, coreOwnerAccess)
	rg.h.clientFor = nil
	rg.h.core = &forgejo.Core{Client: forgejo.NewClient(forgejo.Config{URL: "https://git.example.com", Token: "SERVICE"})}
	c, err := rg.h.viewClient(&domain.ProjectGit{Provider: "forgejo", RepoURL: "https://git.example.com/acme/shop.git", AuthKind: "none"})
	if err != nil || c.Token != "SERVICE" || c.APIBase != "https://git.example.com/api/v1" {
		t.Fatalf("%+v %v", c, err)
	}
	c, err = rg.h.viewClient(&domain.ProjectGit{Provider: "forgejo", RepoURL: "https://other.example.com/acme/shop.git", AuthKind: "none"})
	if err != nil || c.Token != "" {
		t.Fatalf("the service token must never be sent to other hosts: %+v %v", c, err)
	}
	c, _ = rg.h.viewClient(&domain.ProjectGit{Provider: "gitea", RepoURL: "https://g.example.com/a/b.git", AuthKind: "token", Credential: "mine"})
	if c.Token != "mine" {
		t.Fatal("link credential wins")
	}
}

func TestGitGetAddsCloneURLsOnlyForForgejo(t *testing.T) {
	rg := newCoreRig(t, coreOwnerAccess)
	rg.h.gh.CoreLinks = (&forgejo.Core{Client: forgejo.NewClient(forgejo.Config{URL: "https://git.example.com", Token: "t", SSHHost: "git.example.com"})}).Links
	rg.link("forgejo")
	rec := rg.do("GET", "/git", nil)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	if m["clone_url_https"] != "https://git.example.com/acme/shop.git" || m["clone_url_ssh"] != "git@git.example.com:acme/shop.git" || m["web_url"] != "https://git.example.com/acme/shop" {
		t.Fatalf("%v", m)
	}
	if m["provider"] != "forgejo" || m["has_credential"] != true || m["webhook_url"] == nil {
		t.Fatalf("other fields unchanged: %v", m)
	}
	rg.link("github")
	rec = rg.do("GET", "/git", nil)
	if strings.Contains(rec.Body.String(), "clone_url") || strings.Contains(rec.Body.String(), "web_url") {
		t.Fatalf("github link must not get clone urls: %s", rec.Body)
	}
}

func TestCreateRepoNotConfiguredAndConflicts(t *testing.T) {
	rg := newCoreRig(t, coreOwnerAccess)
	if rec := rg.do("POST", "/git/repo", nil); rec.Code != http.StatusNotImplemented {
		t.Fatalf("disabled core: %d %s", rec.Code, rec.Body)
	}
	// enabled but the project already points to another provider: 409 before touching Forgejo
	rg.h.core = &forgejo.Core{Client: forgejo.NewClient(forgejo.Config{URL: "http://127.0.0.1:1", Token: "t"}), PublicURL: "https://api.example.com",
		Git: rg.store, Projects: onlyProject{p: rg.project}, Orgs: coreFakeOrgs{}, Store: coreNoStore{}, Policy: publicPolicy(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rg.link("github")
	if rec := rg.do("POST", "/git/repo", map[string]string{"import_url": ""}); rec.Code != http.StatusConflict {
		t.Fatalf("linked elsewhere: %d %s", rec.Code, rec.Body)
	}
	// SSRF validation of import_url is answered immediately with 422
	rg.store.link = nil
	rg.h.gh.Policy = gitsource.Policy{Lookup: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.1.2.3")}, nil }}
	if rec := rg.do("POST", "/git/repo", map[string]string{"import_url": "https://evil.example.com/x.git"}); rec.Code != 422 {
		t.Fatalf("private import url: %d %s", rec.Code, rec.Body)
	}
	if rec := rg.do("POST", "/git/repo", map[string]string{"import_url": "file:///etc/passwd"}); rec.Code != 422 {
		t.Fatalf("file url: %d", rec.Code)
	}
	if rec := rg.do("POST", "/git/repo", "not-json{"); rec.Code != 400 {
		t.Fatalf("bad json: %d", rec.Code)
	}
}

func TestCreateRepoReturnsURLs(t *testing.T) {
	rg := newCoreRig(t, coreOwnerAccess)
	ff := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := strings.TrimPrefix(r.URL.Path, "/api/v1")
		switch {
		case r.Method == "GET" && strings.HasPrefix(p, "/orgs/"):
			w.Write([]byte(`{}`))
		case r.Method == "GET" && p == "/repos/acme/shop":
			w.WriteHeader(404)
		case r.Method == "POST" && p == "/orgs/acme/repos":
			w.WriteHeader(201)
			w.Write([]byte(`{"name":"shop","default_branch":"main"}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/hooks"):
			w.Write([]byte(`[]`))
		case r.Method == "POST" && strings.HasSuffix(p, "/hooks"):
			w.WriteHeader(201)
			w.Write([]byte(`{"id":1}`))
		default:
			w.Write([]byte(`{"ok":true,"data":[]}`))
		}
	}))
	defer ff.Close()
	rg.h.core = &forgejo.Core{
		Client: forgejo.NewClient(forgejo.Config{URL: "https://git.example.com", Token: "t", SSHHost: "git.example.com"}), PublicURL: "https://api.example.com",
		Git: rg.store, Projects: onlyProject{p: rg.project}, Orgs: coreFakeOrgs{}, Store: coreNoStore{}, Policy: publicPolicy(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	rg.h.core.Client.HTTP = &http.Client{Transport: coreRewriteTo(ff.URL)}
	rec := rg.do("POST", "/git/repo", nil)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	want := `{"web_url":"https://git.example.com/acme/shop","clone_url_https":"https://git.example.com/acme/shop.git","clone_url_ssh":"git@git.example.com:acme/shop.git"}`
	if strings.TrimSpace(rec.Body.String()) != want {
		t.Fatalf("got %s", rec.Body)
	}
	if rg.store.link == nil || rg.store.link.Provider != "forgejo" || !rg.store.link.AutoDeploy {
		t.Fatalf("link %+v", rg.store.link)
	}
}

func TestCreatePreviewByAPI(t *testing.T) {
	rg := newCoreRig(t, coreOwnerAccess)
	rg.link("forgejo")

	rec := rg.do("POST", "/previews", map[string]any{"pr": 12, "ref": "feat/x", "sha": "abcdef1234567"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["pr"] != float64(12) || got["url"] != "https://shop-pr-2.apps.example.com" || got["status"] != "building" || got["deployment_id"] == nil || len(got) != 4 {
		t.Fatalf("%v", got)
	}
	if len(rg.ran) != 1 || rg.ran[0].PR != 12 || rg.ran[0].Branch != "feat/x" || rg.ran[0].SHA != "abcdef1234567" || rg.ran[0].Kind != gitsource.EventPullRequest || rg.ran[0].HeadFork {
		t.Fatalf("event %+v", rg.ran)
	}
	// second call updates the existing preview: 200
	if rec = rg.do("POST", "/previews", map[string]any{"pr": 12, "ref": "feat/x"}); rec.Code != http.StatusOK {
		t.Fatalf("update: %d", rec.Code)
	}

	for name, body := range map[string]map[string]any{
		"zero pr":     {"pr": 0, "ref": "x"},
		"negative pr": {"pr": -1, "ref": "x"},
		"option ref":  {"pr": 1, "ref": "--upload-pack=x"},
		"dotdot ref":  {"pr": 1, "ref": "a..b"},
		"empty ref":   {"pr": 1, "ref": ""},
		"bad sha":     {"pr": 1, "ref": "x", "sha": "zz; rm -rf"},
	} {
		if rec = rg.do("POST", "/previews", body); rec.Code != 422 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	rg.store.link.PreviewEnabled = false
	if rec = rg.do("POST", "/previews", map[string]any{"pr": 3, "ref": "x"}); rec.Code != 422 {
		t.Fatalf("previews disabled: %d", rec.Code)
	}
	rg.store.link = nil
	if rec = rg.do("POST", "/previews", map[string]any{"pr": 3, "ref": "x"}); rec.Code != 404 {
		t.Fatalf("no link: %d", rec.Code)
	}
}

func TestCreatePreviewFailureAndPermission(t *testing.T) {
	rg := newCoreRig(t, coreOwnerAccess)
	rg.link("forgejo")
	rg.h.runPreview = func(context.Context, *domain.ProjectGit, *domain.Project, *gitsource.Event) error {
		return io.ErrUnexpectedEOF
	}
	if rec := rg.do("POST", "/previews", map[string]any{"pr": 3, "ref": "x"}); rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "EOF") {
		t.Fatalf("failure must be generic: %d %s", rec.Code, rec.Body)
	}
	// slow builds answer 202 and keep going
	release := make(chan struct{})
	rg.h.previewWait = 50 * time.Millisecond
	rg.h.runPreview = func(context.Context, *domain.ProjectGit, *domain.Project, *gitsource.Event) error {
		<-release
		return nil
	}
	rec := rg.do("POST", "/previews", map[string]any{"pr": 4, "ref": "x"})
	close(release)
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"status":"building"`) || !strings.Contains(rec.Body.String(), "shop-pr-4.apps.example.com") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rg.h.gh.Service.Wait()

	// viewer: may read but not create or delete previews
	viewer := newCoreRig(t, &authz.OrgAccess{OrgRole: "member", Mode: authz.ModeRestricted, Explicit: nil})
	viewer.link("forgejo")
	viewer.h.SetAuthz(authz.New(fakeAuthzStore{access: &authz.OrgAccess{OrgRole: "member", Mode: authz.ModeOpen, Explicit: map[uuid.UUID]string{viewer.project.ID: "viewer"}}}))
	if rec := viewer.do("POST", "/previews", map[string]any{"pr": 3, "ref": "x"}); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer create: %d", rec.Code)
	}
	if rec := viewer.do("DELETE", "/previews/3", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer delete: %d", rec.Code)
	}
	if rec := viewer.do("GET", "/git/branches", nil); rec.Code != 200 {
		t.Fatalf("viewer read: %d", rec.Code)
	}
	// deployer may
	dep := newCoreRig(t, &authz.OrgAccess{OrgRole: "member", Mode: authz.ModeOpen})
	dep.link("forgejo")
	if rec := dep.do("POST", "/previews", map[string]any{"pr": 3, "ref": "x"}); rec.Code != http.StatusCreated {
		t.Fatalf("deployer create: %d %s", rec.Code, rec.Body)
	}
}

func TestDeletePreviewByAPI(t *testing.T) {
	rg := newCoreRig(t, coreOwnerAccess)
	rg.link("forgejo")
	pvID := uuid.New()
	rg.store.pvs[9] = &domain.Preview{ProjectID: pvID, PR: 9, Slug: "shop-pr-9"}
	if rec := rg.do("DELETE", "/previews/9", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(rg.store.destroyed) != 1 || rg.store.destroyed[0] != pvID {
		t.Fatalf("destroyed %v", rg.store.destroyed)
	}
	if rec := rg.do("DELETE", "/previews/9", nil); rec.Code != 404 {
		t.Fatalf("again: %d", rec.Code)
	}
	if rec := rg.do("DELETE", "/previews/abc", nil); rec.Code != 400 {
		t.Fatalf("bad pr: %d", rec.Code)
	}
}

func TestRepoStatusShowsProvisioningState(t *testing.T) {
	rg := newCoreRig(t, coreOwnerAccess)
	st := &coreStateStore{st: &domain.GitCoreState{ProjectID: rg.project.ID, Status: domain.GitCorePending, Attempts: 2, LastError: "organization: forgejo GET /orgs/acme: HTTP 502"}}
	rg.h.core = &forgejo.Core{Client: forgejo.NewClient(forgejo.Config{URL: "https://git.example.com", Token: "t"}), Orgs: coreFakeOrgs{}, Store: st}
	rec := rg.do("GET", "/git/repo", nil)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	if rec.Code != 200 || m["status"] != "pending" || m["attempts"] != float64(2) || m["last_error"] == nil || m["clone_url_https"] != "https://git.example.com/acme/shop.git" {
		t.Fatalf("%d %v", rec.Code, m)
	}
}

func TestCapabilitiesDefaultsRegistrationAndMerge(t *testing.T) {
	capsMu.Lock()
	saved := capsProv
	capsProv = map[string]CapabilityProvider{}
	capsMu.Unlock()
	defer func() { capsMu.Lock(); capsProv = saved; capsMu.Unlock() }()

	rec := httptest.NewRecorder()
	PlatformCapabilities(rec, httptest.NewRequest("GET", "/api/v1/platform/capabilities", nil))
	want := `{"backups":{"default_schedule":"daily","enabled":false},"git":{"enabled":false,"ssh_host":"","url":""},"ingress":{"host":"","ipv4":"","ipv6":"","mode":"alb"},"oidc":{"enabled":false,"issuer":""},"ports":{"enabled":false,"host":"","range":"41000-41999"}}`
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != want {
		t.Fatalf("defaults: %d %s", rec.Code, rec.Body)
	}

	RegisterCapability("ports", func() any { return map[string]any{"enabled": true, "host": "tcp.example.com"} })
	RegisterCapability("git", func() any {
		return map[string]any{"enabled": true, "url": "https://git.example.com", "ssh_host": "git.example.com"}
	})
	RegisterCapability("backups", func() any { return map[string]any{"enabled": true, "default_schedule": "daily"} })
	RegisterCapabilityProvider(coreOIDCProv{})
	c := Capabilities()
	ports := c["ports"].(map[string]any)
	if ports["enabled"] != true || ports["host"] != "tcp.example.com" || ports["range"] != "41000-41999" {
		t.Fatalf("ports merge: %v", ports)
	}
	if c["git"].(map[string]any)["url"] != "https://git.example.com" || c["backups"].(map[string]any)["enabled"] != true {
		t.Fatalf("%v", c)
	}
	if c["oidc"].(map[string]any)["issuer"] != "https://api.example.com" {
		t.Fatalf("provider: %v", c["oidc"])
	}
}

type coreOIDCProv struct{}

func (coreOIDCProv) Name() string { return "oidc" }
func (coreOIDCProv) Capability() any {
	return map[string]any{"enabled": true, "issuer": "https://api.example.com"}
}

func TestGitCoreHooksAreOptionalAndNeverPanic(t *testing.T) {
	SetGitCoreHooks(GitCoreHooks{})
	notifyProjectCreated(&domain.Project{})
	notifyMembersChanged(uuid.New(), uuid.New())
	notifyOrgChanged(uuid.New())
	var got []string
	SetGitCoreHooks(GitCoreHooks{
		ProjectCreated: func(*domain.Project) { got = append(got, "created") },
		MembersChanged: func(_, _ uuid.UUID) { got = append(got, "members") },
		OrgChanged:     func(uuid.UUID) { got = append(got, "org") },
	})
	defer SetGitCoreHooks(GitCoreHooks{})
	notifyProjectCreated(&domain.Project{})
	notifyMembersChanged(uuid.New(), uuid.New())
	notifyOrgChanged(uuid.New())
	if strings.Join(got, ",") != "created,members,org" {
		t.Fatal(got)
	}
}

// ---- small fakes ---------------------------------------------------------------

type coreFakeOrgs struct{ domain.OrganizationRepository }

func (coreFakeOrgs) GetByID(context.Context, uuid.UUID) (*domain.Organization, error) {
	return &domain.Organization{Slug: "acme"}, nil
}
func (coreFakeOrgs) GetMembers(context.Context, uuid.UUID) ([]*domain.OrgMember, error) { return nil, nil }

type coreNoStore struct{}

func (coreNoStore) GetState(context.Context, uuid.UUID) (*domain.GitCoreState, error) {
	return nil, domain.ErrNotFound
}
func (coreNoStore) PutState(context.Context, *domain.GitCoreState) error { return nil }
func (coreNoStore) ListDueStates(context.Context, time.Time, int) ([]*domain.GitCoreState, error) {
	return nil, nil
}
func (coreNoStore) ReplaceTeamSync(context.Context, uuid.UUID, []uuid.UUID, string, time.Time) error {
	return nil
}
func (coreNoStore) ListDueTeamSync(context.Context, time.Time, int) ([]*domain.GitTeamSync, error) {
	return nil, nil
}

type coreStateStore struct {
	coreNoStore
	st *domain.GitCoreState
}

func (s *coreStateStore) GetState(context.Context, uuid.UUID) (*domain.GitCoreState, error) {
	return s.st, nil
}

type coreRewriteTransport struct{ to string }

func (r coreRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := http.NewRequest(req.Method, r.to+req.URL.RequestURI(), req.Body)
	u.Header = req.Header
	return http.DefaultTransport.RoundTrip(u.WithContext(req.Context()))
}

func coreRewriteTo(to string) http.RoundTripper { return coreRewriteTransport{to: to} }
