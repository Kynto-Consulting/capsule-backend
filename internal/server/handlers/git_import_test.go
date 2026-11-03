package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitcore/fake"
	"github.com/kynto/capsule/backend/internal/gitimport"
	"github.com/kynto/capsule/backend/internal/gitimport/gitimporttest"
	"github.com/kynto/capsule/backend/internal/gitsource"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

const c1Token = "ghp_C1HANDLERSECRETabcdefghijklmnop55"

// c1Projects is a project repository for the handlers: GetByID for the rig's project, plus the
// GetBySlug/Create the import service uses.
type c1Projects struct {
	domain.ProjectRepository
	mem *gitimporttest.Projects
	p   *domain.Project
}

func (f c1Projects) GetBySlug(ctx context.Context, org uuid.UUID, slug string) (*domain.Project, error) {
	return f.mem.GetBySlug(ctx, org, slug)
}
func (f c1Projects) Create(ctx context.Context, p *domain.Project) (*domain.Project, error) {
	return f.mem.Create(ctx, p)
}

func (f c1Projects) GetByID(_ context.Context, id uuid.UUID) (*domain.Project, error) {
	if id != f.p.ID {
		return nil, domain.ErrNotFound
	}
	return f.p, nil
}

type c1Rig struct {
	t      *testing.T
	h      http.Handler
	org    *domain.Organization
	proj   *domain.Project
	mem    *gitimporttest.Mem
	gh     *gitimporttest.GitHub
	fj     *fake.Server
	imp    *gitimport.Service
	mir    *gitimport.MirrorService
	anon   bool
	router chi.Router
}

// c1Opts: role is the effective role of the caller: admin (org admin), owner, member (open mode, so
// it gets deployer-level access... see gapiAccess), viewer, deployer, hidden, none.
func newC1Rig(t *testing.T, role string, anon bool) *c1Rig {
	t.Helper()
	fs := fake.New()
	t.Cleanup(fs.Close)
	gh := gitimporttest.NewGitHub(c1Token)
	t.Cleanup(gh.Close)
	org := &domain.Organization{ID: uuid.New(), Slug: "acme", Name: "Acme"}
	proj := &domain.Project{ID: uuid.New(), OrgID: org.ID, Slug: "shop", Name: "Shop"}
	user := &domain.User{ID: uuid.New(), Email: "bob@example.com", Name: "Bob"}
	access, orgRole := gapiAccess(role, proj.ID)
	if role == "member" {
		access, orgRole = &authz.OrgAccess{OrgRole: "member", Mode: authz.ModeOpen}, "member"
	}
	if role == "owner" {
		access, orgRole = &authz.OrgAccess{OrgRole: "owner", Mode: authz.ModeOpen}, "owner"
	}
	orgs := &gapiOrgs{org: org, role: orgRole}
	fs.AddRepo("acme", "shop")

	core := gitcore.New(gitcore.Config{URL: fs.URL, Token: fake.Token, Timeout: 5 * time.Second, BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond}, nil, nil)
	mem := gitimporttest.NewMem()
	policy := gitsource.Policy{Lookup: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("140.82.112.3")}, nil }}
	projects := c1Projects{mem: gitimporttest.NewProjects(), p: proj}
	imp := gitimport.New(context.Background(), gitimport.Config{GitHubAPI: gh.URL, RepoTimeout: time.Minute}, gitimport.Deps{
		Store: mem, Forge: core, GitHub: &gitimport.GitHub{BaseURL: gh.URL, HTTP: http.DefaultClient},
		Projects: projects, Linker: mem, Audit: mem, Policy: policy,
	})
	mir := gitimport.NewMirrors(context.Background(), gitimport.Config{SyncTimeout: time.Minute}, gitimport.MirrorDeps{Store: mem, Forge: core, Policy: policy, Audit: mem})

	WireGitImport(GitImportWiring{Import: imp, Mirror: mir})
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if anon {
				next.ServeHTTP(w, req)
				return
			}
			next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), user)))
		})
	})
	MountGitImport(r, GitImportDeps{Authz: authz.New(gapiStore{access}), Orgs: orgs, Projects: projects})
	return &c1Rig{t: t, h: r, router: r, org: org, proj: proj, mem: mem, gh: gh, fj: fs, imp: imp, mir: mir}
}

func (g *c1Rig) do(method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	g.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req := httptest.NewRequest(method, path, rd)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	g.h.ServeHTTP(w, req)
	return w
}

func (g *c1Rig) impPath() string { return "/orgs/" + g.org.ID.String() + "/git/imports" }
func (g *c1Rig) mirPath() string {
	return "/orgs/" + g.org.ID.String() + "/projects/" + g.proj.ID.String() + "/git/mirror"
}

func c1Decode(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
}

func c1Code(w *httptest.ResponseRecorder) string {
	var e struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	return e.Error.Code
}

func TestGitImportCreateAndGet(t *testing.T) {
	g := newC1Rig(t, "admin", false)
	g.gh.Add("octo/web", gitimporttest.GitHubRepo{Private: true, Files: map[string]string{"CODEOWNERS": "/src/ @alice\n"}})
	body := map[string]any{"source": "github", "token": c1Token, "repos": []string{"octo/web", "octo/missing"}, "include": []string{"releases"}}
	w := g.do("POST", g.impPath(), body, map[string]string{"Idempotency-Key": "k1"})
	if w.Code != 202 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %s %v", w.Code, w.Body.String(), w.Header())
	}
	var job struct {
		ID     uuid.UUID `json:"id"`
		Status string    `json:"status"`
		Repos  []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"repos"`
	}
	c1Decode(t, w, &job)
	if job.ID == uuid.Nil || len(job.Repos) != 2 {
		t.Fatalf("job: %+v", job)
	}
	g.imp.Wait()

	w = g.do("GET", g.impPath()+"/"+job.ID.String(), nil, nil)
	if w.Code != 200 {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	var got struct {
		Status string `json:"status"`
		Repos  []struct {
			Name       string                            `json:"name"`
			Status     string                            `json:"status"`
			ProjectID  *string                           `json:"project_id"`
			Error      string                            `json:"error"`
			Warnings   []string                          `json:"warnings"`
			CodeOwners *struct{ Path, Converted string } `json:"codeowners"`
		} `json:"repos"`
	}
	c1Decode(t, w, &got)
	if got.Status != "partial" {
		t.Fatalf("status: %s %s", got.Status, w.Body.String())
	}
	for _, r := range got.Repos {
		switch r.Name {
		case "octo/web":
			if r.Status != "success" || r.ProjectID == nil || r.CodeOwners == nil || !strings.Contains(r.CodeOwners.Converted, "src/.* @alice") {
				t.Fatalf("web: %+v", r)
			}
		case "octo/missing":
			if r.Status != "failed" || r.ProjectID != nil || r.Error == "" {
				t.Fatalf("missing: %+v", r)
			}
		}
	}
	// no response ever carries the token
	if strings.Contains(w.Body.String(), "C1HANDLERSECRET") {
		t.Fatal("token in a response")
	}

	// resume through the API with the same key and a token
	g.gh.Add("octo/missing", gitimporttest.GitHubRepo{})
	w = g.do("POST", g.impPath(), body, map[string]string{"Idempotency-Key": "k1"})
	if w.Code != 202 {
		t.Fatalf("resume: %d %s", w.Code, w.Body.String())
	}
	var res struct {
		ID      uuid.UUID `json:"id"`
		Resumed bool      `json:"resumed"`
	}
	c1Decode(t, w, &res)
	g.imp.Wait()
	if res.ID != job.ID || !res.Resumed {
		t.Fatalf("resume: %+v", res)
	}
	w = g.do("GET", g.impPath()+"/"+job.ID.String(), nil, nil)
	c1Decode(t, w, &got)
	if got.Status != "success" {
		t.Fatalf("after resume: %s", w.Body.String())
	}
	if strings.Contains(g.mem.Dump(), "C1HANDLERSECRET") {
		t.Fatal("token persisted")
	}
}

func TestGitImportRejections(t *testing.T) {
	g := newC1Rig(t, "admin", false)
	g.gh.Add("octo/web", gitimporttest.GitHubRepo{})
	cases := []struct {
		name string
		body any
		hdr  map[string]string
		code int
		err  string
	}{
		{"unknown field", `{"source":"github","token":"x","repos":["a/b"],"surprise":1}`, nil, 400, "INVALID_JSON"},
		{"not json", `nope`, nil, 400, "INVALID_JSON"},
		{"trailing data", `{"source":"github","token":"x","repos":["a/b"]} {}`, nil, 400, "INVALID_JSON"},
		{"other source", map[string]any{"source": "gitlab", "token": "x", "repos": []string{"a/b"}}, nil, 422, "VALIDATION_ERROR"},
		{"other org", map[string]any{"source": "github", "token": "x", "repos": []string{"a/b"}, "target_org_id": uuid.NewString()}, nil, 422, "VALIDATION_ERROR"},
		{"no repos", map[string]any{"source": "github", "token": "x", "repos": []string{}}, nil, 422, "VALIDATION_ERROR"},
		{"bad repo", map[string]any{"source": "github", "token": "x", "repos": []string{"../etc"}}, nil, 422, "VALIDATION_ERROR"},
		{"bad token", map[string]any{"source": "github", "token": "ghp_nopenopenopenopenopenope123456", "repos": []string{"octo/web"}}, nil, 422, "TOKEN_INVALID"},
		{"long key", map[string]any{"source": "github", "token": c1Token, "repos": []string{"octo/web"}}, map[string]string{"Idempotency-Key": strings.Repeat("k", 129)}, 422, "VALIDATION_ERROR"},
	}
	for _, c := range cases {
		w := g.do("POST", g.impPath(), c.body, c.hdr)
		if w.Code != c.code || c1Code(w) != c.err {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "nopenope") || strings.Contains(w.Body.String(), "C1HANDLERSECRET") {
			t.Errorf("%s: token echoed: %s", c.name, w.Body.String())
		}
	}
	// same key, other payload
	ok := map[string]any{"source": "github", "token": c1Token, "repos": []string{"octo/web"}}
	if w := g.do("POST", g.impPath(), ok, map[string]string{"Idempotency-Key": "z"}); w.Code != 202 {
		t.Fatalf("first: %d %s", w.Code, w.Body.String())
	}
	g.imp.Wait()
	g.gh.Add("octo/other", gitimporttest.GitHubRepo{})
	other := map[string]any{"source": "github", "token": c1Token, "repos": []string{"octo/other"}}
	if w := g.do("POST", g.impPath(), other, map[string]string{"Idempotency-Key": "z"}); w.Code != 409 || c1Code(w) != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("conflict: %d %s", w.Code, w.Body.String())
	}
	// unknown import and bad id
	if w := g.do("GET", g.impPath()+"/"+uuid.NewString(), nil, nil); w.Code != 404 {
		t.Fatalf("unknown import: %d", w.Code)
	}
	if w := g.do("GET", g.impPath()+"/nope", nil, nil); w.Code != 400 {
		t.Fatalf("bad id: %d", w.Code)
	}
}

func TestGitImportRequiresOrgAdmin(t *testing.T) {
	body := map[string]any{"source": "github", "token": c1Token, "repos": []string{"octo/web"}}
	for role, want := range map[string]int{"admin": 202, "owner": 202, "member": 403, "viewer": 403, "none": 403} {
		g := newC1Rig(t, role, false)
		g.gh.Add("octo/web", gitimporttest.GitHubRepo{})
		if w := g.do("POST", g.impPath(), body, nil); w.Code != want {
			t.Errorf("%s create: %d %s", role, w.Code, w.Body.String())
		}
		g.imp.Wait()
		id := uuid.NewString()
		wantGet := 404
		if want == 403 {
			wantGet = 403
		}
		if w := g.do("GET", g.impPath()+"/"+id, nil, nil); w.Code != wantGet {
			t.Errorf("%s get: %d", role, w.Code)
		}
	}
	g := newC1Rig(t, "admin", true)
	if w := g.do("POST", g.impPath(), body, nil); w.Code != 401 {
		t.Errorf("anonymous: %d", w.Code)
	}
	// an import of another org is invisible
	g = newC1Rig(t, "admin", false)
	g.gh.Add("octo/web", gitimporttest.GitHubRepo{})
	w := g.do("POST", g.impPath(), body, nil)
	var job struct{ ID uuid.UUID }
	c1Decode(t, w, &job)
	g.imp.Wait()
	// the router only knows its org; ask the service for the same id under another org
	if _, err := g.imp.Get(context.Background(), uuid.New(), job.ID); err == nil {
		t.Fatal("an import must be scoped to its organization")
	}
}

func TestGitMirrorRoutes(t *testing.T) {
	g := newC1Rig(t, "admin", false)
	if w := g.do("GET", g.mirPath(), nil, nil); w.Code != 404 {
		t.Fatalf("no mirror: %d %s", w.Code, w.Body.String())
	}
	put := map[string]any{"remote_url": "https://github.com/acme/shop-backup.git", "credential": "ghp_MIRRORHANDLERSECRETabcdefghij12", "branches": []string{"main"}, "interval": "hourly"}
	w := g.do("PUT", g.mirPath(), put, nil)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	var m struct {
		RemoteURL     string   `json:"remote_url"`
		Branches      []string `json:"branches"`
		Interval      string   `json:"interval"`
		HasCredential bool     `json:"has_credential"`
		RemoteHost    string   `json:"remote_host"`
		Notice        string   `json:"notice"`
		LastError     string   `json:"last_error"`
		Syncing       bool     `json:"syncing"`
	}
	c1Decode(t, w, &m)
	if m.RemoteURL != "https://github.com/acme/shop-backup.git" || !m.HasCredential || m.Interval != "hourly" || m.RemoteHost != "github.com" ||
		!strings.Contains(m.Notice, "tercero") || len(m.Branches) != 1 {
		t.Fatalf("mirror: %+v", m)
	}
	for _, resp := range []*httptest.ResponseRecorder{w, g.do("GET", g.mirPath(), nil, nil)} {
		if strings.Contains(resp.Body.String(), "MIRRORHANDLERSECRET") {
			t.Fatalf("credential in a response: %s", resp.Body.String())
		}
	}
	// the credential reached Forgejo (it needs it) and is stored encrypted
	if strings.Contains(g.mem.Dump(), "MIRRORHANDLERSECRET") {
		t.Fatal("credential stored in the clear")
	}
	// the credential field is write-only and optional on replace
	put2 := map[string]any{"remote_url": "https://github.com/acme/shop-backup.git", "branches": []string{"main", "dev"}}
	if w := g.do("PUT", g.mirPath(), put2, nil); w.Code != 200 {
		t.Fatalf("replace: %d %s", w.Code, w.Body.String())
	}
	if w := g.do("GET", g.mirPath(), nil, nil); !strings.Contains(w.Body.String(), `"has_credential":true`) {
		t.Fatalf("credential must survive a replace: %s", w.Body.String())
	}
	// sync
	w = g.do("POST", g.mirPath()+"/sync", nil, map[string]string{"Idempotency-Key": "s1"})
	if w.Code != 202 || !strings.Contains(w.Body.String(), `"status":"queued"`) {
		t.Fatalf("sync: %d %s", w.Code, w.Body.String())
	}
	g.mir.Wait()
	// validation and upstream mapping
	if w := g.do("PUT", g.mirPath(), map[string]any{"remote_url": "http://github.com/a/b.git"}, nil); w.Code != 422 || c1Code(w) != "VALIDATION_ERROR" {
		t.Fatalf("http: %d %s", w.Code, w.Body.String())
	}
	if w := g.do("PUT", g.mirPath(), `{"remote_url":"https://github.com/a/b.git","extra":1}`, nil); w.Code != 400 {
		t.Fatalf("unknown field: %d", w.Code)
	}
	// audit trail: set, set, sync - and never the credential
	acts := g.mem.AuditActions()
	if len(acts) != 3 || acts[0] != gitimport.AuditMirrorSet || acts[2] != gitimport.AuditMirrorSync {
		t.Fatalf("audit: %v", acts)
	}
	if w := g.do("DELETE", g.mirPath(), nil, nil); w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
	if w := g.do("DELETE", g.mirPath(), nil, nil); w.Code != 404 {
		t.Fatalf("delete twice: %d", w.Code)
	}
	if w := g.do("POST", g.mirPath()+"/sync", nil, nil); w.Code != 404 {
		t.Fatalf("sync without mirror: %d", w.Code)
	}
}

func TestGitMirrorRequiresGitAdmin(t *testing.T) {
	put := map[string]any{"remote_url": "https://github.com/acme/shop-backup.git"}
	// admin = org admin (git.admin); deployer/viewer lack it; hidden is 404; non-member is 403
	for role, want := range map[string]int{"admin": 200, "deployer": 403, "viewer": 403, "hidden": 404, "none": 403} {
		g := newC1Rig(t, role, false)
		if w := g.do("PUT", g.mirPath(), put, nil); w.Code != want {
			t.Errorf("%s put: %d %s", role, w.Code, w.Body.String())
		}
		for _, call := range []struct{ m, p string }{{"GET", ""}, {"DELETE", ""}, {"POST", "/sync"}} {
			got := g.do(call.m, g.mirPath()+call.p, nil, nil).Code
			if want != 200 && got != want {
				t.Errorf("%s %s%s: %d, want %d", role, call.m, call.p, got, want)
			}
		}
		if want != 200 && len(g.mem.Audits) != 0 {
			t.Errorf("%s: a refused request must not be audited", role)
		}
	}
	g := newC1Rig(t, "admin", true)
	if w := g.do("PUT", g.mirPath(), put, nil); w.Code != 401 {
		t.Errorf("anonymous: %d", w.Code)
	}
}

func TestGitMirrorMapsForgejoErrors(t *testing.T) {
	g := newC1Rig(t, "admin", false)
	put := map[string]any{"remote_url": "https://github.com/acme/shop-backup.git"}
	g.fj.Fail = func(q fake.Request) int {
		if q.Method == "POST" && strings.HasSuffix(q.Path, "/push_mirrors") {
			return 401 // Forgejo's answer to a private/loopback remote
		}
		return 0
	}
	if w := g.do("PUT", g.mirPath(), put, nil); w.Code != 422 || !strings.Contains(w.Body.String(), "private and loopback") {
		t.Fatalf("401 upstream: %d %s", w.Code, w.Body.String())
	}
	g.fj.Fail = func(q fake.Request) int {
		if q.Method == "POST" && strings.HasSuffix(q.Path, "/push_mirrors") {
			return 500
		}
		return 0
	}
	if w := g.do("PUT", g.mirPath(), put, nil); w.Code != 502 || c1Code(w) != "UPSTREAM_GIT_ERROR" {
		t.Fatalf("500 upstream: %d %s", w.Code, w.Body.String())
	}
}
