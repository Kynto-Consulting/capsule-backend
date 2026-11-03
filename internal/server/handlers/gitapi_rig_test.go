package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/forgejo"
	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitcore/fake"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// ---- fakes (prefixed gapi to stay clear of the other test files of the package) -------------

type gapiOrgs struct {
	domain.OrganizationRepository
	org  *domain.Organization
	role string
}

func (o *gapiOrgs) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	if id != o.org.ID {
		return nil, domain.ErrNotFound
	}
	return o.org, nil
}
func (o *gapiOrgs) GetMemberRole(context.Context, uuid.UUID, uuid.UUID) (string, error) {
	if o.role == "" {
		return "", domain.ErrNotFound
	}
	return o.role, nil
}
func (o *gapiOrgs) IsMember(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return o.role != "", nil
}

type gapiProjects struct {
	domain.ProjectRepository
	p *domain.Project
}

func (f gapiProjects) GetByID(_ context.Context, id uuid.UUID) (*domain.Project, error) {
	if id != f.p.ID {
		return nil, domain.ErrNotFound
	}
	return f.p, nil
}

type gapiStore struct{ access *authz.OrgAccess }

func (s gapiStore) LoadOrgAccess(context.Context, uuid.UUID, uuid.UUID) (*authz.OrgAccess, error) {
	return s.access, nil
}
func (s gapiStore) UserGrants(context.Context, uuid.UUID) ([]authz.Grant, error) { return nil, nil }

type gapiGitRepo struct {
	domain.GitRepository
	link *domain.ProjectGit
}

func (g gapiGitRepo) Get(context.Context, uuid.UUID) (*domain.ProjectGit, error) {
	if g.link == nil {
		return nil, domain.ErrNotFound
	}
	return g.link, nil
}
func (g gapiGitRepo) ListPreviews(context.Context, uuid.UUID) ([]*domain.Preview, error) {
	return nil, nil
}

// gapiExt lights up the optional capabilities gitcore does not expose yet.
type gapiExt struct {
	gitcore.Core
	reruns int
}

func (e *gapiExt) RerunRun(_ context.Context, _ gitcore.RepoRef, id int64, _ bool) (*gitcore.Run, error) {
	e.reruns++
	return &gitcore.Run{ID: id + 100, Index: id + 100, WorkflowID: "ci.yml", Ref: "main", Status: "waiting", StartedAt: time.Now()}, nil
}
func (e *gapiExt) ListSecrets(context.Context, gitcore.RepoRef) ([]gitapi.SecretInfo, error) {
	return []gitapi.SecretInfo{{Name: "MY_SECRET", UpdatedAt: time.Now()}}, nil
}
func (e *gapiExt) ListRunners(context.Context, string) ([]gitapi.Runner, error) {
	return []gitapi.Runner{{ID: "1", Name: "r1", Labels: []string{"ubuntu"}, Status: "online", Trusted: true}}, nil
}
func (e *gapiExt) ListArtifacts(context.Context, gitcore.RepoRef, int64) ([]gitapi.Artifact, error) {
	return []gitapi.Artifact{{Name: "dist", Size: 10, DownloadURL: "https://x/dist.zip", ExpiresAt: time.Now()}}, nil
}

// ---- the rig ---------------------------------------------------------------------------------

const (
	gapiOrgSlug  = "acme"
	gapiRepoSlug = "shop"
	gapiActor    = "bob" // the requesting user's Forgejo login; the pull request author is "alice"
)

type gapiRig struct {
	t       *testing.T
	fs      *fake.Server
	core    *gitcore.Service
	h       http.Handler
	org     *domain.Organization
	proj    *domain.Project
	user    *domain.User
	prefix  string
	runID   int64
	jobID   int64
	mainSHA string
	feature string
	actor   *string
	legacy  *GitCoreHandler
	router  chi.Router
}

type gapiOpts struct {
	role     string // viewer|deployer|admin|hidden|none (default admin)
	core     func(*gitcore.Service) gitcore.Core
	disabled bool
	link     *domain.ProjectGit
	legacy   bool
	noWeb    bool // no CAPSULE_GIT_BOT_PASSWORD: jobs, logs, cancel, artifacts degrade
}

func gapiAccess(role string, pid uuid.UUID) (*authz.OrgAccess, string) {
	switch role {
	case "viewer", "deployer":
		return &authz.OrgAccess{OrgRole: "member", Mode: authz.ModeRestricted, Explicit: map[uuid.UUID]string{pid: role}}, "member"
	case "hidden":
		return &authz.OrgAccess{OrgRole: "member", Mode: authz.ModeRestricted, Explicit: map[uuid.UUID]string{}}, "member"
	case "none":
		return nil, ""
	}
	return &authz.OrgAccess{OrgRole: "admin", Mode: authz.ModeOpen}, "admin"
}

func newGapiRig(t *testing.T, o gapiOpts) *gapiRig {
	t.Helper()
	if o.role == "" {
		o.role = "admin"
	}
	fs := fake.New()
	t.Cleanup(fs.Close)
	cfg := gitcore.Config{URL: fs.URL, Token: fake.Token, Timeout: 2 * time.Second, BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond}
	if !o.noWeb {
		cfg.BotLogin, cfg.BotPassword, cfg.WebVersions = fake.BotLogin, fake.BotPassword, []string{"15.0.*"}
	}
	if o.disabled {
		cfg = gitcore.Config{}
	}
	fixCore := gitcore.New(gitcore.Config{URL: fs.URL, Token: fake.Token, Timeout: 2 * time.Second, BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond}, nil, nil)
	core := gitcore.New(cfg, nil, nil)
	org := &domain.Organization{ID: uuid.New(), Slug: gapiOrgSlug, Name: "Acme"}
	proj := &domain.Project{ID: uuid.New(), OrgID: org.ID, Slug: gapiRepoSlug, Name: "Shop"}
	user := &domain.User{ID: uuid.New(), Email: "bob@example.com", Name: "Bob"}
	access, orgRole := gapiAccess(o.role, proj.ID)
	orgs := &gapiOrgs{org: org, role: orgRole}
	var cc gitcore.Core = core
	if o.core != nil {
		cc = o.core(core)
	}
	actor := gapiActor
	deps := GitAPIDeps{Core: cc, Authz: authz.New(gapiStore{access}), Orgs: orgs, Projects: gapiProjects{p: proj},
		Actor: func(context.Context, *domain.User) (string, error) { return actor, nil }}
	if o.link != nil || o.legacy {
		gh := NewGitHandler(GitDeps{Git: gapiGitRepo{link: o.link}, Projects: gapiProjects{p: proj}, Orgs: orgs})
		deps.Git = gh
		deps.Legacy = NewGitCoreHandler(gh, &forgejo.Core{Client: forgejo.NewClient(forgejo.Config{})}, nil)
	}
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), user)))
		})
	})
	MountGitAPI(r, deps)
	g := &gapiRig{t: t, fs: fs, core: fixCore, h: r, router: r, actor: &actor, legacy: deps.Legacy, org: org, proj: proj, user: user,
		prefix: "/orgs/" + org.ID.String() + "/projects/" + proj.ID.String() + "/git"}
	g.fixture()
	return g
}

func (g *gapiRig) fixture() {
	fs, ctx := g.fs, context.Background()
	ref := gitcore.RepoRef{Owner: gapiOrgSlug, Repo: gapiRepoSlug}
	fs.AddUser(gapiActor)
	fs.AddUser("alice")
	fs.AddRepo(gapiOrgSlug, gapiRepoSlug)
	g.mainSHA = fs.Commit(gapiOrgSlug, gapiRepoSlug, "main", "add ci and sources", map[string]string{
		".forgejo/workflows/ci.yml": "name: CI\non:\n  push:\n  workflow_dispatch:\njobs:\n  build:\n    runs-on: ubuntu\n",
		"src/app.go":                "package main\n\nfunc main() {}\n",
	})
	g.feature = fs.Commit(gapiOrgSlug, gapiRepoSlug, "feature", "feat: add x", map[string]string{"x.txt": "x\n"})
	fs.Commit(gapiOrgSlug, gapiRepoSlug, "feature2", "feat: add y", map[string]string{"y.txt": "y\n"})
	fs.AddPull(gapiOrgSlug, gapiRepoSlug, "Add x", "feature", "main")
	g.runID, g.jobID = fs.AddRun(gapiOrgSlug, gapiRepoSlug, "success", "step 1\nexport API_TOKEN=abc123supersecret\ntoken: cgt_0123456789abcdef0123456789\ndone\n")
	gapiMust(g.t, gapiIgnore(g.core.CreateTag(ctx, ref, "v1", "main", "")))
	gapiMust(g.t, g.core.SetVariable(ctx, ref, "MY_VAR", "1"))
	gapiMust(g.t, g.core.SetSecret(ctx, ref, "MY_SECRET", "s3cr3t"))
	gapiMust(g.t, g.core.SetVariable(ctx, gitcore.RepoRef{Owner: gapiOrgSlug}, "ORG_VAR", "o"))
	gapiMust(g.t, g.core.SetSecret(ctx, gitcore.RepoRef{Owner: gapiOrgSlug}, "ORG_SECRET", "o"))
}

func gapiIgnore[T any](_ T, err error) error { return err }

func gapiMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// do sends a request under the project's /git prefix; a path starting with "/orgs/" is used as is.
func (g *gapiRig) do(method, path string, body any, hdr ...string) *httptest.ResponseRecorder {
	g.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
	}
	if !strings.HasPrefix(path, "/orgs/") {
		path = g.prefix + path
	}
	req := httptest.NewRequest(method, path, rd)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	g.h.ServeHTTP(rec, req)
	return rec
}

func (g *gapiRig) orgPath(p string) string { return "/orgs/" + g.org.ID.String() + p }

func gapiMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("not a JSON object (%d): %s", rec.Code, rec.Body.String())
	}
	return m
}

func gapiErrCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	m := gapiMap(t, rec)
	e, _ := m["error"].(map[string]any)
	if e == nil {
		t.Fatalf("no error envelope (%d): %s", rec.Code, rec.Body.String())
	}
	c, _ := e["code"].(string)
	return c
}

func gapiWant(t *testing.T, rec *httptest.ResponseRecorder, code int) {
	t.Helper()
	if rec.Code != code {
		t.Fatalf("status %d, want %d: %s", rec.Code, code, rec.Body.String())
	}
}

func gapiItems(t *testing.T, m map[string]any) []any {
	t.Helper()
	l, ok := m["items"].([]any)
	if !ok {
		t.Fatalf("no items array in %v", m)
	}
	return l
}

// as changes the Forgejo login the requesting user acts as ("" = identity not ready).
func (g *gapiRig) as(login string) { *g.actor = login }

// routes lists "METHOD pattern" of every mounted route with regex constraints removed.
func (g *gapiRig) routes() []string {
	var out []string
	_ = chi.Walk(g.router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.TrimSuffix(route, "/")
		route = strings.Replace(route, "/git/branches/*", "/git/branches/{branch}", 1)
		route = strings.Replace(route, "/git/tags/*", "/git/tags/{tag}", 1)
		out = append(out, method+" "+route)
		return nil
	})
	return out
}
