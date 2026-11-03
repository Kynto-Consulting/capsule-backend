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
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitsource"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/internal/service"
)

type memGit struct {
	domain.GitRepository
	link     *domain.ProjectGit
	previews []*domain.Preview
}

func (m *memGit) Get(_ context.Context, id uuid.UUID) (*domain.ProjectGit, error) {
	if m.link != nil && m.link.ProjectID == id {
		c := *m.link
		return &c, nil
	}
	return nil, domain.ErrNotFound
}
func (m *memGit) Upsert(_ context.Context, g *domain.ProjectGit) (*domain.ProjectGit, error) {
	c := *g
	c.CreatedAt, c.UpdatedAt = time.Now(), time.Now()
	m.link = &c
	return &c, nil
}
func (m *memGit) Delete(_ context.Context, id uuid.UUID) error {
	if m.link == nil {
		return domain.ErrNotFound
	}
	m.link = nil
	return nil
}
func (m *memGit) IsPreview(context.Context, uuid.UUID) (bool, error) { return false, nil }
func (m *memGit) ListPreviews(context.Context, uuid.UUID) ([]*domain.Preview, error) {
	return m.previews, nil
}

type onlyProject struct {
	domain.ProjectRepository
	p *domain.Project
}

func (o onlyProject) GetByID(_ context.Context, id uuid.UUID) (*domain.Project, error) {
	if o.p.ID == id {
		return o.p, nil
	}
	return nil, domain.ErrNotFound
}

type denyAll struct{}

func (denyAll) CanManage(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (bool, error) {
	return false, nil
}
func (denyAll) CanDeploy(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (bool, error) {
	return false, nil
}

type fakeFetch struct{ branches []string }

func (f fakeFetch) Fetch(context.Context, string, string, gitsource.Auth) (*gitsource.Snapshot, error) {
	return nil, io.EOF
}
func (f fakeFetch) ListBranches(context.Context, string, gitsource.Auth) ([]string, error) {
	return f.branches, nil
}

func publicPolicy() gitsource.Policy {
	return gitsource.Policy{Lookup: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil }}
}

type gitRig struct {
	h       *GitHandler
	store   *memGit
	project *domain.Project
	user    *domain.User
	router  chi.Router
}

func newGitRig(t *testing.T) *gitRig {
	t.Helper()
	p := &domain.Project{ID: uuid.New(), OrgID: uuid.New(), Slug: "shop"}
	store := &memGit{}
	svc := &service.GitService{Git: store, Fetcher: fakeFetch{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), AppsDomain: "apps.example.com"}
	h := NewGitHandler(GitDeps{
		Git: store, Projects: onlyProject{p: p}, Orgs: fakeOrgRepo{role: "owner"}, Policy: publicPolicy(),
		Fetcher: fakeFetch{branches: []string{"main", "dev"}}, Service: svc, PublicHost: "api.example.com",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	user := &domain.User{ID: uuid.New()}
	r := chi.NewRouter()
	r.Post("/hooks/git/{projectID}", h.Webhook)
	r.Route("/orgs/{orgID}/projects/{projectID}", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), user)))
			})
		})
		r.Get("/git", h.Get)
		r.Put("/git", h.Put)
		r.Delete("/git", h.Delete)
		r.Post("/git/test", h.Test)
		r.Get("/previews", h.Previews)
	})
	return &gitRig{h: h, store: store, project: p, user: user, router: r}
}

func (g *gitRig) do(method, path string, body any) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	rec := httptest.NewRecorder()
	g.router.ServeHTTP(rec, req)
	return rec
}

func (g *gitRig) base() string {
	return "/orgs/" + g.project.OrgID.String() + "/projects/" + g.project.ID.String()
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("bad json %q: %v", rec.Body.String(), err)
	}
	return m
}

func TestGitAPILifecycleNeverLeaksSecrets(t *testing.T) {
	g := newGitRig(t)
	rec := g.do("PUT", g.base()+"/git", map[string]any{
		"repo_url": "https://git.example.com/acme/shop.git", "provider": "forgejo", "auth_kind": "token", "token": "super-token-123",
		"auto_deploy": true, "preview_enabled": true,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}
	created := decode(t, rec)
	secret, _ := created["webhook_secret"].(string)
	if len(secret) < 32 {
		t.Fatalf("webhook_secret must be returned on creation: %v", created)
	}
	if created["webhook_url"] != "https://api.example.com/hooks/git/"+g.project.ID.String() {
		t.Fatalf("webhook_url %v", created["webhook_url"])
	}
	if created["has_credential"] != true || created["preview_max"] != float64(5) || created["preview_ttl_hours"] != float64(168) || created["branch"] != "main" {
		t.Fatalf("defaults: %v", created)
	}
	if strings.Contains(rec.Body.String(), "super-token-123") {
		t.Fatal("token leaked in PUT response")
	}

	rec = g.do("GET", g.base()+"/git", nil)
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	got := rec.Body.String()
	if strings.Contains(got, "super-token-123") || strings.Contains(got, secret) || strings.Contains(got, "webhook_secret") || strings.Contains(got, "auth_enc") {
		t.Fatalf("GET leaked secret material: %s", got)
	}
	if m := decode(t, rec); m["webhook_url"] == nil || m["has_credential"] != true {
		t.Fatalf("GET body %v", m)
	}

	// update without credential keeps the stored one; no new secret revealed
	rec = g.do("PUT", g.base()+"/git", map[string]any{"branch": "develop"})
	m := decode(t, rec)
	if rec.Code != 200 || m["branch"] != "develop" || m["has_credential"] != true || m["webhook_secret"] != nil {
		t.Fatalf("update: %d %v", rec.Code, m)
	}
	if g.store.link.Credential != "super-token-123" || g.store.link.WebhookSecret != secret {
		t.Fatal("credential and secret must be preserved on update")
	}

	// rotation reveals a NEW secret once
	rec = g.do("PUT", g.base()+"/git", map[string]any{"rotate_webhook_secret": true})
	m = decode(t, rec)
	if s2, _ := m["webhook_secret"].(string); s2 == "" || s2 == secret || g.store.link.WebhookSecret != s2 {
		t.Fatalf("rotation: %v", m)
	}

	if rec = g.do("DELETE", g.base()+"/git", nil); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	if rec = g.do("GET", g.base()+"/git", nil); rec.Code != 404 {
		t.Fatal(rec.Code)
	}
}

func TestGitAPIValidation(t *testing.T) {
	g := newGitRig(t)
	bad := []map[string]any{
		{"repo_url": "http://git.example.com/a/b"},
		{"repo_url": "https://u:p@git.example.com/a/b"},
		{"repo_url": "https://git.example.com/a/b", "branch": "--upload-pack=x"},
		{"repo_url": "https://git.example.com/a/b", "provider": "svn"},
		{"repo_url": "https://git.example.com/a/b", "auth_kind": "token"},
		{"repo_url": "https://git.example.com/a/b", "auth_kind": "token", "token": "a\r\nX-Evil: 1"},
		{"repo_url": "https://git.example.com/a/b", "auth_kind": "ssh_key", "ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nx"},
		{"repo_url": "ssh://git@git.example.com/a/b", "auth_kind": "token", "token": "t"},
		{"repo_url": "https://git.example.com/a/b", "preview_max": 0},
		{"repo_url": "https://git.example.com/a/b", "preview_ttl_hours": 100000},
		{"auth_kind": "none"}, // no repo_url
	}
	for i, b := range bad {
		if rec := g.do("PUT", g.base()+"/git", b); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("case %d (%v): got %d %s", i, b, rec.Code, rec.Body)
		}
	}
	if g.store.link != nil {
		t.Fatal("nothing may be stored for invalid requests")
	}
}

func TestGitAPISSRFOnPut(t *testing.T) {
	g := newGitRig(t)
	g.h.Policy = gitsource.Policy{Lookup: func(_ context.Context, host string) ([]net.IP, error) {
		if host == "internal.corp" {
			return []net.IP{net.ParseIP("10.0.0.7")}, nil
		}
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}}
	for _, u := range []string{"https://internal.corp/a/b", "https://169.254.169.254/a/b", "https://127.0.0.1/a/b", "ssh://git@10.1.1.1/a/b"} {
		if rec := g.do("PUT", g.base()+"/git", map[string]any{"repo_url": u}); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d", u, rec.Code)
		}
	}
}

func TestGitAPIPermissionsAndTest(t *testing.T) {
	g := newGitRig(t)
	g.do("PUT", g.base()+"/git", map[string]any{"repo_url": "https://git.example.com/a/b", "branch": "dev"})
	rec := g.do("POST", g.base()+"/git/test", nil)
	m := decode(t, rec)
	if rec.Code != 200 || m["ok"] != true || m["branch_found"] != true {
		t.Fatalf("test: %d %v", rec.Code, m)
	}
	g.h.SetAuthorizer(denyAll{})
	for _, c := range [][2]string{{"GET", "/git"}, {"PUT", "/git"}, {"DELETE", "/git"}, {"POST", "/git/test"}, {"GET", "/previews"}} {
		if rec := g.do(c[0], g.base()+c[1], map[string]any{"repo_url": "https://git.example.com/a/b"}); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: %d", c[0], c[1], rec.Code)
		}
	}
}

func TestOrgRoleAuthorizerDefault(t *testing.T) {
	for role, want := range map[string]bool{"owner": true, "admin": true, "member": true, "readonly": false, "": false} {
		ok, err := OrgRoleAuthorizer{Orgs: fakeOrgRepo{role: role}}.CanManage(context.Background(), uuid.New(), uuid.New(), uuid.New())
		if err != nil || ok != want {
			t.Errorf("role %q: %v %v", role, ok, err)
		}
	}
}

func TestPreviewsList(t *testing.T) {
	g := newGitRig(t)
	exp := time.Now().Add(time.Hour)
	g.store.previews = []*domain.Preview{{ProjectID: uuid.New(), Slug: "shop-pr-3", PR: 3, Status: "created", ExpiresAt: &exp, DeploymentStatus: "success"}}
	rec := g.do("GET", g.base()+"/previews", nil)
	var out struct {
		Data []map[string]any `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || len(out.Data) != 1 || out.Data[0]["url"] != "https://shop-pr-3.apps.example.com" || out.Data[0]["pr"] != float64(3) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

// ---- webhook -----------------------------------------------------------------------

func (g *gitRig) hook(id uuid.UUID, headers map[string]string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/hooks/git/"+id.String(), bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	g.router.ServeHTTP(rec, req)
	return rec
}

func TestWebhookAuthAndRouting(t *testing.T) {
	g := newGitRig(t)
	g.store.link = &domain.ProjectGit{ProjectID: g.project.ID, Provider: "github", RepoURL: "https://github.com/acme/shop.git",
		Branch: "main", WebhookSecret: "topsecret", AutoDeploy: true, PreviewEnabled: false}
	push := func(branch string) []byte {
		b, _ := json.Marshal(map[string]any{"ref": "refs/heads/" + branch, "after": "0123456789abcdef0123456789abcdef01234567",
			"repository": map[string]any{"clone_url": "https://github.com/acme/shop.git"}})
		return b
	}
	signed := func(body []byte, secret string) map[string]string {
		return map[string]string{"X-GitHub-Event": "push", "X-Hub-Signature-256": gitsource.Sign(body, secret)}
	}

	unauth := []struct {
		name string
		id   uuid.UUID
		hdr  map[string]string
		body []byte
	}{
		{"no signature", g.project.ID, map[string]string{"X-GitHub-Event": "push"}, push("main")},
		{"wrong secret", g.project.ID, signed(push("main"), "wrong"), push("main")},
		{"tampered body", g.project.ID, signed(push("main"), "topsecret"), push("dev")},
		{"unknown project", uuid.New(), signed(push("main"), "topsecret"), push("main")},
	}
	var bodies []string
	for _, c := range unauth {
		rec := g.hook(c.id, c.hdr, c.body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", c.name, rec.Code)
		}
		bodies = append(bodies, rec.Body.String())
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("401 responses must be identical (no hints): %q vs %q", b, bodies[0])
		}
	}

	// valid signature, non-configured branch / non-push event -> 202 ignored
	rec := g.hook(g.project.ID, signed(push("feature"), "topsecret"), push("feature"))
	if rec.Code != 202 || decode(t, rec)["status"] != "ignored" {
		t.Fatalf("other branch: %d %s", rec.Code, rec.Body)
	}
	ping := []byte(`{"zen":"x"}`)
	rec = g.hook(g.project.ID, map[string]string{"X-GitHub-Event": "ping", "X-Hub-Signature-256": gitsource.Sign(ping, "topsecret")}, ping)
	if rec.Code != 202 || decode(t, rec)["status"] != "ignored" {
		t.Fatalf("ping: %d %s", rec.Code, rec.Body)
	}
	// other repository under the same secret is ignored
	other, _ := json.Marshal(map[string]any{"ref": "refs/heads/main", "after": "0123456789abcdef0123456789abcdef01234567",
		"repository": map[string]any{"clone_url": "https://github.com/evil/other.git"}})
	rec = g.hook(g.project.ID, signed(other, "topsecret"), other)
	if rec.Code != 202 || decode(t, rec)["status"] != "ignored" {
		t.Fatalf("other repo: %d %s", rec.Code, rec.Body)
	}
	// PR events with previews disabled are ignored (except close)
	pr, _ := json.Marshal(map[string]any{"action": "opened", "number": 1, "pull_request": map[string]any{
		"head": map[string]any{"ref": "f", "sha": "abcdef1", "repo": map[string]any{"full_name": "acme/shop"}},
		"base": map[string]any{"ref": "main", "repo": map[string]any{"full_name": "acme/shop", "clone_url": "https://github.com/acme/shop.git"}}}})
	rec = g.hook(g.project.ID, map[string]string{"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": gitsource.Sign(pr, "topsecret")}, pr)
	if rec.Code != 202 || decode(t, rec)["status"] != "ignored" {
		t.Fatalf("pr disabled: %d %s", rec.Code, rec.Body)
	}

	// Forgejo-style hex signature header also works (accepted without a service wired -> ignored, but authenticated)
	body := push("main")
	rec = g.hook(g.project.ID, map[string]string{"X-Forgejo-Event": "push",
		"X-Forgejo-Signature": strings.TrimPrefix(gitsource.Sign(body, "topsecret"), "sha256=")}, body)
	if rec.Code != 202 {
		t.Fatalf("forgejo signature: %d %s", rec.Code, rec.Body)
	}
}

func TestWebhookValidPushIsAcceptedAndProcessedInBackground(t *testing.T) {
	g := newGitRig(t)
	g.store.link = &domain.ProjectGit{ProjectID: g.project.ID, Provider: "github", RepoURL: "https://github.com/acme/shop.git",
		Branch: "main", WebhookSecret: "topsecret", AutoDeploy: true}
	body, _ := json.Marshal(map[string]any{"ref": "refs/heads/main", "after": "0123456789abcdef0123456789abcdef01234567",
		"repository": map[string]any{"clone_url": "https://github.com/acme/shop.git"}})
	start := time.Now()
	rec := g.hook(g.project.ID, map[string]string{"X-GitHub-Event": "push", "X-Hub-Signature-256": gitsource.Sign(body, "topsecret")}, body)
	if rec.Code != 202 || decode(t, rec)["status"] != "accepted" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if time.Since(start) > time.Second {
		t.Fatal("webhook must answer fast")
	}
	g.h.Service.Wait() // background task ran (fails quietly: no fetcher wired in this fake) and did not panic
}
