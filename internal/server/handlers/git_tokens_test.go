package handlers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gittokens"
	"github.com/kynto/capsule/backend/internal/gittokens/gittokenstest"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// gtAPITokenStub answers GetByHash for one cap_ token; everything else panics (unused).
type gtAPITokenStub struct {
	domain.APITokenRepository
	hash string
	rec  *domain.APIToken
}

func (s gtAPITokenStub) GetByHash(_ context.Context, h string) (*domain.APIToken, error) {
	if h == s.hash {
		return s.rec, nil
	}
	return nil, domain.ErrNotFound
}

type gtEnv struct {
	h        *GitTokensHandler
	svc      *gittokens.Service
	store    *gittokenstest.MemStore
	clock    *gittokenstest.Clock
	access   *gittokenstest.Access
	org      uuid.UUID
	web      gittokens.ProjectRef
	admin    *domain.User
	deployer *domain.User
	capTok   string
	capID    uuid.UUID
}

func gtNewEnv(t *testing.T, cfg gittokens.Config) *gtEnv {
	t.Helper()
	e := &gtEnv{clock: gittokenstest.NewClock(), access: gittokenstest.NewAccess(), org: uuid.New()}
	e.store = gittokenstest.NewMemStore(e.clock)
	e.web = gittokens.ProjectRef{OrgID: e.org, ProjectID: uuid.New(), OrgSlug: "acme", ProjectSlug: "web"}
	e.admin = &domain.User{ID: uuid.New(), Email: "ada@example.com"}
	e.deployer = &domain.User{ID: uuid.New(), Email: "dev@example.com"}
	e.access.Set(e.admin.ID, e.web.ProjectID, authz.RoleAdmin)
	e.access.Set(e.deployer.ID, e.web.ProjectID, authz.RoleDeployer)
	ident := &gittokenstest.Identity{Logins: map[uuid.UUID]string{e.admin.ID: "ada", e.deployer.ID: "dev"}}
	fj := gittokenstest.NewForgejoKeys()
	e.svc = gittokens.New(cfg, gittokens.Deps{
		Store: e.store, Access: e.access, Directory: &gittokenstest.Directory{Projects: []gittokens.ProjectRef{e.web}},
		Identity: ident, Keys: func() gitcore.Keys { return fj }, Now: e.clock.Now, Async: func(f func()) { f() },
	})
	e.capTok = "cap_" + strings.Repeat("ab", 32)
	e.capID = uuid.New()
	e.h = &GitTokensHandler{svc: e.svc, apiTokens: gtAPITokenStub{hash: gittokens.Hash(e.capTok), rec: &domain.APIToken{ID: e.capID, UserID: e.deployer.ID}}}
	return e
}

// router mounts the user routes with the given user authenticated.
func (e *gtEnv) router(u *domain.User) http.Handler {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), u)))
			})
		})
		r.Post("/user/git-credentials", e.h.Issue)
		r.Get("/user/git-tokens", e.h.List)
		r.Post("/user/git-tokens", e.h.Create)
		r.Delete("/user/git-tokens", e.h.RevokeSession)
		r.Delete("/user/git-tokens/{tokenID}", e.h.Revoke)
		r.Get("/user/git-ssh-keys", e.h.ListKeys)
		r.Post("/user/git-ssh-keys", e.h.AddKey)
		r.Delete("/user/git-ssh-keys/{keyID}", e.h.DeleteKey)
		r.Get("/orgs/{orgID}/projects/{projectID}/git/service-tokens", e.h.ListService)
		r.Post("/orgs/{orgID}/projects/{projectID}/git/service-tokens", e.h.CreateService)
		r.Delete("/orgs/{orgID}/projects/{projectID}/git/service-tokens/{tokenID}", e.h.RevokeService)
	})
	return r
}

func gtDo(t *testing.T, h http.Handler, method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func gtBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON: %q", rec.Body.String())
	}
	return m
}

func gtWant(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d: %s", rec.Code, status, rec.Body.String())
	}
}

// ---- /internal/git-auth ------------------------------------------------------------------

func gtBasic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func gtAuthReq(h http.Handler, authz, method, uri string, extra map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/internal/git-auth", nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	req.Header.Set("X-Forwarded-Method", method)
	req.Header.Set("X-Forwarded-Uri", uri)
	req.Header.Set("X-Forwarded-For", "198.51.100.20")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const gtSecret = "edge-shared-secret"

func gtNewInternal(t *testing.T, cfg gittokens.Config) (*gtEnv, *GitAuthInternalHandler) {
	e := gtNewEnv(t, cfg)
	return e, &GitAuthInternalHandler{svc: e.svc}
}

func TestGitAuthInternalClosedWithoutSecret(t *testing.T) {
	_, h := gtNewInternal(t, gittokens.Config{})
	rec := gtAuthReq(h, "", "GET", "/acme/web.git/info/refs", nil)
	gtWant(t, rec, http.StatusServiceUnavailable)
	if rec.Header().Get("X-WEBAUTH-USER") != "" {
		t.Fatal("never a login when closed")
	}
}

func TestGitAuthInternalUnsecuredOnlyWhenExplicit(t *testing.T) {
	_, h := gtNewInternal(t, gittokens.Config{AllowUnsecured: true})
	gtWant(t, gtAuthReq(h, "", "GET", "/acme/web.git/info/refs", nil), http.StatusOK)
}

func TestGitAuthInternalRejectsExternalCallers(t *testing.T) {
	e, h := gtNewInternal(t, gittokens.Config{AuthSecret: gtSecret})
	cred, err := e.svc.Issue(context.Background(), e.deployer.ID, gittokens.IssueInput{Path: "acme/web", SessionRef: "cli:abcdefghijklmnop"})
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]string{gitAuthSecretHeader: gtSecret}
	uri := "/acme/web.git/info/refs?service=git-upload-pack"

	for name, extra := range map[string]map[string]string{
		"no secret":    nil,
		"wrong secret": {gitAuthSecretHeader: "guess"},
		"empty secret": {gitAuthSecretHeader: ""},
		"through ALB":  {gitAuthSecretHeader: gtSecret, "X-Amzn-Trace-Id": "Root=1-67891233-abcdef012345678912345678"},
	} {
		rec := gtAuthReq(h, gtBasic("x", cred.Password), "GET", uri, extra)
		if rec.Code != http.StatusForbidden || rec.Header().Get("X-WEBAUTH-USER") != "" {
			t.Fatalf("%s: status %d, header %q (must be 403 and no login)", name, rec.Code, rec.Header().Get("X-WEBAUTH-USER"))
		}
	}
	rec := gtAuthReq(h, gtBasic("x", cred.Password), "GET", uri, ok)
	gtWant(t, rec, http.StatusOK)
	if rec.Header().Get("X-WEBAUTH-USER") != "dev" {
		t.Fatalf("login header %q", rec.Header().Get("X-WEBAUTH-USER"))
	}
}

func TestGitAuthInternalContract(t *testing.T) {
	e, h := gtNewInternal(t, gittokens.Config{AuthSecret: gtSecret, FailBurst: 3, FailRefill: time.Hour})
	cred, _ := e.svc.Issue(context.Background(), e.deployer.ID, gittokens.IssueInput{Path: "acme/web", Scope: "read", SessionRef: "cli:abcdefghijklmnop"})
	edge := map[string]string{gitAuthSecretHeader: gtSecret}
	fetch := "/acme/web.git/info/refs?service=git-upload-pack"

	// Not a cgt_ credential: 200 and NO login, even if the caller tries to smuggle one.
	smuggle := map[string]string{gitAuthSecretHeader: gtSecret, "X-WEBAUTH-USER": "admin"}
	rec := gtAuthReq(h, gtBasic("someone", "oauth2-token-from-gcm"), "GET", fetch, smuggle)
	gtWant(t, rec, http.StatusOK)
	if rec.Header().Get("X-WEBAUTH-USER") != "" {
		t.Fatal("pass-through must not set X-WEBAUTH-USER, and an inbound one is never echoed")
	}
	// Anonymous (no Authorization): same.
	rec = gtAuthReq(h, "", "GET", fetch, edge)
	gtWant(t, rec, http.StatusOK)
	if rec.Header().Get("X-WEBAUTH-USER") != "" {
		t.Fatal("anonymous must not get a login")
	}

	// Valid token: 200 with the login, never cached by intermediaries.
	rec = gtAuthReq(h, gtBasic("whatever", cred.Password), "GET", fetch, edge)
	gtWant(t, rec, http.StatusOK)
	if rec.Header().Get("X-WEBAUTH-USER") != "dev" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%v", rec.Header())
	}

	// Read token pushing: 403.
	gtWant(t, gtAuthReq(h, gtBasic("x", cred.Password), "POST", "/acme/web.git/git-receive-pack", edge), http.StatusForbidden)
	// Unknown token: 401 with the challenge.
	bad, _, _ := gittokens.Generate(nil)
	rec = gtAuthReq(h, gtBasic("x", bad), "GET", fetch, edge)
	gtWant(t, rec, http.StatusUnauthorized)
	if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Basic") || rec.Header().Get("X-WEBAUTH-USER") != "" {
		t.Fatalf("%v", rec.Header())
	}
	// Brute force: after the failure allowance, 429 with Retry-After.
	for i := 0; i < 5; i++ {
		rec = gtAuthReq(h, gtBasic("x", bad), "GET", fetch, edge)
	}
	gtWant(t, rec, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 needs Retry-After")
	}
	// The response never contains the token.
	if strings.Contains(rec.Body.String(), bad) || strings.Contains(rec.Body.String(), cred.Password) {
		t.Fatal("token leaked in a response body")
	}
}

func TestGitAuthInternalDoesNotLogCredentials(t *testing.T) {
	var buf bytes.Buffer
	e, h := gtNewInternal(t, gittokens.Config{AuthSecret: gtSecret})
	h.logger = gtLogger(&buf)
	bad, _, _ := gittokens.Generate(nil)
	gtAuthReq(h, gtBasic("x", bad), "GET", "/acme/web.git/info/refs", map[string]string{gitAuthSecretHeader: gtSecret})
	_ = e
	if buf.Len() == 0 {
		t.Fatal("denials are logged")
	}
	if strings.Contains(buf.String(), bad) || strings.Contains(buf.String(), gittokens.Hash(bad)) {
		t.Fatalf("log contains the credential: %s", buf.String())
	}
}

// ---- user routes -------------------------------------------------------------------------

func TestIssueEndpointRequiresCLISession(t *testing.T) {
	e := gtNewEnv(t, gittokens.Config{})
	h := e.router(e.deployer)
	body := map[string]any{"protocol": "https", "host": "git.tumi-ai.com", "path": "acme/web.git"}

	// A browser session (JWT, no CLI id): refused.
	rec := gtDo(t, h, "POST", "/user/git-credentials", body, map[string]string{"Authorization": "Bearer eyJ.fake.jwt"})
	gtWant(t, rec, http.StatusForbidden)
	if gtBody(t, rec)["error"].(map[string]any)["code"] != "CLI_SESSION_REQUIRED" {
		t.Fatal(rec.Body.String())
	}
	// A CLI login via JWT identifies its session with cli_session_id.
	body["cli_session_id"] = "0123456789abcdef0123"
	rec = gtDo(t, h, "POST", "/user/git-credentials", body, map[string]string{"Authorization": "Bearer eyJ.fake.jwt"})
	gtWant(t, rec, http.StatusOK)
	got := gtBody(t, rec)
	if !gittokens.WellFormed(got["password"].(string)) || got["username"] != "dev" || got["scope"] != "write" || got["project_id"] != e.web.ProjectID.String() {
		t.Fatalf("%v", got)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credentials must not be cached")
	}
	for _, k := range []string{"expires_at", "renew_after"} {
		if _, err := time.Parse(time.RFC3339, got[k].(string)); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
	// A cap_ API token is itself the session.
	delete(body, "cli_session_id")
	rec = gtDo(t, h, "POST", "/user/git-credentials", body, map[string]string{"Authorization": "Bearer " + e.capTok})
	gtWant(t, rec, http.StatusOK)
	for _, tok := range e.store.Tokens {
		if tok.SessionRef == gittokens.CapSessionRef(e.capID) {
			return
		}
	}
	t.Fatal("ephemeral token must be bound to the cap_ token that asked for it")
}

func TestIssueEndpointValidation(t *testing.T) {
	e := gtNewEnv(t, gittokens.Config{})
	h := e.router(e.deployer)
	hdr := map[string]string{"Authorization": "Bearer " + e.capTok}
	for name, body := range map[string]map[string]any{
		"http protocol": {"protocol": "http", "host": "h", "path": "acme/web"},
		"no host":       {"protocol": "https", "path": "acme/web"},
		"bad path":      {"protocol": "https", "host": "h", "path": "../etc"},
		"bad scope":     {"protocol": "https", "host": "h", "path": "acme/web", "scope": "root"},
	} {
		if rec := gtDo(t, h, "POST", "/user/git-credentials", body, hdr); rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	rec := gtDo(t, h, "POST", "/user/git-credentials", map[string]any{"protocol": "https", "host": "h", "path": "acme/ghost"}, hdr)
	gtWant(t, rec, http.StatusNotFound)
	req := httptest.NewRequest("POST", "/user/git-credentials", strings.NewReader("{not json"))
	req.Header.Set("Authorization", "Bearer "+e.capTok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	gtWant(t, rr, http.StatusBadRequest)
}

func TestPersonalTokenRoutes(t *testing.T) {
	e := gtNewEnv(t, gittokens.Config{})
	h := e.router(e.deployer)

	rec := gtDo(t, h, "POST", "/user/git-tokens", map[string]any{"name": "laptop", "scope": "read", "projects": []string{e.web.ProjectID.String()}, "expires_in_days": 30}, nil)
	gtWant(t, rec, http.StatusCreated)
	created := gtBody(t, rec)
	plain, _ := created["token"].(string)
	if !gittokens.WellFormed(plain) || created["kind"] != "personal" || created["scope"] != "read" || created["prefix"] != plain[:8] {
		t.Fatalf("%v", created)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("no-store")
	}
	id := created["id"].(string)

	// Listing never shows the value.
	rec = gtDo(t, h, "GET", "/user/git-tokens", nil, nil)
	gtWant(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), plain) || strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("the list must not include the token value: %s", rec.Body.String())
	}
	items := gtBody(t, rec)["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["id"] != id {
		t.Fatalf("%v", items)
	}

	// Validation errors.
	gtWant(t, gtDo(t, h, "POST", "/user/git-tokens", map[string]any{"name": "x", "scope": "read", "expires_in_days": 365}, nil), http.StatusUnprocessableEntity)
	gtWant(t, gtDo(t, h, "POST", "/user/git-tokens", map[string]any{"scope": "read", "expires_in_days": 5}, nil), http.StatusUnprocessableEntity)

	// Revoke: others get 404, owner 204, then the list is empty.
	gtWant(t, gtDo(t, e.router(e.admin), "DELETE", "/user/git-tokens/"+id, nil, nil), http.StatusNotFound)
	gtWant(t, gtDo(t, h, "DELETE", "/user/git-tokens/not-a-uuid", nil, nil), http.StatusBadRequest)
	gtWant(t, gtDo(t, h, "DELETE", "/user/git-tokens/"+id, nil, nil), http.StatusNoContent)
	rec = gtDo(t, h, "GET", "/user/git-tokens", nil, nil)
	if n := len(gtBody(t, rec)["items"].([]any)); n != 0 {
		t.Fatalf("revoked token still listed: %d", n)
	}
}

func TestRevokeSessionRoute(t *testing.T) {
	e := gtNewEnv(t, gittokens.Config{})
	h := e.router(e.deployer)
	hdr := map[string]string{"Authorization": "Bearer jwt"}
	body := map[string]any{"protocol": "https", "host": "h", "path": "acme/web", "cli_session_id": "0123456789abcdef0123"}
	gtWant(t, gtDo(t, h, "POST", "/user/git-credentials", body, hdr), http.StatusOK)

	gtWant(t, gtDo(t, h, "DELETE", "/user/git-tokens", nil, hdr), http.StatusBadRequest) // no session to identify
	rec := gtDo(t, h, "DELETE", "/user/git-tokens?session_id=0123456789abcdef0123", nil, hdr)
	gtWant(t, rec, http.StatusOK)
	if gtBody(t, rec)["revoked"] != float64(1) {
		t.Fatal(rec.Body.String())
	}
}

func TestServiceTokenRoutes(t *testing.T) {
	e := gtNewEnv(t, gittokens.Config{})
	base := "/orgs/" + e.org.String() + "/projects/" + e.web.ProjectID.String() + "/git/service-tokens"
	in := map[string]any{"name": "ci", "scope": "write", "expires_in_days": 90}

	// x-permission git.admin: a deployer is refused on every route.
	dev := e.router(e.deployer)
	gtWant(t, gtDo(t, dev, "POST", base, in, nil), http.StatusForbidden)
	gtWant(t, gtDo(t, dev, "GET", base, nil, nil), http.StatusForbidden)

	adm := e.router(e.admin)
	rec := gtDo(t, adm, "POST", base, in, nil)
	gtWant(t, rec, http.StatusCreated)
	created := gtBody(t, rec)
	if created["kind"] != "service" || !gittokens.WellFormed(created["token"].(string)) {
		t.Fatalf("%v", created)
	}
	rec = gtDo(t, adm, "GET", base, nil, nil)
	gtWant(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), created["token"].(string)) {
		t.Fatal("value shown again")
	}
	gtWant(t, gtDo(t, dev, "DELETE", base+"/"+created["id"].(string), nil, nil), http.StatusForbidden)
	gtWant(t, gtDo(t, adm, "DELETE", base+"/"+created["id"].(string), nil, nil), http.StatusNoContent)
	gtWant(t, gtDo(t, adm, "DELETE", base+"/"+created["id"].(string), nil, nil), http.StatusNotFound)
	// Wrong org in the URL.
	wrongOrg := "/orgs/" + uuid.NewString() + "/projects/" + e.web.ProjectID.String() + "/git/service-tokens"
	gtWant(t, gtDo(t, adm, "GET", wrongOrg, nil, nil), http.StatusNotFound)
	gtWant(t, gtDo(t, adm, "GET", "/orgs/x/projects/y/git/service-tokens", nil, nil), http.StatusBadRequest)
}

func TestSSHKeyRoutes(t *testing.T) {
	e := gtNewEnv(t, gittokens.Config{})
	h := e.router(e.deployer)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " me@host"

	rec := gtDo(t, h, "POST", "/user/git-ssh-keys", map[string]any{"title": "laptop", "key": key}, nil)
	gtWant(t, rec, http.StatusCreated)
	k := gtBody(t, rec)
	if k["title"] != "laptop" || k["forgejo_synced"] != true || !strings.HasPrefix(k["fingerprint"].(string), "SHA256:") {
		t.Fatalf("%v", k)
	}
	if strings.Contains(rec.Body.String(), "ssh-ed25519") {
		t.Fatal("the response carries the fingerprint, not the key")
	}
	gtWant(t, gtDo(t, h, "POST", "/user/git-ssh-keys", map[string]any{"title": "dup", "key": key}, nil), http.StatusConflict)
	gtWant(t, gtDo(t, h, "POST", "/user/git-ssh-keys", map[string]any{"title": "bad", "key": "-----BEGIN OPENSSH PRIVATE KEY-----"}, nil), http.StatusUnprocessableEntity)

	rec = gtDo(t, h, "GET", "/user/git-ssh-keys", nil, nil)
	gtWant(t, rec, http.StatusOK)
	if n := len(gtBody(t, rec)["items"].([]any)); n != 1 {
		t.Fatalf("%d", n)
	}
	gtWant(t, gtDo(t, e.router(e.admin), "DELETE", "/user/git-ssh-keys/"+k["id"].(string), nil, nil), http.StatusNotFound)
	gtWant(t, gtDo(t, h, "DELETE", "/user/git-ssh-keys/"+k["id"].(string), nil, nil), http.StatusNoContent)
	gtWant(t, gtDo(t, h, "DELETE", "/user/git-ssh-keys/nope", nil, nil), http.StatusBadRequest)
}

func TestPaginate(t *testing.T) {
	items := make([]int, 7)
	for i := range items {
		items[i] = i
	}
	page, next := paginate(items, "", 3)
	if len(page) != 3 || next == nil {
		t.Fatal("first page")
	}
	page, next = paginate(items, *next, 3)
	if len(page) != 3 || page[0] != 3 || next == nil {
		t.Fatalf("second page %v", page)
	}
	page, next = paginate(items, *next, 3)
	if len(page) != 1 || next != nil {
		t.Fatalf("last page %v %v", page, next)
	}
	if page, next = paginate(items, "garbage!", 100); len(page) != 7 || next != nil {
		t.Fatal("bad cursor starts over")
	}
	if page, _ = paginate(items, base64.RawURLEncoding.EncodeToString([]byte("99")), 3); len(page) != 0 {
		t.Fatal("cursor past the end")
	}
}

func TestMountWithoutWiringDoesNothing(t *testing.T) {
	gitTokensMu.Lock()
	saved := gitTokensShared
	gitTokensShared = nil
	gitTokensMu.Unlock()
	defer func() { gitTokensMu.Lock(); gitTokensShared = saved; gitTokensMu.Unlock() }()
	r := chi.NewRouter()
	MountGitTokens(r)
	MountGitAuthInternal(r)
	if len(r.Routes()) != 0 {
		t.Fatal("routes must not be mounted before WireGitTokens ran")
	}
}

func gtLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }

func TestMountRegistersTheContractRoutes(t *testing.T) {
	e := gtNewEnv(t, gittokens.Config{})
	gitTokensMu.Lock()
	saved := gitTokensShared
	gitTokensShared = e.h
	gitTokensMu.Unlock()
	defer func() { gitTokensMu.Lock(); gitTokensShared = saved; gitTokensMu.Unlock() }()

	r := chi.NewRouter()
	MountGitTokens(r)
	root := chi.NewRouter()
	MountGitAuthInternal(root)
	got := map[string]bool{}
	_ = chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		got[method+" "+route] = true
		return nil
	})
	for _, want := range []string{
		"POST /user/git-credentials", "GET /user/git-tokens", "POST /user/git-tokens", "DELETE /user/git-tokens/{tokenID}",
		"GET /user/git-ssh-keys", "POST /user/git-ssh-keys", "DELETE /user/git-ssh-keys/{keyID}",
		"GET /orgs/{orgID}/projects/{projectID}/git/service-tokens", "POST /orgs/{orgID}/projects/{projectID}/git/service-tokens",
		"DELETE /orgs/{orgID}/projects/{projectID}/git/service-tokens/{tokenID}",
	} {
		if !got[want] {
			t.Errorf("missing route %s", want)
		}
	}
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest("GET", "/internal/git-auth", nil))
	if rec.Code != http.StatusServiceUnavailable { // reachable at the root, closed without the shared secret
		t.Fatalf("internal route at root: %d", rec.Code)
	}
}
