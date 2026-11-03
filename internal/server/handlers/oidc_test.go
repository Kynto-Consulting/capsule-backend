package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/oidc"
	"github.com/kynto/capsule/backend/internal/oidc/oidctest"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/internal/service"
)

const (
	oidcTestIssuer   = "https://api.test.local"
	oidcTestRedirect = "https://git.test.local/cb"
	oidcTestVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

type oidcFakeOrgs struct {
	domain.OrganizationRepository
	org  *domain.Organization
	role string
}

func (f oidcFakeOrgs) GetByID(context.Context, uuid.UUID) (*domain.Organization, error) {
	return f.org, nil
}
func (f oidcFakeOrgs) GetMemberRole(context.Context, uuid.UUID, uuid.UUID) (string, error) {
	if f.role == "" {
		return "", domain.ErrNotFound
	}
	return f.role, nil
}

type oidcHarness struct {
	t      *testing.T
	router http.Handler
	store  *oidctest.MemStore
	users  *oidctest.Users
	user   *domain.User
	svc    *oidc.Service
	orgs   *oidcFakeOrgs
}

func newOIDCHarness(t *testing.T, orgRole string) *oidcHarness {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store := oidctest.NewMemStore()
	user := &domain.User{ID: uuid.New(), Email: "ana@example.com", Name: "Ana", Role: "member"}
	users := &oidctest.Users{ByID: map[uuid.UUID]*domain.User{user.ID: user}}
	svc := oidc.New(oidc.Config{Issuer: oidcTestIssuer, FrontendURL: "https://app.test.local"}, store, users, oidc.NewKeySet(key), nil)
	orgs := &oidcFakeOrgs{org: &domain.Organization{ID: uuid.New(), Slug: "acme"}, role: orgRole}
	h := NewOIDCHandler(svc, orgs)

	r := chi.NewRouter()
	h.MountPublic(r, func(next http.Handler) http.Handler { return next })
	r.Route("/api/v1", func(r chi.Router) {
		h.MountAPIPublic(r)
		r.Group(func(r chi.Router) {
			// stand-in for middleware.Auth: role comes from X-Test-Role
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					u := *user
					if v := req.Header.Get("X-Test-Role"); v != "" {
						u.Role = v
					}
					next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), &u)))
				})
			})
			h.MountAPI(r)
		})
	})
	return &oidcHarness{t: t, router: r, store: store, users: users, user: user, svc: svc, orgs: orgs}
}

func (h *oidcHarness) do(method, target, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func (h *oidcHarness) createClient(public, firstParty bool) (clientID, secret string) {
	body, _ := json.Marshal(map[string]any{"name": "Forgejo", "redirect_uris": []string{oidcTestRedirect}, "public": public, "first_party": firstParty})
	rec := h.do("POST", "/api/v1/oauth/clients", string(body), map[string]string{"X-Test-Role": "admin", "Content-Type": "application/json"})
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("create client: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ClientID string `json:"client_id"`
		Secret   string `json:"client_secret"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ClientID, out.Secret
}

func TestOIDCHTTPFullFlow(t *testing.T) {
	h := newOIDCHarness(t, "")
	clientID, secret := h.createClient(false, true)
	if secret == "" || !strings.HasPrefix(secret, "cos_") {
		t.Fatalf("no secret returned on create: %q", secret)
	}

	// Discovery + JWKS: public, CORS *, cacheable.
	rec := h.do("GET", "/.well-known/openid-configuration", "", nil)
	var disc map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &disc)
	if rec.Code != 200 || disc["issuer"] != oidcTestIssuer || rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("discovery: %d %v %v", rec.Code, disc, rec.Header())
	}
	rec = h.do("GET", "/oauth/jwks", "", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"RS256"`) {
		t.Fatalf("jwks: %d %s", rec.Code, rec.Body)
	}
	if rec = h.do("OPTIONS", "/oauth/token", "", map[string]string{"Origin": "https://spa.example", "Access-Control-Request-Method": "POST"}); rec.Code != 204 ||
		rec.Header().Get("Access-Control-Allow-Origin") != "*" || strings.Contains(rec.Header().Get("Access-Control-Allow-Credentials"), "true") {
		t.Fatalf("preflight: %d %v", rec.Code, rec.Header())
	}

	// authorize -> 302 to the dashboard.
	q := url.Values{
		"client_id": {clientID}, "redirect_uri": {oidcTestRedirect}, "response_type": {"code"},
		"scope": {"openid profile email groups offline_access"}, "state": {"xyz"}, "nonce": {"nn"},
		"code_challenge": {oidc.ChallengeS256(oidcTestVerifier)}, "code_challenge_method": {"S256"},
	}
	rec = h.do("GET", "/oauth/authorize?"+q.Encode(), "", nil)
	loc := rec.Header().Get("Location")
	if rec.Code != 302 || !strings.HasPrefix(loc, "https://app.test.local/oauth/authorize?request=") {
		t.Fatalf("authorize: %d %q", rec.Code, loc)
	}
	reqID := strings.TrimPrefix(loc, "https://app.test.local/oauth/authorize?request=")

	// Dashboard: info then approve.
	rec = h.do("GET", "/api/v1/oauth/requests/"+reqID, "", nil)
	var info map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	if rec.Code != 200 || info["client_name"] != "Forgejo" || info["redirect_host"] != "git.test.local" || info["first_party"] != true || info["scopes"] == nil {
		t.Fatalf("request info: %d %s", rec.Code, rec.Body)
	}
	rec = h.do("POST", "/api/v1/oauth/requests/"+reqID+"/approve", "", nil)
	var appr map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &appr)
	ru, _ := url.Parse(appr["redirect_url"])
	code := ru.Query().Get("code")
	if rec.Code != 200 || code == "" || ru.Query().Get("state") != "xyz" || ru.Scheme+"://"+ru.Host+ru.Path != oidcTestRedirect {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}

	// token with client_secret_basic.
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {oidcTestRedirect}, "code_verifier": {oidcTestVerifier}}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(clientID)+":"+url.QueryEscape(secret)))
	rec = h.do("POST", "/oauth/token", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": basic})
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("token: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	var tok oidc.TokenResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	if tok.TokenType != "Bearer" || tok.ExpiresIn != 3600 || tok.IDToken == "" || tok.RefreshToken == "" || tok.AccessToken == "" {
		t.Fatalf("token body: %+v", tok)
	}

	// replay -> invalid_grant JSON.
	rec = h.do("POST", "/oauth/token", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": basic})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), `"error":"invalid_grant"`) {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body)
	}
	// replay revoked the first tokens.
	rec = h.do("GET", "/oauth/userinfo", "", map[string]string{"Authorization": "Bearer " + tok.AccessToken})
	if rec.Code != 401 || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("userinfo after replay: %d %v", rec.Code, rec.Header())
	}
}

func TestOIDCHTTPUserinfoAndAPIIsolation(t *testing.T) {
	h := newOIDCHarness(t, "")
	clientID, secret := h.createClient(false, true)
	q := url.Values{
		"client_id": {clientID}, "redirect_uri": {oidcTestRedirect}, "response_type": {"code"}, "scope": {"openid email"},
		"code_challenge": {oidc.ChallengeS256(oidcTestVerifier)}, "code_challenge_method": {"S256"},
	}
	rec := h.do("GET", "/oauth/authorize?"+q.Encode(), "", nil)
	reqID := strings.SplitN(rec.Header().Get("Location"), "request=", 2)[1]
	rec = h.do("POST", "/api/v1/oauth/requests/"+reqID+"/approve", "", nil)
	var appr map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &appr)
	ru, _ := url.Parse(appr["redirect_url"])
	form := url.Values{"grant_type": {"authorization_code"}, "code": {ru.Query().Get("code")}, "redirect_uri": {oidcTestRedirect},
		"code_verifier": {oidcTestVerifier}, "client_id": {clientID}, "client_secret": {secret}}
	rec = h.do("POST", "/oauth/token", form.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	var tok oidc.TokenResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	if tok.AccessToken == "" {
		t.Fatalf("token: %d %s", rec.Code, rec.Body)
	}

	rec = h.do("GET", "/oauth/userinfo", "", map[string]string{"Authorization": "Bearer " + tok.AccessToken})
	var ui map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &ui)
	if rec.Code != 200 || ui["email"] != "ana@example.com" || ui["sub"] != h.user.ID.String() || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("userinfo: %d %s", rec.Code, rec.Body)
	}
	if rec = h.do("GET", "/oauth/userinfo", "", nil); rec.Code != 401 {
		t.Fatalf("userinfo without token: %d", rec.Code)
	}

	// The REST API's real Auth middleware must reject every OIDC token.
	authSvc := service.NewAuthService(h.users, nil, "platform-secret", time.Hour, time.Hour, nil)
	protected := middleware.Auth(authSvc, nil, h.users)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for name, bearer := range map[string]string{"access": tok.AccessToken, "id": tok.IDToken} {
		req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("OIDC %s token authenticated on the REST API: %d", name, w.Code)
		}
	}
}

func TestOIDCHTTPAuthorizeNeverRedirectsOnBadClient(t *testing.T) {
	h := newOIDCHarness(t, "")
	clientID, _ := h.createClient(true, false)
	q := url.Values{"client_id": {clientID}, "redirect_uri": {"https://evil.example/cb"}, "response_type": {"code"}, "scope": {"openid"}}
	rec := h.do("GET", "/oauth/authorize?"+q.Encode(), "", nil)
	if rec.Code != 400 || rec.Header().Get("Location") != "" {
		t.Fatalf("open redirect: %d %v", rec.Code, rec.Header())
	}
	// Deny works without a session and redirects with access_denied.
	q.Set("redirect_uri", oidcTestRedirect)
	q.Set("state", "s")
	q.Set("code_challenge", oidc.ChallengeS256(oidcTestVerifier))
	q.Set("code_challenge_method", "S256")
	rec = h.do("GET", "/oauth/authorize?"+q.Encode(), "", nil)
	reqID := strings.SplitN(rec.Header().Get("Location"), "request=", 2)[1]
	rec = h.do("POST", "/api/v1/oauth/requests/"+reqID+"/deny", "", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "error=access_denied") {
		t.Fatalf("deny: %d %s", rec.Code, rec.Body)
	}
	if rec = h.do("POST", "/api/v1/oauth/requests/"+reqID+"/deny", "", nil); rec.Code != 404 {
		t.Fatalf("second deny: %d", rec.Code)
	}
}

func TestOIDCClientAdminPermissions(t *testing.T) {
	body := func(org string, firstParty bool) string {
		m := map[string]any{"name": "App", "redirect_uris": []string{oidcTestRedirect}, "first_party": firstParty}
		if org != "" {
			m["org_id"] = org
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	mk := func(role, platformRole, payload string) *httptest.ResponseRecorder {
		h := newOIDCHarness(t, role)
		return h.do("POST", "/api/v1/oauth/clients", payload, map[string]string{"X-Test-Role": platformRole})
	}
	orgID := uuid.NewString()

	if rec := mk("", "member", body("", false)); rec.Code != 403 {
		t.Errorf("plain member, no org: %d", rec.Code)
	}
	if rec := mk("member", "member", body(orgID, false)); rec.Code != 403 {
		t.Errorf("org member: %d", rec.Code)
	}
	if rec := mk("admin", "member", body(orgID, false)); rec.Code != 201 {
		t.Errorf("org admin: %d %s", rec.Code, rec.Body)
	}
	if rec := mk("owner", "member", body(orgID, true)); rec.Code != 403 {
		t.Errorf("org owner creating first_party: %d", rec.Code)
	}
	if rec := mk("", "admin", body("", true)); rec.Code != 201 {
		t.Errorf("platform admin: %d %s", rec.Code, rec.Body)
	}
	if rec := mk("", "admin", `{"name":"x","redirect_uris":["http://evil.com/cb"]}`); rec.Code != 422 {
		t.Errorf("insecure redirect accepted: %d", rec.Code)
	}

	// list hides secrets; patch + delete (revokes); strangers get 404.
	h := newOIDCHarness(t, "")
	clientID, _ := h.createClient(false, false)
	rec := h.do("GET", "/api/v1/oauth/clients", "", map[string]string{"X-Test-Role": "admin"})
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "client_secret") || strings.Contains(rec.Body.String(), "secret_hash") || !strings.Contains(rec.Body.String(), clientID) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if rec = h.do("GET", "/api/v1/oauth/clients", "", nil); strings.Contains(rec.Body.String(), clientID) {
		t.Fatal("non-admin without orgs can list foreign clients")
	}
	if rec = h.do("PATCH", "/api/v1/oauth/clients/"+clientID, `{"redirect_uris":["https://git.test.local/new"]}`, map[string]string{"X-Test-Role": "member"}); rec.Code != 404 {
		t.Fatalf("stranger patch: %d", rec.Code)
	}
	if rec = h.do("PATCH", "/api/v1/oauth/clients/"+clientID, `{"redirect_uris":["https://git.test.local/new"]}`, map[string]string{"X-Test-Role": "admin"}); rec.Code != 200 || !strings.Contains(rec.Body.String(), "/new") {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	if rec = h.do("PATCH", "/api/v1/oauth/clients/"+clientID, `{"redirect_uris":["ftp://x"]}`, map[string]string{"X-Test-Role": "admin"}); rec.Code != 422 {
		t.Fatalf("bad patch: %d", rec.Code)
	}
	if rec = h.do("DELETE", "/api/v1/oauth/clients/"+clientID, "", map[string]string{"X-Test-Role": "admin"}); rec.Code != 204 {
		t.Fatalf("delete: %d", rec.Code)
	}
	q := url.Values{"client_id": {clientID}, "redirect_uri": {"https://git.test.local/new"}, "response_type": {"code"}, "scope": {"openid"}}
	if rec = h.do("GET", "/oauth/authorize?"+q.Encode(), "", nil); rec.Code != 400 {
		t.Fatalf("revoked client still authorizes: %d", rec.Code)
	}
}
