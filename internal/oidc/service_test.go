package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/oidc"
	"github.com/kynto/capsule/backend/internal/oidc/oidctest"
	"github.com/kynto/capsule/backend/internal/service"
)

const (
	issuer   = "https://api.test.local"
	frontend = "https://app.test.local"
	redirect = "https://git.test.local/user/oauth2/capsule/callback"
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 appendix B
)

var (
	keyOnce sync.Once
	keyA    *rsa.PrivateKey
	keyB    *rsa.PrivateKey
)

func testKeys(t testing.TB) (*rsa.PrivateKey, *rsa.PrivateKey) {
	keyOnce.Do(func() {
		var err error
		if keyA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if keyB, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return keyA, keyB
}

type env struct {
	svc    *oidc.Service
	store  *oidctest.MemStore
	users  *oidctest.Users
	user   *domain.User
	client *oidc.Client
	secret string
	keys   *oidc.KeySet
}

func newEnv(t *testing.T, public bool) *env {
	t.Helper()
	a, _ := testKeys(t)
	store := oidctest.NewMemStore()
	user := &domain.User{ID: uuid.New(), Email: "Jane.Doe@example.com", Name: "Jane Doe", Role: "member"}
	users := &oidctest.Users{ByID: map[uuid.UUID]*domain.User{user.ID: user}}
	keys := oidc.NewKeySet(a)
	svc := oidc.New(oidc.Config{Issuer: issuer + "/", FrontendURL: frontend + "/"}, store, users, keys, nil)
	client, secret, err := svc.CreateClient(context.Background(), oidc.NewClientParams{
		Name: "Forgejo", RedirectURIs: []string{redirect}, FirstParty: true, Public: public, CreatedBy: user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &env{svc: svc, store: store, users: users, user: user, client: client, secret: secret, keys: keys}
}

func (e *env) authQuery(scope string) url.Values {
	return url.Values{
		"client_id": {e.client.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"scope": {scope}, "state": {"st4te"}, "nonce": {"n0nce"},
		"code_challenge": {oidc.ChallengeS256(verifier)}, "code_challenge_method": {"S256"},
	}
}

// authorize runs authorize+approve and returns the authorization code.
func (e *env) authorize(t *testing.T, scope string) string {
	t.Helper()
	res := e.svc.Authorize(context.Background(), e.authQuery(scope))
	if res.Fatal != nil || !strings.HasPrefix(res.RedirectURL, frontend+"/oauth/authorize?request=") {
		t.Fatalf("authorize: %+v", res)
	}
	u, _ := url.Parse(res.RedirectURL)
	back, err := e.svc.Approve(context.Background(), u.Query().Get("request"), e.user)
	if err != nil {
		t.Fatal(err)
	}
	bu, _ := url.Parse(back)
	if bu.Query().Get("state") != "st4te" || bu.Query().Get("code") == "" || !strings.HasPrefix(back, redirect) {
		t.Fatalf("bad approve redirect %s", back)
	}
	return bu.Query().Get("code")
}

func (e *env) tokenForm(code string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"code_verifier": {verifier}, "client_id": {e.client.ClientID}, "client_secret": {e.secret},
	}
}

func (e *env) exchange(t *testing.T, scope string) *oidc.TokenResponse {
	t.Helper()
	code := e.authorize(t, scope)
	resp, oe := e.svc.Token(context.Background(), oidc.TokenRequest{Form: e.tokenForm(code)})
	if oe != nil {
		t.Fatalf("token: %v", oe)
	}
	return resp
}

func (e *env) refreshForm(rt string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {e.client.ClientID}, "client_secret": {e.secret}}
}

func parseClaims(t *testing.T, raw string, keys *oidc.KeySet) (jwt.MapClaims, *jwt.Token) {
	t.Helper()
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims, func(tk *jwt.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		pub := keys.Lookup(kid)
		if pub == nil {
			t.Fatalf("unknown kid %q", kid)
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatal(err)
	}
	return claims, tok
}

func TestPKCE(t *testing.T) {
	ch := oidc.ChallengeS256(verifier)
	if ch != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" { // RFC 7636 appendix B
		t.Fatalf("unexpected challenge %s", ch)
	}
	if !oidc.VerifyPKCE(ch, verifier) {
		t.Fatal("correct verifier rejected")
	}
	for name, v := range map[string]string{
		"wrong":  "aBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		"short":  "abc",
		"empty":  "",
		"badchr": verifier[:42] + "!",
	} {
		if oidc.VerifyPKCE(ch, v) {
			t.Errorf("%s verifier accepted", name)
		}
	}
	if oidc.VerifyPKCE("", verifier) {
		t.Error("empty challenge accepted")
	}
}

func TestPKCEEnforcedAtTokenEndpoint(t *testing.T) {
	e := newEnv(t, false)
	code := e.authorize(t, "openid")
	f := e.tokenForm(code)
	f.Set("code_verifier", "aBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	if _, oe := e.svc.Token(context.Background(), oidc.TokenRequest{Form: f}); oe == nil || oe.Code != "invalid_grant" {
		t.Fatalf("wrong verifier: %v", oe)
	}
	// the code is burned even by a failed attempt
	if _, oe := e.svc.Token(context.Background(), oidc.TokenRequest{Form: e.tokenForm(code)}); oe == nil {
		t.Fatal("code survived a failed PKCE check")
	}
}

func TestAuthorizeValidation(t *testing.T) {
	e := newEnv(t, true) // public client
	ctx := context.Background()

	// Unverified redirect_uri / client: fatal, never a redirect.
	q := e.authQuery("openid")
	q.Set("redirect_uri", redirect+"/evil")
	if r := e.svc.Authorize(ctx, q); r.Fatal == nil || r.RedirectURL != "" {
		t.Fatalf("different redirect_uri must be fatal: %+v", r)
	}
	q = e.authQuery("openid")
	q.Set("redirect_uri", redirect+"?x=1") // exact match only
	if r := e.svc.Authorize(ctx, q); r.Fatal == nil {
		t.Fatal("prefix/extended redirect_uri accepted")
	}
	q = e.authQuery("openid")
	q.Set("client_id", "nope")
	if r := e.svc.Authorize(ctx, q); r.Fatal == nil || r.Fatal.Code != "invalid_client" {
		t.Fatalf("unknown client: %+v", r)
	}

	// Recoverable errors redirect to the registered URI with state.
	check := func(mut func(url.Values), wantErr string) {
		t.Helper()
		q := e.authQuery("openid")
		mut(q)
		r := e.svc.Authorize(ctx, q)
		if r.Fatal != nil || !strings.HasPrefix(r.RedirectURL, redirect) {
			t.Fatalf("want redirect with %s, got %+v", wantErr, r)
		}
		u, _ := url.Parse(r.RedirectURL)
		if u.Query().Get("error") != wantErr || u.Query().Get("state") != "st4te" {
			t.Fatalf("want %s, got %s", wantErr, r.RedirectURL)
		}
	}
	check(func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type")
	check(func(q url.Values) { q.Set("scope", "profile") }, "invalid_scope")
	check(func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request")
	check(func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") }, "invalid_request") // public => PKCE mandatory
}

func TestCodeReuseRevokesTokens(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	code := e.authorize(t, "openid email offline_access")
	first, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: e.tokenForm(code)})
	if oe != nil {
		t.Fatal(oe)
	}
	if _, oe := e.svc.UserInfo(ctx, first.AccessToken); oe != nil {
		t.Fatalf("fresh access token rejected: %v", oe)
	}
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: e.tokenForm(code)}); oe == nil || oe.Code != "invalid_grant" {
		t.Fatalf("reused code accepted: %v", oe)
	}
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: e.refreshForm(first.RefreshToken)}); oe == nil {
		t.Fatal("refresh token issued from a reused code still works")
	}
	if _, oe := e.svc.UserInfo(ctx, first.AccessToken); oe == nil {
		t.Fatal("access token issued from a reused code still works")
	}
}

func TestCodeBoundToClientRedirectAndExpiry(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()

	code := e.authorize(t, "openid")
	f := e.tokenForm(code)
	f.Set("redirect_uri", redirect+"/other")
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: f}); oe == nil || oe.Code != "invalid_grant" {
		t.Fatalf("different redirect_uri: %v", oe)
	}

	// another client cannot redeem it
	other, otherSecret, _ := e.svc.CreateClient(ctx, oidc.NewClientParams{Name: "x", RedirectURIs: []string{redirect}, CreatedBy: e.user.ID})
	code = e.authorize(t, "openid")
	f = e.tokenForm(code)
	f.Set("client_id", other.ClientID)
	f.Set("client_secret", otherSecret)
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: f}); oe == nil || oe.Code != "invalid_grant" {
		t.Fatalf("code redeemed by another client: %v", oe)
	}

	// expiry (60 s)
	code = e.authorize(t, "openid")
	for _, c := range e.store.Codes {
		c.ExpiresAt = time.Now().Add(-time.Second)
	}
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: e.tokenForm(code)}); oe == nil || oe.Code != "invalid_grant" {
		t.Fatalf("expired code: %v", oe)
	}
}

func TestClientAuthentication(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()

	// client_secret_basic
	code := e.authorize(t, "openid")
	f := e.tokenForm(code)
	f.Del("client_id")
	f.Del("client_secret")
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: f, HasBasic: true, BasicID: e.client.ClientID, BasicSecret: e.secret}); oe != nil {
		t.Fatalf("basic auth: %v", oe)
	}
	// wrong secret
	code = e.authorize(t, "openid")
	f = e.tokenForm(code)
	f.Set("client_secret", e.secret+"x")
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: f}); oe == nil || oe.Code != "invalid_client" || oe.Status != 401 {
		t.Fatalf("wrong secret: %v", oe)
	}
	// missing secret on a confidential client
	f.Del("client_secret")
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: f}); oe == nil || oe.Code != "invalid_client" {
		t.Fatalf("missing secret: %v", oe)
	}
	// unsupported grant, missing grant
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: url.Values{"grant_type": {"password"}}}); oe == nil || oe.Code != "unsupported_grant_type" {
		t.Fatalf("password grant: %v", oe)
	}
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: url.Values{}}); oe == nil || oe.Code != "invalid_request" {
		t.Fatalf("no grant_type: %v", oe)
	}
	// secret stored hashed, never in clear
	for _, c := range e.store.Clients {
		if c.SecretHash == e.secret || c.SecretHash != oidc.HashSecret(e.secret) {
			t.Fatal("client secret is not stored as SHA-256")
		}
	}
	if len(e.secret) < 4+43 {
		t.Fatalf("client secret too short: %d", len(e.secret))
	}
}

func TestPublicClientFlow(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	if e.secret != "" {
		t.Fatal("public client got a secret")
	}
	code := e.authorize(t, "openid offline_access")
	f := e.tokenForm(code)
	f.Del("client_secret")
	resp, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: f})
	if oe != nil || resp.RefreshToken == "" {
		t.Fatalf("public client exchange failed: %v", oe)
	}
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	first := e.exchange(t, "openid email offline_access")
	if first.RefreshToken == "" {
		t.Fatal("no refresh token with offline_access")
	}
	for _, r := range e.store.Refresh {
		if r.TokenHash == first.RefreshToken {
			t.Fatal("refresh token stored in clear")
		}
	}

	second, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: e.refreshForm(first.RefreshToken)})
	if oe != nil {
		t.Fatalf("refresh: %v", oe)
	}
	if second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
		t.Fatal("refresh token did not rotate")
	}
	if second.IDToken == "" || second.AccessToken == "" {
		t.Fatal("refresh response incomplete")
	}

	// Replaying the old token is theft: it fails AND kills the new family.
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: e.refreshForm(first.RefreshToken)}); oe == nil || oe.Code != "invalid_grant" {
		t.Fatalf("replayed refresh token accepted: %v", oe)
	}
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: e.refreshForm(second.RefreshToken)}); oe == nil {
		t.Fatal("rotated token still valid after reuse detection")
	}
	if _, oe := e.svc.UserInfo(ctx, second.AccessToken); oe == nil {
		t.Fatal("access token survived grant revocation")
	}
}

func TestRefreshOnlyWithOfflineAccess(t *testing.T) {
	e := newEnv(t, false)
	if r := e.exchange(t, "openid email"); r.RefreshToken != "" {
		t.Fatal("refresh token issued without offline_access")
	}
}

func TestRefreshWrongClientAndScopeEscalation(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	first := e.exchange(t, "openid offline_access")
	f := e.refreshForm(first.RefreshToken)
	f.Set("scope", "openid groups offline_access")
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: f}); oe == nil || oe.Code != "invalid_scope" {
		t.Fatalf("scope escalation: %v", oe)
	}
}

func TestSigningVerificationAndKeyRotation(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	resp := e.exchange(t, "openid")
	claims, tok := parseClaims(t, resp.AccessToken, e.keys)
	if tok.Header["kid"] != e.keys.Active.KID || tok.Header["typ"] != "at+jwt" || claims["iss"] != issuer {
		t.Fatalf("bad access token: %v %v", tok.Header, claims)
	}
	if _, oe := e.svc.UserInfo(ctx, resp.AccessToken); oe != nil {
		t.Fatal(oe)
	}

	// Rotate: key B becomes active, A stays published as previous.
	a, b := testKeys(t)
	rotated := oidc.NewKeySet(b, a)
	svc2 := oidc.New(oidc.Config{Issuer: issuer, FrontendURL: frontend}, e.store, e.users, rotated, nil)
	if _, oe := svc2.UserInfo(ctx, resp.AccessToken); oe != nil {
		t.Fatalf("token signed by previous key rejected after rotation: %v", oe)
	}
	jwks := rotated.JWKS()["keys"].([]oidc.JWK)
	if len(jwks) != 2 || jwks[0].Kid == jwks[1].Kid || jwks[0].Alg != "RS256" || jwks[0].Kty != "RSA" {
		t.Fatalf("bad JWKS %+v", jwks)
	}
	if oidc.KidFor(&b.PublicKey) != rotated.Active.KID {
		t.Fatal("kid is not stable")
	}
	// A key set without A must not accept A's tokens.
	svc3 := oidc.New(oidc.Config{Issuer: issuer, FrontendURL: frontend}, e.store, e.users, oidc.NewKeySet(b), nil)
	if _, oe := svc3.UserInfo(ctx, resp.AccessToken); oe == nil {
		t.Fatal("token verified with an unrelated key set")
	}
}

func TestIDTokenAndClaimsByScope(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	orgA := uuid.New()
	e.store.Orgs[e.user.ID] = []oidc.OrgRole{{OrgID: orgA, Slug: "acme", Role: "owner"}, {OrgID: uuid.New(), Slug: "beta", Role: "member"}}
	e.svc.ExtraGroups = func(context.Context, uuid.UUID) ([]string, error) {
		return []string{"project:acme/web:maintainer", "org:acme"}, nil // duplicate must collapse
	}

	full := e.exchange(t, "openid profile email groups")
	idc, tok := parseClaims(t, full.IDToken, e.keys)
	if tok.Header["kid"] == nil || idc["nonce"] != "n0nce" || idc["iss"] != issuer || idc["sub"] != e.user.ID.String() {
		t.Fatalf("id_token: %v", idc)
	}
	if aud, _ := idc["aud"].([]any); len(aud) != 1 || aud[0] != e.client.ClientID {
		t.Fatalf("id_token aud: %v", idc["aud"])
	}
	if idc["email"] != "Jane.Doe@example.com" || idc["email_verified"] != true || idc["name"] != "Jane Doe" || idc["preferred_username"] != "jane.doe" {
		t.Fatalf("claims: %v", idc)
	}
	want := []any{"org:acme", "org:acme:owner", "org:beta", "org:beta:member", "project:acme/web:maintainer"}
	got, _ := idc["groups"].([]any)
	if len(got) != len(want) {
		t.Fatalf("groups %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("groups %v", got)
		}
	}
	ui, oe := e.svc.UserInfo(ctx, full.AccessToken)
	if oe != nil || ui["email"] == nil || ui["groups"] == nil || ui["sub"] != e.user.ID.String() {
		t.Fatalf("userinfo: %v %v", ui, oe)
	}

	// Scope gating.
	minimal := e.exchange(t, "openid")
	mc, _ := parseClaims(t, minimal.IDToken, e.keys)
	for _, k := range []string{"email", "email_verified", "name", "preferred_username", "groups"} {
		if _, ok := mc[k]; ok {
			t.Errorf("claim %q emitted without its scope", k)
		}
	}
	mi, _ := e.svc.UserInfo(ctx, minimal.AccessToken)
	if len(mi) != 1 || mi["sub"] == nil {
		t.Fatalf("minimal userinfo: %v", mi)
	}
	onlyEmail := e.exchange(t, "openid email")
	ec, _ := parseClaims(t, onlyEmail.IDToken, e.keys)
	if ec["email"] == nil || ec["groups"] != nil || ec["name"] != nil {
		t.Fatalf("email-only claims: %v", ec)
	}

	// A failing ExtraGroups must not silently drop groups.
	e.svc.ExtraGroups = func(context.Context, uuid.UUID) ([]string, error) { return nil, context.DeadlineExceeded }
	code := e.authorize(t, "openid groups")
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: e.tokenForm(code)}); oe == nil || oe.Code != "server_error" {
		t.Fatalf("ExtraGroups failure: %v", oe)
	}
}

func TestPreferredUsernameCollisionAndSanitizing(t *testing.T) {
	e := newEnv(t, false)
	e.store.Taken["jane.doe"] = true
	r := e.exchange(t, "openid profile")
	c, _ := parseClaims(t, r.IDToken, e.keys)
	want := "jane.doe-" + e.user.ID.String()[:6]
	if c["preferred_username"] != want {
		t.Fatalf("got %v want %s", c["preferred_username"], want)
	}
	// stable across calls
	r2 := e.exchange(t, "openid profile")
	c2, _ := parseClaims(t, r2.IDToken, e.keys)
	if c2["preferred_username"] != want {
		t.Fatal("suffix not stable")
	}
	for in, out := range map[string]string{
		"A.B+tag@x.io": "a.b-tag", "@x.io": "user", "...@x.io": "user", "ñandú@x.io": "and",
		strings.Repeat("a", 50) + "@x.io": strings.Repeat("a", 32),
	} {
		if got := oidc.SanitizeUsername(in); got != out {
			t.Errorf("SanitizeUsername(%q)=%q want %q", in, got, out)
		}
	}
}

func TestOIDCTokensDoNotAuthenticateTheAPIAndViceVersa(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	resp := e.exchange(t, "openid profile email groups offline_access")

	const secret = "platform-secret"
	api := service.NewAuthService(e.users, nil, secret, time.Hour, time.Hour, nil)
	for name, tok := range map[string]string{"access": resp.AccessToken, "id": resp.IDToken, "refresh": resp.RefreshToken} {
		if _, err := api.ValidateAccessToken(ctx, tok); err == nil {
			t.Errorf("OIDC %s token authenticated against the REST API", name)
		}
	}

	// API-session JWT (HS256, same shape as AuthService issues) must not work on userinfo.
	now := time.Now()
	apiTok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid": e.user.ID.String(), "type": "access", "sub": e.user.ID.String(), "iss": issuer,
		"aud": []string{issuer + "/oauth/userinfo"}, "gid": uuid.NewString(), "client_id": e.client.ClientID,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}).SignedString([]byte(secret))
	if _, oe := e.svc.UserInfo(ctx, apiTok); oe == nil {
		t.Fatal("HS256 API token accepted by userinfo")
	}
	// id_token is not an access token.
	if _, oe := e.svc.UserInfo(ctx, resp.IDToken); oe == nil {
		t.Fatal("id_token accepted by userinfo")
	}
	if _, oe := e.svc.UserInfo(ctx, "garbage"); oe == nil || oe.Status != 401 {
		t.Fatal("garbage accepted")
	}
}

func TestAccessTokenIssAudExpChecks(t *testing.T) {
	e := newEnv(t, false)
	a, _ := testKeys(t)
	ctx := context.Background()
	resp := e.exchange(t, "openid")
	base, _ := parseClaims(t, resp.AccessToken, e.keys)

	mint := func(mut func(jwt.MapClaims), typ string) string {
		c := jwt.MapClaims{}
		for k, v := range base {
			c[k] = v
		}
		mut(c)
		tk := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
		tk.Header["kid"] = e.keys.Active.KID
		tk.Header["typ"] = typ
		s, err := tk.SignedString(a)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if _, oe := e.svc.UserInfo(ctx, mint(func(jwt.MapClaims) {}, "at+jwt")); oe != nil {
		t.Fatalf("control token rejected: %v", oe)
	}
	cases := map[string]string{
		"expired":   mint(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, "at+jwt"),
		"no exp":    mint(func(c jwt.MapClaims) { delete(c, "exp") }, "at+jwt"),
		"wrong iss": mint(func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }, "at+jwt"),
		"wrong aud": mint(func(c jwt.MapClaims) { c["aud"] = []string{"https://other"} }, "at+jwt"),
		"wrong typ": mint(func(c jwt.MapClaims) {}, "JWT"),
	}
	for name, tok := range cases {
		if _, oe := e.svc.UserInfo(ctx, tok); oe == nil {
			t.Errorf("%s token accepted", name)
		}
	}
}

func TestRevokedClientAndSuspendedUser(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	resp := e.exchange(t, "openid offline_access")
	if err := e.store.RevokeClient(ctx, e.client.ID); err != nil {
		t.Fatal(err)
	}
	if _, oe := e.svc.UserInfo(ctx, resp.AccessToken); oe == nil {
		t.Fatal("userinfo works for a revoked client")
	}
	if _, oe := e.svc.Token(ctx, oidc.TokenRequest{Form: e.refreshForm(resp.RefreshToken)}); oe == nil || oe.Code != "invalid_client" {
		t.Fatalf("revoked client refresh: %v", oe)
	}
	if r := e.svc.Authorize(ctx, e.authQuery("openid")); r.Fatal == nil {
		t.Fatal("authorize works for a revoked client")
	}

	e2 := newEnv(t, false)
	r2 := e2.exchange(t, "openid offline_access")
	e2.users.ByID[e2.user.ID].Role = "suspended"
	if _, oe := e2.svc.UserInfo(ctx, r2.AccessToken); oe == nil {
		t.Fatal("suspended user can call userinfo")
	}
	if _, oe := e2.svc.Token(ctx, oidc.TokenRequest{Form: e2.refreshForm(r2.RefreshToken)}); oe == nil {
		t.Fatal("suspended user can refresh")
	}
}

func TestDenyAndRequestLifecycle(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	res := e.svc.Authorize(ctx, e.authQuery("openid profile"))
	u, _ := url.Parse(res.RedirectURL)
	id := u.Query().Get("request")
	info, err := e.svc.RequestInfo(ctx, id)
	if err != nil || info.ClientName != "Forgejo" || !info.FirstParty || info.RedirectHost != "git.test.local" ||
		len(info.Scopes) != 2 || info.Scopes[0] != "openid" {
		t.Fatalf("info: %+v %v", info, err)
	}
	back, err := e.svc.Deny(ctx, id)
	bu, _ := url.Parse(back)
	if err != nil || bu.Query().Get("error") != "access_denied" || bu.Query().Get("state") != "st4te" {
		t.Fatalf("deny: %s %v", back, err)
	}
	if _, err := e.svc.Approve(ctx, id, e.user); err != oidc.ErrRequestNotFound {
		t.Fatalf("request reusable after deny: %v", err)
	}
	// Expiry.
	res = e.svc.Authorize(ctx, e.authQuery("openid"))
	u, _ = url.Parse(res.RedirectURL)
	for _, r := range e.store.Requests {
		r.ExpiresAt = time.Now().Add(-time.Second)
	}
	if _, err := e.svc.RequestInfo(ctx, u.Query().Get("request")); err != oidc.ErrRequestNotFound {
		t.Fatalf("expired request visible: %v", err)
	}
}

func TestDiscovery(t *testing.T) {
	e := newEnv(t, false)
	d := e.svc.Discovery()
	str := func(k string) string { s, _ := d[k].(string); return s }
	if str("issuer") != issuer || str("authorization_endpoint") != issuer+"/oauth/authorize" ||
		str("token_endpoint") != issuer+"/oauth/token" || str("userinfo_endpoint") != issuer+"/oauth/userinfo" ||
		str("jwks_uri") != issuer+"/oauth/jwks" {
		t.Fatalf("endpoints: %v", d)
	}
	eq := func(k string, want ...string) {
		t.Helper()
		got, _ := d[k].([]string)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s = %v want %v", k, got, want)
		}
	}
	eq("scopes_supported", "openid", "profile", "email", "groups", "offline_access")
	eq("response_types_supported", "code")
	eq("grant_types_supported", "authorization_code", "refresh_token")
	eq("code_challenge_methods_supported", "S256")
	eq("id_token_signing_alg_values_supported", "RS256")
	if d["claims_supported"] == nil {
		t.Error("claims_supported missing")
	}
}

func TestRedirectURIValidation(t *testing.T) {
	ok := []string{"https://git.example.com/cb", "http://localhost:3000/cb", "http://127.0.0.1/cb"}
	bad := []string{"", "git.example.com/cb", "http://example.com/cb", "https://x.com/cb#frag", "https://u:p@x.com/cb", "javascript:alert(1)", "ftp://x.com/cb"}
	for _, u := range ok {
		if err := oidc.ValidateRedirectURI(u); err != nil {
			t.Errorf("%q rejected: %v", u, err)
		}
	}
	for _, u := range bad {
		if err := oidc.ValidateRedirectURI(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if _, err := oidc.ValidateRedirectURIs(nil); err == nil {
		t.Error("empty list accepted")
	}
}

func TestLoadKeySetPersistsEncryptedKey(t *testing.T) {
	ctx := context.Background()
	st := &memSettings{m: map[string]string{}}
	k1, err := oidc.LoadKeySet(ctx, st, "platform-secret", "", "")
	if err != nil {
		t.Fatal(err)
	}
	raw := st.m["oidc_signing_key"]
	if raw == "" || strings.Contains(raw, "PRIVATE KEY") {
		t.Fatal("key not stored, or stored in clear")
	}
	k2, err := oidc.LoadKeySet(ctx, st, "platform-secret", "", "")
	if err != nil || k2.Active.KID != k1.Active.KID {
		t.Fatalf("key changed across restarts: %v", err)
	}
	if _, err := oidc.LoadKeySet(ctx, st, "other-secret", "", ""); err == nil {
		t.Fatal("decrypted with the wrong platform secret")
	}
	// Env key wins; previous key stays in the JWKS.
	a, b := testKeys(t)
	pemA := string(pemEncode(a))
	pemB := string(pemEncode(b))
	k3, err := oidc.LoadKeySet(ctx, st, "platform-secret", strings.ReplaceAll(pemB, "\n", `\n`), pemA)
	if err != nil {
		t.Fatal(err)
	}
	if k3.Active.KID != oidc.KidFor(&b.PublicKey) || len(k3.Previous) != 1 || k3.Previous[0].KID != oidc.KidFor(&a.PublicKey) {
		t.Fatal("env keys not honoured")
	}
	if _, err := oidc.LoadKeySet(ctx, st, "x", "not a pem", ""); err == nil {
		t.Fatal("garbage PEM accepted")
	}
}

type memSettings struct{ m map[string]string }

func (s *memSettings) Get(_ context.Context, k string) (string, error) { return s.m[k], nil }
func (s *memSettings) Set(_ context.Context, k, v string) error        { s.m[k] = v; return nil }
