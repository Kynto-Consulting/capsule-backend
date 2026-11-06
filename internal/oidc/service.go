package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

// Config configures the provider.
type Config struct {
	Issuer      string // e.g. https://api.tumi-ai.com (no trailing slash)
	FrontendURL string // dashboard that resolves consent, e.g. https://app.tumi-ai.com
}

// Service is the OIDC provider core.
type Service struct {
	cfg    Config
	store  Store
	users  domain.UserRepository
	keys   *KeySet
	logger *slog.Logger
	now    func() time.Time

	// ExtraGroups optionally contributes additional group claims
	// (e.g. project:<org>/<project>:<role>). Nil-safe.
	ExtraGroups func(ctx context.Context, userID uuid.UUID) ([]string, error)
}

func New(cfg Config, store Store, users domain.UserRepository, keys *KeySet, logger *slog.Logger) *Service {
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	cfg.FrontendURL = strings.TrimRight(cfg.FrontendURL, "/")
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{cfg: cfg, store: store, users: users, keys: keys, logger: logger, now: time.Now}
}

func (s *Service) Issuer() string       { return s.cfg.Issuer }
func (s *Service) userinfoURL() string  { return s.cfg.Issuer + "/oauth/userinfo" }
func (s *Service) JWKS() map[string]any { return s.keys.JWKS() }

// Discovery returns the OpenID Provider Metadata document.
func (s *Service) Discovery() map[string]any {
	return map[string]any{
		"issuer":                                s.cfg.Issuer,
		"authorization_endpoint":                s.cfg.Issuer + "/oauth/authorize",
		"token_endpoint":                        s.cfg.Issuer + "/oauth/token",
		"userinfo_endpoint":                     s.userinfoURL(),
		"jwks_uri":                              s.cfg.Issuer + "/oauth/jwks",
		"scopes_supported":                      supportedScopes,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"code_challenge_methods_supported":      []string{"S256"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash",
			"email", "email_verified", "name", "preferred_username", "groups",
		},
	}
}

// ---- helpers ---------------------------------------------------------------

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("oidc: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashSecret returns the hex SHA-256 used for client secrets, codes and refresh tokens.
func HashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func splitScope(s string) []string { return strings.Fields(s) }

func hasScope(scope, want string) bool {
	for _, v := range splitScope(scope) {
		if v == want {
			return true
		}
	}
	return false
}

func isSupportedScope(v string) bool {
	for _, s := range supportedScopes {
		if s == v {
			return true
		}
	}
	return false
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func withQuery(base string, kv map[string]string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for k, v := range kv {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// ---- authorize -------------------------------------------------------------

// AuthorizeResult is the outcome of /oauth/authorize validation. Exactly one of
// RedirectURL or Fatal is set. Fatal errors must NOT redirect (unknown client
// or unverified redirect_uri: no open redirect).
type AuthorizeResult struct {
	RedirectURL string
	Fatal       *OAuthError
}

// Authorize validates an authorization request and stores it as pending.
func (s *Service) Authorize(ctx context.Context, q url.Values) AuthorizeResult {
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	if clientID == "" {
		return AuthorizeResult{Fatal: oerr(400, "invalid_request", "client_id is required")}
	}
	client, err := s.store.GetClientByClientID(ctx, clientID)
	if err != nil || client.RevokedAt != nil {
		return AuthorizeResult{Fatal: oerr(400, "invalid_client", "unknown client")}
	}
	if redirectURI == "" {
		return AuthorizeResult{Fatal: oerr(400, "invalid_request", "redirect_uri is required")}
	}
	if !containsString(client.RedirectURIs, redirectURI) { // exact match only
		return AuthorizeResult{Fatal: oerr(400, "invalid_request", "redirect_uri is not registered for this client")}
	}

	state := q.Get("state")
	fail := func(code, desc string) AuthorizeResult {
		return AuthorizeResult{RedirectURL: withQuery(redirectURI, map[string]string{
			"error": code, "error_description": desc, "state": state, "iss": s.cfg.Issuer,
		})}
	}

	if q.Get("response_type") != "code" {
		return fail("unsupported_response_type", "only response_type=code is supported")
	}

	var scopes []string
	for _, v := range splitScope(q.Get("scope")) {
		if isSupportedScope(v) && !containsString(scopes, v) {
			scopes = append(scopes, v)
		}
	}
	if !containsString(scopes, ScopeOpenID) {
		// Every client of this server is an OIDC login: a missing or mangled scope must not block the sign-in.
		s.logger.Warn("oidc authorize: scope without openid, adding it", "client_id", q.Get("client_id"), "scope_raw", q.Get("scope"))
		scopes = append([]string{ScopeOpenID}, scopes...)
	}

	challenge := q.Get("code_challenge")
	if challenge != "" {
		if m := q.Get("code_challenge_method"); m != "S256" {
			return fail("invalid_request", "code_challenge_method must be S256")
		}
		if !validChallenge(challenge) {
			return fail("invalid_request", "invalid code_challenge")
		}
	} else if client.Public() {
		return fail("invalid_request", "PKCE (code_challenge, S256) is required for public clients")
	}

	if len(state) > 2048 || len(q.Get("nonce")) > 2048 {
		return fail("invalid_request", "state or nonce too long")
	}

	now := s.now()
	req := &AuthRequest{
		ID: randomToken(32), ClientUUID: client.ID, RedirectURI: redirectURI,
		Scope: strings.Join(scopes, " "), State: state, Nonce: q.Get("nonce"),
		CodeChallenge: challenge, CreatedAt: now, ExpiresAt: now.Add(RequestTTL),
	}
	if err := s.store.CreateRequest(ctx, req); err != nil {
		s.logger.Error("oidc: storing authorization request", "error", err)
		return fail("server_error", "could not store the request")
	}
	return AuthorizeResult{RedirectURL: s.cfg.FrontendURL + "/oauth/authorize?request=" + url.QueryEscape(req.ID)}
}

// RequestInfo is what the dashboard shows on the consent screen.
type RequestInfo struct {
	ClientName   string   `json:"client_name"`
	Scopes       []string `json:"scopes"`
	RedirectHost string   `json:"redirect_host"`
	FirstParty   bool     `json:"first_party"`
}

var ErrRequestNotFound = errors.New("authorization request not found or expired")

func (s *Service) RequestInfo(ctx context.Context, id string) (*RequestInfo, error) {
	req, err := s.store.GetRequest(ctx, id)
	if err != nil {
		return nil, mapNotFound(err, ErrRequestNotFound)
	}
	client, err := s.store.GetClientByUUID(ctx, req.ClientUUID)
	if err != nil || client.RevokedAt != nil {
		return nil, ErrRequestNotFound
	}
	host := ""
	if u, err := url.Parse(req.RedirectURI); err == nil {
		host = u.Host
	}
	return &RequestInfo{ClientName: client.Name, Scopes: splitScope(req.Scope), RedirectHost: host, FirstParty: client.FirstParty}, nil
}

func mapNotFound(err, to error) error {
	if errors.Is(err, domain.ErrNotFound) {
		return to
	}
	return err
}

// Approve issues an authorization code for the authenticated user and returns
// the redirect URL back to the client.
func (s *Service) Approve(ctx context.Context, requestID string, user *domain.User) (string, error) {
	if user == nil || user.Role == "suspended" {
		return "", domain.ErrUnauthorized
	}
	req, err := s.store.TakeRequest(ctx, requestID)
	if err != nil {
		return "", mapNotFound(err, ErrRequestNotFound)
	}
	client, err := s.store.GetClientByUUID(ctx, req.ClientUUID)
	if err != nil || client.RevokedAt != nil {
		return "", ErrRequestNotFound
	}
	plain := randomToken(32)
	now := s.now()
	code := &Code{
		ID: uuid.New(), CodeHash: HashSecret(plain), ClientUUID: client.ID, UserID: user.ID,
		RedirectURI: req.RedirectURI, Scope: req.Scope, Nonce: req.Nonce, CodeChallenge: req.CodeChallenge,
		AuthTime: now, ExpiresAt: now.Add(CodeTTL), CreatedAt: now,
	}
	if err := s.store.CreateCode(ctx, code); err != nil {
		return "", err
	}
	return withQuery(req.RedirectURI, map[string]string{"code": plain, "state": req.State, "iss": s.cfg.Issuer}), nil
}

// Deny rejects a pending request and returns the error redirect URL.
func (s *Service) Deny(ctx context.Context, requestID string) (string, error) {
	req, err := s.store.TakeRequest(ctx, requestID)
	if err != nil {
		return "", mapNotFound(err, ErrRequestNotFound)
	}
	return withQuery(req.RedirectURI, map[string]string{
		"error": "access_denied", "state": req.State, "iss": s.cfg.Issuer,
	}), nil
}

// ---- token -----------------------------------------------------------------

// TokenRequest is a parsed /oauth/token call.
type TokenRequest struct {
	Form        url.Values
	BasicID     string
	BasicSecret string
	HasBasic    bool
}

// TokenResponse is the JSON body of a successful token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

func (s *Service) authenticateClient(ctx context.Context, tr TokenRequest) (*Client, *OAuthError) {
	id, secret := tr.Form.Get("client_id"), tr.Form.Get("client_secret")
	if tr.HasBasic {
		if tr.Form.Get("client_secret") != "" {
			return nil, oerr(400, "invalid_request", "multiple client authentication methods")
		}
		if id != "" && id != tr.BasicID {
			return nil, oerr(400, "invalid_request", "client_id mismatch")
		}
		id, secret = tr.BasicID, tr.BasicSecret
	}
	fail := func() (*Client, *OAuthError) {
		e := oerr(401, "invalid_client", "client authentication failed")
		e.Basic = tr.HasBasic
		return nil, e
	}
	if id == "" {
		return fail()
	}
	client, err := s.store.GetClientByClientID(ctx, id)
	if err != nil || client.RevokedAt != nil {
		return fail()
	}
	if client.Public() {
		if secret != "" {
			return fail()
		}
		return client, nil
	}
	if secret == "" || subtle.ConstantTimeCompare([]byte(HashSecret(secret)), []byte(client.SecretHash)) != 1 {
		return fail()
	}
	return client, nil
}

// Token handles the token endpoint.
func (s *Service) Token(ctx context.Context, tr TokenRequest) (*TokenResponse, *OAuthError) {
	grantType := tr.Form.Get("grant_type")
	if grantType == "" {
		return nil, oerr(400, "invalid_request", "grant_type is required")
	}
	if grantType != "authorization_code" && grantType != "refresh_token" {
		return nil, oerr(400, "unsupported_grant_type", "supported: authorization_code, refresh_token")
	}
	client, e := s.authenticateClient(ctx, tr)
	if e != nil {
		return nil, e
	}
	if grantType == "authorization_code" {
		return s.exchangeCode(ctx, client, tr.Form)
	}
	return s.refresh(ctx, client, tr.Form)
}

func (s *Service) loadActiveUser(ctx context.Context, id uuid.UUID) (*domain.User, *OAuthError) {
	user, err := s.users.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, oerr(400, "invalid_grant", "user no longer exists")
		}
		s.logger.Error("oidc: loading user", "error", err)
		return nil, oerr(500, "server_error", "internal error")
	}
	if user.Role == "suspended" {
		return nil, oerr(400, "invalid_grant", "user is suspended")
	}
	return user, nil
}

func (s *Service) exchangeCode(ctx context.Context, client *Client, form url.Values) (*TokenResponse, *OAuthError) {
	plain := form.Get("code")
	if plain == "" {
		return nil, oerr(400, "invalid_request", "code is required")
	}
	code, ok, err := s.store.ConsumeCode(ctx, HashSecret(plain))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, oerr(400, "invalid_grant", "invalid authorization code")
		}
		s.logger.Error("oidc: consuming code", "error", err)
		return nil, oerr(500, "server_error", "internal error")
	}
	if !ok {
		// Replay: revoke everything issued with this code.
		s.logger.Warn("oidc: authorization code reuse; revoking grant", "grant", code.ID, "client", client.ClientID)
		if err := s.store.RevokeGrant(ctx, code.ID); err != nil {
			s.logger.Error("oidc: revoking grant", "error", err)
		}
		return nil, oerr(400, "invalid_grant", "authorization code already used")
	}
	if code.ClientUUID != client.ID {
		return nil, oerr(400, "invalid_grant", "code was issued to a different client")
	}
	if !s.now().Before(code.ExpiresAt) {
		return nil, oerr(400, "invalid_grant", "authorization code expired")
	}
	if form.Get("redirect_uri") != code.RedirectURI {
		return nil, oerr(400, "invalid_grant", "redirect_uri does not match the authorization request")
	}
	if code.CodeChallenge != "" {
		if !VerifyPKCE(code.CodeChallenge, form.Get("code_verifier")) {
			return nil, oerr(400, "invalid_grant", "PKCE verification failed")
		}
	} else if client.Public() {
		return nil, oerr(400, "invalid_grant", "PKCE is required")
	}
	user, e := s.loadActiveUser(ctx, code.UserID)
	if e != nil {
		return nil, e
	}
	return s.issue(ctx, client, user, code.ID, code.Scope, code.Nonce, code.AuthTime)
}

func (s *Service) refresh(ctx context.Context, client *Client, form url.Values) (*TokenResponse, *OAuthError) {
	plain := form.Get("refresh_token")
	if plain == "" {
		return nil, oerr(400, "invalid_request", "refresh_token is required")
	}
	rt, ok, err := s.store.UseRefresh(ctx, HashSecret(plain))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, oerr(400, "invalid_grant", "invalid refresh token")
		}
		s.logger.Error("oidc: using refresh token", "error", err)
		return nil, oerr(500, "server_error", "internal error")
	}
	if rt.ClientUUID != client.ID {
		return nil, oerr(400, "invalid_grant", "refresh token was issued to a different client")
	}
	if !ok {
		if rt.UsedAt != nil && rt.RevokedAt == nil {
			// A rotated token came back: assume theft, kill the whole grant.
			s.logger.Warn("oidc: refresh token reuse detected; revoking grant", "grant", rt.GrantID, "client", client.ClientID)
			if err := s.store.RevokeGrant(ctx, rt.GrantID); err != nil {
				s.logger.Error("oidc: revoking grant", "error", err)
			}
		}
		return nil, oerr(400, "invalid_grant", "refresh token is no longer valid")
	}
	scope := rt.Scope
	if req := form.Get("scope"); req != "" {
		for _, v := range splitScope(req) {
			if !hasScope(rt.Scope, v) {
				return nil, oerr(400, "invalid_scope", "requested scope exceeds the original grant")
			}
		}
		scope = strings.Join(splitScope(req), " ")
		if !hasScope(scope, ScopeOfflineAccess) {
			// Keep rotation alive: the grant's refresh scope is not narrowed away.
			scope += " " + ScopeOfflineAccess
		}
	}
	user, e := s.loadActiveUser(ctx, rt.UserID)
	if e != nil {
		return nil, e
	}
	return s.issue(ctx, client, user, rt.GrantID, scope, "", s.now())
}

// issue mints the token set for a grant.
func (s *Service) issue(ctx context.Context, client *Client, user *domain.User, grantID uuid.UUID, scope, nonce string, authTime time.Time) (*TokenResponse, *OAuthError) {
	claims, err := s.userClaims(ctx, user, scope)
	if err != nil {
		s.logger.Error("oidc: building claims", "error", err)
		return nil, oerr(500, "server_error", "internal error")
	}
	now := s.now()

	atClaims := jwt.MapClaims{
		"iss": s.cfg.Issuer, "sub": user.ID.String(),
		"aud":       []string{s.userinfoURL(), client.ClientID},
		"client_id": client.ClientID, "scope": scope, "gid": grantID.String(),
		"jti": uuid.NewString(), "iat": now.Unix(), "exp": now.Add(AccessTokenTTL).Unix(),
		"auth_time": authTime.Unix(),
	}
	access, err := s.sign(atClaims, "at+jwt")
	if err != nil {
		return nil, oerr(500, "server_error", "internal error")
	}

	idClaims := jwt.MapClaims{
		"iss": s.cfg.Issuer, "sub": user.ID.String(), "aud": []string{client.ClientID},
		"iat": now.Unix(), "exp": now.Add(AccessTokenTTL).Unix(), "auth_time": authTime.Unix(),
		"at_hash": atHash(access),
	}
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	for k, v := range claims {
		if k != "sub" {
			idClaims[k] = v
		}
	}
	idToken, err := s.sign(idClaims, "JWT")
	if err != nil {
		return nil, oerr(500, "server_error", "internal error")
	}

	resp := &TokenResponse{
		AccessToken: access, TokenType: "Bearer", ExpiresIn: int(AccessTokenTTL.Seconds()),
		IDToken: idToken, Scope: scope,
	}
	if hasScope(scope, ScopeOfflineAccess) {
		plain := randomToken(32)
		rt := &RefreshToken{
			ID: uuid.New(), TokenHash: HashSecret(plain), GrantID: grantID, ClientUUID: client.ID,
			UserID: user.ID, Scope: scope, ExpiresAt: now.Add(RefreshTokenTTL), CreatedAt: now,
		}
		if err := s.store.CreateRefresh(ctx, rt); err != nil {
			s.logger.Error("oidc: storing refresh token", "error", err)
			return nil, oerr(500, "server_error", "internal error")
		}
		resp.RefreshToken = plain
	}
	return resp, nil
}

func atHash(access string) string {
	sum := sha256.Sum256([]byte(access))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func (s *Service) sign(claims jwt.MapClaims, typ string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = s.keys.Active.KID
	t.Header["typ"] = typ
	return t.SignedString(s.keys.Active.Private)
}

// ---- claims ----------------------------------------------------------------

// SanitizeUsername derives the base preferred_username from an email: local
// part, lowercased, [^a-z0-9._-] -> "-", max 32 chars, edges trimmed. The SQL
// in oidc_repo.UsernameTaken mirrors these exact steps.
func SanitizeUsername(email string) string {
	local := email
	if i := strings.Index(email, "@"); i >= 0 {
		local = email[:i]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(local) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if len(out) > 32 {
		out = out[:32]
	}
	out = strings.Trim(out, "-._")
	if out == "" {
		out = "user"
	}
	return out
}

func (s *Service) username(ctx context.Context, user *domain.User) (string, error) {
	base := SanitizeUsername(user.Email)
	taken, err := s.store.UsernameTaken(ctx, user.ID, base)
	if err != nil {
		return "", err
	}
	if taken {
		return base + "-" + hex.EncodeToString(user.ID[:3]), nil
	}
	return base, nil
}

func (s *Service) groups(ctx context.Context, userID uuid.UUID) ([]string, error) {
	orgs, err := s.store.UserOrgs(ctx, userID)
	if err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
	for _, o := range orgs {
		set["org:"+o.Slug] = struct{}{}
		if o.Role != "" {
			set["org:"+o.Slug+":"+o.Role] = struct{}{}
		}
	}
	if s.ExtraGroups != nil {
		extra, err := s.ExtraGroups(ctx, userID)
		if err != nil {
			return nil, err
		}
		for _, g := range extra {
			if g != "" {
				set[g] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out, nil
}

// userClaims builds the identity claims allowed by scope.
func (s *Service) userClaims(ctx context.Context, user *domain.User, scope string) (map[string]any, error) {
	c := map[string]any{"sub": user.ID.String()}
	if hasScope(scope, ScopeProfile) {
		name := user.Name
		if name == "" {
			name = SanitizeUsername(user.Email)
		}
		uname, err := s.username(ctx, user)
		if err != nil {
			return nil, err
		}
		c["name"] = name
		c["preferred_username"] = uname
	}
	if hasScope(scope, ScopeEmail) {
		c["email"] = user.Email
		// Accounts are created by an admin or behind invite+TOTP onboarding;
		// there is no separate mail-verification flow, so addresses are trusted.
		c["email_verified"] = true
	}
	if hasScope(scope, ScopeGroups) {
		g, err := s.groups(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		c["groups"] = g
	}
	return c, nil
}

// ---- verification / userinfo -----------------------------------------------

// AccessClaims are the verified claims of an OIDC access token.
type AccessClaims struct {
	UserID   uuid.UUID
	ClientID string
	Scope    string
	GrantID  uuid.UUID
}

// VerifyAccessToken validates signature (RS256, kid), iss, aud, exp and the
// at+jwt type. API-session JWTs (HS256) and id_tokens never pass.
func (s *Service) VerifyAccessToken(raw string) (*AccessClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(s.cfg.Issuer),
		jwt.WithAudience(s.userinfoURL()),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(5*time.Second),
		jwt.WithTimeFunc(s.now),
	)
	claims := jwt.MapClaims{}
	tok, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		pub := s.keys.Lookup(kid)
		if pub == nil {
			return nil, errors.New("unknown kid")
		}
		return pub, nil
	})
	if err != nil || !tok.Valid {
		return nil, errors.New("invalid token")
	}
	if typ, _ := tok.Header["typ"].(string); typ != "at+jwt" {
		return nil, errors.New("not an access token")
	}
	sub, _ := claims["sub"].(string)
	uid, err := uuid.Parse(sub)
	if err != nil {
		return nil, errors.New("invalid subject")
	}
	gid, err := uuid.Parse(asString(claims["gid"]))
	if err != nil {
		return nil, errors.New("invalid grant")
	}
	return &AccessClaims{UserID: uid, ClientID: asString(claims["client_id"]), Scope: asString(claims["scope"]), GrantID: gid}, nil
}

func asString(v any) string { s, _ := v.(string); return s }

// UserInfo resolves a Bearer access token to the userinfo claims.
func (s *Service) UserInfo(ctx context.Context, bearer string) (map[string]any, *OAuthError) {
	invalid := func() (map[string]any, *OAuthError) {
		return nil, oerr(401, "invalid_token", "the access token is invalid or expired")
	}
	ac, err := s.VerifyAccessToken(bearer)
	if err != nil {
		return invalid()
	}
	client, err := s.store.GetClientByClientID(ctx, ac.ClientID)
	if err != nil || client.RevokedAt != nil {
		return invalid()
	}
	active, err := s.store.GrantActive(ctx, ac.GrantID)
	if err != nil || !active {
		return invalid()
	}
	user, err := s.users.GetByID(ctx, ac.UserID)
	if err != nil || user.Role == "suspended" {
		return invalid()
	}
	claims, err := s.userClaims(ctx, user, ac.Scope)
	if err != nil {
		s.logger.Error("oidc: building userinfo claims", "error", err)
		return nil, oerr(500, "server_error", "internal error")
	}
	return claims, nil
}

// ---- client management -----------------------------------------------------

// NewClientParams describes a client to register.
type NewClientParams struct {
	Name         string
	RedirectURIs []string
	OrgID        *uuid.UUID
	FirstParty   bool
	Public       bool
	CreatedBy    uuid.UUID
}

// ValidateRedirectURIs checks and de-duplicates a list of redirect URIs.
func ValidateRedirectURIs(uris []string) ([]string, error) {
	if len(uris) == 0 {
		return nil, errInvalidRedirect("at least one redirect URI is required")
	}
	if len(uris) > 20 {
		return nil, errInvalidRedirect("at most 20 redirect URIs")
	}
	out := make([]string, 0, len(uris))
	for _, u := range uris {
		if err := ValidateRedirectURI(u); err != nil {
			return nil, err
		}
		if !containsString(out, u) {
			out = append(out, u)
		}
	}
	return out, nil
}

// CreateClient registers a client. The returned secret (empty for public
// clients) is shown to the caller exactly once.
func (s *Service) CreateClient(ctx context.Context, p NewClientParams) (*Client, string, error) {
	uris, err := ValidateRedirectURIs(p.RedirectURIs)
	if err != nil {
		return nil, "", err
	}
	secret := ""
	hash := ""
	if !p.Public {
		secret = "cos_" + randomToken(32) // 32 random bytes
		hash = HashSecret(secret)
	}
	by := p.CreatedBy
	c := &Client{
		ID: uuid.New(), ClientID: "cc_" + randomToken(16), SecretHash: hash, Name: p.Name,
		RedirectURIs: uris, OrgID: p.OrgID, FirstParty: p.FirstParty, CreatedBy: &by, CreatedAt: s.now(),
	}
	if err := s.store.CreateClient(ctx, c); err != nil {
		return nil, "", err
	}
	return c, secret, nil
}

// Store exposes the store for the admin handlers.
func (s *Service) Store() Store { return s.store }
