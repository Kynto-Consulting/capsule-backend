package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

func (e *env) authorize(route uuid.UUID, ctype, cred, ip string) *AuthorizeResponse {
	e.t.Helper()
	res, err := e.svc.Authorize(context.Background(), AuthorizeRequest{RouteID: route.String(), SrcIP: ip, CredentialType: ctype, Credential: cred, Access: "capsule_uri"})
	if err != nil {
		e.t.Fatalf("authorize: %v", err)
	}
	return res
}

func TestAuthorizeRolesWithCapToken(t *testing.T) {
	e := newEnv(t)
	e.expose("db", "postgres", 5432)
	route := e.routeID("db")
	cases := []struct {
		name  string
		user  uuid.UUID
		allow bool
	}{{"admin", e.admin, true}, {"deployer", e.deployer, true}, {"viewer", e.viewer, false}, {"outsider", e.outsider, false}, {"hidden", e.hidden, false}}
	for _, c := range cases {
		tok := e.capToken(c.user, nil)
		res := e.authorize(route, CredCap, tok, "203.0.113.9")
		if res.Allow != c.allow {
			t.Errorf("%s: allow = %v, want %v (%+v)", c.name, res.Allow, c.allow, res)
		}
		if !c.allow && res.DenyReason != DenyUnauthorized {
			t.Errorf("%s: deny reason %q, want unauthorized", c.name, res.DenyReason)
		}
	}
}

func TestAuthorizeAllowCarriesLimitsAndCacheHint(t *testing.T) {
	e := newEnv(t)
	e.expose("db", "postgres", 5432)
	res := e.authorize(e.routeID("db"), CredCap, e.capToken(e.admin, nil), "203.0.113.9")
	if !res.Allow || res.PrincipalID == "" || res.MaxConns != 200 || res.MaxConnsPerIP != 50 || res.CacheTTLSeconds != 30 || res.IdleTimeoutSecond != 3600 {
		t.Fatalf("unexpected allow: %+v", res)
	}
}

func TestAuthorizeCapTokenScopeProjectAndLifecycle(t *testing.T) {
	e := newEnv(t)
	e.expose("db", "postgres", 5432)
	route := e.routeID("db")
	other := uuid.New()
	past := e.now.Add(-time.Hour)
	revoked := e.now.Add(-time.Minute)
	cases := []struct {
		name string
		mod  func(*domain.APIToken)
		want bool
	}{
		{"plain full-access token", nil, true},
		{"explicit star scope", func(t *domain.APIToken) { t.Scopes = "*" }, true},
		{"gateway scope", func(t *domain.APIToken) { t.Scopes = "gateway" }, true},
		{"deploy-only scope", func(t *domain.APIToken) { t.Scopes = "deploy"; p := e.project.ID; t.ProjectID = &p }, false},
		{"security-only scope", func(t *domain.APIToken) { t.Scopes = "security:write" }, false},
		{"bound to this project", func(t *domain.APIToken) { p := e.project.ID; t.ProjectID = &p }, true},
		{"bound to another project", func(t *domain.APIToken) { t.ProjectID = &other }, false},
		{"expired", func(t *domain.APIToken) { t.ExpiresAt = &past }, false},
		{"revoked", func(t *domain.APIToken) { t.RevokedAt = &revoked }, false},
	}
	for _, c := range cases {
		res := e.authorize(route, CredCap, e.capToken(e.admin, c.mod), "203.0.113.9")
		if res.Allow != c.want {
			t.Errorf("%s: allow = %v, want %v", c.name, res.Allow, c.want)
		}
	}
	// a token whose user was deleted
	gone := uuid.New()
	e.az.m[gone] = e.az.m[e.admin]
	tok := e.capToken(gone, nil)
	e.users.gone[gone] = true
	if e.authorize(route, CredCap, tok, "203.0.113.9").Allow {
		t.Error("token of a deleted user must not connect")
	}
	// unknown token and a token with the wrong prefix
	if e.authorize(route, CredCap, "cap_nope", "203.0.113.9").Allow || e.authorize(route, CredCap, "xyz", "203.0.113.9").Allow {
		t.Error("unknown token must not connect")
	}
}

func TestAuthorizeUniformAnswerForUnknownRouteTokenAndPermission(t *testing.T) {
	e := newEnv(t)
	e.expose("db", "postgres", 5432)
	route := e.routeID("db")
	good := e.capToken(e.viewer, nil) // valid token, no project.connect
	cases := map[string]AuthorizeRequest{
		"viewer on existing route":     {RouteID: route.String(), SrcIP: "198.51.100.1", CredentialType: CredCap, Credential: good},
		"unknown token":                {RouteID: route.String(), SrcIP: "198.51.100.2", CredentialType: CredCap, Credential: "cap_unknown"},
		"unknown route, valid token":   {RouteID: uuid.NewString(), SrcIP: "198.51.100.3", CredentialType: CredCap, Credential: e.capToken(e.admin, nil)},
		"no credential":                {RouteID: route.String(), SrcIP: "198.51.100.4", CredentialType: CredNone},
		"git token on a non-git route": {RouteID: route.String(), SrcIP: "198.51.100.5", CredentialType: CredCgt, Credential: "cgt_abc"},
	}
	var first []byte
	for name, req := range cases {
		res, err := e.svc.Authorize(context.Background(), req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, _ := json.Marshal(res)
		if first == nil {
			first = b
		} else if string(first) != string(b) {
			t.Errorf("%s: answer %s differs from %s", name, b, first)
		}
	}
	if string(first) != `{"allow":false,"deny_reason":"unauthorized","cache_ttl_seconds":0}` {
		t.Fatalf("unexpected uniform answer: %s", first)
	}
}

func TestAuthorizeIPListIPv4IPv6AndMapped(t *testing.T) {
	e := newEnv(t)
	e.expose("db", "postgres", 5432)
	route := e.routeID("db")
	tok := e.capToken(e.admin, nil)
	e.ips.restricted = true
	e.ips.cidrs = []string{"203.0.113.0/24", "2001:db8:abcd::/48"}
	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.77", true},
		{"::ffff:203.0.113.77", true}, // mapped IPv4 is canonicalised before comparing
		{"198.51.100.1", false},
		{"2001:db8:abcd::1", true},
		{"2001:0db8:abcd:0:0:0:0:99", true}, // same address, other spelling
		{"2001:db8:ffff::1", false},
	}
	for _, c := range cases {
		res := e.authorize(route, CredCap, tok, c.ip)
		if res.Allow != c.want {
			t.Errorf("%s: allow = %v, want %v", c.ip, res.Allow, c.want)
		}
		if !c.want && res.DenyReason != DenyIPDenied {
			t.Errorf("%s: reason %q, want ip_denied", c.ip, res.DenyReason)
		}
	}
	// the IPv4 any-rule does not cover an IPv6 client
	e.ips.cidrs = []string{"0.0.0.0/0"}
	if e.authorize(route, CredCap, tok, "2001:db8::1").Allow {
		t.Error("0.0.0.0/0 must not allow an IPv6 client")
	}
	if !e.authorize(route, CredCap, tok, "8.8.8.8").Allow {
		t.Error("0.0.0.0/0 must allow IPv4")
	}
	e.ips.cidrs = []string{"::/0"}
	if !e.authorize(route, CredCap, tok, "2001:db8::1").Allow {
		t.Error("::/0 must allow IPv6")
	}
	// an explicit empty list denies everything; no list at all restricts nothing
	e.ips.cidrs = nil
	if e.authorize(route, CredCap, tok, "203.0.113.77").Allow {
		t.Error("an explicit empty list must deny all")
	}
	e.ips.restricted = false
	if !e.authorize(route, CredCap, tok, "203.0.113.77").Allow {
		t.Error("no list must not restrict")
	}
}

func TestAuthorizeIPDeniedOnlyShownAfterPermission(t *testing.T) {
	e := newEnv(t)
	e.expose("db", "postgres", 5432)
	route := e.routeID("db")
	e.ips.restricted, e.ips.cidrs = true, []string{"203.0.113.0/24"}
	// no permission + blocked IP -> still plain unauthorized (the IP verdict is not revealed)
	res := e.authorize(route, CredCap, e.capToken(e.viewer, nil), "198.51.100.1")
	if res.DenyReason != DenyUnauthorized {
		t.Fatalf("reason %q, want unauthorized", res.DenyReason)
	}
	// IP lookup failure fails closed
	e.ips.err = context.DeadlineExceeded
	res = e.authorize(route, CredCap, e.capToken(e.admin, nil), "203.0.113.5")
	if res.Allow || res.DenyReason != DenyUnavailable {
		t.Fatalf("ip list error must fail closed, got %+v", res)
	}
}

func TestAuthorizeServiceTokenScope(t *testing.T) {
	e := newEnv(t)
	e.expose("db", "postgres", 5432)
	e.expose("cache", "redis", 6379)
	ctx := context.Background()
	whole, err := e.svc.CreateServiceToken(ctx, e.project, Actor{UserID: e.admin}, ServiceTokenInput{Name: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	onlyDB, err := e.svc.CreateServiceToken(ctx, e.project, Actor{UserID: e.admin}, ServiceTokenInput{Name: "db only", Service: "db", ExpiresInDays: 7})
	if err != nil {
		t.Fatal(err)
	}
	db, cache := e.routeID("db"), e.routeID("cache")
	if !e.authorize(db, CredCgs, whole.Token, "203.0.113.1").Allow || !e.authorize(cache, CredCgs, whole.Token, "203.0.113.1").Allow {
		t.Error("project-wide service token must reach every service of the project")
	}
	if !e.authorize(db, CredCgs, onlyDB.Token, "203.0.113.1").Allow {
		t.Error("service-scoped token must reach its service")
	}
	if e.authorize(cache, CredCgs, onlyDB.Token, "203.0.113.1").Allow {
		t.Error("service-scoped token must not reach another service")
	}
	// another project's route
	otherProj := &domain.Project{ID: uuid.New(), OrgID: e.org, Slug: "other"}
	e.svc.d.Projects.(fakeProjects).m[otherProj.ID] = otherProj
	if _, err := e.svc.CreateService(ctx, otherProj, Actor{UserID: e.admin}, CreateInput{Name: "db", Protocol: "postgres", ContainerPort: 5432}); err != nil {
		t.Fatal(err)
	}
	rv, _ := e.st.ResolveService(ctx, otherProj.ID, "db", "tcp")
	if e.authorize(rv.ID, CredCgs, whole.Token, "203.0.113.1").Allow {
		t.Error("service token of project A must not reach project B")
	}
	// expiry and revocation
	*e.now = e.now.Add(91 * 24 * time.Hour)
	if e.authorize(db, CredCgs, whole.Token, "203.0.113.2").Allow {
		t.Error("expired service token must not connect")
	}
	*e.now = e.now.Add(-91 * 24 * time.Hour)
	if err := e.svc.RevokeServiceToken(ctx, e.project, Actor{UserID: e.admin}, whole.ID); err != nil {
		t.Fatal(err)
	}
	if e.authorize(db, CredCgs, whole.Token, "203.0.113.3").Allow {
		t.Error("revoked service token must not connect")
	}
}

func TestServiceTokenLimitsAndStorage(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.svc.CreateServiceToken(ctx, e.project, Actor{UserID: e.admin}, ServiceTokenInput{Name: "x", ExpiresInDays: 91}); err == nil {
		t.Error("expiry over 90 days must be refused")
	}
	if _, err := e.svc.CreateServiceToken(ctx, e.project, Actor{UserID: e.admin}, ServiceTokenInput{Name: ""}); err == nil {
		t.Error("empty name must be refused")
	}
	c, err := e.svc.CreateServiceToken(ctx, e.project, Actor{UserID: e.admin}, ServiceTokenInput{Name: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.Token, CGSPrefix) || len(c.Token) < 40 || c.ExpiresAt.Sub(c.CreatedAt) != 90*24*time.Hour {
		t.Fatalf("token shape: %q expires in %v", c.Token[:8], c.ExpiresAt.Sub(c.CreatedAt))
	}
	for _, st := range e.svcTok.m {
		if st.Hash == c.Token || strings.Contains(st.Hash, c.Token) || st.Hash != sha256Hex(c.Token) {
			t.Fatal("only the SHA-256 of the token may be stored")
		}
	}
	list, _ := e.svc.ListServiceTokens(ctx, e.project)
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), c.Token) {
		t.Fatal("listing must never include the token value")
	}
	small := newEnv(t, func(c *Config) { c.ServiceTokenMax = 1 })
	if _, err := small.svc.CreateServiceToken(ctx, small.project, Actor{UserID: small.admin}, ServiceTokenInput{Name: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := small.svc.CreateServiceToken(ctx, small.project, Actor{UserID: small.admin}, ServiceTokenInput{Name: "b"}); err == nil {
		t.Error("per-project cap must apply")
	}
}

func TestAuthorizeConnectionTokenSingleUseAndScope(t *testing.T) {
	e := newEnv(t)
	e.expose("db", "postgres", 5432)
	e.expose("cache", "redis", 6379)
	ctx := context.Background()
	res, err := e.svc.IssueConnectionToken(ctx, e.project, Actor{UserID: e.deployer}, "db")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.Token, CGCPrefix) || res.Route != "shop/db" || res.Port != 443 || res.Host != "tcp.apps.example.test" {
		t.Fatalf("unexpected issue result: %+v", res)
	}
	if res.ExpiresAt.Sub(*e.now) != 300*time.Second {
		t.Fatalf("a connection token lives at most 5 minutes, got %v", res.ExpiresAt.Sub(*e.now))
	}
	db, cache := e.routeID("db"), e.routeID("cache")
	if e.authorize(cache, CredCgc, res.Token, "203.0.113.1").Allow {
		t.Fatal("a token for shop/db must not open shop/cache")
	}
	first := e.authorize(db, CredCgc, res.Token, "203.0.113.1")
	if !first.Allow || first.CacheTTLSeconds != 0 {
		t.Fatalf("first use must be allowed and uncacheable: %+v", first)
	}
	if e.authorize(db, CredCgc, res.Token, "203.0.113.1").Allow {
		t.Fatal("a cgc_ token is single use")
	}
	// expiry (beyond the 30 s tolerance)
	res2, _ := e.svc.IssueConnectionToken(ctx, e.project, Actor{UserID: e.deployer}, "db")
	*e.now = e.now.Add(331 * time.Second)
	if e.authorize(db, CredCgc, res2.Token, "203.0.113.1").Allow {
		t.Fatal("expired cgc_ must not connect")
	}
	// the role is re-evaluated at use
	res3, _ := e.svc.IssueConnectionToken(ctx, e.project, Actor{UserID: e.deployer}, "db")
	e.az.m[e.deployer] = e.az.m[e.viewer]
	if e.authorize(db, CredCgc, res3.Token, "203.0.113.1").Allow {
		t.Fatal("a user demoted after issuing must not connect")
	}
}

func TestConnectionTokenUnavailableWithoutKey(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.SigningKey = "" })
	e.expose("db", "postgres", 5432)
	_, err := e.svc.IssueConnectionToken(context.Background(), e.project, Actor{UserID: e.admin}, "db")
	if ee, ok := asError(err); !ok || ee.Status != 501 || ee.Code != "not_configured" {
		t.Fatalf("want 501 not_configured, got %v", err)
	}
}

func TestAuthorizeRandomPortRequiresLease(t *testing.T) {
	e := newEnv(t)
	e.expose("db", "postgres", 5432)
	e.st.SeedPortPool(context.Background(), 20000, 20010)
	route := e.routeID("db")
	tok := e.capToken(e.admin, nil)
	req := AuthorizeRequest{RouteID: route.String(), SrcIP: "203.0.113.1", CredentialType: CredCap, Credential: tok, Access: "random_port", Port: 20003}
	res, _ := e.svc.Authorize(context.Background(), req)
	if res.Allow || res.DenyReason != DenyUnavailable {
		t.Fatalf("no lease: want unavailable, got %+v", res)
	}
	if _, err := e.svc.LeasePort(context.Background(), e.project, Actor{UserID: e.admin}, "db"); err != nil {
		t.Fatal(err)
	}
	res, _ = e.svc.Authorize(context.Background(), req)
	if !res.Allow {
		t.Fatalf("with a lease: %+v", res)
	}
	if e.st.count("TouchLease") != 1 {
		t.Fatal("an allowed random-port connection must touch the lease")
	}
}

func TestAuthorizeBruteForceBlocksAddressAndLimitsRate(t *testing.T) {
	e := newEnv(t)
	e.expose("db", "postgres", 5432)
	route := e.routeID("db")
	ctx := context.Background()
	req := AuthorizeRequest{RouteID: route.String(), SrcIP: "198.51.100.77", CredentialType: CredCap, Credential: "cap_guess"}
	for i := 0; i < 10; i++ {
		if res, err := e.svc.Authorize(ctx, req); err != nil || res.Allow {
			t.Fatalf("attempt %d: %v %+v", i, err, res)
		}
	}
	// blocked now: even a VALID token from that address gets 429 (the block does not reveal whether a token exists)
	req.Credential = e.capToken(e.admin, nil)
	_, err := e.svc.Authorize(ctx, req)
	ee, ok := asError(err)
	if !ok || ee.Status != 429 || ee.Code != "rate_limited" {
		t.Fatalf("want 429 rate_limited, got %v", err)
	}
	if secs, _ := ee.Details["retry_after_seconds"].(int); secs < 1 || secs > 301 {
		t.Fatalf("retry_after_seconds = %v", ee.Details["retry_after_seconds"])
	}
	// another address is unaffected
	req.SrcIP = "198.51.100.78"
	if res, err := e.svc.Authorize(ctx, req); err != nil || !res.Allow {
		t.Fatalf("other address: %v %+v", err, res)
	}
	// the block expires
	*e.now = e.now.Add(6 * time.Minute)
	req.SrcIP = "198.51.100.77"
	if res, err := e.svc.Authorize(ctx, req); err != nil || !res.Allow {
		t.Fatalf("after the block: %v %+v", err, res)
	}
}

func TestAuthorizeRateLimitPerSourceAddress(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.RatePerSecond, c.RateBurst = 1, 3 })
	e.expose("db", "postgres", 5432)
	req := AuthorizeRequest{RouteID: e.routeID("db").String(), SrcIP: "203.0.113.50", CredentialType: CredCap, Credential: e.capToken(e.admin, nil)}
	var limited bool
	for i := 0; i < 6; i++ {
		if _, err := e.svc.Authorize(context.Background(), req); err != nil {
			if ee, ok := asError(err); ok && ee.Status == 429 {
				limited = true
			}
		}
	}
	if !limited {
		t.Fatal("a burst beyond the bucket must be rate limited")
	}
}

func TestAuthorizeBadInput(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	bad := []AuthorizeRequest{
		{RouteID: "nope", SrcIP: "1.2.3.4", CredentialType: CredCap},
		{RouteID: uuid.NewString(), SrcIP: "not-an-ip", CredentialType: CredCap},
		{RouteID: uuid.NewString(), SrcIP: "1.2.3.4", CredentialType: "weird"},
		{RouteID: uuid.NewString(), SrcIP: "fe80::1%eth0x", CredentialType: CredCap},
		{RouteID: uuid.NewString(), SrcIP: "1.2.3.4", CredentialType: CredCap, Credential: strings.Repeat("a", 5000)},
	}
	for i, r := range bad {
		_, err := e.svc.Authorize(ctx, r)
		if ee, ok := asError(err); !ok || ee.Status != 400 {
			t.Errorf("case %d: want 400, got %v", i, err)
		}
	}
}

func TestSecretsNeverReachLogsErrorsOrAudit(t *testing.T) {
	e := newEnv(t)
	e.expose("db", "postgres", 5432)
	ctx := context.Background()
	route := e.routeID("db")
	capTok := e.capToken(e.admin, nil)
	cgs, _ := e.svc.CreateServiceToken(ctx, e.project, Actor{UserID: e.admin}, ServiceTokenInput{Name: "ci"})
	cgc, _ := e.svc.IssueConnectionToken(ctx, e.project, Actor{UserID: e.deployer}, "db")
	wrong := "cap_wrong-" + uuid.NewString()
	var collected []string
	for _, r := range []AuthorizeRequest{
		{RouteID: route.String(), SrcIP: "203.0.113.1", CredentialType: CredCap, Credential: capTok},
		{RouteID: route.String(), SrcIP: "203.0.113.1", CredentialType: CredCgs, Credential: cgs.Token},
		{RouteID: route.String(), SrcIP: "203.0.113.1", CredentialType: CredCgc, Credential: cgc.Token},
		{RouteID: route.String(), SrcIP: "203.0.113.1", CredentialType: CredCap, Credential: wrong},
		{RouteID: uuid.NewString(), SrcIP: "203.0.113.2", CredentialType: CredCap, Credential: wrong},
		{RouteID: route.String(), SrcIP: "bad", CredentialType: CredCap, Credential: wrong},
	} {
		res, err := e.svc.Authorize(ctx, r)
		if err != nil {
			collected = append(collected, err.Error())
		}
		b, _ := json.Marshal(res)
		collected = append(collected, string(b))
	}
	e.audit.mu.Lock()
	ab, _ := json.Marshal(e.audit.entries)
	e.audit.mu.Unlock()
	blob := strings.Join(collected, "\n") + "\n" + string(ab) + "\n" + e.logs.String()
	for name, secret := range map[string]string{"cap": capTok, "cgs": cgs.Token, "cgc": cgc.Token, "wrong": wrong, "gateway secret": testSecret} {
		if strings.Contains(blob, secret) {
			t.Errorf("%s token/secret leaked into logs, errors or audit", name)
		}
	}
	// the cgc payload/signature fragments must not leak either
	for _, part := range strings.Split(strings.TrimPrefix(cgc.Token, CGCPrefix), ".") {
		if len(part) > 12 && strings.Contains(blob, part) {
			t.Error("a fragment of the connection token leaked")
		}
	}
	acts := e.audit.actions()
	var allow, deny int
	for _, a := range acts {
		switch a {
		case "gateway.connect.allow":
			allow++
		case "gateway.connect.deny":
			deny++
		}
	}
	if allow != 3 || deny != 1 { // unknown route and bad input leave no row (org unknown); only the wrong token on a real route does
		t.Fatalf("audit rows: allow=%d deny=%d (actions %v)", allow, deny, acts)
	}
}
