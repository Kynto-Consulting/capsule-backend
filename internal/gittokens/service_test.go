package gittokens_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gittokens"
	"github.com/kynto/capsule/backend/internal/gittokens/gittokenstest"
)

type env struct {
	t        *testing.T
	svc      *gittokens.Service
	store    *gittokenstest.MemStore
	clock    *gittokenstest.Clock
	access   *gittokenstest.Access
	sessions *gittokenstest.Sessions
	ident    *gittokenstest.Identity

	org              uuid.UUID
	web, api, hidden gittokens.ProjectRef
	alice, bob, carl uuid.UUID // alice admin of web, bob deployer of web, carl viewer of web
}

func newEnv(t *testing.T, cfg gittokens.Config) *env {
	t.Helper()
	e := &env{t: t, clock: gittokenstest.NewClock(), access: gittokenstest.NewAccess(), sessions: &gittokenstest.Sessions{}}
	e.store = gittokenstest.NewMemStore(e.clock)
	e.org = uuid.New()
	mk := func(slug string) gittokens.ProjectRef {
		return gittokens.ProjectRef{OrgID: e.org, ProjectID: uuid.New(), OrgSlug: "acme", ProjectSlug: slug}
	}
	e.web, e.api, e.hidden = mk("web"), mk("api"), mk("secret")
	e.alice, e.bob, e.carl = uuid.New(), uuid.New(), uuid.New()
	e.access.Set(e.alice, e.web.ProjectID, authz.RoleAdmin)
	e.access.Set(e.alice, e.api.ProjectID, authz.RoleAdmin)
	e.access.Set(e.bob, e.web.ProjectID, authz.RoleDeployer)
	e.access.Set(e.bob, e.api.ProjectID, authz.RoleDeployer)
	e.access.Set(e.carl, e.web.ProjectID, authz.RoleViewer)
	e.ident = &gittokenstest.Identity{Logins: map[uuid.UUID]string{e.alice: "alice", e.bob: "bob", e.carl: "carl"}}
	e.svc = gittokens.New(cfg, gittokens.Deps{
		Store:     e.store,
		Access:    e.access,
		Directory: &gittokenstest.Directory{Projects: []gittokens.ProjectRef{e.web, e.api, e.hidden}},
		Identity:  e.ident,
		Sessions:  e.sessions,
		Now:       e.clock.Now,
		Async:     func(f func()) { f() }, // bookkeeping inline: deterministic tests
	})
	return e
}

func (e *env) issue(user uuid.UUID, path, scope, session string) *gittokens.Credential {
	e.t.Helper()
	c, err := e.svc.Issue(context.Background(), user, gittokens.IssueInput{Path: path, Scope: scope, SessionRef: session, IP: "203.0.113.9"})
	if err != nil {
		e.t.Fatalf("issue: %v", err)
	}
	return c
}

func (e *env) auth(token, method, uri string) gittokens.Decision {
	return e.svc.Authenticate(context.Background(), gittokens.AuthRequest{HasBasic: true, User: "anything", Password: token, Method: method, URI: uri, IP: "198.51.100.7"})
}

const (
	fetchRefs = "/acme/web.git/info/refs?service=git-upload-pack"
	pushRefs  = "/acme/web.git/info/refs?service=git-receive-pack"
)

func wantOutcome(t *testing.T, d gittokens.Decision, want gittokens.Outcome) {
	t.Helper()
	if d.Outcome != want {
		t.Fatalf("outcome %d (%s), want %d", d.Outcome, d.Reason, want)
	}
}

func wantStatus(t *testing.T, err error, status int) {
	t.Helper()
	ge, ok := gittokens.AsError(err)
	if !ok || ge.Status != status {
		t.Fatalf("error %v, want status %d", err, status)
	}
}

// ---- issuance and renewal ----------------------------------------------------------------

func TestIssueScopeByRole(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	if c := e.issue(e.bob, "acme/web", "", "cli:s1"); c.Scope != "write" || c.Username != "bob" {
		t.Fatalf("deployer gets write by default: %+v", c)
	}
	if c := e.issue(e.carl, "acme/web.git", "", "cli:s1"); c.Scope != "read" {
		t.Fatalf("viewer is degraded to read when no scope asked: %+v", c)
	}
	_, err := e.svc.Issue(context.Background(), e.carl, gittokens.IssueInput{Path: "acme/web", Scope: "write", SessionRef: "cli:s1"})
	wantStatus(t, err, http.StatusForbidden)
	// No role at all and unknown repo look the same: hidden projects do not reveal themselves.
	_, err = e.svc.Issue(context.Background(), e.bob, gittokens.IssueInput{Path: "acme/secret", SessionRef: "cli:s1"})
	wantStatus(t, err, http.StatusNotFound)
	_, err = e.svc.Issue(context.Background(), e.bob, gittokens.IssueInput{Path: "acme/nope", SessionRef: "cli:s1"})
	wantStatus(t, err, http.StatusNotFound)
	_, err = e.svc.Issue(context.Background(), e.bob, gittokens.IssueInput{Path: "acme/web", Scope: "admin", SessionRef: "cli:s1"})
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

func TestIssueRequiresCLISession(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	_, err := e.svc.Issue(context.Background(), e.bob, gittokens.IssueInput{Path: "acme/web"})
	ge, ok := gittokens.AsError(err)
	if !ok || ge.Status != 403 || ge.Code != "CLI_SESSION_REQUIRED" {
		t.Fatalf("browser sessions must be refused: %v", err)
	}
}

func TestIssueStoresOnlyTheHash(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	c := e.issue(e.bob, "acme/web", "", "cli:s1")
	if !gittokens.WellFormed(c.Password) {
		t.Fatalf("bad token %q", c.Password)
	}
	for _, tok := range e.store.Tokens {
		if tok.Hash != gittokens.Hash(c.Password) {
			t.Fatal("stored hash must be the SHA-256 of the value")
		}
		for _, f := range []string{tok.Name, tok.Prefix, tok.Hash, tok.SessionRef, tok.CreatedIP, tok.LastUsedIP, tok.RevokedReason} {
			if strings.Contains(f, c.Password) {
				t.Fatal("the token value leaked into a stored field")
			}
		}
		if tok.Kind != gittokens.KindEphemeral || tok.SessionRef != "cli:s1" || len(tok.ProjectIDs) != 1 || tok.ProjectIDs[0] != e.web.ProjectID {
			t.Fatalf("ephemeral token must be bound to one repo and the session: %+v", tok)
		}
		if got := tok.ExpiresAt.Sub(e.clock.Now()); got != time.Hour {
			t.Fatalf("default ttl is 1h, got %s", got)
		}
	}
	for _, a := range e.store.Audits {
		if a.Action == gittokens.ActionIssue {
			return
		}
	}
	t.Fatal("issuing must be audited")
}

func TestIssueReusesUntilTenMinutesLeftThenRenews(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	first := e.issue(e.bob, "acme/web", "write", "cli:s1")

	e.clock.Advance(30 * time.Minute) // 30 min left: reuse
	again := e.issue(e.bob, "acme/web", "write", "cli:s1")
	if again.Password != first.Password || len(e.store.Tokens) != 1 {
		t.Fatal("a token with more than 10 minutes left must be reused")
	}
	if !again.RenewAfter.Equal(first.ExpiresAt.Add(-10 * time.Minute)) {
		t.Fatalf("renew_after must be expiry - 10m: %s", again.RenewAfter)
	}

	e.clock.Advance(21 * time.Minute) // 9 min left: renew
	renewed := e.issue(e.bob, "acme/web", "write", "cli:s1")
	if renewed.Password == first.Password || len(e.store.Tokens) != 2 {
		t.Fatal("a token with less than 10 minutes left must be replaced")
	}

	other := e.issue(e.bob, "acme/web", "write", "cli:other-session")
	if other.Password == renewed.Password {
		t.Fatal("sessions never share tokens")
	}
	apiTok := e.issue(e.bob, "acme/api", "write", "cli:s1")
	if apiTok.Password == renewed.Password || apiTok.ProjectID != e.api.ProjectID {
		t.Fatal("tokens are per repo")
	}
}

func TestIssuedTokenRevokedIsNotReused(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	first := e.issue(e.bob, "acme/web", "write", "cli:s1")
	for id := range e.store.Tokens {
		if _, err := e.store.RevokeToken(context.Background(), id, "test"); err != nil {
			t.Fatal(err)
		}
	}
	if again := e.issue(e.bob, "acme/web", "write", "cli:s1"); again.Password == first.Password {
		t.Fatal("a revoked token must never be handed out again")
	}
}

func TestEphemeralTokensPrunedPerUser(t *testing.T) {
	e := newEnv(t, gittokens.Config{MaxActiveEphemeral: 3})
	for i := 0; i < 5; i++ {
		e.issue(e.bob, "acme/web", "write", "cli:session-number-"+string(rune('a'+i)))
	}
	active := 0
	for _, tok := range e.store.Tokens {
		if tok.Active(e.clock.Now()) {
			active++
		}
	}
	if active != 3 {
		t.Fatalf("active ephemeral tokens must be capped at 3, got %d", active)
	}
}

// ---- validation behind forward_auth ------------------------------------------------------

func TestAuthenticatePassThroughForOtherCredentials(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	for _, req := range []gittokens.AuthRequest{
		{HasBasic: false},
		{HasBasic: true, User: "bob", Password: "gto_oauth2token"},
		{HasBasic: true, User: "bob", Password: ""},
	} {
		d := e.svc.Authenticate(context.Background(), req)
		wantOutcome(t, d, gittokens.OutcomePass)
		if d.Login != "" {
			t.Fatal("a pass-through must never carry a login: X-WEBAUTH-USER would impersonate")
		}
	}
}

func TestAuthenticateAllowsInScope(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	c := e.issue(e.bob, "acme/web", "write", "cli:s1")
	for _, tc := range []struct{ method, uri string }{
		{"GET", fetchRefs}, {"POST", "/acme/web.git/git-upload-pack"}, {"GET", pushRefs}, {"POST", "/acme/web.git/git-receive-pack"},
	} {
		d := e.auth(c.Password, tc.method, tc.uri)
		wantOutcome(t, d, gittokens.OutcomeAllow)
		if d.Login != "bob" {
			t.Fatalf("login must be the token owner's Forgejo login, got %q", d.Login)
		}
	}
	// The Basic username is ignored: whatever the client sends, the login comes from the token.
	d := e.svc.Authenticate(context.Background(), gittokens.AuthRequest{HasBasic: true, User: "alice", Password: c.Password, Method: "GET", URI: fetchRefs, IP: "1.2.3.4"})
	if d.Outcome != gittokens.OutcomeAllow || d.Login != "bob" {
		t.Fatalf("a client cannot pick the login: %+v", d)
	}
}

func TestAuthenticateRejectsInvalidTokens(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	unknown, _, _ := gittokens.Generate(nil)
	for name, tok := range map[string]string{
		"unknown":   unknown,
		"malformed": "cgt_short",
		"empty":     "cgt_",
		"wrong len": unknown + "00",
	} {
		wantOutcome(t, e.auth(tok, "GET", fetchRefs), gittokens.OutcomeUnauthorized)
		_ = name
	}
}

func TestAuthenticateOtherRepoIsForbidden(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	c := e.issue(e.bob, "acme/web", "write", "cli:s1")
	d := e.auth(c.Password, "GET", "/acme/api.git/info/refs?service=git-upload-pack")
	wantOutcome(t, d, gittokens.OutcomeForbidden)
	if d.Reason != "other_repo" {
		t.Fatalf("reason %s", d.Reason)
	}
	// even though bob IS deployer of api: the token is bound to web.
	if d := e.auth(c.Password, "POST", "/acme/api.git/git-receive-pack"); d.Outcome != gittokens.OutcomeForbidden {
		t.Fatal("scope to another repo must be rejected")
	}
	// A repo that does not exist is forbidden too (no existence oracle).
	wantOutcome(t, e.auth(c.Password, "GET", "/acme/ghost.git/info/refs?service=git-upload-pack"), gittokens.OutcomeForbidden)
	// Path tricks do not escape the repo check.
	wantOutcome(t, e.auth(c.Password, "GET", "/acme/web.git/../api.git/info/refs?service=git-upload-pack"), gittokens.OutcomeForbidden)
	wantOutcome(t, e.auth(c.Password, "GET", "/acme/web%2f..%2fapi.git/info/refs"), gittokens.OutcomeForbidden)
	// Non-git routes of Forgejo are never allowed with a cgt_ token.
	wantOutcome(t, e.auth(c.Password, "GET", "/api/v1/user"), gittokens.OutcomeForbidden)
}

func TestAuthenticateReadTokenCannotPush(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	c := e.issue(e.bob, "acme/web", "read", "cli:s1")
	wantOutcome(t, e.auth(c.Password, "GET", fetchRefs), gittokens.OutcomeAllow)
	wantOutcome(t, e.auth(c.Password, "POST", "/acme/web.git/git-upload-pack"), gittokens.OutcomeAllow)
	d := e.auth(c.Password, "GET", pushRefs)
	wantOutcome(t, d, gittokens.OutcomeForbidden)
	wantOutcome(t, e.auth(c.Password, "POST", "/acme/web.git/git-receive-pack"), gittokens.OutcomeForbidden)
	wantOutcome(t, e.auth(c.Password, "PUT", "/acme/web.git/info/lfs/objects/abc/1"), gittokens.OutcomeForbidden)
	wantOutcome(t, e.auth(c.Password, "POST", "/acme/web.git/info/lfs/objects/batch"), gittokens.OutcomeAllow)
}

func TestAuthenticateRoleRemovedCutsWithinThirtySeconds(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	c := e.issue(e.bob, "acme/web", "write", "cli:s1")
	wantOutcome(t, e.auth(c.Password, "GET", pushRefs), gittokens.OutcomeAllow)

	e.access.Set(e.bob, e.web.ProjectID, "") // role removed

	e.clock.Advance(29 * time.Second) // still inside the cache window: the bound is 30 s, not "immediately"
	e.auth(c.Password, "GET", pushRefs)
	e.clock.Advance(2 * time.Second) // 31 s after the cached verdict
	d := e.auth(c.Password, "GET", pushRefs)
	wantOutcome(t, d, gittokens.OutcomeForbidden)
	if d.Reason != "role" {
		t.Fatalf("reason %s", d.Reason)
	}
	wantOutcome(t, e.auth(c.Password, "GET", fetchRefs), gittokens.OutcomeForbidden)
}

func TestAuthenticateRoleDowngradeKeepsReadOnly(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	c := e.issue(e.bob, "acme/web", "write", "cli:s1")
	wantOutcome(t, e.auth(c.Password, "GET", pushRefs), gittokens.OutcomeAllow)
	e.access.Set(e.bob, e.web.ProjectID, authz.RoleViewer) // deployer -> viewer: the write scope no longer helps
	e.clock.Advance(31 * time.Second)
	wantOutcome(t, e.auth(c.Password, "GET", pushRefs), gittokens.OutcomeForbidden)
	wantOutcome(t, e.auth(c.Password, "GET", fetchRefs), gittokens.OutcomeAllow)
}

func TestAuthenticateCacheLifetimeNeverExceedsThirtySeconds(t *testing.T) {
	e := newEnv(t, gittokens.Config{CacheTTL: time.Hour})
	if e.svc.Config().CacheTTL > 30*time.Second {
		t.Fatalf("configured cache ttl must be capped: %s", e.svc.Config().CacheTTL)
	}
}

func TestAuthenticateRevocation(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	c := e.issue(e.bob, "acme/web", "write", "cli:s1")
	wantOutcome(t, e.auth(c.Password, "GET", fetchRefs), gittokens.OutcomeAllow)

	var id uuid.UUID
	for k := range e.store.Tokens {
		id = k
	}
	if err := e.svc.RevokeOwn(context.Background(), e.bob, id, "9.9.9.9"); err != nil {
		t.Fatal(err)
	}
	d := e.auth(c.Password, "GET", fetchRefs) // same process: effective at once, not after 30 s
	wantOutcome(t, d, gittokens.OutcomeUnauthorized)
	if d.Reason != "revoked" {
		t.Fatalf("reason %s", d.Reason)
	}
	// Revoked by another instance (store only): the cache bound still applies.
	c2 := e.issue(e.bob, "acme/web", "write", "cli:s2")
	wantOutcome(t, e.auth(c2.Password, "GET", fetchRefs), gittokens.OutcomeAllow)
	for k, tok := range e.store.Tokens {
		if tok.SessionRef == "cli:s2" {
			_, _ = e.store.RevokeToken(context.Background(), k, "other instance")
		}
	}
	e.clock.Advance(31 * time.Second)
	wantOutcome(t, e.auth(c2.Password, "GET", fetchRefs), gittokens.OutcomeUnauthorized)

	found := false
	for _, a := range e.store.AuditActions() {
		found = found || a == gittokens.ActionRevoke
	}
	if !found {
		t.Fatal("revocation must be audited")
	}
}

func TestAuthenticateExpiry(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	c := e.issue(e.bob, "acme/web", "write", "cli:s1")
	e.clock.Advance(59 * time.Minute)
	wantOutcome(t, e.auth(c.Password, "GET", fetchRefs), gittokens.OutcomeAllow)
	e.clock.Advance(2 * time.Minute) // expiry is checked live, not through the cache
	d := e.auth(c.Password, "GET", fetchRefs)
	wantOutcome(t, d, gittokens.OutcomeUnauthorized)
	if d.Reason != "expired" {
		t.Fatalf("reason %s", d.Reason)
	}
}

func TestSessionRevocationAndEndedSession(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	a := e.issue(e.bob, "acme/web", "write", "cli:s1")
	b := e.issue(e.bob, "acme/api", "write", "cli:s1")
	other := e.issue(e.bob, "acme/web", "write", "cli:s2")
	for _, c := range []*gittokens.Credential{a, b, other} {
		wantOutcome(t, e.auth(c.Password, "GET", "/"+"acme/"+map[uuid.UUID]string{e.web.ProjectID: "web", e.api.ProjectID: "api"}[c.ProjectID]+".git/info/refs?service=git-upload-pack"), gittokens.OutcomeAllow)
	}
	n, err := e.svc.RevokeSession(context.Background(), e.bob, "cli:s1", "1.1.1.1")
	if err != nil || n != 2 {
		t.Fatalf("revoke session: n=%d err=%v", n, err)
	}
	wantOutcome(t, e.auth(a.Password, "GET", fetchRefs), gittokens.OutcomeUnauthorized)
	wantOutcome(t, e.auth(b.Password, "GET", "/acme/api.git/info/refs?service=git-upload-pack"), gittokens.OutcomeUnauthorized)
	wantOutcome(t, e.auth(other.Password, "GET", fetchRefs), gittokens.OutcomeAllow)
	// A user cannot revoke somebody else's session.
	if n, _ := e.svc.RevokeSession(context.Background(), e.alice, "cli:s2", ""); n != 0 {
		t.Fatal("sessions are per user")
	}

	// Session ended on the identity side (cap_ token revoked): tokens stop within the cache bound.
	e.sessions.Kill("cli:s2")
	e.clock.Advance(31 * time.Second)
	d := e.auth(other.Password, "GET", fetchRefs)
	wantOutcome(t, d, gittokens.OutcomeUnauthorized)
	if d.Reason != "session_ended" {
		t.Fatalf("reason %s", d.Reason)
	}
}

func TestAuthenticateRateLimitAndBruteForce(t *testing.T) {
	e := newEnv(t, gittokens.Config{FailBurst: 3, FailRefill: time.Minute})
	good := e.issue(e.bob, "acme/web", "write", "cli:s1")
	guess, _, _ := gittokens.Generate(nil)
	ip := "198.51.100.77"
	req := func(tok string) gittokens.Decision {
		return e.svc.Authenticate(context.Background(), gittokens.AuthRequest{HasBasic: true, Password: tok, Method: "GET", URI: fetchRefs, IP: ip})
	}
	for i := 0; i < 3; i++ {
		wantOutcome(t, req(guess), gittokens.OutcomeUnauthorized)
	}
	d := req(good.Password) // even the valid token is limited from an IP that just guessed 3 times
	wantOutcome(t, d, gittokens.OutcomeLimited)
	if d.RetryAfter <= 0 {
		t.Fatal("429 needs a Retry-After")
	}
	// Other IPs are unaffected.
	d = e.svc.Authenticate(context.Background(), gittokens.AuthRequest{HasBasic: true, Password: good.Password, Method: "GET", URI: fetchRefs, IP: "198.51.100.78"})
	wantOutcome(t, d, gittokens.OutcomeAllow)
	e.clock.Advance(2 * time.Minute)
	wantOutcome(t, req(good.Password), gittokens.OutcomeAllow)
}

func TestAuthenticateRequestRateLimit(t *testing.T) {
	e := newEnv(t, gittokens.Config{RatePerSecond: 1, RateBurst: 5})
	c := e.issue(e.bob, "acme/web", "write", "cli:s1")
	limited := 0
	for i := 0; i < 20; i++ {
		if e.auth(c.Password, "GET", fetchRefs).Outcome == gittokens.OutcomeLimited {
			limited++
		}
	}
	if limited < 10 {
		t.Fatalf("a burst far above the limit must be throttled, limited %d of 20", limited)
	}
}

func TestAuthenticateFailsClosedWhenDependenciesFail(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	c := e.issue(e.bob, "acme/web", "write", "cli:s1")
	e.access.Err = errors.New("db down")
	d := e.auth(c.Password, "GET", fetchRefs)
	wantOutcome(t, d, gittokens.OutcomeUnavailable)
	if d.Login != "" {
		t.Fatal("never a login on failure")
	}
}

func TestAuthenticateUserWithoutForgejoIdentity(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	c := e.issue(e.bob, "acme/web", "write", "cli:s1")
	delete(e.ident.Logins, e.bob) // user deleted
	e.clock.Advance(31 * time.Second)
	wantOutcome(t, e.auth(c.Password, "GET", fetchRefs), gittokens.OutcomeUnauthorized)
}

func TestFirstUseAuditedOnceAndLastUsedRecorded(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	c := e.issue(e.bob, "acme/web", "write", "cli:s1")
	e.auth(c.Password, "GET", fetchRefs)
	e.clock.Advance(2 * time.Minute)
	e.auth(c.Password, "GET", fetchRefs)
	first := 0
	for _, a := range e.store.AuditActions() {
		if a == gittokens.ActionFirstUse {
			first++
		}
	}
	if first != 1 {
		t.Fatalf("first use must be audited exactly once, got %d", first)
	}
	for _, tok := range e.store.Tokens {
		if tok.LastUsedAt == nil || tok.LastUsedIP != "198.51.100.7" {
			t.Fatalf("last use and IP must be recorded: %+v", tok)
		}
	}
}

func TestDeniedUseIsAuditedThrottled(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	c := e.issue(e.bob, "acme/web", "read", "cli:s1")
	for i := 0; i < 5; i++ {
		e.auth(c.Password, "GET", pushRefs)
	}
	n := 0
	for _, a := range e.store.AuditActions() {
		if a == gittokens.ActionDenied {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("repeated denials of the same token and reason produce one audit row per minute, got %d", n)
	}
}

// ---- personal and service tokens ---------------------------------------------------------

func TestPersonalTokenLifecycle(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	ctx := context.Background()
	tok, plain, err := e.svc.CreatePersonal(ctx, e.bob, gittokens.CreateInput{Name: "ci laptop", Scope: "write", ExpiresInDays: 30, IP: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Kind != gittokens.KindPersonal || tok.Hash != gittokens.Hash(plain) || len(tok.ProjectIDs) != 0 {
		t.Fatalf("%+v", tok)
	}
	if got := tok.ExpiresAt.Sub(e.clock.Now()); got != 30*24*time.Hour {
		t.Fatalf("expiry %s", got)
	}
	// Empty project list = every project the user reaches, checked per request.
	wantOutcome(t, e.auth(plain, "GET", pushRefs), gittokens.OutcomeAllow)
	wantOutcome(t, e.auth(plain, "GET", "/acme/api.git/info/refs?service=git-receive-pack"), gittokens.OutcomeAllow)
	wantOutcome(t, e.auth(plain, "GET", "/acme/secret.git/info/refs?service=git-upload-pack"), gittokens.OutcomeForbidden)

	list, err := e.svc.ListUserTokens(ctx, e.bob)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	if err := e.svc.RevokeOwn(ctx, e.alice, tok.ID, ""); err == nil {
		t.Fatal("another user must not revoke the token")
	}
	if err := e.svc.RevokeOwn(ctx, e.bob, tok.ID, ""); err != nil {
		t.Fatal(err)
	}
	wantOutcome(t, e.auth(plain, "GET", fetchRefs), gittokens.OutcomeUnauthorized)
	if err := e.svc.RevokeOwn(ctx, e.bob, tok.ID, ""); err == nil {
		t.Fatal("revoking twice is not found")
	}
}

func TestPersonalTokenProjectRestriction(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	ctx := context.Background()
	_, plain, err := e.svc.CreatePersonal(ctx, e.bob, gittokens.CreateInput{Name: "only web", Scope: "read", ProjectIDs: []uuid.UUID{e.web.ProjectID}, ExpiresInDays: 7})
	if err != nil {
		t.Fatal(err)
	}
	wantOutcome(t, e.auth(plain, "GET", fetchRefs), gittokens.OutcomeAllow)
	d := e.auth(plain, "GET", "/acme/api.git/info/refs?service=git-upload-pack")
	wantOutcome(t, d, gittokens.OutcomeForbidden)
	if d.Reason != "other_repo" {
		t.Fatalf("reason %s", d.Reason)
	}
}

func TestPersonalTokenValidation(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	ctx := context.Background()
	bad := []gittokens.CreateInput{
		{Name: "", Scope: "read", ExpiresInDays: 7},
		{Name: strings.Repeat("x", 101), Scope: "read", ExpiresInDays: 7},
		{Name: "a\nb", Scope: "read", ExpiresInDays: 7},
		{Name: "n", Scope: "admin", ExpiresInDays: 7},
		{Name: "n", Scope: "", ExpiresInDays: 7},
		{Name: "n", Scope: "read", ExpiresInDays: 0},
		{Name: "n", Scope: "read", ExpiresInDays: 91},
	}
	for i, in := range bad {
		if _, _, err := e.svc.CreatePersonal(ctx, e.bob, in); err == nil {
			t.Fatalf("case %d must be rejected", i)
		} else {
			wantStatus(t, err, http.StatusUnprocessableEntity)
		}
	}
	// Cannot mint a token for a project the role does not allow.
	_, _, err := e.svc.CreatePersonal(ctx, e.carl, gittokens.CreateInput{Name: "n", Scope: "write", ProjectIDs: []uuid.UUID{e.web.ProjectID}, ExpiresInDays: 7})
	wantStatus(t, err, http.StatusForbidden)
	_, _, err = e.svc.CreatePersonal(ctx, e.bob, gittokens.CreateInput{Name: "n", Scope: "read", ProjectIDs: []uuid.UUID{e.hidden.ProjectID}, ExpiresInDays: 7})
	wantStatus(t, err, http.StatusForbidden)
	if _, _, err := e.svc.CreatePersonal(ctx, e.carl, gittokens.CreateInput{Name: "n", Scope: "read", ProjectIDs: []uuid.UUID{e.web.ProjectID}, ExpiresInDays: 90}); err != nil {
		t.Fatalf("90 days is allowed: %v", err)
	}
}

func TestPersonalTokenLimit(t *testing.T) {
	e := newEnv(t, gittokens.Config{MaxPersonal: 2})
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, _, err := e.svc.CreatePersonal(ctx, e.bob, gittokens.CreateInput{Name: "t", Scope: "read", ExpiresInDays: 1}); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := e.svc.CreatePersonal(ctx, e.bob, gittokens.CreateInput{Name: "t", Scope: "read", ExpiresInDays: 1})
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

func TestServiceTokens(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	ctx := context.Background()
	in := gittokens.CreateInput{Name: "ci", Scope: "write", ExpiresInDays: 60}
	// Only git.admin: a deployer (git.write, no git.admin) and a viewer cannot.
	_, _, err := e.svc.CreateService(ctx, e.bob, e.org, e.web.ProjectID, in)
	wantStatus(t, err, http.StatusForbidden)
	_, err = e.svc.ListServiceTokens(ctx, e.bob, e.org, e.web.ProjectID)
	wantStatus(t, err, http.StatusForbidden)
	// Wrong org in the URL.
	_, _, err = e.svc.CreateService(ctx, e.alice, uuid.New(), e.web.ProjectID, in)
	wantStatus(t, err, http.StatusNotFound)
	// A service token is bound to the route's repo.
	bound := in
	bound.ProjectIDs = []uuid.UUID{e.api.ProjectID}
	_, _, err = e.svc.CreateService(ctx, e.alice, e.org, e.web.ProjectID, bound)
	wantStatus(t, err, http.StatusUnprocessableEntity)

	tok, plain, err := e.svc.CreateService(ctx, e.alice, e.org, e.web.ProjectID, in)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Kind != gittokens.KindService || len(tok.ProjectIDs) != 1 || tok.ProjectIDs[0] != e.web.ProjectID {
		t.Fatalf("%+v", tok)
	}
	wantOutcome(t, e.auth(plain, "GET", pushRefs), gittokens.OutcomeAllow)
	wantOutcome(t, e.auth(plain, "GET", "/acme/api.git/info/refs?service=git-upload-pack"), gittokens.OutcomeForbidden)

	list, err := e.svc.ListServiceTokens(ctx, e.alice, e.org, e.web.ProjectID)
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %d", err, len(list))
	}
	// Not in the personal list, not revocable as a personal token.
	if pl, _ := e.svc.ListUserTokens(ctx, e.alice); len(pl) != 0 {
		t.Fatal("service tokens are not personal tokens")
	}
	if err := e.svc.RevokeOwn(ctx, e.alice, tok.ID, ""); err == nil {
		t.Fatal("service tokens are revoked through the repo route")
	}
	if err := e.svc.RevokeService(ctx, e.bob, e.org, e.web.ProjectID, tok.ID, ""); err == nil {
		t.Fatal("revoking needs git.admin")
	}
	if err := e.svc.RevokeService(ctx, e.alice, e.org, e.api.ProjectID, tok.ID, ""); err == nil {
		t.Fatal("a token of another repo is not found under this repo")
	}
	if err := e.svc.RevokeService(ctx, e.alice, e.org, e.web.ProjectID, tok.ID, "2.2.2.2"); err != nil {
		t.Fatal(err)
	}
	wantOutcome(t, e.auth(plain, "GET", fetchRefs), gittokens.OutcomeUnauthorized)
}

func TestServiceTokenDiesWithCreatorRole(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	_, plain, err := e.svc.CreateService(context.Background(), e.alice, e.org, e.web.ProjectID, gittokens.CreateInput{Name: "ci", Scope: "write", ExpiresInDays: 10})
	if err != nil {
		t.Fatal(err)
	}
	wantOutcome(t, e.auth(plain, "GET", pushRefs), gittokens.OutcomeAllow)
	e.access.Set(e.alice, e.web.ProjectID, "")
	e.clock.Advance(31 * time.Second)
	wantOutcome(t, e.auth(plain, "GET", pushRefs), gittokens.OutcomeForbidden)
}

type botIdentity struct{}

func (botIdentity) ServiceLogin(_ context.Context, ref gittokens.ProjectRef, scope string) (string, error) {
	return "capsule-bot-" + ref.ProjectSlug + "-" + scope, nil
}

func TestServiceTokenUsesBotIdentityWhenConfigured(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	svc := gittokens.New(gittokens.Config{}, gittokens.Deps{
		Store: e.store, Access: e.access, Directory: &gittokenstest.Directory{Projects: []gittokens.ProjectRef{e.web}},
		Identity: e.ident, ServiceIdentity: botIdentity{}, Now: e.clock.Now, Async: func(f func()) { f() },
	})
	_, plain, err := svc.CreateService(context.Background(), e.alice, e.org, e.web.ProjectID, gittokens.CreateInput{Name: "ci", Scope: "read", ExpiresInDays: 5})
	if err != nil {
		t.Fatal(err)
	}
	d := svc.Authenticate(context.Background(), gittokens.AuthRequest{HasBasic: true, Password: plain, Method: "GET", URI: fetchRefs, IP: "1.1.1.1"})
	if d.Outcome != gittokens.OutcomeAllow || d.Login != "capsule-bot-web-read" {
		t.Fatalf("%+v", d)
	}
}

// ---- maintenance -------------------------------------------------------------------------

type notifier struct{ got []uuid.UUID }

func (n *notifier) TokenExpiring(_ context.Context, t *gittokens.Token) error {
	n.got = append(n.got, t.ID)
	return nil
}

func TestExpiryWarningSentOnce(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	n := &notifier{}
	svc := gittokens.New(gittokens.Config{}, gittokens.Deps{
		Store: e.store, Access: e.access, Directory: &gittokenstest.Directory{}, Identity: e.ident, Notifier: n, Now: e.clock.Now,
	})
	ctx := context.Background()
	soon, _, _ := svc.CreatePersonal(ctx, e.bob, gittokens.CreateInput{Name: "soon", Scope: "read", ExpiresInDays: 5})
	_, _, _ = svc.CreatePersonal(ctx, e.bob, gittokens.CreateInput{Name: "later", Scope: "read", ExpiresInDays: 60})
	e.issue(e.bob, "acme/web", "read", "cli:s1") // ephemeral: never warned
	if got := svc.WarnExpiring(ctx); got != 1 || len(n.got) != 1 || n.got[0] != soon.ID {
		t.Fatalf("exactly the token expiring within 7 days is warned: %d %v", got, n.got)
	}
	if got := svc.WarnExpiring(ctx); got != 0 {
		t.Fatal("warning is sent once")
	}
}

func TestPurgeRemovesOnlyOldEphemeral(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	ctx := context.Background()
	e.issue(e.bob, "acme/web", "read", "cli:s1")
	_, _, _ = e.svc.CreatePersonal(ctx, e.bob, gittokens.CreateInput{Name: "p", Scope: "read", ExpiresInDays: 1})
	e.clock.Advance(10 * 24 * time.Hour)
	n, err := e.store.PurgeEphemeral(ctx, e.clock.Now().Add(-7*24*time.Hour))
	if err != nil || n != 1 || len(e.store.Tokens) != 1 {
		t.Fatalf("n=%d err=%v left=%d", n, err, len(e.store.Tokens))
	}
}
