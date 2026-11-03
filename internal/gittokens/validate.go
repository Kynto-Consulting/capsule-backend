package gittokens

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
)

// Outcome is the verdict of /internal/git-auth.
type Outcome int

const (
	// OutcomePass: not a cgt_ credential (or none). 200 WITHOUT X-WEBAUTH-USER: Forgejo decides
	// (OAuth2 tokens of GCM, anonymous public clones...).
	OutcomePass Outcome = iota
	// OutcomeAllow: valid token, repo and operation inside its scope. 200 + X-WEBAUTH-USER.
	OutcomeAllow
	// OutcomeUnauthorized: unknown, malformed, expired or revoked token, or ended session. 401.
	OutcomeUnauthorized
	// OutcomeForbidden: valid token but the request is outside its scope or the role no longer allows it. 403.
	OutcomeForbidden
	// OutcomeLimited: rate limit. 429 + Retry-After.
	OutcomeLimited
	// OutcomeUnavailable: a dependency failed; never fall through to "allow". 503.
	OutcomeUnavailable
)

// AuthRequest is one forward_auth call.
type AuthRequest struct {
	HasBasic bool
	User     string // ignored: the login comes from the token
	Password string
	Method   string // X-Forwarded-Method
	URI      string // X-Forwarded-Uri (path and query as the client sent them)
	IP       string // client IP (X-Forwarded-For set by Caddy)
}

// Decision is the result of Authenticate. Reason is for logs only and is never sent to the client.
type Decision struct {
	Outcome    Outcome
	Login      string
	RetryAfter time.Duration
	TokenID    uuid.UUID
	Reason     string
}

type tokenEntry struct {
	tok          *Token
	login        string // Forgejo login of the owner ("" until resolved)
	sessionAlive bool
	at           time.Time
}

type roleEntry struct {
	ok bool
	at time.Time
}

type projEntry struct {
	ref *ProjectRef // nil = does not exist
	at  time.Time
}

type loginEntry struct {
	login string
	at    time.Time
}

// validationCache keeps validation results for at most ttl (<= 30 s, SPEC 6.5), so a revoked
// token, a removed role or an ended session stops working within that bound. Revocation made
// through this process drops the entries immediately.
type validationCache struct {
	mu     sync.Mutex
	ttl    time.Duration
	now    func() time.Time
	tokens map[string]tokenEntry
	roles  map[string]roleEntry
	projs  map[string]projEntry
	logins map[string]loginEntry
	byID   map[uuid.UUID]string
}

func newValidationCache(ttl time.Duration, now func() time.Time) *validationCache {
	return &validationCache{ttl: ttl, now: now, tokens: map[string]tokenEntry{}, roles: map[string]roleEntry{},
		projs: map[string]projEntry{}, logins: map[string]loginEntry{}, byID: map[uuid.UUID]string{}}
}

const maxCacheEntries = 10000

func (c *validationCache) fresh(at time.Time) bool { return c.now().Sub(at) < c.ttl }

func (c *validationCache) guard() {
	if len(c.tokens)+len(c.roles)+len(c.projs)+len(c.logins) < maxCacheEntries {
		return
	}
	c.tokens, c.roles, c.projs, c.logins = map[string]tokenEntry{}, map[string]roleEntry{}, map[string]projEntry{}, map[string]loginEntry{}
	c.byID = map[uuid.UUID]string{}
}

func (c *validationCache) getToken(hash string) (tokenEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.tokens[hash]
	if !ok || !c.fresh(e.at) {
		return tokenEntry{}, false
	}
	return e, true
}

func (c *validationCache) putToken(hash string, e tokenEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.guard()
	e.at = c.now()
	c.tokens[hash] = e
	c.byID[e.tok.ID] = hash
}

// dropID forgets everything cached for a token id (and the role verdicts derived from it).
func (c *validationCache) dropID(id uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h, ok := c.byID[id]
	if !ok {
		return
	}
	delete(c.tokens, h)
	delete(c.byID, id)
	for k := range c.roles {
		if len(k) >= len(h) && k[:len(h)] == h {
			delete(c.roles, k)
		}
	}
}

func (c *validationCache) getRole(k string) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.roles[k]
	if !ok || !c.fresh(e.at) {
		return false, false
	}
	return e.ok, true
}

func (c *validationCache) putRole(k string, v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.guard()
	c.roles[k] = roleEntry{ok: v, at: c.now()}
}

func (c *validationCache) getProj(k string) (projEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.projs[k]
	if !ok || !c.fresh(e.at) {
		return projEntry{}, false
	}
	return e, true
}

func (c *validationCache) putProj(k string, ref *ProjectRef) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.guard()
	c.projs[k] = projEntry{ref: ref, at: c.now()}
}

func (c *validationCache) getLogin(k string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.logins[k]
	if !ok || !c.fresh(e.at) {
		return "", false
	}
	return e.login, true
}

func (c *validationCache) putLogin(k, login string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.guard()
	c.logins[k] = loginEntry{login: login, at: c.now()}
}

// Authenticate is the logic behind /internal/git-auth. It never returns the token or its hash.
func (s *Service) Authenticate(ctx context.Context, req AuthRequest) Decision {
	if !req.HasBasic || !IsToken(req.Password) {
		return Decision{Outcome: OutcomePass}
	}
	if ok, wait := s.limiter.Allow(req.IP); !ok {
		return Decision{Outcome: OutcomeLimited, RetryAfter: wait, Reason: "rate_limited"}
	}
	if !WellFormed(req.Password) {
		s.limiter.Fail(req.IP)
		return Decision{Outcome: OutcomeUnauthorized, Reason: "malformed"}
	}
	hash := Hash(req.Password)
	ent, err := s.loadToken(ctx, hash)
	switch {
	case errors.Is(err, domain.ErrNotFound):
		s.limiter.Fail(req.IP)
		return Decision{Outcome: OutcomeUnauthorized, Reason: "unknown_token"}
	case err != nil:
		s.log().Warn("git auth: token lookup failed", "error", err.Error())
		return Decision{Outcome: OutcomeUnavailable, Reason: "store_error"}
	}
	tok := ent.tok
	d := Decision{TokenID: tok.ID}
	if !HashEqual(tok.Hash, hash) {
		s.limiter.Fail(req.IP)
		d.Outcome, d.Reason = OutcomeUnauthorized, "hash_mismatch"
		return d
	}
	now := s.now()
	if tok.RevokedAt != nil {
		s.limiter.Fail(req.IP)
		d.Outcome, d.Reason = OutcomeUnauthorized, "revoked"
		return d
	}
	if !now.Before(tok.ExpiresAt) {
		s.limiter.Fail(req.IP)
		d.Outcome, d.Reason = OutcomeUnauthorized, "expired"
		return d
	}
	if tok.SessionRef != "" && !ent.sessionAlive {
		d.Outcome, d.Reason = OutcomeUnauthorized, "session_ended"
		return d
	}
	target, err := ClassifyGitRequest(req.Method, req.URI)
	if err != nil {
		d.Outcome, d.Reason = OutcomeForbidden, "unsupported_request"
		return d
	}
	ref, err := s.projectBySlugs(ctx, target.Owner, target.Repo)
	if err != nil {
		s.log().Warn("git auth: project lookup failed", "error", err.Error())
		d.Outcome, d.Reason = OutcomeUnavailable, "store_error"
		return d
	}
	if ref == nil {
		d.Outcome, d.Reason = OutcomeForbidden, "repo_not_found"
		return d
	}
	if !tok.AllowsProject(ref.ProjectID) {
		d.Outcome, d.Reason = OutcomeForbidden, "other_repo"
		s.auditDenied(tok, "other_repo", req.IP)
		return d
	}
	if target.Op == OpWrite && tok.Scope != ScopeWrite {
		d.Outcome, d.Reason = OutcomeForbidden, "scope_read_only"
		s.auditDenied(tok, "scope_read_only", req.IP)
		return d
	}
	act := authz.GitRead
	if target.Op == OpWrite {
		act = authz.GitWrite
	}
	allowed, err := s.roleAllows(ctx, hash, tok.UserID, ref, act)
	if err != nil {
		s.log().Warn("git auth: role check failed", "error", err.Error())
		d.Outcome, d.Reason = OutcomeUnavailable, "authz_error"
		return d
	}
	if !allowed {
		d.Outcome, d.Reason = OutcomeForbidden, "role"
		s.auditDenied(tok, "role", req.IP)
		return d
	}
	login, err := s.loginFor(ctx, hash, ent, ref)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			d.Outcome, d.Reason = OutcomeUnauthorized, "no_identity"
			return d
		}
		s.log().Warn("git auth: identity lookup failed", "error", err.Error())
		d.Outcome, d.Reason = OutcomeUnavailable, "identity_error"
		return d
	}
	s.touchUsed(tok, req.IP, ref)
	d.Outcome, d.Login = OutcomeAllow, login
	return d
}

func (s *Service) loadToken(ctx context.Context, hash string) (tokenEntry, error) {
	if e, ok := s.vc.getToken(hash); ok {
		return e, nil
	}
	tok, err := s.d.Store.GetTokenByHash(ctx, hash)
	if err != nil {
		return tokenEntry{}, err
	}
	e := tokenEntry{tok: tok, sessionAlive: true}
	if tok.SessionRef != "" && s.d.Sessions != nil {
		alive, err := s.d.Sessions.Alive(ctx, tok.UserID, tok.SessionRef)
		if err != nil {
			return tokenEntry{}, err
		}
		e.sessionAlive = alive
	}
	s.vc.putToken(hash, e)
	return e, nil
}

func (s *Service) projectBySlugs(ctx context.Context, owner, repo string) (*ProjectRef, error) {
	k := owner + "/" + repo
	if e, ok := s.vc.getProj(k); ok {
		return e.ref, nil
	}
	ref, err := s.d.Directory.BySlugs(ctx, owner, repo)
	if errors.Is(err, domain.ErrNotFound) {
		s.vc.putProj(k, nil)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.vc.putProj(k, ref)
	return ref, nil
}

// roleAllows re-evaluates the owner's project role (cached at most 30 s).
func (s *Service) roleAllows(ctx context.Context, hash string, userID uuid.UUID, ref *ProjectRef, act authz.Action) (bool, error) {
	k := hash + "|" + ref.ProjectID.String() + "|" + string(act)
	if v, ok := s.vc.getRole(k); ok {
		return v, nil
	}
	ok, err := s.d.Access.Can(ctx, userID, ref.OrgID, ref.ProjectID, act)
	if err != nil {
		return false, err
	}
	s.vc.putRole(k, ok)
	return ok, nil
}

// loginFor returns the Forgejo login to inject: the owner's, or the bot's for service tokens when
// a ServiceIdentityResolver is configured.
func (s *Service) loginFor(ctx context.Context, hash string, ent tokenEntry, ref *ProjectRef) (string, error) {
	tok := ent.tok
	if tok.Kind == KindService && s.d.ServiceIdentity != nil {
		k := "svc|" + ref.ProjectID.String() + "|" + tok.Scope
		if l, ok := s.vc.getLogin(k); ok {
			return l, nil
		}
		l, err := s.d.ServiceIdentity.ServiceLogin(ctx, *ref, tok.Scope)
		if err != nil {
			return "", err
		}
		s.vc.putLogin(k, l)
		return l, nil
	}
	k := "user|" + tok.UserID.String()
	if l, ok := s.vc.getLogin(k); ok {
		return l, nil
	}
	l, err := s.d.Identity.ForgejoLogin(ctx, tok.UserID)
	if err != nil {
		return "", err
	}
	if l == "" {
		return "", domain.ErrNotFound
	}
	s.vc.putLogin(k, l)
	return l, nil
}

// touchUsed records last use. The first use of a token is audited; later writes are throttled to
// one per minute per token so a busy CI does not turn every fetch into a database write.
func (s *Service) touchUsed(tok *Token, ip string, ref *ProjectRef) {
	now := s.now()
	s.mu.Lock()
	last, seen := s.touched[tok.ID]
	if seen && now.Sub(last) < time.Minute {
		s.mu.Unlock()
		return
	}
	if len(s.touched) > 20000 {
		s.touched = map[uuid.UUID]time.Time{}
	}
	s.touched[tok.ID] = now
	s.mu.Unlock()
	id, owner, org, proj := tok.ID, tok.UserID, ref.OrgID, ref.ProjectID
	s.d.Async(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		first, err := s.d.Store.TouchUsed(ctx, id, ip)
		if err != nil {
			s.log().Warn("git auth: recording last use failed", "error", err.Error())
			return
		}
		if first {
			s.recordAudit(ctx, AuditRecord{UserID: owner, OrgID: orgPtr(org), Action: ActionFirstUse, ResourceType: "git_token", ResourceID: id, IP: ip,
				Meta: map[string]any{"project_id": proj}})
		}
	})
}

// auditDenied writes one audit row per (token, reason) per minute for requests a valid token
// made outside its scope: they are the signal of a leaked or misused token.
func (s *Service) auditDenied(tok *Token, reason, ip string) {
	now := s.now()
	k := tok.ID.String() + "|" + reason
	s.mu.Lock()
	if last, ok := s.denySeen[k]; ok && now.Sub(last) < time.Minute {
		s.mu.Unlock()
		return
	}
	if len(s.denySeen) > 20000 {
		s.denySeen = map[string]time.Time{}
	}
	s.denySeen[k] = now
	s.mu.Unlock()
	rec := AuditRecord{UserID: tok.UserID, Action: ActionDenied, ResourceType: "git_token", ResourceID: tok.ID, IP: ip,
		Meta: map[string]any{"reason": reason, "kind": tok.Kind}}
	s.d.Async(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.recordAudit(ctx, rec)
	})
}
