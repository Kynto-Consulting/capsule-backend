package gittokens

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

// Deps are the collaborators of the Service. Store, Access, Directory and Identity are required.
type Deps struct {
	Store     Store
	Access    AccessChecker
	Directory ProjectDirectory
	Identity  IdentityResolver
	// ServiceIdentity is optional (see ServiceIdentityResolver).
	ServiceIdentity ServiceIdentityResolver
	// Sessions is optional; without it "cap:" sessions are never considered ended.
	Sessions SessionChecker
	// Keys returns the Forgejo SSH key API (gitcore.Shared() in production). nil => keys stay unsynced.
	Keys     func() gitcore.Keys
	Notifier Notifier
	Logger   *slog.Logger
	// Test seams.
	Now   func() time.Time
	Rand  io.Reader
	Async func(func()) // runs background bookkeeping (default: go f())
}

// Service is the whole A7 domain logic. It is safe for concurrent use.
type Service struct {
	cfg     Config
	d       Deps
	now     func() time.Time
	limiter *ipLimiter
	vc      *validationCache
	issued  *issuedCache

	mu       sync.Mutex
	touched  map[uuid.UUID]time.Time // last time a token's last_used_at was written
	denySeen map[string]time.Time    // throttle for denial audit rows
}

// New builds the Service.
func New(cfg Config, d Deps) *Service {
	cfg = cfg.withDefaults()
	now := d.Now
	if now == nil {
		now = time.Now
	}
	d.Now = now
	if d.Async == nil {
		d.Async = func(f func()) { go f() }
	}
	return &Service{
		cfg:      cfg,
		d:        d,
		now:      now,
		limiter:  newIPLimiter(cfg.RatePerSecond, cfg.RateBurst, cfg.FailBurst, cfg.FailRefill, now),
		vc:       newValidationCache(cfg.CacheTTL, now),
		issued:   newIssuedCache(now),
		touched:  map[uuid.UUID]time.Time{},
		denySeen: map[string]time.Time{},
	}
}

// Config returns the effective configuration.
func (s *Service) Config() Config { return s.cfg }

func (s *Service) log() *slog.Logger {
	if s.d.Logger != nil {
		return s.d.Logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ---- inputs --------------------------------------------------------------------------------

// CreateInput is the body of POST /user/git-tokens and of the service-token routes.
type CreateInput struct {
	Name          string
	Scope         string
	ProjectIDs    []uuid.UUID
	ExpiresInDays int
	IP            string
}

func (s *Service) validateCreate(in *CreateInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if n := len([]rune(in.Name)); n < 1 || n > 100 {
		return errInvalid("name must have 1 to 100 characters")
	}
	for _, r := range in.Name {
		if unicode.IsControl(r) {
			return errInvalid("name must not contain control characters")
		}
	}
	if in.Scope != ScopeRead && in.Scope != ScopeWrite {
		return errInvalid("scope must be read or write")
	}
	if in.ExpiresInDays < 1 || in.ExpiresInDays > s.cfg.PersonalMaxDays {
		return errInvalid("expires_in_days must be between 1 and 90")
	}
	return nil
}

func actionFor(scope string) authz.Action {
	if scope == ScopeWrite {
		return authz.GitWrite
	}
	return authz.GitRead
}

func (s *Service) recordAudit(ctx context.Context, r AuditRecord) {
	if err := s.d.Store.Audit(ctx, r); err != nil {
		s.log().Warn("git tokens: audit write failed", "action", r.Action, "error", err.Error())
	}
}

func orgPtr(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func mapNotFound(err error, what string) error {
	if errors.Is(err, domain.ErrNotFound) {
		return errNotFound(what + " not found")
	}
	return err
}

// ---- personal and service tokens -----------------------------------------------------------

// CreatePersonal creates a named personal token. The returned plain value is shown once.
// Every listed project must be reachable by the user with at least the token scope; an empty
// list means "every project the user can reach" (the role is re-evaluated on each use anyway).
func (s *Service) CreatePersonal(ctx context.Context, userID uuid.UUID, in CreateInput) (*Token, string, error) {
	if err := s.validateCreate(&in); err != nil {
		return nil, "", err
	}
	if len(in.ProjectIDs) > 50 {
		return nil, "", errInvalid("at most 50 projects per token")
	}
	seen := map[uuid.UUID]bool{}
	var ids []uuid.UUID
	var firstOrg uuid.UUID
	for _, pid := range in.ProjectIDs {
		if seen[pid] {
			continue
		}
		seen[pid] = true
		ref, err := s.d.Directory.ByID(ctx, pid)
		if err != nil {
			return nil, "", mapNotFound(err, "project")
		}
		ok, err := s.d.Access.Can(ctx, userID, ref.OrgID, ref.ProjectID, actionFor(in.Scope))
		if err != nil {
			return nil, "", err
		}
		if !ok {
			return nil, "", errForbidden("your project role does not allow a " + in.Scope + " token for this project")
		}
		if firstOrg == uuid.Nil {
			firstOrg = ref.OrgID
		}
		ids = append(ids, ref.ProjectID)
	}
	n, err := s.d.Store.CountActive(ctx, userID, KindPersonal, s.now())
	if err != nil {
		return nil, "", err
	}
	if n >= s.cfg.MaxPersonal {
		return nil, "", errLimit("too many active personal tokens; revoke one first")
	}
	tok, plain, err := s.mint(ctx, &Token{
		UserID: userID, Kind: KindPersonal, Name: in.Name, Scope: in.Scope, ProjectIDs: ids,
		CreatedIP: in.IP, ExpiresAt: s.now().Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour),
	})
	if err != nil {
		return nil, "", err
	}
	var org *uuid.UUID
	if len(ids) == 1 {
		org = orgPtr(firstOrg)
	}
	s.recordAudit(ctx, AuditRecord{UserID: userID, OrgID: org, Action: ActionCreate, ResourceType: "git_token", ResourceID: tok.ID, IP: in.IP,
		Meta: map[string]any{"kind": KindPersonal, "scope": in.Scope, "projects": len(ids), "expires_at": tok.ExpiresAt}})
	return tok, plain, nil
}

// CreateService creates a service token for one repo. The actor needs git.admin on it.
func (s *Service) CreateService(ctx context.Context, actorID, orgID, projectID uuid.UUID, in CreateInput) (*Token, string, error) {
	if err := s.validateCreate(&in); err != nil {
		return nil, "", err
	}
	if len(in.ProjectIDs) > 0 && (len(in.ProjectIDs) != 1 || in.ProjectIDs[0] != projectID) {
		return nil, "", errInvalid("a service token is bound to this repo only")
	}
	ref, err := s.requireAdmin(ctx, actorID, orgID, projectID)
	if err != nil {
		return nil, "", err
	}
	list, err := s.d.Store.ListServiceTokens(ctx, projectID, s.now())
	if err != nil {
		return nil, "", err
	}
	active := 0
	for _, t := range list {
		if t.Active(s.now()) {
			active++
		}
	}
	if active >= s.cfg.MaxServicePerRepo {
		return nil, "", errLimit("too many active service tokens for this repo")
	}
	tok, plain, err := s.mint(ctx, &Token{
		UserID: actorID, Kind: KindService, Name: in.Name, Scope: in.Scope, ProjectIDs: []uuid.UUID{projectID},
		CreatedIP: in.IP, ExpiresAt: s.now().Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour),
	})
	if err != nil {
		return nil, "", err
	}
	s.recordAudit(ctx, AuditRecord{UserID: actorID, OrgID: orgPtr(ref.OrgID), Action: ActionCreate, ResourceType: "git_token", ResourceID: tok.ID, IP: in.IP,
		Meta: map[string]any{"kind": KindService, "scope": in.Scope, "project_id": projectID, "expires_at": tok.ExpiresAt}})
	return tok, plain, nil
}

// mint generates the value, stores only the hash and returns the plain value to the caller.
func (s *Service) mint(ctx context.Context, t *Token) (*Token, string, error) {
	plain, hash, err := Generate(s.d.Rand)
	if err != nil {
		return nil, "", err
	}
	t.Hash = hash
	t.Prefix = DisplayPrefix(plain)
	out, err := s.d.Store.CreateToken(ctx, t)
	if err != nil {
		return nil, "", err
	}
	return out, plain, nil
}

// ListUserTokens returns the user's personal tokens and active ephemeral ones (never values).
func (s *Service) ListUserTokens(ctx context.Context, userID uuid.UUID) ([]*Token, error) {
	return s.d.Store.ListUserTokens(ctx, userID, s.now())
}

// ListServiceTokens returns the repo's service tokens. The actor needs git.admin.
func (s *Service) ListServiceTokens(ctx context.Context, actorID, orgID, projectID uuid.UUID) ([]*Token, error) {
	if _, err := s.requireAdmin(ctx, actorID, orgID, projectID); err != nil {
		return nil, err
	}
	return s.d.Store.ListServiceTokens(ctx, projectID, s.now())
}

func (s *Service) requireAdmin(ctx context.Context, actorID, orgID, projectID uuid.UUID) (*ProjectRef, error) {
	ref, err := s.d.Directory.ByID(ctx, projectID)
	if err != nil {
		return nil, mapNotFound(err, "project")
	}
	if ref.OrgID != orgID {
		return nil, errNotFound("project not found")
	}
	ok, err := s.d.Access.Can(ctx, actorID, ref.OrgID, ref.ProjectID, authz.GitAdmin)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errForbidden("git.admin is required to manage service tokens")
	}
	return ref, nil
}

// RevokeOwn revokes one of the user's own personal or ephemeral tokens.
func (s *Service) RevokeOwn(ctx context.Context, userID, tokenID uuid.UUID, ip string) error {
	t, err := s.d.Store.GetToken(ctx, tokenID)
	if err != nil {
		return mapNotFound(err, "token")
	}
	if t.UserID != userID || t.Kind == KindService {
		return errNotFound("token not found")
	}
	return s.revoke(ctx, t, userID, ip, "user")
}

// RevokeService revokes a service token of the repo. The actor needs git.admin.
func (s *Service) RevokeService(ctx context.Context, actorID, orgID, projectID, tokenID uuid.UUID, ip string) error {
	if _, err := s.requireAdmin(ctx, actorID, orgID, projectID); err != nil {
		return err
	}
	t, err := s.d.Store.GetToken(ctx, tokenID)
	if err != nil {
		return mapNotFound(err, "token")
	}
	if t.Kind != KindService || !t.AllowsProject(projectID) {
		return errNotFound("token not found")
	}
	return s.revoke(ctx, t, actorID, ip, "admin")
}

func (s *Service) revoke(ctx context.Context, t *Token, actor uuid.UUID, ip, reason string) error {
	changed, err := s.d.Store.RevokeToken(ctx, t.ID, reason)
	if err != nil {
		return err
	}
	s.vc.dropID(t.ID)
	s.issued.dropToken(t.ID)
	if !changed {
		return errNotFound("token not found")
	}
	var org *uuid.UUID
	if len(t.ProjectIDs) == 1 {
		if ref, err := s.d.Directory.ByID(ctx, t.ProjectIDs[0]); err == nil {
			org = orgPtr(ref.OrgID)
		}
	}
	s.recordAudit(ctx, AuditRecord{UserID: actor, OrgID: org, Action: ActionRevoke, ResourceType: "git_token", ResourceID: t.ID, IP: ip,
		Meta: map[string]any{"kind": t.Kind, "reason": reason}})
	return nil
}

// RevokeSession revokes every active ephemeral token of a CLI session (capsule logout).
func (s *Service) RevokeSession(ctx context.Context, userID uuid.UUID, sessionRef, ip string) (int, error) {
	if sessionRef == "" {
		return 0, errInvalid("session is required")
	}
	ids, err := s.d.Store.RevokeSession(ctx, userID, sessionRef, "session")
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		s.vc.dropID(id)
	}
	s.issued.dropSession(userID, sessionRef)
	if len(ids) > 0 {
		s.recordAudit(ctx, AuditRecord{UserID: userID, Action: ActionRevokeSes, ResourceType: "git_token", ResourceID: ids[0], IP: ip,
			Meta: map[string]any{"revoked": len(ids)}})
	}
	return len(ids), nil
}

// ---- credential helper (ephemeral tokens) --------------------------------------------------

// IssueInput is the body of POST /user/git-credentials plus what the handler derived.
type IssueInput struct {
	Path       string // "org/repo" or "org/repo.git" (git credential with useHttpPath)
	Scope      string // "" = the best the role allows
	SessionRef string // required: CapSessionRef or CLISessionRef
	IP         string
}

// Credential is what the credential helper hands to Git.
type Credential struct {
	Username   string
	Password   string
	ExpiresAt  time.Time
	RenewAfter time.Time
	Scope      string
	ProjectID  uuid.UUID
}

// ParseRepoPath splits "org/repo[.git]" (an optional leading slash is accepted).
func ParseRepoPath(p string) (org, repo string, err error) {
	p = strings.Trim(strings.TrimSpace(p), "/")
	p = strings.TrimSuffix(p, ".git")
	parts := strings.Split(p, "/")
	if len(parts) != 2 || !reSlug.MatchString(parts[0]) || !reSlug.MatchString(parts[1]) {
		return "", "", errInvalid("path must be org/repo")
	}
	return strings.ToLower(parts[0]), strings.ToLower(parts[1]), nil
}

// Issue emits (or reuses) the ephemeral token of this user, repo, scope and CLI session. An
// issued token is reused while more than Config.RenewBefore (10 min) of its life remains; the
// value is kept only in this process's memory for that purpose (the database has just the hash),
// so after a restart or on another instance a fresh token is issued instead.
func (s *Service) Issue(ctx context.Context, userID uuid.UUID, in IssueInput) (*Credential, error) {
	if in.SessionRef == "" {
		return nil, newErr(403, "CLI_SESSION_REQUIRED", "git credentials are only issued to a Capsule CLI session")
	}
	if in.Scope != "" && in.Scope != ScopeRead && in.Scope != ScopeWrite {
		return nil, errInvalid("scope must be read or write")
	}
	orgSlug, repoSlug, err := ParseRepoPath(in.Path)
	if err != nil {
		return nil, err
	}
	ref, err := s.d.Directory.BySlugs(ctx, orgSlug, repoSlug)
	if err != nil {
		return nil, mapNotFound(err, "repository")
	}
	canRead, err := s.d.Access.Can(ctx, userID, ref.OrgID, ref.ProjectID, authz.GitRead)
	if err != nil {
		return nil, err
	}
	if !canRead {
		return nil, errNotFound("repository not found") // hidden projects do not reveal themselves
	}
	scope := in.Scope
	if scope == "" || scope == ScopeWrite {
		canWrite, err := s.d.Access.Can(ctx, userID, ref.OrgID, ref.ProjectID, authz.GitWrite)
		if err != nil {
			return nil, err
		}
		switch {
		case canWrite:
			scope = ScopeWrite
		case in.Scope == ScopeWrite:
			return nil, errForbidden("your project role does not allow write access")
		default:
			scope = ScopeRead
		}
	}
	login, err := s.d.Identity.ForgejoLogin(ctx, userID)
	if err != nil {
		return nil, mapNotFound(err, "git identity")
	}
	key := issuedKey(userID, ref.ProjectID, scope, in.SessionRef)
	now := s.now()
	if e, ok := s.issued.get(key); ok && e.expires.Sub(now) > s.cfg.RenewBefore {
		if t, err := s.d.Store.GetToken(ctx, e.tokenID); err == nil && t.Active(now) {
			return &Credential{Username: login, Password: e.plain, ExpiresAt: e.expires, RenewAfter: e.expires.Add(-s.cfg.RenewBefore), Scope: scope, ProjectID: ref.ProjectID}, nil
		}
		s.issued.drop(key)
	}
	tok, plain, err := s.mint(ctx, &Token{
		UserID: userID, Kind: KindEphemeral, Name: "capsule git credential", Scope: scope, ProjectIDs: []uuid.UUID{ref.ProjectID},
		SessionRef: in.SessionRef, CreatedIP: in.IP, ExpiresAt: now.Add(s.cfg.EphemeralTTL),
	})
	if err != nil {
		return nil, err
	}
	if ids, err := s.d.Store.PruneEphemeral(ctx, userID, s.cfg.MaxActiveEphemeral, now); err == nil {
		for _, id := range ids {
			s.vc.dropID(id)
			s.issued.dropToken(id)
		}
	}
	s.issued.put(key, issuedEntry{plain: plain, tokenID: tok.ID, userID: userID, session: in.SessionRef, expires: tok.ExpiresAt})
	s.recordAudit(ctx, AuditRecord{UserID: userID, OrgID: orgPtr(ref.OrgID), Action: ActionIssue, ResourceType: "git_token", ResourceID: tok.ID, IP: in.IP,
		Meta: map[string]any{"scope": scope, "project_id": ref.ProjectID, "expires_at": tok.ExpiresAt}})
	return &Credential{Username: login, Password: plain, ExpiresAt: tok.ExpiresAt, RenewAfter: tok.ExpiresAt.Add(-s.cfg.RenewBefore), Scope: scope, ProjectID: ref.ProjectID}, nil
}

// ---- issued-token memory (reuse) -----------------------------------------------------------

type issuedEntry struct {
	plain   string
	tokenID uuid.UUID
	userID  uuid.UUID
	session string
	expires time.Time
}

type issuedCache struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]issuedEntry
}

func newIssuedCache(now func() time.Time) *issuedCache {
	return &issuedCache{now: now, m: map[string]issuedEntry{}}
}

func issuedKey(user, project uuid.UUID, scope, session string) string {
	return user.String() + "|" + project.String() + "|" + scope + "|" + session
}

func (c *issuedCache) get(k string) (issuedEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if ok && !c.now().Before(e.expires) {
		delete(c.m, k)
		return issuedEntry{}, false
	}
	return e, ok
}

func (c *issuedCache) put(k string, e issuedEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= 4096 {
		now := c.now()
		for kk, v := range c.m {
			if !now.Before(v.expires) {
				delete(c.m, kk)
			}
		}
		if len(c.m) >= 4096 {
			c.m = map[string]issuedEntry{}
		}
	}
	c.m[k] = e
}

func (c *issuedCache) drop(k string) {
	c.mu.Lock()
	delete(c.m, k)
	c.mu.Unlock()
}

func (c *issuedCache) dropToken(id uuid.UUID) {
	c.mu.Lock()
	for k, v := range c.m {
		if v.tokenID == id {
			delete(c.m, k)
		}
	}
	c.mu.Unlock()
}

func (c *issuedCache) dropSession(user uuid.UUID, session string) {
	c.mu.Lock()
	for k, v := range c.m {
		if v.userID == user && v.session == session {
			delete(c.m, k)
		}
	}
	c.mu.Unlock()
}
