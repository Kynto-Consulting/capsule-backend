// Package gittokens implements Git Capsule package A7 (SPEC 6.5): cgt_ tokens for Git over HTTPS,
// the server side of the credential helper, the edge validation behind Caddy's forward_auth
// (/internal/git-auth) and SSH keys synchronized with Forgejo.
//
// Security model in one paragraph: a token is 32 random bytes shown once; only its SHA-256 is
// stored. Forgejo never sees it: Caddy asks /internal/git-auth, which validates the token, checks
// the repo and operation against the token scope, re-evaluates the owner's project role (cache
// <= 30 s) and answers with X-WEBAUTH-USER so Forgejo authenticates the request by reverse proxy.
package gittokens

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
)

// Token prefix and kinds.
const (
	Prefix = "cgt_"

	KindEphemeral = "ephemeral" // credential helper, bound to a CLI session
	KindPersonal  = "personal"  // named, created in the dashboard
	KindService   = "service"   // CI / automation, one repo

	ScopeRead  = "read"
	ScopeWrite = "write"
)

// Audit actions (audit_logs.action is varchar(50)).
const (
	ActionIssue     = "git_token.issue"
	ActionCreate    = "git_token.create"
	ActionRevoke    = "git_token.revoke"
	ActionRevokeSes = "git_token.revoke_session"
	ActionFirstUse  = "git_token.first_use"
	ActionDenied    = "git_token.denied"
	ActionKeyAdd    = "git_ssh_key.add"
	ActionKeyDelete = "git_ssh_key.delete"
)

// Token is a git_access_tokens row. The value is never part of it.
type Token struct {
	ID             uuid.UUID
	UserID         uuid.UUID // owner (service tokens: the admin who created it)
	Kind           string
	Name           string
	Hash           string // hex SHA-256 of the full token
	Prefix         string // "cgt_" + 4 chars, for display
	Scope          string
	ProjectIDs     []uuid.UUID // ephemeral/service: exactly one; personal: empty = every project the user can reach
	SessionRef     string      // ephemeral: "cap:<api token id>" or "cli:<cli session id>"
	CreatedIP      string
	ExpiresAt      time.Time
	LastUsedAt     *time.Time
	LastUsedIP     string
	RevokedAt      *time.Time
	RevokedReason  string
	ExpiryWarnedAt *time.Time
	CreatedAt      time.Time
}

// Active reports whether the token can still be used at now.
func (t *Token) Active(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt)
}

// AllowsProject reports whether the token's project list admits id.
func (t *Token) AllowsProject(id uuid.UUID) bool {
	if len(t.ProjectIDs) == 0 {
		return t.Kind == KindPersonal
	}
	for _, p := range t.ProjectIDs {
		if p == id {
			return true
		}
	}
	return false
}

// SSHKey is a git_ssh_keys row.
type SSHKey struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	Title        string
	PublicKey    string
	KeyType      string
	Fingerprint  string
	ForgejoKeyID *int64
	SyncedAt     *time.Time
	SyncError    string
	SyncAttempts int
	NextSyncAt   time.Time
	LastUsedAt   *time.Time
	DeletedAt    *time.Time
	CreatedAt    time.Time
}

// ForgejoSynced reports whether the key is registered in Forgejo.
func (k *SSHKey) ForgejoSynced() bool { return k.ForgejoKeyID != nil && k.SyncedAt != nil }

// AuditRecord is one audit_logs row. OrgID is nil for account-level events (personal tokens
// without a project, SSH keys), which is why this does not reuse authz.AuditEntry (its OrgID is
// not nullable and audit_logs.org_id has a foreign key).
type AuditRecord struct {
	UserID       uuid.UUID
	OrgID        *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   uuid.UUID
	IP           string
	Meta         map[string]any
}

// TokenStore persists git_access_tokens. Not found => domain.ErrNotFound.
type TokenStore interface {
	CreateToken(ctx context.Context, t *Token) (*Token, error)
	GetToken(ctx context.Context, id uuid.UUID) (*Token, error)
	GetTokenByHash(ctx context.Context, hash string) (*Token, error)
	// ListUserTokens returns the user's personal tokens and their non-expired ephemeral ones.
	ListUserTokens(ctx context.Context, userID uuid.UUID, now time.Time) ([]*Token, error)
	ListServiceTokens(ctx context.Context, projectID uuid.UUID, now time.Time) ([]*Token, error)
	// RevokeToken reports whether a row changed.
	RevokeToken(ctx context.Context, id uuid.UUID, reason string) (bool, error)
	// RevokeSession revokes the user's active ephemeral tokens of a session and returns their ids.
	RevokeSession(ctx context.Context, userID uuid.UUID, sessionRef, reason string) ([]uuid.UUID, error)
	// PruneEphemeral revokes the user's oldest active ephemeral tokens beyond keep and returns their ids.
	PruneEphemeral(ctx context.Context, userID uuid.UUID, keep int, now time.Time) ([]uuid.UUID, error)
	CountActive(ctx context.Context, userID uuid.UUID, kind string, now time.Time) (int, error)
	// TouchUsed records the use and reports whether it was the first one.
	TouchUsed(ctx context.Context, id uuid.UUID, ip string) (first bool, err error)
	ListExpiring(ctx context.Context, from, to time.Time, limit int) ([]*Token, error)
	MarkExpiryWarned(ctx context.Context, id uuid.UUID) error
	// PurgeEphemeral deletes ephemeral tokens expired or revoked before cutoff.
	PurgeEphemeral(ctx context.Context, cutoff time.Time) (int64, error)
}

// KeyStore persists git_ssh_keys. Duplicate live fingerprint => domain.ErrConflict.
type KeyStore interface {
	CreateKey(ctx context.Context, k *SSHKey) (*SSHKey, error)
	GetKey(ctx context.Context, id uuid.UUID) (*SSHKey, error)
	ListKeys(ctx context.Context, userID uuid.UUID) ([]*SSHKey, error)
	MarkKeySynced(ctx context.Context, id uuid.UUID, forgejoKeyID int64) error
	MarkKeySyncFailed(ctx context.Context, id uuid.UUID, msg string, next time.Time) error
	// SoftDeleteKey sets deleted_at (the key disappears from lists at once).
	SoftDeleteKey(ctx context.Context, id uuid.UUID, next time.Time) error
	// MarkKeyRemoved clears forgejo_key_id after Forgejo no longer has the key.
	MarkKeyRemoved(ctx context.Context, id uuid.UUID) error
	// ListPendingKeys returns keys to create in Forgejo or to remove from it that are due.
	ListPendingKeys(ctx context.Context, now time.Time, limit int) ([]*SSHKey, error)
}

// Auditor writes audit rows.
type Auditor interface {
	Audit(ctx context.Context, r AuditRecord) error
}

// Store is everything the Service persists.
type Store interface {
	TokenStore
	KeyStore
	Auditor
}

// ProjectRef is a project resolved from slugs or an id (owner = org slug, repo = project slug).
type ProjectRef struct {
	OrgID       uuid.UUID
	ProjectID   uuid.UUID
	OrgSlug     string
	ProjectSlug string
}

// ProjectDirectory resolves repositories. Not found => domain.ErrNotFound.
type ProjectDirectory interface {
	BySlugs(ctx context.Context, orgSlug, projectSlug string) (*ProjectRef, error)
	ByID(ctx context.Context, projectID uuid.UUID) (*ProjectRef, error)
}

// AccessChecker is satisfied by *authz.Service. The role is re-evaluated on every validation.
type AccessChecker interface {
	Can(ctx context.Context, userID, orgID, projectID uuid.UUID, a authz.Action) (bool, error)
}

// IdentityResolver maps a Capsule user to its Forgejo login (the value of X-WEBAUTH-USER).
//
// NOTE (dependency on A2): package A2 (gitsync, table git_identities) builds the authoritative
// Capsule->Forgejo resolver. This interface is the minimal contract A7 needs; NameRules is the
// default implementation, based on the same naming rules as the OIDC provider (the login Forgejo
// stores is the preferred_username claim). The integrator should pass A2's resolver here.
type IdentityResolver interface {
	ForgejoLogin(ctx context.Context, userID uuid.UUID) (string, error)
}

// ServiceIdentityResolver is optional. When set, service tokens authenticate as the returned
// Forgejo login (a bot with permissions on that repo only) instead of as their creator.
type ServiceIdentityResolver interface {
	ServiceLogin(ctx context.Context, ref ProjectRef, scope string) (string, error)
}

// SessionChecker says whether the session an ephemeral token is bound to is still alive.
type SessionChecker interface {
	Alive(ctx context.Context, userID uuid.UUID, sessionRef string) (bool, error)
}

// Notifier receives expiry warnings (7 days before). Optional (A5/C2 provide it).
type Notifier interface {
	TokenExpiring(ctx context.Context, t *Token) error
}

// ---- errors --------------------------------------------------------------------------------

// Error is an error the HTTP layer can answer with directly.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func newErr(status int, code, msg string) *Error {
	return &Error{Status: status, Code: code, Message: msg}
}

// AsError extracts an *Error.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

func errInvalid(msg string) *Error {
	return newErr(http.StatusUnprocessableEntity, "VALIDATION_ERROR", msg)
}
func errForbidden(msg string) *Error { return newErr(http.StatusForbidden, "FORBIDDEN", msg) }
func errNotFound(msg string) *Error  { return newErr(http.StatusNotFound, "NOT_FOUND", msg) }
func errConflict(msg string) *Error  { return newErr(http.StatusConflict, "CONFLICT", msg) }
func errLimit(msg string) *Error     { return newErr(http.StatusUnprocessableEntity, "LIMIT_REACHED", msg) }
