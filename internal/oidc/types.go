// Package oidc implements Capsule's OpenID Connect provider (authorization
// code flow with PKCE, refresh token rotation, RS256 JWTs). HTTP wiring lives
// in internal/server/handlers; persistence in internal/repository/oidc_repo.go.
package oidc

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Supported scopes.
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeGroups        = "groups"
	ScopeOfflineAccess = "offline_access"
)

var supportedScopes = []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeGroups, ScopeOfflineAccess}

// Token lifetimes.
const (
	AccessTokenTTL  = time.Hour
	RefreshTokenTTL = 30 * 24 * time.Hour
	CodeTTL         = 60 * time.Second
	RequestTTL      = 10 * time.Minute
)

// Client is a registered OAuth client. An empty SecretHash marks a public
// client, which must use PKCE.
type Client struct {
	ID           uuid.UUID  `json:"id"`
	ClientID     string     `json:"client_id"`
	SecretHash   string     `json:"-"`
	Name         string     `json:"name"`
	RedirectURIs []string   `json:"redirect_uris"`
	OrgID        *uuid.UUID `json:"org_id,omitempty"`
	FirstParty   bool       `json:"first_party"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

func (c *Client) Public() bool { return c.SecretHash == "" }

// AuthRequest is a validated /oauth/authorize call waiting for the user's
// decision in the dashboard.
type AuthRequest struct {
	ID            string
	ClientUUID    uuid.UUID
	RedirectURI   string
	Scope         string
	State         string
	Nonce         string
	CodeChallenge string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// Code is a one-time authorization code. Its ID doubles as the grant id that
// ties together every token issued from it.
type Code struct {
	ID            uuid.UUID
	CodeHash      string
	ClientUUID    uuid.UUID
	UserID        uuid.UUID
	RedirectURI   string
	Scope         string
	Nonce         string
	CodeChallenge string
	AuthTime      time.Time
	ExpiresAt     time.Time
	UsedAt        *time.Time
	RevokedAt     *time.Time
	CreatedAt     time.Time
}

// RefreshToken is the server-side record of an opaque refresh token.
type RefreshToken struct {
	ID         uuid.UUID
	TokenHash  string
	GrantID    uuid.UUID
	ClientUUID uuid.UUID
	UserID     uuid.UUID
	Scope      string
	ExpiresAt  time.Time
	UsedAt     *time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

// OrgRole is one organization membership of a user.
type OrgRole struct {
	OrgID uuid.UUID
	Slug  string
	Role  string
}

// Store is the persistence the provider needs. domain.ErrNotFound is returned
// for missing rows.
type Store interface {
	CreateClient(ctx context.Context, c *Client) error
	GetClientByClientID(ctx context.Context, clientID string) (*Client, error)
	GetClientByUUID(ctx context.Context, id uuid.UUID) (*Client, error)
	// GetClient resolves either the row uuid or the public client_id.
	GetClient(ctx context.Context, ref string) (*Client, error)
	// ListClients returns all clients when all is true, otherwise those owned by orgIDs.
	ListClients(ctx context.Context, all bool, orgIDs []uuid.UUID) ([]*Client, error)
	UpdateRedirectURIs(ctx context.Context, id uuid.UUID, uris []string) error
	// RevokeClient revokes the client plus all its codes and refresh tokens.
	RevokeClient(ctx context.Context, id uuid.UUID) error

	CreateRequest(ctx context.Context, r *AuthRequest) error
	GetRequest(ctx context.Context, id string) (*AuthRequest, error)
	// TakeRequest atomically deletes and returns a non-expired request.
	TakeRequest(ctx context.Context, id string) (*AuthRequest, error)

	CreateCode(ctx context.Context, c *Code) error
	// ConsumeCode marks the code used. ok=false means it was already used or
	// revoked (the existing row is returned); domain.ErrNotFound if unknown.
	ConsumeCode(ctx context.Context, hash string) (code *Code, ok bool, err error)
	RevokeGrant(ctx context.Context, grantID uuid.UUID) error
	GrantActive(ctx context.Context, grantID uuid.UUID) (bool, error)

	CreateRefresh(ctx context.Context, t *RefreshToken) error
	// UseRefresh marks a usable refresh token as used. ok=false means it was
	// already used, revoked or expired (the existing row is returned).
	UseRefresh(ctx context.Context, hash string) (t *RefreshToken, ok bool, err error)

	UserOrgs(ctx context.Context, userID uuid.UUID) ([]OrgRole, error)
	// UsernameTaken reports whether an older user already owns the sanitized
	// local-part base (see SanitizeUsername).
	UsernameTaken(ctx context.Context, userID uuid.UUID, base string) (bool, error)
}

// OAuthError is a standard OAuth 2.0 error response.
type OAuthError struct {
	Code   string `json:"error"`
	Desc   string `json:"error_description,omitempty"`
	Status int    `json:"-"`
	Basic  bool   `json:"-"` // add WWW-Authenticate: Basic (client auth via header failed)
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Desc }

func oerr(status int, code, desc string) *OAuthError {
	return &OAuthError{Code: code, Desc: desc, Status: status}
}
