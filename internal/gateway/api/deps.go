package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gateway/store"
	"github.com/kynto/capsule/backend/internal/gitaudit"
)

// The interfaces below are the narrow slices of the existing repositories this package needs; the production
// implementations are the repositories themselves (see cmd/server/gateway_wiring.go) and the tests use fakes.

// ProjectReader loads projects. domain.ErrNotFound when missing.
type ProjectReader interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Project, error)
}

// OrgReader is the slice of domain.OrganizationRepository used for the organisation policy.
type OrgReader interface {
	GetMemberRole(ctx context.Context, orgID, userID uuid.UUID) (string, error)
}

// UserReader loads users (a deleted or missing user loses access immediately).
type UserReader interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

// Authorizer is satisfied by *authz.Service.
type Authorizer interface {
	Access(ctx context.Context, userID, orgID, projectID uuid.UUID) (authz.Access, error)
}

// APITokens is the slice of domain.APITokenRepository used to validate cap_ tokens.
type APITokens interface {
	GetByHash(ctx context.Context, hash string) (*domain.APIToken, error)
}

// Auditor writes audit rows (satisfied by *repository.AuditRepository). Never receives secrets.
type Auditor interface {
	Append(ctx context.Context, e gitaudit.Entry) error
}

// IPLists returns the IP list that governs a service: THE SAME rules netaccess applies on the firewall
// (database access rules, project port rules) or, for a service with no firewall-managed port, the project
// allowlist. restricted=false means "no list": every address is allowed. restricted=true with an empty list denies all.
type IPLists interface {
	AllowedCIDRs(ctx context.Context, svc *store.Service) (cidrs []string, restricted bool, err error)
}

// Sources lists the existing published ports and databases of a project, which the gateway services mirror.
type Sources interface {
	Ports(ctx context.Context, projectID uuid.UUID) ([]*domain.ProjectPort, error)
	Databases(ctx context.Context, projectID uuid.UUID) ([]*domain.Database, error)
}

// ServiceTokenStore persists cgs_ tokens. Only the SHA-256 hex of the token is stored.
type ServiceTokenStore interface {
	Create(ctx context.Context, t *ServiceToken) error
	GetByHash(ctx context.Context, hash string) (*ServiceToken, error)
	List(ctx context.Context, projectID uuid.UUID) ([]*ServiceToken, error)
	CountActive(ctx context.Context, projectID uuid.UUID, now time.Time) (int, error)
	Revoke(ctx context.Context, projectID, id uuid.UUID) (bool, error)
	TouchUsed(ctx context.Context, id uuid.UUID) error
}

// ServiceToken is a cgs_ token row (the value is never part of it).
type ServiceToken struct {
	ID         uuid.UUID  `json:"id"`
	OrgID      uuid.UUID  `json:"org_id"`
	ProjectID  uuid.UUID  `json:"project_id"`
	ServiceID  *uuid.UUID `json:"service_id,omitempty"`
	Name       string     `json:"name"`
	Hash       string     `json:"-"`
	Prefix     string     `json:"prefix"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// Active reports whether the token can be used at now.
func (t *ServiceToken) Active(now time.Time) bool {
	return t.RevokedAt == nil && now.Before(t.ExpiresAt)
}

// Deps are the collaborators of the Service. Store, Projects, Authz, Tokens, Users, IPLists and Sources are required.
type Deps struct {
	Store     store.RouteStore
	Projects  ProjectReader
	Orgs      OrgReader
	Users     UserReader
	Authz     Authorizer
	APITokens APITokens
	SvcTokens ServiceTokenStore // nil: cgs_ tokens are neither issued nor accepted
	IPLists   IPLists
	Sources   Sources
	Audit     Auditor // nil: audit rows are skipped (the structured log still records the verdict)
	Logger    *slog.Logger
	Config    Config

	// Test seams.
	Now func() time.Time
}
