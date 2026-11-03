package gittokens

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/oidc"
)

// UsernameTaker is what oidc.Store implements: whether an older user already owns the base name.
type UsernameTaker interface {
	UsernameTaken(ctx context.Context, userID uuid.UUID, base string) (bool, error)
}

// NameRules is the default IdentityResolver: the Forgejo login is the OIDC preferred_username
// (oidc.SanitizeUsername of the email; "-<6 hex of the user id>" when an older user took the
// name), exactly as the OIDC provider computes it for the Forgejo login.
type NameRules struct {
	Users domain.UserRepository
	Taken UsernameTaker
}

// ForgejoLogin implements IdentityResolver.
func (n NameRules) ForgejoLogin(ctx context.Context, userID uuid.UUID) (string, error) {
	u, err := n.Users.GetByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if u == nil || u.DeletedAt != nil {
		return "", domain.ErrNotFound
	}
	base := oidc.SanitizeUsername(u.Email)
	if n.Taken == nil {
		return base, nil
	}
	taken, err := n.Taken.UsernameTaken(ctx, userID, base)
	if err != nil {
		return "", err
	}
	if taken {
		return base + "-" + hex.EncodeToString(userID[:3]), nil
	}
	return base, nil
}

// DomainDirectory resolves projects with the existing repositories.
type DomainDirectory struct {
	Orgs     domain.OrganizationRepository
	Projects domain.ProjectRepository
}

// BySlugs implements ProjectDirectory.
func (d DomainDirectory) BySlugs(ctx context.Context, orgSlug, projectSlug string) (*ProjectRef, error) {
	o, err := d.Orgs.GetBySlug(ctx, orgSlug)
	if err != nil {
		return nil, err
	}
	p, err := d.Projects.GetBySlug(ctx, o.ID, projectSlug)
	if err != nil {
		return nil, err
	}
	return &ProjectRef{OrgID: o.ID, ProjectID: p.ID, OrgSlug: o.Slug, ProjectSlug: p.Slug}, nil
}

// ByID implements ProjectDirectory.
func (d DomainDirectory) ByID(ctx context.Context, projectID uuid.UUID) (*ProjectRef, error) {
	p, err := d.Projects.GetByID(ctx, projectID)
	if err != nil {
		return nil, err
	}
	o, err := d.Orgs.GetByID(ctx, p.OrgID)
	if err != nil {
		return nil, err
	}
	return &ProjectRef{OrgID: o.ID, ProjectID: p.ID, OrgSlug: o.Slug, ProjectSlug: p.Slug}, nil
}

// APITokenSessions implements SessionChecker for sessions backed by a cap_ API token
// ("cap:<token id>"): the session lives while that token is neither revoked nor expired.
// "cli:<id>" sessions (JWT logins) have no server-side record: they are bounded by the ephemeral
// token lifetime and revoked explicitly on logout (Service.RevokeSession).
type APITokenSessions struct {
	Tokens domain.APITokenRepository
	Now    func() time.Time
}

const (
	sessionCapPrefix = "cap:"
	sessionCLIPrefix = "cli:"
)

// CapSessionRef is the session reference for a cap_ API token.
func CapSessionRef(apiTokenID uuid.UUID) string { return sessionCapPrefix + apiTokenID.String() }

// CLISessionRef is the session reference for a client-chosen CLI session id.
func CLISessionRef(id string) string { return sessionCLIPrefix + id }

// Alive implements SessionChecker.
func (a APITokenSessions) Alive(ctx context.Context, userID uuid.UUID, ref string) (bool, error) {
	if len(ref) <= len(sessionCapPrefix) || ref[:len(sessionCapPrefix)] != sessionCapPrefix {
		return true, nil
	}
	id, err := uuid.Parse(ref[len(sessionCapPrefix):])
	if err != nil {
		return false, nil
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	list, err := a.Tokens.ListByUser(ctx, userID) // returns only non-revoked tokens
	if err != nil {
		return false, err
	}
	for _, t := range list {
		if t.ID == id {
			return t.RevokedAt == nil && (t.ExpiresAt == nil || now().Before(*t.ExpiresAt)), nil
		}
	}
	return false, nil
}

var errNoIdentity = errors.New("gittokens: no forgejo identity for user")
