package gittokens

import (
	"context"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitsync"
)

// GitsyncIdentity is the production IdentityResolver: the Forgejo login is the one A2 registers
// in git_identities (gitsync.Identities.Resolve), so the login the internal git-auth endpoint
// hands to Forgejo (X-WEBAUTH-USER) is exactly the account A2 puts in the project teams.
// IDs is read lazily (A2 publishes it after wiring). Without it (git sync off) it falls back to
// Fallback (NameRules).
type GitsyncIdentity struct {
	IDs      func() *gitsync.Identities
	Users    domain.UserRepository
	Fallback IdentityResolver
}

// ForgejoLogin implements IdentityResolver.
func (g GitsyncIdentity) ForgejoLogin(ctx context.Context, userID uuid.UUID) (string, error) {
	var ids *gitsync.Identities
	if g.IDs != nil {
		ids = g.IDs()
	}
	if ids == nil {
		if g.Fallback == nil {
			return "", domain.ErrNotFound
		}
		return g.Fallback.ForgejoLogin(ctx, userID)
	}
	u, err := g.Users.GetByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if u == nil || u.DeletedAt != nil {
		return "", domain.ErrNotFound
	}
	id, err := ids.Resolve(ctx, userID, u.Email)
	if err != nil {
		return "", err
	}
	return id.ForgejoUsername, nil
}
