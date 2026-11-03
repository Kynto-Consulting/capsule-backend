package gitsync

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/oidc"
)

var (
	// ErrNoIdentity: the user has no git_identities row.
	ErrNoIdentity = errors.New("gitsync: no identity for user")
	// ErrUsernameTaken: another user already owns that Forgejo login.
	ErrUsernameTaken = errors.New("gitsync: forgejo username already taken by another user")
)

// UsernameTaken reports whether base is the OIDC preferred_username already used by a user
// other than userID (satisfied by *repository.OIDCRepository).
type UsernameTaken func(ctx context.Context, userID uuid.UUID, base string) (bool, error)

// Identities resolves and records the Forgejo login of Capsule users.
type Identities struct {
	Store IdentityStore
	Taken UsernameTaken // nil = never taken (tests)

	mu   sync.Mutex
	seen map[uuid.UUID]string
}

// DeriveLogin is the Forgejo login the OIDC provider hands out as preferred_username for the
// user: the sanitized e-mail, with the id suffix when the base is taken (same rule as
// oidc.Service.username).
func (i *Identities) DeriveLogin(ctx context.Context, userID uuid.UUID, email string) (string, error) {
	base := oidc.SanitizeUsername(email)
	if i.Taken != nil {
		taken, err := i.Taken(ctx, userID, base)
		if err != nil {
			return "", err
		}
		if taken {
			return base + "-" + hex.EncodeToString(userID[:3]), nil
		}
	}
	return base, nil
}

// Resolve returns the lowercase Forgejo login of the user: the stored identity if there is
// one, otherwise the derived login, which is recorded. The stored login wins so a later
// change of the e-mail never silently re-points an account.
func (i *Identities) Resolve(ctx context.Context, userID uuid.UUID, email string) (*Identity, error) {
	got, err := i.Store.Get(ctx, userID)
	if err == nil {
		return got, nil
	}
	if !errors.Is(err, ErrNoIdentity) {
		return nil, err
	}
	login, err := i.DeriveLogin(ctx, userID, email)
	if err != nil {
		return nil, err
	}
	return i.Store.Ensure(ctx, userID, strings.ToLower(login))
}

// OnLogin records the identity at the first OIDC login (cheap on later logins: it remembers
// the users it already stored in this process). Errors are returned for the caller to log.
func (i *Identities) OnLogin(ctx context.Context, userID uuid.UUID, email string) error {
	i.mu.Lock()
	if i.seen == nil {
		i.seen = map[uuid.UUID]string{}
	}
	_, done := i.seen[userID]
	i.mu.Unlock()
	if done {
		return nil
	}
	id, err := i.Resolve(ctx, userID, email)
	if err != nil {
		return err
	}
	i.mu.Lock()
	i.seen[userID] = id.ForgejoUsername
	i.mu.Unlock()
	return nil
}
