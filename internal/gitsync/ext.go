package gitsync

import (
	"context"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// WithExt wraps a Forge so that the optional TeamPatcher and UserResolver are backed by the
// gitcore additions (gitcore.TeamAdmin.PatchTeam and gitcore.UserDirectory.GetUser) when the
// underlying core has them. The shared *gitcore.Service has both.
func WithExt(f Forge) Forge { return forgeExt{Forge: f} }

type forgeExt struct{ Forge }

var (
	_ TeamPatcher  = forgeExt{}
	_ UserResolver = forgeExt{}
)

// PatchTeam sets the team's permission and units to the spec: a "-admin" team created by an older
// wave with permission admin goes back to write (settings stay out of reach of Forgejo teams).
func (f forgeExt) PatchTeam(ctx context.Context, _ string, teamID int64, spec gitcore.TeamSpec) error {
	ta, ok := f.Forge.(gitcore.TeamAdmin)
	if !ok {
		return nil
	}
	_, err := ta.PatchTeam(ctx, teamID, gitcore.TeamPatch{Permission: spec.Permission, Units: spec.Units})
	return err
}

// ForgejoUserID returns the numeric Forgejo id of login (false when the account does not exist).
func (f forgeExt) ForgejoUserID(ctx context.Context, login string) (int64, bool, error) {
	ud, ok := f.Forge.(gitcore.UserDirectory)
	if !ok {
		return 0, false, nil
	}
	u, err := ud.GetUser(ctx, login)
	if err != nil {
		if isNotFound(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return u.ID, u.ID > 0, nil
}

func isNotFound(err error) bool {
	e, ok := gitcore.AsError(err)
	return ok && e.Code == gitcore.CodeNotFound
}
