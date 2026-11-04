package wire

import (
	"context"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// Effective is the part of engine.Engine the token decision needs.
type Effective interface {
	EffectiveStrict(ctx context.Context, user, org uuid.UUID, sc engine.Scope) (engine.Access, engine.Set, error)
}

// DecideToken is the full rule of SPEC 9.1: allowed when every perm is in Effective(user, scope) ∩ token.permissions and the
// resource scope of the token matches. Token decisions use the strict path (epoch comparison). project may be uuid.Nil
// (organization scope). A session (ti.Restricted=false) is decided by the user side only.
func DecideToken(ctx context.Context, eff Effective, ti middleware.TokenInfo, user, org, project uuid.UUID, perms ...string) (bool, error) {
	sc := engine.OrgScope()
	if project != uuid.Nil {
		sc = engine.ProjectScope(project)
	}
	acc, set, err := eff.EffectiveStrict(ctx, user, org, sc)
	if err != nil || !acc.Member || acc.Hidden {
		return false, err
	}
	want, unknown := catalog.ParseSet(perms)
	if len(unknown) > 0 || len(perms) == 0 || !set.ContainsAll(want) {
		return false, nil
	}
	if ti.Restricted {
		if !ti.Set.ContainsAll(want) {
			return false, nil
		}
		if ti.OrgID != nil && *ti.OrgID != org {
			return false, nil
		}
		if ti.ProjectID != nil && *ti.ProjectID != project {
			return false, nil
		}
	}
	return true, nil
}
