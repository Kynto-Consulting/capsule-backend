// Package legacyv2 is imported (blank) by test packages only: when CAPSULE_AUTHZ_MODE is v2 or shadow, every authz.New(store) in
// their tests gets the new engine over that same legacy store, so the old suites run unchanged with the new engine deciding
// (docs/permissions/MIGRATION.md 5.2). Production binaries never import it.
package legacyv2

import (
	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/authz/v2adapter"
)

func init() { authz.RegisterLegacyFactory(v2adapter.NewLegacyV2) }
