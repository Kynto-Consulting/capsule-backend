package environments

// Runs this package's tests with the new permission engine deciding when CAPSULE_AUTHZ_MODE=v2 (or shadow): authz.New(store) then wires
// the engine over the same legacy store (docs/permissions/MIGRATION.md 5.2). With the default mode (v1) it changes nothing.
import _ "github.com/kynto/capsule/backend/internal/authz/wire/legacyv2"
