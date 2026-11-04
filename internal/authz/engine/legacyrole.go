package engine

import (
	"sync"

	"github.com/kynto/capsule/backend/internal/authz/systemtemplates"
)

// Legacy project role names (the labels of today's project_members.role and of the compatibility API).
const (
	LegacyAdmin    = "admin"
	LegacyDeployer = "deployer"
	LegacyViewer   = "viewer"
)

var (
	legacyOnce                        sync.Once
	legacyAdminSet, legacyDeployerSet Set
)

func loadLegacy() {
	legacyOnce.Do(func() {
		a, ok1 := systemtemplates.Project("admin")
		d, ok2 := systemtemplates.Project("deployer")
		if !ok1 || !ok2 {
			panic("engine: system project templates missing")
		}
		legacyAdminSet, legacyDeployerSet = a.Permissions, d.Permissions
	})
}

// LegacyRole translates a project-level permission set into the old role label, for the compatibility
// surfaces (members API, Forgejo and OIDC projections, SPEC 10.2): "admin" when the set contains every
// permission of the system admin template, else "deployer" when it contains the deployer template, else
// "viewer" when the project is visible (project:view), else "" (no access). Labels never overstate: a
// custom set that is only partly a role gets the lower role.
func LegacyRole(s Set) string {
	loadLegacy()
	switch {
	case s.ContainsAll(legacyAdminSet):
		return LegacyAdmin
	case s.ContainsAll(legacyDeployerSet):
		return LegacyDeployer
	case s.HasBit(bitView):
		return LegacyViewer
	}
	return ""
}
