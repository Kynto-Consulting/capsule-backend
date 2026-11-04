package authz_test

// FROZEN ORACLE of the permission behaviour that existed before the atomic permission engine
// (docs/permissions/MIGRATION.md F0 and section 5.1). It is a verbatim copy, taken on 2026-11-03/04, of
// authz.Resolve, of the role matrix (authz.go plus the init() grants of git_actions.go and
// gateway_actions.go) and of the three action lists. It deliberately shares no code with production, so
// the equivalence tests keep working after the legacy code is retired (MIGRATION F5).
//
// Particularities it preserves on purpose (SPEC section 0 and 5.3):
//   - owner and admin are project admin everywhere: an explicit row never lowers them.
//   - readonly never gets more than viewer, even with an explicit "admin" row (the hidden ceiling),
//     and in restricted mode it needs a valid explicit row just to see the project.
//   - member with a valid explicit row: the row REPLACES the inherited deployer (it can go down to viewer).
//   - an unknown explicit role is ignored as if there were no row.
//   - an unknown organization role is a member who must not learn the project exists (Hidden).
//   - project_access_mode: only "restricted" restricts; "" (and anything else) behaves as "open".
//   - env.approve is granted by no role.
//
// Do not "fix" this file. If production behaviour changes on purpose, that is a behaviour change with its
// own procedure (MIGRATION section 7), and the frozen copy stays as the record of what equivalence meant.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
)

// legacyActions are the 23 old actions: AllActions (9) + GitActions (13) + GatewayActions (1).
var legacyActions = []string{
	// AllActions
	"project.read", "project.deploy", "project.env_write", "project.env_reveal", "project.ops",
	"project.databases", "project.network", "project.members", "project.delete",
	// GitActions
	"git.read", "git.write", "git.review", "git.merge", "git.admin",
	"security.read", "security.triage", "security.admin",
	"env.read", "env.request", "env.admin", "env.approve", "webhooks.manage",
	// GatewayActions
	"project.connect",
}

// legacyMatrix is the role -> action grant table.
var legacyMatrix = map[string]map[string]bool{
	"viewer": actionSet("project.read", "git.read", "security.read", "env.read"),
	"deployer": actionSet("project.read", "project.deploy", "project.env_write", "project.ops",
		"git.read", "git.write", "git.review", "git.merge", "security.read", "security.triage",
		"env.read", "env.request", "project.connect"),
	"admin": actionSet("project.read", "project.deploy", "project.env_write", "project.env_reveal", "project.ops",
		"project.databases", "project.network", "project.members", "project.delete",
		"git.read", "git.write", "git.review", "git.merge", "git.admin",
		"security.read", "security.triage", "security.admin",
		"env.read", "env.request", "env.admin", "webhooks.manage", "project.connect"),
}

func actionSet(as ...string) map[string]bool {
	m := make(map[string]bool, len(as))
	for _, a := range as {
		m[a] = true
	}
	return m
}

func legacyValidProjectRole(s string) bool { return s == "admin" || s == "deployer" || s == "viewer" }

// legacyAccess mirrors authz.Access.
type legacyAccess struct {
	Role   string
	Source string // org | explicit | inherited
	Member bool
	Hidden bool
}

// legacyResolve is the frozen copy of authz.Resolve.
func legacyResolve(orgRole, mode, explicit string) legacyAccess {
	if orgRole == "" {
		return legacyAccess{}
	}
	a := legacyAccess{Member: true}
	switch orgRole {
	case "owner", "admin":
		a.Role, a.Source = "admin", "org"
		return a
	case "readonly":
		if mode == "restricted" && !legacyValidProjectRole(explicit) {
			a.Hidden = true
			return a
		}
		a.Role, a.Source = "viewer", "inherited"
		if legacyValidProjectRole(explicit) {
			a.Source = "explicit"
		}
		return a
	case "member":
		if legacyValidProjectRole(explicit) {
			a.Role, a.Source = explicit, "explicit"
			return a
		}
		if mode == "restricted" {
			a.Hidden = true
			return a
		}
		a.Role, a.Source = "deployer", "inherited"
		return a
	}
	a.Hidden = true
	return a
}

// legacyCan is Service.Can: the effective role's grant.
func legacyCan(orgRole, mode, explicit, action string) bool {
	return legacyMatrix[legacyResolve(orgRole, mode, explicit).Role][action]
}

// The dimensions of the exhaustive matrix (MIGRATION 5.1): 6 x 3 x 5 x 23 = 2 070 cases.
var (
	matrixOrgRoles  = []string{"owner", "admin", "member", "readonly", "", "bogus"}
	matrixModes     = []string{"open", "restricted", ""}
	matrixExplicits = []string{"", "viewer", "deployer", "admin", "bogus"}
)

// While the legacy code still exists, the frozen copy must be identical to it. This test is the proof that
// the copy is faithful; it can be deleted when authz.Resolve is retired.
func TestLegacyOracleMatchesLiveCode(t *testing.T) {
	live := append(append(append([]authz.Action{}, authz.AllActions...), authz.GitActions...), authz.GatewayActions...)
	if len(live) != 23 || len(legacyActions) != 23 {
		t.Fatalf("action lists: live %d, frozen %d, want 23", len(live), len(legacyActions))
	}
	for i, a := range live {
		if string(a) != legacyActions[i] {
			t.Fatalf("action %d: live %q, frozen %q", i, a, legacyActions[i])
		}
	}
	cases := 0
	for _, org := range matrixOrgRoles {
		for _, mode := range matrixModes {
			for _, ex := range matrixExplicits {
				l := authz.Resolve(org, mode, ex)
				o := legacyResolve(org, mode, ex)
				if string(l.Role) != o.Role || string(l.Source) != o.Source || l.Member != o.Member || l.Hidden != o.Hidden {
					t.Errorf("Resolve(%q,%q,%q): live %+v, frozen %+v", org, mode, ex, l, o)
				}
				for _, a := range live {
					cases++
					if got, want := authz.RoleAllows(l.Role, a), legacyCan(org, mode, ex, string(a)); got != want {
						t.Errorf("Can(%q,%q,%q,%s): live %v, frozen %v", org, mode, ex, a, got, want)
					}
				}
			}
		}
	}
	if cases != 2070 {
		t.Fatalf("matrix has %d cases, want 2070", cases)
	}
	for _, role := range []authz.Role{authz.RoleViewer, authz.RoleDeployer, authz.RoleAdmin} {
		for _, a := range live {
			if authz.RoleAllows(role, a) != legacyMatrix[string(role)][string(a)] {
				t.Errorf("matrix %s/%s differs", role, a)
			}
		}
	}
}

// Baseline of the current decision cost (MIGRATION F0): pure Resolve plus the matrix lookup, and the full
// Service.Can path with an in-memory store. The engine of P1 is compared against these numbers.
func BenchmarkLegacyResolveCan(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		a := authz.Resolve("member", "open", "viewer")
		if !authz.RoleAllows(a.Role, authz.ProjectRead) {
			b.Fatal("viewer must read")
		}
	}
}

type benchStore struct{ oa *authz.OrgAccess }

func (s benchStore) LoadOrgAccess(context.Context, uuid.UUID, uuid.UUID) (*authz.OrgAccess, error) {
	return s.oa, nil
}
func (benchStore) UserGrants(context.Context, uuid.UUID) ([]authz.Grant, error) { return nil, nil }

func BenchmarkLegacyServiceCan(b *testing.B) {
	org, proj, user := uuid.New(), uuid.New(), uuid.New()
	svc := authz.New(benchStore{&authz.OrgAccess{OrgRole: "member", Mode: "restricted", Explicit: map[uuid.UUID]string{proj: "deployer"}}})
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ok, err := svc.Can(ctx, user, org, proj, authz.ProjectDeploy)
		if err != nil || !ok {
			b.Fatal("deployer must deploy")
		}
	}
}
