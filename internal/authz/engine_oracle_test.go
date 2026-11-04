package authz_test

// The engine of P1 against the FROZEN oracle (legacy_oracle_test.go, not modified): the 2 070-case matrix
// of MIGRATION 5.1 and the 90 Access combinations. engine/equivalence_test.go runs the same matrix against
// the live authz.Resolve; this file closes the loop with the frozen copy so the guarantee survives the
// retirement of authz.Resolve (MIGRATION F5).

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
	"github.com/kynto/capsule/backend/internal/authz/systemtemplates"
)

type oneUserStore struct{ d engine.AccessData }

func (s oneUserStore) LoadAccess(context.Context, uuid.UUID, uuid.UUID) (*engine.AccessData, error) {
	d := s.d
	return &d, nil
}
func (oneUserStore) Epochs(context.Context, uuid.UUID, uuid.UUID) (engine.Epochs, error) {
	return engine.Epochs{}, nil
}

func TestEngineMatchesFrozenOracle(t *testing.T) {
	cases, combos := 0, 0
	for _, role := range matrixOrgRoles {
		for _, mode := range matrixModes {
			for _, ex := range matrixExplicits {
				proj := uuid.New()
				d := engine.AccessData{Policy: mode}
				switch role {
				case "":
				case "bogus":
					d.Member, d.UserActive, d.MemberActive = true, true, true
				default:
					tt, ok := systemtemplates.Org(role)
					if !ok {
						t.Fatalf("no system template %s", role)
					}
					d.Member, d.UserActive, d.MemberActive = true, true, true
					d.Template = &engine.OrgTemplate{ID: tt.ID, Slug: tt.Slug, Version: tt.Version, Permissions: tt.Permissions,
						Floor: tt.Floor, Base: tt.Base, HasCeiling: tt.HasCeiling, Ceiling: tt.Ceiling, CeilingProject: tt.CeilingProject}
				}
				if legacyValidProjectRole(ex) {
					pt, _ := systemtemplates.Project(ex)
					d.Assignments = []engine.Assignment{{ID: uuid.New(), SubjectKind: engine.SubjectUser, Scope: engine.ScopeProject,
						ScopeID: proj, ProjectID: proj, TemplateID: pt.ID, Permissions: pt.Permissions}}
				}
				eng := engine.New(oneUserStore{d}, engine.Options{})
				user, org := uuid.New(), uuid.New()
				old := legacyResolve(role, mode, ex)
				acc, set, err := eng.Effective(context.Background(), user, org, engine.ProjectScope(proj))
				if err != nil {
					t.Fatal(err)
				}
				combos++
				if old.Member != acc.Member || old.Hidden != acc.Hidden || old.Source != string(acc.Source) || old.Role != engine.LegacyRole(set) {
					t.Errorf("Access(%q,%q,%q): oracle %+v, engine %+v role %q", role, mode, ex, old, acc, engine.LegacyRole(set))
				}
				if ok, _ := eng.Can(context.Background(), user, org, engine.EnvScope(proj, uuid.New()), "promotion:approve"); ok {
					t.Errorf("(%q,%q,%q): env approve must be false", role, mode, ex)
				}
				for _, a := range legacyActions {
					cases++
					got, err := eng.CanAll(context.Background(), user, org, engine.ProjectScope(proj), catalog.Expand(a)...)
					if err != nil {
						t.Fatal(err)
					}
					if want := legacyCan(role, mode, ex, a); got != want {
						t.Errorf("Can(%q,%q,%q,%s): oracle %v, engine %v", role, mode, ex, a, want, got)
					}
				}
			}
		}
	}
	if cases != 2070 || combos != 90 {
		t.Fatalf("%d cases / %d combinations, want 2070 / 90", cases, combos)
	}
	t.Logf("frozen oracle: %d cases, %d combinations, 0 differences", cases, combos)
}
