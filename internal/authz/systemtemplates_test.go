package authz_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/internal/specdoc"
	"github.com/kynto/capsule/backend/internal/authz/systemtemplates"
)

// ref is the minimal in-memory evaluator of SPEC 5.3 restricted to org -> project scope with system
// templates only. It exists so P0 can prove the DATA (templates, floor, base, ceiling) before the real
// engine (package engine, P1) exists; P1 reuses the same matrix against its own implementation.
type refAccess struct {
	Member, Hidden bool
	Set            catalog.Set
	Source         string
}

func refEffective(orgRole, mode, explicit string, ceilingAtOrg bool) refAccess {
	if orgRole == "" {
		return refAccess{}
	}
	T, ok := systemtemplates.Org(orgRole)
	if !ok {
		return refAccess{Member: true, Hidden: true} // the template does not resolve: closed (SPEC 5.3 rule 4)
	}
	var own catalog.Set
	hasOwn := false
	if e, ok := systemtemplates.Project(explicit); ok {
		own, hasOwn = e.Permissions, true // a project assignment of a system template
	}
	var fallback catalog.Set
	if mode != "restricted" { // "open" and "" both enable the base
		fallback = T.Base
	}
	base := fallback
	if hasOwn {
		base = own // the closest level wins
	}
	set := base.Union(T.Floor)
	if T.HasCeiling {
		if ceilingAtOrg {
			set = set.Intersect(T.Ceiling)
		} else {
			set = set.Intersect(T.CeilingProject)
		}
	}
	a := refAccess{Member: true, Set: set}
	if !set.Has("project:view") {
		return refAccess{Member: true, Hidden: true}
	}
	switch {
	case T.FloorID != uuid.Nil:
		a.Source = "org"
	case hasOwn:
		a.Source = "explicit"
	default:
		a.Source = "inherited"
	}
	return a
}

// legacyRoleOf is LegacyRole(set): the highest system project role whose set the set contains.
func legacyRoleOf(s catalog.Set) string {
	for _, r := range []string{"admin", "deployer", "viewer"} {
		if t, _ := systemtemplates.Project(r); s.ContainsAll(t.Permissions) {
			return r
		}
	}
	return ""
}

func expandUnion(role string) catalog.Set {
	var s catalog.Set
	for _, a := range legacyActions {
		if legacyMatrix[role][a] {
			s = s.Union(catalog.ExpandSet(a))
		}
	}
	return s
}

// Acceptance (2): the exhaustive matrix of MIGRATION 5.1, 2 070 cases, zero differences.
func TestSystemTemplatesMatchLegacyMatrix(t *testing.T) {
	// 1. each old role's template is EXACTLY the union of the expansions of the actions it grants
	//    (not "includes": this detects gifted permissions).
	for _, role := range []string{"viewer", "deployer", "admin"} {
		tpl, ok := systemtemplates.Project(role)
		if !ok {
			t.Fatalf("no project template %q", role)
		}
		want := expandUnion(role)
		if tpl.Permissions != want {
			t.Errorf("project/%s: extra %v, missing %v", role,
				tpl.Permissions.Minus(want).IDs(), want.Minus(tpl.Permissions).IDs())
		}
	}

	// 2. the four organization templates reproduce TestResolveDecisionTable (written out by hand here).
	type key struct{ org, mode, explicit string }
	want := map[key]string{}
	for _, mode := range []string{"open", "restricted"} {
		for _, ex := range []string{"", "admin", "deployer", "viewer"} {
			want[key{"owner", mode, ex}] = "admin"
			want[key{"admin", mode, ex}] = "admin"
		}
	}
	for _, ex := range []string{"admin", "deployer", "viewer"} {
		want[key{"member", "open", ex}] = ex
		want[key{"member", "restricted", ex}] = ex
		want[key{"readonly", "open", ex}] = "viewer"
		want[key{"readonly", "restricted", ex}] = "viewer"
	}
	want[key{"member", "open", ""}] = "deployer"
	want[key{"member", "restricted", ""}] = "-"
	want[key{"readonly", "open", ""}] = "viewer"
	want[key{"readonly", "restricted", ""}] = "-"
	if len(want) != 32 {
		t.Fatalf("decision table has %d rows", len(want))
	}
	for k, w := range want {
		a := refEffective(k.org, k.mode, k.explicit, false)
		if !a.Member {
			t.Errorf("%+v: must be a member", k)
		}
		if w == "-" {
			if !a.Hidden || !a.Set.IsEmpty() {
				t.Errorf("%+v: want hidden, got %+v", k, a)
			}
			continue
		}
		if got := legacyRoleOf(a.Set); got != w || a.Hidden {
			t.Errorf("%+v: want %s, got %q hidden=%v", k, w, got, a.Hidden)
		}
	}

	// 3. the exhaustive matrix: Old.Can(A) == New.CanAll(expand(A)) for 6 x 3 x 5 x 23 = 2 070 cases, and
	//    for each of the 90 combinations Member, Hidden, Source and Role agree.
	cases, diffs, combos := 0, 0, 0
	for _, org := range matrixOrgRoles {
		for _, mode := range matrixModes {
			for _, ex := range matrixExplicits {
				combos++
				o := legacyResolve(org, mode, ex)
				n := refEffective(org, mode, ex, false)
				if o.Member != n.Member || o.Hidden != n.Hidden || o.Source != n.Source || o.Role != legacyRoleOf(n.Set) {
					diffs++
					t.Errorf("access(%q,%q,%q): old %+v, new member=%v hidden=%v source=%q role=%q",
						org, mode, ex, o, n.Member, n.Hidden, n.Source, legacyRoleOf(n.Set))
				}
				// stronger than the role label: the effective set is exactly what the old role granted
				if exact := expandUnion(o.Role); n.Set != exact {
					diffs++
					t.Errorf("set(%q,%q,%q): extra %v, missing %v", org, mode, ex, n.Set.Minus(exact).IDs(), exact.Minus(n.Set).IDs())
				}
				for _, a := range legacyActions {
					cases++
					old := legacyCan(org, mode, ex, a)
					new := n.Set.ContainsAll(catalog.ExpandSet(a))
					if old != new {
						diffs++
						t.Errorf("Can(%q,%q,%q,%s): old %v, new %v", org, mode, ex, a, old, new)
					}
					if a == "env.approve" && new {
						diffs++
						t.Errorf("env.approve granted to a system template (%q,%q,%q)", org, mode, ex)
					}
				}
			}
		}
	}
	t.Logf("matrix: %d cases over %d combinations, %d differences", cases, combos, diffs)
	if cases != 2070 || combos != 90 {
		t.Fatalf("matrix size: %d cases, %d combinations; want 2070 and 90", cases, combos)
	}
	if diffs != 0 {
		t.Fatalf("%d differences", diffs)
	}
}

// D1 (docs/permissions/P0-NOTES.md): database:create and domain:manage belong to every organization
// template (G7) and are also project-admin permissions. If the readonly ceiling of SPEC 4.1 (organization
// permissions + viewer set) were applied unchanged at project scope, a readonly user with an explicit
// project admin row would hold them, while the old code gives viewer. The data therefore carries a
// project-scope ceiling. This test pins both facts.
func TestReadonlyCeilingNeedsProjectScopeVariant(t *testing.T) {
	leaky := refEffective("readonly", "restricted", "admin", true)
	if !leaky.Set.Has("database:create") || !leaky.Set.Has("domain:manage") {
		t.Fatal("expected the organization-scope ceiling to leak database:create and domain:manage at project scope")
	}
	fixed := refEffective("readonly", "restricted", "admin", false)
	viewer, _ := systemtemplates.Project("viewer")
	if fixed.Set != viewer.Permissions {
		t.Fatalf("project-scope ceiling must leave exactly the viewer set, got extra %v", fixed.Set.Minus(viewer.Permissions).IDs())
	}
}

// Acceptance (3): 23 of 23 old actions have an expansion, using the real authz constants.
func TestEveryOldActionExpands(t *testing.T) {
	all := append(append(append([]authz.Action{}, authz.AllActions...), authz.GitActions...), authz.GatewayActions...)
	if len(all) != 23 {
		t.Fatalf("%d old actions, want 23", len(all))
	}
	covered := 0
	for _, a := range all {
		ex := catalog.Expand(a)
		if len(ex) == 0 {
			t.Errorf("%s has no Expand", a)
			continue
		}
		covered++
		for _, id := range ex {
			if !catalog.Has(id) {
				t.Errorf("%s expands to %q, not in the catalog", a, id)
			}
		}
	}
	t.Logf("old actions with Expand: %d of %d", covered, len(all))
	if covered != 23 {
		t.Fatalf("%d of 23", covered)
	}
}

func orgColumnTemplate(t *testing.T, doc *specdoc.Doc, col string) catalog.Set {
	t.Helper()
	var ids []string
	for _, r := range doc.Rows {
		if r.Cols[col] {
			ids = append(ids, r.ID)
		}
	}
	// SPEC 3.1 "Además": the organization-level project permissions every organization template carries.
	ids = append(ids, "database:read", "database:create", "domain:read", "domain:manage")
	return catalog.NewSet(ids...)
}

// The templates equal the columns of SPEC 3.1 / 3.2 and the contents of SPEC 4.2.
func TestSystemTemplatesMatchSpecTables(t *testing.T) {
	doc, err := specdoc.Load()
	if errors.Is(err, specdoc.ErrNotFound) {
		t.Skip("docs/permissions/SPEC.md is not reachable from this checkout")
	}
	if err != nil {
		t.Fatal(err)
	}
	for slug, col := range map[string]string{"owner": "O", "admin": "A", "member": "M", "readonly": "R"} {
		tpl, ok := systemtemplates.Org(slug)
		if !ok {
			t.Fatalf("no org template %s", slug)
		}
		if want := orgColumnTemplate(t, doc, col); tpl.Permissions != want {
			t.Errorf("org/%s: extra %v, missing %v", slug, tpl.Permissions.Minus(want).IDs(), want.Minus(tpl.Permissions).IDs())
		}
	}
	for slug, col := range map[string]string{"viewer": "V", "deployer": "D", "admin": "P"} {
		tpl, ok := systemtemplates.Project(slug)
		if !ok {
			t.Fatalf("no project template %s", slug)
		}
		var ids []string
		for _, r := range doc.Rows {
			if r.Cols[col] {
				ids = append(ids, r.ID)
			}
		}
		if want := catalog.NewSet(ids...); tpl.Permissions != want {
			t.Errorf("project/%s: extra %v, missing %v", slug, tpl.Permissions.Minus(want).IDs(), want.Minus(tpl.Permissions).IDs())
		}
	}

	// SPEC 4.2: project admin = the "*" of project scope except promotion:approve.
	var star []string
	for _, p := range catalog.All() {
		if (p.HasScope(catalog.ScopeProject) || p.HasScope(catalog.ScopeRepo) || p.HasScope(catalog.ScopeEnv)) && p.ID != "promotion:approve" {
			star = append(star, p.ID)
		}
	}
	if admin, _ := systemtemplates.Project("admin"); admin.Permissions != catalog.NewSet(star...) {
		t.Error("project/admin is not every project-scope permission but promotion:approve")
	}
	// no system template grants promotion:approve (it is decided by the environment)
	for _, tpl := range systemtemplates.All() {
		if tpl.Permissions.Has("promotion:approve") {
			t.Errorf("%s/%s grants promotion:approve", tpl.Kind, tpl.Slug)
		}
	}

	// SPEC 4.2 repo templates.
	rr, _ := systemtemplates.Repo("repo-read")
	rw, _ := systemtemplates.Repo("repo-write")
	if rr.Permissions != catalog.NewSet("project:view", "git:read", "ci:read") {
		t.Errorf("repo-read: %v", rr.Permissions.IDs())
	}
	if rw.Permissions != rr.Permissions.Union(catalog.NewSet("git:write", "git:review", "git:merge", "ci:run")) {
		t.Errorf("repo-write: %v", rw.Permissions.IDs())
	}

	// SPEC 4.1 / 4.2: floor, base and ceiling of the organization templates.
	padmin, _ := systemtemplates.Project("admin")
	pdep, _ := systemtemplates.Project("deployer")
	pview, _ := systemtemplates.Project("viewer")
	owner, _ := systemtemplates.Org("owner")
	admin, _ := systemtemplates.Org("admin")
	member, _ := systemtemplates.Org("member")
	ro, _ := systemtemplates.Org("readonly")
	if owner.FloorID != padmin.ID || admin.FloorID != padmin.ID || owner.BaseID != uuid.Nil || admin.BaseID != uuid.Nil || owner.HasCeiling || admin.HasCeiling {
		t.Error("owner/admin: floor must be project admin, no base, no ceiling")
	}
	if member.BaseID != pdep.ID || member.FloorID != uuid.Nil || member.HasCeiling {
		t.Error("member: base must be deployer, no floor, no ceiling")
	}
	if ro.BaseID != pview.ID || ro.FloorID != uuid.Nil || !ro.HasCeiling {
		t.Error("readonly: base must be viewer with a ceiling")
	}
	if want := ro.Permissions.Union(pview.Permissions); ro.Ceiling != want {
		t.Errorf("readonly ceiling must be org(readonly) + viewer set; extra %v missing %v", ro.Ceiling.Minus(want).IDs(), want.Minus(ro.Ceiling).IDs())
	}
	if ro.CeilingProject != pview.Permissions {
		t.Error("readonly ceiling_project must be the viewer set")
	}
	leave := catalog.NewSet("member:leave")
	if !owner.Permissions.ContainsAll(admin.Permissions.Minus(leave)) || !admin.Permissions.ContainsAll(member.Permissions) || !member.Permissions.ContainsAll(ro.Permissions) {
		t.Error("org templates must nest owner >= admin >= member >= readonly (owner cannot leave)")
	}
	if owner.Permissions.Has("member:leave") || !admin.Permissions.Has("member:leave") {
		t.Error("member:leave: admin, member and readonly yes; owner no (SPEC 3.1)")
	}
}

func TestSystemTemplatesFileIntegrity(t *testing.T) {
	tpls := systemtemplates.All()
	if len(tpls) != 9 {
		t.Fatalf("%d templates, want 9 (SPEC 4.2)", len(tpls))
	}
	// deterministic ids: uuid v5 of kind/slug, equal across loads and as documented
	if systemtemplates.Namespace != uuid.NewSHA1(uuid.NameSpaceURL, []byte("urn:capsule:permissions:system-templates")) {
		t.Fatal("namespace changed")
	}
	again, err := systemtemplates.Parse(authz.SystemTemplatesJSON)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[uuid.UUID]bool{}
	for i, tpl := range tpls {
		if again[i].ID != tpl.ID || tpl.ID != systemtemplates.ID(tpl.Kind, tpl.Slug) {
			t.Errorf("%s/%s: id not deterministic", tpl.Kind, tpl.Slug)
		}
		if ids[tpl.ID] {
			t.Errorf("%s/%s: duplicate id", tpl.Kind, tpl.Slug)
		}
		ids[tpl.ID] = true
		if got, ok := systemtemplates.ByID(tpl.ID); !ok || got.Slug != tpl.Slug {
			t.Errorf("ByID %s", tpl.ID)
		}
		for _, id := range tpl.PermissionIDs {
			if strings.ContainsAny(id, "*") {
				t.Errorf("%s/%s: wildcard %q in v1 file", tpl.Kind, tpl.Slug, id)
			}
		}
	}
	// dependencies of every template are satisfied (Parse enforces it); unknown or hostile files are rejected
	bad := map[string]string{
		"unknown perm":    strings.Replace(string(authz.SystemTemplatesJSON), `"project:view"`, `"project:viewx"`, 1),
		"wrong schema":    strings.Replace(string(authz.SystemTemplatesJSON), `"schema_version": 1`, `"schema_version": 2`, 1),
		"wrong namespace": strings.Replace(string(authz.SystemTemplatesJSON), systemtemplates.Namespace.String(), uuid.NewString(), 1),
		"unknown field":   strings.Replace(string(authz.SystemTemplatesJSON), `"templates"`, `"extra": 1, "templates"`, 1),
	}
	for name, doc := range bad {
		if _, err := systemtemplates.Parse([]byte(doc)); err == nil {
			t.Errorf("Parse accepted a file with %s", name)
		}
	}
}
