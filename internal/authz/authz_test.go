package authz

import (
	"context"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// Expected role (or hidden) for every org role x mode x explicit role, written out by hand.
// "-" = no access (project hidden); "" explicit = no row.
func TestResolveDecisionTable(t *testing.T) {
	type key struct{ org, mode, explicit string }
	want := map[key]string{}
	for _, mode := range []string{ModeOpen, ModeRestricted} {
		for _, ex := range []string{"", "admin", "deployer", "viewer"} {
			want[key{"owner", mode, ex}] = "admin"
			want[key{"admin", mode, ex}] = "admin"
		}
	}
	// member: explicit wins (even when lower); open default is deployer; restricted without row is hidden.
	for _, ex := range []string{"admin", "deployer", "viewer"} {
		want[key{"member", ModeOpen, ex}] = ex
		want[key{"member", ModeRestricted, ex}] = ex
	}
	want[key{"member", ModeOpen, ""}] = "deployer"
	want[key{"member", ModeRestricted, ""}] = "-"
	// readonly: never more than viewer.
	for _, ex := range []string{"admin", "deployer", "viewer"} {
		want[key{"readonly", ModeOpen, ex}] = "viewer"
		want[key{"readonly", ModeRestricted, ex}] = "viewer"
	}
	want[key{"readonly", ModeOpen, ""}] = "viewer"
	want[key{"readonly", ModeRestricted, ""}] = "-"

	if len(want) != 4*2*4 {
		t.Fatalf("table incomplete: %d", len(want))
	}
	for k, w := range want {
		a := Resolve(k.org, k.mode, k.explicit)
		if !a.Member {
			t.Errorf("%+v: must be a member", k)
		}
		if w == "-" {
			if a.Role != "" || !a.Hidden {
				t.Errorf("%+v: want hidden, got %+v", k, a)
			}
			continue
		}
		if string(a.Role) != w || a.Hidden {
			t.Errorf("%+v: want %s, got %+v", k, w, a)
		}
	}
	// non-member and unknown org role
	if a := Resolve("", ModeOpen, "admin"); a.Member || a.Role != "" || a.Hidden {
		t.Errorf("non-member: %+v", a)
	}
	if a := Resolve("weird", ModeOpen, "admin"); a.Role != "" || !a.Hidden {
		t.Errorf("unknown org role must fail closed: %+v", a)
	}
	// an invalid explicit role is ignored, never trusted
	if a := Resolve("member", ModeOpen, "root"); a.Role != RoleDeployer {
		t.Errorf("invalid explicit role: %+v", a)
	}
}

func TestMatrix(t *testing.T) {
	want := map[Role][]Action{
		RoleViewer:   {ProjectRead},
		RoleDeployer: {ProjectRead, ProjectDeploy, ProjectEnvWrite, ProjectOps},
		RoleAdmin:    AllActions,
	}
	for role, allowed := range want {
		set := map[Action]bool{}
		for _, a := range allowed {
			set[a] = true
		}
		for _, a := range AllActions {
			if RoleAllows(role, a) != set[a] {
				t.Errorf("%s/%s: got %v want %v", role, a, RoleAllows(role, a), set[a])
			}
		}
	}
	for _, a := range AllActions {
		if RoleAllows("", a) || RoleAllows("owner", a) {
			t.Errorf("empty/unknown role must allow nothing (%s)", a)
		}
	}
	if len(AllActions) != 9 {
		t.Fatal("AllActions out of sync")
	}
}

type fakeStore struct {
	access map[uuid.UUID]*OrgAccess // by org
	grants []Grant
}

func (f *fakeStore) LoadOrgAccess(_ context.Context, orgID, _ uuid.UUID) (*OrgAccess, error) {
	return f.access[orgID], nil
}
func (f *fakeStore) UserGrants(context.Context, uuid.UUID) ([]Grant, error) { return f.grants, nil }

func TestServiceCanEveryCombination(t *testing.T) {
	ctx := context.Background()
	org, proj, user := uuid.New(), uuid.New(), uuid.New()
	for _, orgRole := range []string{"owner", "admin", "member", "readonly"} {
		for _, mode := range []string{ModeOpen, ModeRestricted} {
			for _, ex := range []string{"", "admin", "deployer", "viewer"} {
				oa := &OrgAccess{OrgRole: orgRole, Mode: mode, Explicit: map[uuid.UUID]string{}}
				if ex != "" {
					oa.Explicit[proj] = ex
				}
				svc := New(&fakeStore{access: map[uuid.UUID]*OrgAccess{org: oa}})
				exp := Resolve(orgRole, mode, ex)
				for _, a := range AllActions {
					got, err := svc.Can(ctx, user, org, proj, a)
					if err != nil || got != RoleAllows(exp.Role, a) {
						t.Errorf("%s/%s/%q/%s: got %v err %v", orgRole, mode, ex, a, got, err)
					}
				}
				role, _ := svc.EffectiveRole(ctx, user, org, proj)
				if role != exp.Role {
					t.Errorf("EffectiveRole %s/%s/%q = %q want %q", orgRole, mode, ex, role, exp.Role)
				}
			}
		}
	}
	// not a member of the org at all
	svc := New(&fakeStore{access: map[uuid.UUID]*OrgAccess{}})
	if ok, _ := svc.Can(ctx, user, org, proj, ProjectRead); ok {
		t.Error("non-member can read")
	}
	// an explicit role in ANOTHER org's project never leaks across orgs
	other := uuid.New()
	svc = New(&fakeStore{access: map[uuid.UUID]*OrgAccess{other: {OrgRole: "member", Mode: ModeRestricted, Explicit: map[uuid.UUID]string{proj: "admin"}}}})
	if ok, _ := svc.Can(ctx, user, org, proj, ProjectRead); ok {
		t.Error("cross-org leak")
	}
}

func TestFilterProjectsAndVisibility(t *testing.T) {
	ctx := context.Background()
	org, user := uuid.New(), uuid.New()
	a, b, c := &domain.Project{ID: uuid.New()}, &domain.Project{ID: uuid.New()}, &domain.Project{ID: uuid.New()}
	all := []*domain.Project{a, b, c}

	restricted := New(&fakeStore{access: map[uuid.UUID]*OrgAccess{org: {OrgRole: "member", Mode: ModeRestricted, Explicit: map[uuid.UUID]string{b.ID: "viewer"}}}})
	got, err := restricted.FilterProjects(ctx, user, org, all)
	if err != nil || len(got) != 1 || got[0] != b {
		t.Fatalf("restricted member: %v %v", got, err)
	}
	vis, _ := restricted.Visibility(ctx, user, org)
	if vis(a.ID) || !vis(b.ID) {
		t.Error("visibility mismatch")
	}

	open := New(&fakeStore{access: map[uuid.UUID]*OrgAccess{org: {OrgRole: "member", Mode: ModeOpen}}})
	if got, _ := open.FilterProjects(ctx, user, org, all); len(got) != 3 {
		t.Fatalf("open member sees all, got %d", len(got))
	}
	owner := New(&fakeStore{access: map[uuid.UUID]*OrgAccess{org: {OrgRole: "owner", Mode: ModeRestricted}}})
	if got, _ := owner.FilterProjects(ctx, user, org, all); len(got) != 3 {
		t.Fatalf("owner sees all, got %d", len(got))
	}
	stranger := New(&fakeStore{})
	if got, _ := stranger.FilterProjects(ctx, user, org, all); len(got) != 0 {
		t.Fatalf("stranger sees %d", len(got))
	}
}

func TestProjectGroupsExactFormat(t *testing.T) {
	user := uuid.New()
	svc := New(&fakeStore{grants: []Grant{
		{OrgSlug: "acme", ProjectSlug: "web", OrgRole: "owner", Mode: ModeRestricted},
		{OrgSlug: "acme", ProjectSlug: "api", OrgRole: "member", Mode: ModeOpen},
		{OrgSlug: "acme", ProjectSlug: "secret", OrgRole: "member", Mode: ModeRestricted},
		{OrgSlug: "acme", ProjectSlug: "ro", OrgRole: "readonly", Mode: ModeOpen, ExplicitRole: "admin"},
		{OrgSlug: "evvg", ProjectSlug: "vega", OrgRole: "member", Mode: ModeRestricted, ExplicitRole: "viewer"},
	}})
	got, err := svc.ProjectGroups(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"project:acme/api:deployer",
		"project:acme/ro:viewer",
		"project:acme/web:admin",
		"project:evvg/vega:viewer",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	// empty must be a non-nil empty slice (serializes as [] in the OIDC claim)
	none, _ := New(&fakeStore{}).ProjectGroups(context.Background(), user)
	if none == nil || len(none) != 0 {
		t.Fatalf("want empty non-nil, got %#v", none)
	}
}

// A deploy-scoped token stays bound by the middleware route allowlist AND by the
// owner's project role: both must allow.
func TestDeployTokenLimitedByMiddlewareAndRole(t *testing.T) {
	proj := uuid.New()
	tok := &domain.APIToken{Scopes: middleware.ScopeDeploy, ProjectID: &proj}
	base := "/api/v1/orgs/" + uuid.NewString() + "/projects/" + proj.String()

	if middleware.TokenAllows(tok, "POST", base+"/deployments") != true {
		t.Fatal("deploy token must be able to deploy")
	}
	if middleware.TokenAllows(tok, "PUT", base+"/env") || middleware.TokenAllows(tok, "DELETE", base) || middleware.TokenAllows(tok, "GET", base+"/members") {
		t.Fatal("deploy token escaped its scope")
	}
	// Even for a token-allowed route, a viewer owner cannot deploy.
	if RoleAllows(RoleViewer, ProjectDeploy) || !RoleAllows(RoleDeployer, ProjectDeploy) {
		t.Fatal("role matrix must gate deploy")
	}
}
