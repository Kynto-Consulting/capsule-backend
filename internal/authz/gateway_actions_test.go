package authz

import "testing"

func TestProjectConnectMatrix(t *testing.T) {
	cases := []struct {
		role Role
		want bool
	}{{RoleViewer, false}, {RoleDeployer, true}, {RoleAdmin, true}, {Role(""), false}}
	for _, c := range cases {
		if got := RoleAllows(c.role, ProjectConnect); got != c.want {
			t.Errorf("role %q: ProjectConnect = %v, want %v", c.role, got, c.want)
		}
	}
	// Same people as the SQL explorer (ProjectOps) and strictly a subset of what ProjectNetwork grants plus deployers.
	for _, r := range []Role{RoleViewer, RoleDeployer, RoleAdmin} {
		if RoleAllows(r, ProjectConnect) != RoleAllows(r, ProjectOps) {
			t.Errorf("role %q: connect must match the database explorer permission", r)
		}
	}
}

func TestProjectConnectResolvedFromOrgRoles(t *testing.T) {
	// org member in open mode is a deployer; a viewer-only explicit role in restricted mode cannot connect.
	if !RoleAllows(Resolve("member", ModeOpen, "").Role, ProjectConnect) {
		t.Fatal("open-mode org member (deployer) must connect")
	}
	if RoleAllows(Resolve("readonly", ModeOpen, "").Role, ProjectConnect) {
		t.Fatal("readonly org member must not connect")
	}
	if RoleAllows(Resolve("member", ModeRestricted, "viewer").Role, ProjectConnect) {
		t.Fatal("explicit viewer must not connect")
	}
	if !RoleAllows(Resolve("owner", ModeRestricted, "").Role, ProjectConnect) {
		t.Fatal("org owner must connect")
	}
}
