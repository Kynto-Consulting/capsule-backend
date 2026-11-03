package authz

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// wantGit is the intended matrix, written out independently of git_actions.go.
var wantGit = map[Role]map[Action]bool{
	RoleViewer: {GitRead: true, SecurityRead: true, EnvRead: true},
	RoleDeployer: {
		GitRead: true, GitWrite: true, GitReview: true, GitMerge: true,
		SecurityRead: true, SecurityTriage: true, EnvRead: true, EnvRequest: true,
	},
	RoleAdmin: {
		GitRead: true, GitWrite: true, GitReview: true, GitMerge: true, GitAdmin: true,
		SecurityRead: true, SecurityTriage: true, SecurityAdmin: true,
		EnvRead: true, EnvRequest: true, EnvAdmin: true, WebhooksManage: true,
	},
}

func TestGitActionMatrix(t *testing.T) {
	if len(GitActions) != 13 {
		t.Fatalf("GitActions has %d entries, want 13", len(GitActions))
	}
	for _, role := range []Role{RoleViewer, RoleDeployer, RoleAdmin, ""} {
		for _, a := range GitActions {
			if got, want := RoleAllows(role, a), wantGit[role][a]; got != want {
				t.Errorf("RoleAllows(%q, %s) = %v, want %v", role, a, got, want)
			}
		}
	}
	// env.approve is never granted by a role: the environment's approver list decides.
	for _, role := range []Role{RoleViewer, RoleDeployer, RoleAdmin} {
		if RoleAllows(role, EnvApprove) {
			t.Errorf("role %s must not grant env.approve", role)
		}
	}
	// A viewer never writes.
	for _, a := range []Action{GitWrite, GitReview, GitMerge, GitAdmin, SecurityTriage, SecurityAdmin, EnvRequest, EnvAdmin, WebhooksManage} {
		if RoleAllows(RoleViewer, a) {
			t.Errorf("viewer must not have %s", a)
		}
	}
}

func TestGitActionsDoNotLeakIntoProjectActions(t *testing.T) {
	for _, a := range AllActions {
		if IsGitAction(a) {
			t.Errorf("%s listed in both AllActions and GitActions", a)
		}
	}
	// the Git actions grant nothing on project.* and vice versa
	for _, role := range []Role{RoleViewer, RoleDeployer, RoleAdmin} {
		if len(GitActionsFor(role)) == 0 {
			t.Errorf("role %s has no git actions", role)
		}
	}
	if IsGitAction(ProjectRead) || !IsGitAction(GitMerge) {
		t.Fatal("IsGitAction wrong")
	}
}

// Exhaustive: org role x access mode x explicit project role x action.
func TestGitDecisionTable(t *testing.T) {
	orgRoles := []string{"", "owner", "admin", "member", "readonly", "bogus"}
	modes := []string{ModeOpen, ModeRestricted}
	explicits := []string{"", "viewer", "deployer", "admin", "junk"}

	// expected effective role, derived by hand from the rules in SPEC §2.1 and the owner decisions.
	eff := func(org, mode, explicit string) Role {
		valid := explicit == "viewer" || explicit == "deployer" || explicit == "admin"
		switch org {
		case "owner", "admin":
			return RoleAdmin
		case "readonly":
			if mode == ModeRestricted && !valid {
				return "" // hidden: in no team, sees nothing
			}
			return RoleViewer // never more than viewer, even with an explicit admin row
		case "member":
			if valid {
				return Role(explicit)
			}
			if mode == ModeRestricted {
				return ""
			}
			return RoleDeployer
		}
		return "" // not a member / unknown role: fail closed
	}

	n := 0
	for _, org := range orgRoles {
		for _, mode := range modes {
			for _, ex := range explicits {
				role := eff(org, mode, ex)
				if got := Resolve(org, mode, ex).Role; got != role {
					t.Errorf("Resolve(%q,%q,%q).Role = %q, want %q", org, mode, ex, got, role)
				}
				for _, a := range GitActions {
					n++
					if got, want := CanGit(org, mode, ex, a), wantGit[role][a]; got != want {
						t.Errorf("CanGit(%q,%q,%q,%s) = %v, want %v", org, mode, ex, a, got, want)
					}
				}
			}
		}
	}
	if n != len(orgRoles)*len(modes)*len(explicits)*len(GitActions) {
		t.Fatal("table not exhaustive")
	}
}

// readonly in restricted mode without a row is hidden: no git action at all.
func TestReadonlyRestrictedWithoutRowHasNoGitAccess(t *testing.T) {
	for _, a := range GitActions {
		if CanGit("readonly", ModeRestricted, "", a) {
			t.Errorf("hidden readonly user got %s", a)
		}
	}
	if !CanGit("readonly", ModeRestricted, "viewer", GitRead) || CanGit("readonly", ModeRestricted, "admin", GitWrite) {
		t.Error("readonly with a row is a viewer, never more")
	}
}

type gitOneStore struct{ oa *OrgAccess }

func (f gitOneStore) LoadOrgAccess(context.Context, uuid.UUID, uuid.UUID) (*OrgAccess, error) {
	return f.oa, nil
}
func (f gitOneStore) UserGrants(context.Context, uuid.UUID) ([]Grant, error) { return nil, nil }

func TestServiceCanUsesGitActions(t *testing.T) {
	p := uuid.New()
	svc := New(gitOneStore{&OrgAccess{OrgRole: "member", Mode: ModeRestricted, Explicit: map[uuid.UUID]string{p: "viewer"}}})
	ctx := context.Background()
	for _, tc := range []struct {
		a    Action
		want bool
	}{{GitRead, true}, {GitWrite, false}, {GitAdmin, false}, {EnvRead, true}} {
		got, err := svc.Can(ctx, uuid.New(), uuid.New(), p, tc.a)
		if err != nil || got != tc.want {
			t.Errorf("Can(%s) = %v, %v; want %v", tc.a, got, err, tc.want)
		}
	}
	none := New(gitOneStore{nil})
	if ok, _ := none.Can(ctx, uuid.New(), uuid.New(), p, GitRead); ok {
		t.Error("non member must not read")
	}
}
