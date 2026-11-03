package handlers

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
)

type roleStore struct{ oa *authz.OrgAccess }

func (s roleStore) LoadOrgAccess(context.Context, uuid.UUID, uuid.UUID) (*authz.OrgAccess, error) {
	return s.oa, nil
}
func (s roleStore) UserGrants(context.Context, uuid.UUID) ([]authz.Grant, error) { return nil, nil }

func TestAuthzAuthorizerFollowsProjectRoles(t *testing.T) {
	p := uuid.New()
	ctx := context.Background()
	cases := []struct {
		name           string
		oa             *authz.OrgAccess
		manage, deploy bool
	}{
		{"org member viewer row (open)", &authz.OrgAccess{OrgRole: "member", Mode: authz.ModeOpen, Explicit: map[uuid.UUID]string{p: "viewer"}}, false, true},
		{"org member default deployer", &authz.OrgAccess{OrgRole: "member", Mode: authz.ModeOpen}, true, true},
		{"org member restricted no row", &authz.OrgAccess{OrgRole: "member", Mode: authz.ModeRestricted}, false, false},
		{"org readonly", &authz.OrgAccess{OrgRole: "readonly", Mode: authz.ModeOpen}, false, true},
		{"org admin", &authz.OrgAccess{OrgRole: "admin", Mode: authz.ModeRestricted}, true, true},
		{"not a member", nil, false, false},
	}
	for _, tc := range cases {
		a := AuthzAuthorizer{Svc: authz.New(roleStore{tc.oa})}
		m, err := a.CanManage(ctx, uuid.New(), uuid.New(), p)
		d, err2 := a.CanDeploy(ctx, uuid.New(), uuid.New(), p)
		if err != nil || err2 != nil || m != tc.manage || d != tc.deploy {
			t.Errorf("%s: manage=%v deploy=%v (errs %v %v), want %v %v", tc.name, m, d, err, err2, tc.manage, tc.deploy)
		}
	}
}
