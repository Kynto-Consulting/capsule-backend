package middleware

import (
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

func tokenFor(scopes string, p uuid.UUID) *domain.APIToken {
	return &domain.APIToken{Scopes: scopes, ProjectID: &p}
}

func TestSecurityWriteScope(t *testing.T) {
	p, other := uuid.New(), uuid.New()
	org := uuid.New()
	base := "/api/v1/orgs/" + org.String() + "/projects/" + p.String()
	tok := tokenFor("security:write", p)

	allow := []struct{ m, path string }{
		{"POST", base + "/security/sarif"},
		{"GET", base + "/security/sarif/" + uuid.NewString()},
	}
	for _, c := range allow {
		if !TokenAllows(tok, c.m, c.path) {
			t.Errorf("security:write must allow %s %s", c.m, c.path)
		}
	}
	deny := []struct{ m, path string }{
		{"GET", base + "/security/alerts"},            // reading alerts is a user action
		{"POST", base + "/security/alerts/x/dismiss"}, // dismissing is not CI's job
		{"PUT", base + "/security/policy"},            // policy is admin only
		{"POST", base + "/deployments"},               // not a deploy token
		{"GET", base + "/env"},                        // no secrets for a security token
		{"POST", "/api/v1/orgs/" + org.String() + "/projects/" + other.String() + "/security/sarif"}, // another project
		{"DELETE", base + "/security/sarif"},
		{"GET", "/api/v1/auth/me"},
	}
	for _, c := range deny {
		if TokenAllows(tok, c.m, c.path) {
			t.Errorf("security:write must NOT allow %s %s", c.m, c.path)
		}
	}
}

func TestDeployScopePromotions(t *testing.T) {
	p, other := uuid.New(), uuid.New()
	org := uuid.New()
	base := "/api/v1/orgs/" + org.String() + "/projects/" + p.String()
	tok := tokenFor("deploy", p)

	for _, c := range []struct{ m, path string }{
		{"POST", base + "/promotions"},
		{"GET", base + "/promotions/" + uuid.NewString()},
		{"GET", base + "/environments"},
		{"GET", base + "/environments/production"},
		{"GET", base + "/environments/production/deployments"},
	} {
		if !TokenAllows(tok, c.m, c.path) {
			t.Errorf("deploy token must allow %s %s", c.m, c.path)
		}
	}
	for _, c := range []struct{ m, path string }{
		{"POST", base + "/promotions/" + uuid.NewString() + "/approve"}, // approvals stay human
		{"POST", base + "/promotions/" + uuid.NewString() + "/reject"},
		{"POST", base + "/promotions/" + uuid.NewString() + "/cancel"},
		{"POST", base + "/environments"}, // configuring environments is admin
		{"PUT", base + "/environments/production"},
		{"DELETE", base + "/environments/production"},
		{"POST", "/api/v1/orgs/" + org.String() + "/projects/" + other.String() + "/promotions"},
		{"POST", base + "/security/sarif"}, // needs its own scope
	} {
		if TokenAllows(tok, c.m, c.path) {
			t.Errorf("deploy token must NOT allow %s %s", c.m, c.path)
		}
	}
	both := tokenFor("deploy,security:write", p)
	if !TokenAllows(both, "POST", base+"/security/sarif") || !TokenAllows(both, "POST", base+"/deployments") {
		t.Error("a token may carry both project-bound scopes")
	}
}
