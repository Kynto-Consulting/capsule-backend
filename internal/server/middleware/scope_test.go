package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

func TestTokenAllows(t *testing.T) {
	pid := uuid.New()
	other := uuid.New()
	org := uuid.New()
	dep := uuid.New()
	base := "/api/v1/orgs/" + org.String() + "/projects/" + pid.String()
	deploy := &domain.APIToken{Scopes: "deploy", ProjectID: &pid}
	full := &domain.APIToken{Scopes: "*"}

	cases := []struct {
		name   string
		tok    *domain.APIToken
		method string
		path   string
		want   bool
	}{
		{"deploy upload-url", deploy, "POST", base + "/deployments/upload-url", true},
		{"deploy create", deploy, "POST", base + "/deployments", true},
		{"deploy list", deploy, "GET", base + "/deployments", true},
		{"deploy get", deploy, "GET", base + "/deployments/" + dep.String(), true},
		{"deploy logs", deploy, "GET", base + "/deployments/" + dep.String() + "/logs", true},
		{"deploy cancel", deploy, "POST", base + "/deployments/" + dep.String() + "/cancel", true},
		{"deploy rollback", deploy, "POST", base + "/deployments/" + dep.String() + "/rollback", true},
		{"deploy rollback get denied", deploy, "GET", base + "/deployments/" + dep.String() + "/rollback", false},
		{"deploy rollback other project denied", deploy, "POST", "/api/v1/orgs/" + org.String() + "/projects/" + other.String() + "/deployments/" + dep.String() + "/rollback", false},
		{"deploy project health patch denied", deploy, "PATCH", base, false},
		{"deploy read env", deploy, "GET", base + "/env", true},
		{"deploy write env denied", deploy, "PUT", base + "/env", false},
		{"deploy delete env denied", deploy, "DELETE", base + "/env/FOO", false},
		{"deploy other project denied", deploy, "POST", "/api/v1/orgs/" + org.String() + "/projects/" + other.String() + "/deployments", false},
		{"deploy project get denied", deploy, "GET", base, false},
		{"deploy delete project denied", deploy, "DELETE", base, false},
		{"deploy databases denied", deploy, "GET", base + "/databases", false},
		{"deploy org env denied", deploy, "GET", "/api/v1/orgs/" + org.String() + "/env", false},
		{"deploy tokens denied", deploy, "POST", "/api/v1/user/tokens", false},
		{"deploy me denied", deploy, "GET", "/api/v1/auth/me", false},
		{"deploy delete deployment denied", deploy, "DELETE", base + "/deployments/" + dep.String(), false},
		{"deploy without project denied", &domain.APIToken{Scopes: "deploy"}, "GET", base + "/deployments", false},
		{"deploy previews list", deploy, "GET", base + "/previews", true},
		{"deploy previews create", deploy, "POST", base + "/previews", true},
		{"deploy previews delete", deploy, "DELETE", base + "/previews/12", true},
		{"deploy previews patch denied", deploy, "PATCH", base + "/previews", false},
		{"deploy previews delete collection denied", deploy, "DELETE", base + "/previews", false},
		{"deploy previews get one denied", deploy, "GET", base + "/previews/12", false},
		{"deploy previews deeper denied", deploy, "DELETE", base + "/previews/12/x", false},
		{"deploy previews other project denied", deploy, "POST", "/api/v1/orgs/" + org.String() + "/projects/" + other.String() + "/previews", false},
		{"deploy git link denied", deploy, "GET", base + "/git", false},
		{"deploy git repo denied", deploy, "POST", base + "/git/repo", false},
		{"deploy git commits denied", deploy, "GET", base + "/git/commits", false},
		{"deploy platform capabilities denied", deploy, "GET", "/api/v1/platform/capabilities", false},
		{"full token anything", full, "DELETE", base, true},
		{"legacy empty scopes unrestricted", &domain.APIToken{}, "DELETE", base, true},
	}
	for _, c := range cases {
		if got := TokenAllows(c.tok, c.method, c.path); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

type fakeTokenRepo struct {
	domain.APITokenRepository
	tok *domain.APIToken
}

func (f fakeTokenRepo) GetByHash(_ context.Context, _ string) (*domain.APIToken, error) {
	return f.tok, nil
}
func (f fakeTokenRepo) TouchLastUsed(context.Context, uuid.UUID) error { return nil }

type fakeUserRepo struct{ domain.UserRepository }

func (fakeUserRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	return &domain.User{ID: id}, nil
}

func TestAuthMiddlewareEnforcesDeployScope(t *testing.T) {
	pid := uuid.New()
	org := uuid.New()
	plain := "cap_testtoken"
	tok := &domain.APIToken{ID: uuid.New(), UserID: uuid.New(), Scopes: "deploy", ProjectID: &pid}

	h := Auth(nil, fakeTokenRepo{tok: tok}, fakeUserRepo{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	do := func(method, path string) int {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+plain)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	base := "/api/v1/orgs/" + org.String() + "/projects/" + pid.String()
	if c := do("GET", base+"/deployments"); c != http.StatusOK {
		t.Errorf("deploy list: got %d want 200", c)
	}
	if c := do("GET", base+"/databases"); c != http.StatusForbidden {
		t.Errorf("databases: got %d want 403", c)
	}
	if c := do("POST", "/api/v1/user/tokens"); c != http.StatusForbidden {
		t.Errorf("create token: got %d want 403", c)
	}

	tok.Scopes, tok.ProjectID = "*", nil
	if c := do("GET", base+"/databases"); c != http.StatusOK {
		t.Errorf("full token: got %d want 200", c)
	}
}
