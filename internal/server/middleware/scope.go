package middleware

import (
	"strings"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

// Token scopes.
const (
	ScopeAll    = "*"
	ScopeDeploy = "deploy"
)

// ParseScopes splits the comma-separated scopes column.
func ParseScopes(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// TokenAllows reports whether an API token may perform method+path (path is the
// full request path, e.g. /api/v1/orgs/...). Tokens carrying "*" (or with
// empty scopes, for legacy rows) are unrestricted. A "deploy" token is bound to
// its project_id and may only: request upload URLs, create/list/read/cancel
// deployments, read deployment logs and read the project's env.
func TokenAllows(t *domain.APIToken, method, path string) bool {
	scopes := ParseScopes(t.Scopes)
	if len(scopes) == 0 {
		return true
	}
	for _, s := range scopes {
		if s == ScopeAll {
			return true
		}
	}
	for _, s := range scopes {
		if s == ScopeDeploy && t.ProjectID != nil && deployRouteAllowed(*t.ProjectID, method, path) {
			return true
		}
	}
	return false
}

func deployRouteAllowed(projectID uuid.UUID, method, path string) bool {
	path = strings.TrimPrefix(path, "/api/v1/")
	seg := strings.Split(strings.Trim(path, "/"), "/")
	// orgs/{org}/projects/{project}/<rest...>
	if len(seg) < 5 || seg[0] != "orgs" || seg[2] != "projects" {
		return false
	}
	if pid, err := uuid.Parse(seg[3]); err != nil || pid != projectID {
		return false
	}
	rest := seg[4:]
	switch {
	case len(rest) == 1 && rest[0] == "env":
		return method == "GET"
	case rest[0] != "deployments":
		return false
	case len(rest) == 1: // /deployments
		return method == "GET" || method == "POST"
	case len(rest) == 2 && rest[1] == "upload-url":
		return method == "POST"
	case len(rest) == 2: // /deployments/{id}
		return method == "GET"
	case len(rest) == 3 && rest[2] == "logs":
		return method == "GET"
	case len(rest) == 3 && rest[2] == "cancel":
		return method == "POST"
	}
	return false
}
