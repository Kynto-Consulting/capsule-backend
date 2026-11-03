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
	// ScopeSecurityWrite lets CI upload security scan results (SARIF) for ONE project.
	ScopeSecurityWrite = "security:write"
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
		if s == ScopeSecurityWrite && t.ProjectID != nil && securityWriteRouteAllowed(*t.ProjectID, method, path) {
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
	case rest[0] == "previews":
		// PR previews of the PARENT project (CI without webhook): list, create, delete.
		switch len(rest) {
		case 1:
			return method == "GET" || method == "POST"
		case 2:
			return method == "DELETE"
		}
		return false
	case rest[0] == "environments":
		// read-only: a CI job needs to know the environments it promotes to.
		return method == "GET"
	case rest[0] == "promotions":
		// request a promotion and follow it. Approving/rejecting/cancelling stays human.
		switch len(rest) {
		case 1:
			return method == "POST"
		case 2:
			return method == "GET"
		}
		return false
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
	case len(rest) == 3 && rest[2] == "rollback":
		return method == "POST"
	}
	return false
}

// securityWriteRouteAllowed: only the SARIF upload of the token's own project and its status.
func securityWriteRouteAllowed(projectID uuid.UUID, method, path string) bool {
	path = strings.TrimPrefix(path, "/api/v1/")
	seg := strings.Split(strings.Trim(path, "/"), "/")
	// orgs/{org}/projects/{project}/security/sarif[/{id}]
	if len(seg) < 6 || seg[0] != "orgs" || seg[2] != "projects" || seg[4] != "security" || seg[5] != "sarif" {
		return false
	}
	if pid, err := uuid.Parse(seg[3]); err != nil || pid != projectID {
		return false
	}
	switch len(seg) {
	case 6:
		return method == "POST"
	case 7:
		return method == "GET"
	}
	return false
}
