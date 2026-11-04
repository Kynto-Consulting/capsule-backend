package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/domain"
)

// RouteKind classifies a row of the route table (server.routePermissions).
type RouteKind string

const (
	KindPerm    RouteKind = "perm"    // needs every atom of Perms
	KindMember  RouteKind = "member"  // membership of the organization only
	KindSession RouteKind = "session" // any session, never a scoped token
	KindPublic  RouteKind = "public"  // no user authentication
)

// RouteEntry is what the route table says about one route.
type RouteEntry struct {
	Kind  RouteKind
	Perms []string
}

// RouteTable resolves a request to its row. Implemented by server.routeTable.
type RouteTable interface {
	Lookup(method, path string) (RouteEntry, bool)
}

// ---------------------------------------------------------------- pattern matching

type patternRoute struct {
	segs     []string
	wildcard bool // trailing "*"
	score    int
	entry    RouteEntry
}

// PatternMatcher finds the row whose chi pattern matches a concrete path. Literal segments beat {params}, and a pattern without
// trailing "*" beats one with it.
type PatternMatcher struct{ byMethod map[string][]patternRoute }

// NewPatternMatcher returns an empty matcher.
func NewPatternMatcher() *PatternMatcher {
	return &PatternMatcher{byMethod: map[string][]patternRoute{}}
}

// Add registers pattern under method ("ANY" matches every method).
func (m *PatternMatcher) Add(method, pattern string, e RouteEntry) {
	segs := strings.Split(strings.Trim(pattern, "/"), "/")
	pr := patternRoute{entry: e}
	if n := len(segs); n > 0 && segs[n-1] == "*" {
		pr.wildcard, segs = true, segs[:n-1]
	}
	pr.segs = segs
	for _, s := range segs {
		if !strings.HasPrefix(s, "{") {
			pr.score += 2
		}
	}
	if !pr.wildcard {
		pr.score++
	}
	m.byMethod[method] = append(m.byMethod[method], pr)
}

func (p *patternRoute) matches(segs []string) bool {
	if p.wildcard {
		if len(segs) < len(p.segs) {
			return false
		}
	} else if len(segs) != len(p.segs) {
		return false
	}
	for i, ps := range p.segs {
		if strings.HasPrefix(ps, "{") {
			if segs[i] == "" {
				return false
			}
		} else if ps != segs[i] {
			return false
		}
	}
	return true
}

// Lookup returns the best row for method and path.
func (m *PatternMatcher) Lookup(method, path string) (RouteEntry, bool) {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	best, found := -1, RouteEntry{}
	for _, meth := range [2]string{method, "ANY"} {
		for i := range m.byMethod[meth] {
			p := &m.byMethod[meth][i]
			if p.score > best && p.matches(segs) {
				best, found = p.score, p.entry
			}
		}
	}
	return found, best >= 0
}

// ---------------------------------------------------------------- token permissions

// Atoms of the legacy token scopes (SPEC 9.2). The table is checked route by route against TokenAllows (tokengate_test.go).
var (
	deployAtoms = catalog.NewSet("deployment:read", "deployment:create", "deployment:cancel", "deployment:rollback",
		"envvar:read", "preview:read", "preview:manage", "environment:read", "promotion:request")
	securityWriteAtoms = catalog.NewSet("security:upload")
)

// TokenInfo is the token side of "Effective(user) ∩ token.permissions" (SPEC 9.1). Restricted=false is the legacy "*"/empty
// token: it adds no limit.
type TokenInfo struct {
	TokenID    uuid.UUID
	Restricted bool
	Set        catalog.Set
	OrgID      *uuid.UUID // explicit-permission tokens carry their organization
	ProjectID  *uuid.UUID // resource scope: legacy deploy/security:write tokens always have one
}

// TokenInfoFor translates a token: explicit permissions are used as they are; otherwise the legacy scopes are translated with the
// table of SPEC 9.2 (deploy and security:write only count with a project_id, as in TokenAllows).
func TokenInfoFor(t *domain.APIToken) TokenInfo {
	ti := TokenInfo{TokenID: t.ID, OrgID: t.OrgID, ProjectID: t.ProjectID}
	if t.Permissions != nil {
		ti.Restricted, ti.Set = true, catalog.NewSet(t.Permissions...)
		return ti
	}
	scopes := ParseScopes(t.Scopes)
	if len(scopes) == 0 {
		return ti
	}
	for _, s := range scopes {
		if s == ScopeAll {
			return ti
		}
	}
	ti.Restricted = true
	if t.ProjectID == nil {
		return ti
	}
	for _, s := range scopes {
		switch s {
		case ScopeDeploy:
			ti.Set = ti.Set.Union(deployAtoms)
		case ScopeSecurityWrite:
			ti.Set = ti.Set.Union(securityWriteAtoms)
		}
	}
	return ti
}

type tokenCtxKey struct{}

// WithTokenInfo stores the token side of the decision in the request context.
func WithTokenInfo(ctx context.Context, ti TokenInfo) context.Context {
	return context.WithValue(ctx, tokenCtxKey{}, ti)
}

// GetTokenInfo returns the info of the API token of the request (ok=false for sessions).
func GetTokenInfo(ctx context.Context) (TokenInfo, bool) {
	ti, ok := ctx.Value(tokenCtxKey{}).(TokenInfo)
	return ti, ok
}

// TokenPerms returns the permission ceiling of the API token of the request. ok is true only when the token restricts something:
// sessions and legacy "*" tokens return ok=false (no ceiling).
func TokenPerms(ctx context.Context) (catalog.Set, bool) {
	ti, ok := GetTokenInfo(ctx)
	if !ok || !ti.Restricted {
		return catalog.Set{}, false
	}
	return ti.Set, true
}

// ---------------------------------------------------------------- gate

// Allows is the pure decision of the gate for a token: closed for routes without a perm row, session-only and membership-only routes,
// and for routes whose atoms the token does not hold or whose project/organization is not the token's.
func (ti TokenInfo) Allows(e RouteEntry, found bool, orgInPath, projectInPath uuid.UUID) bool {
	if !ti.Restricted {
		return true
	}
	if !found || e.Kind != KindPerm || len(e.Perms) == 0 {
		return false
	}
	want, unknown := catalog.ParseSet(e.Perms)
	if len(unknown) > 0 || !ti.Set.ContainsAll(want) {
		return false
	}
	if ti.OrgID != nil && orgInPath != uuid.Nil && orgInPath != *ti.OrgID {
		return false
	}
	if ti.ProjectID != nil && (projectInPath == uuid.Nil || projectInPath != *ti.ProjectID) {
		return false
	}
	return true
}

// PathIDs extracts the organization and project ids of /api/v1/orgs/{org}/projects/{project}/... (uuid.Nil when absent or not a uuid).
func PathIDs(path string) (org, project uuid.UUID) {
	seg := strings.Split(strings.Trim(strings.TrimPrefix(path, "/api/v1/"), "/"), "/")
	if len(seg) >= 2 && seg[0] == "orgs" {
		org, _ = uuid.Parse(seg[1])
	}
	if len(seg) >= 4 && seg[0] == "orgs" && seg[2] == "projects" {
		project, _ = uuid.Parse(seg[3])
	}
	return
}

// PathLabel replaces uuids by {id} (log label without resource identifiers).
func PathLabel(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if _, err := uuid.Parse(s); err == nil {
			segs[i] = "{id}"
		}
	}
	return strings.Join(segs, "/")
}

// TokenGate decides, before the handler, whether an API token may make a request. The authorization mode (v1|shadow|v2) says how: v1
// and shadow decide with TokenAllows (shadow also computes the new decision and records differences), v2 decides with the route
// table. Tokens with explicit permissions are new and always use the table.
type TokenGate struct {
	Routes RouteTable
	// Mode returns the mode for the organization of the request (uuid.Nil: global). Nil means v1.
	Mode    func(ctx context.Context, org uuid.UUID) string
	Observe func(kind string, d time.Duration, mismatch bool)
	Log     *slog.Logger
}

// Allow reports whether t may perform r.
func (g *TokenGate) Allow(r *http.Request, t *domain.APIToken) bool {
	if t.Permissions != nil {
		return g.decideNew(r, t)
	}
	org, _ := PathIDs(r.URL.Path)
	if org == uuid.Nil && t.OrgID != nil {
		org = *t.OrgID
	}
	mode := "v1"
	if g.Mode != nil {
		mode = g.Mode(r.Context(), org)
	}
	switch mode {
	case "v2":
		return g.decideNew(r, t)
	case "shadow":
		ov := TokenAllows(t, r.Method, r.URL.Path)
		func() {
			defer func() { _ = recover() }()
			start := time.Now()
			nv := g.decideNew(r, t)
			if g.Observe != nil {
				g.Observe("token", time.Since(start), nv != ov)
			}
			if nv != ov && g.Log != nil {
				g.Log.Warn("authz shadow mismatch", "kind", "token", "method", r.Method, "route", PathLabel(r.URL.Path),
					"token_id", t.ID, "user", t.UserID, "old", ov, "new", nv)
			}
		}()
		return ov
	}
	return TokenAllows(t, r.Method, r.URL.Path)
}

func (g *TokenGate) decideNew(r *http.Request, t *domain.APIToken) bool {
	ti := TokenInfoFor(t)
	if !ti.Restricted {
		return true
	}
	if g.Routes == nil {
		return false
	}
	e, found := g.Routes.Lookup(r.Method, r.URL.Path)
	org, project := PathIDs(r.URL.Path)
	return ti.Allows(e, found, org, project)
}
