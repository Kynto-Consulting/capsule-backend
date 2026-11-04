package handlers

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// authzHolder is embedded by handlers that enforce per-project permissions.
// Without SetAuthz it falls back to organization roles only (open mode, no
// explicit project roles), which keeps unit tests that wire only an org repo working.
type authzHolder struct{ svc *authz.Service }

// SetAuthz wires the project permission service.
func (a *authzHolder) SetAuthz(s *authz.Service) { a.svc = s }

func (a *authzHolder) service(orgs domain.OrganizationRepository) *authz.Service {
	if a.svc != nil {
		return a.svc
	}
	return authz.New(authz.OrgOnlyStore{Orgs: orgs})
}

// authorize checks that the authenticated user may perform act on the project
// and writes the error response when not. act is an old action (authz.ProjectRead)
// or an atomic permission of the catalog ("deployment:create"; an untyped string
// constant converts to authz.Action). Responses:
//   - not an org member:            403 FORBIDDEN "not a member"
//   - member who cannot see it:     404 NOT_FOUND (does not leak existence)
//   - visible but role too low:     403 FORBIDDEN
//   - atom outside the API token:   403 TOKEN_SCOPE (SPEC 9.3: Effective(user) ∩ token.permissions)
//
// The decision is made by authz.Service.Check, which delegates to the engine in force
// (v1, shadow or v2); the visible behaviour with v1 is the one handlers always had.
func (a *authzHolder) authorize(w http.ResponseWriter, r *http.Request, orgs domain.OrganizationRepository, orgID, projectID uuid.UUID, act authz.Action) bool {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return false
	}
	ctx := r.Context()
	if rc := chi.RouteContext(ctx); rc != nil {
		ctx = authz.WithRoute(ctx, rc.RoutePattern())
	}
	out, err := a.service(orgs).Check(ctx, user.ID, orgID, projectID, act)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check permissions")
		return false
	}
	switch {
	case !out.Access.Member:
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return false
	case out.Access.Hidden:
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return false
	case !tokenAllowsAtom(ctx, act, orgID, projectID):
		respondError(w, http.StatusForbidden, "TOKEN_SCOPE", "token scope does not permit this request")
		return false
	case !out.Allowed:
		respondError(w, http.StatusForbidden, "FORBIDDEN", "your project role does not allow this action")
		return false
	}
	return true
}

// authorizePerm is authorize for an atom held in a string.
func (a *authzHolder) authorizePerm(w http.ResponseWriter, r *http.Request, orgs domain.OrganizationRepository, orgID, projectID uuid.UUID, perm string) bool {
	return a.authorize(w, r, orgs, orgID, projectID, authz.Action(perm))
}

// tokenAllowsAtom applies the token side of SPEC 9.1 to an atom: with an API token that restricts anything, the atom must be in the
// token and its organization and project must be the token's. Old actions are decided by the TokenGate per route (the legacy
// token scopes translate per route, not per action), sessions and unrestricted tokens always pass.
func tokenAllowsAtom(ctx context.Context, act authz.Action, orgID, projectID uuid.UUID) bool {
	if !authz.IsAtom(act) {
		return true
	}
	ti, ok := middleware.GetTokenInfo(ctx)
	if !ok || !ti.Restricted {
		return true
	}
	if !ti.Set.Has(string(act)) {
		return false
	}
	if ti.OrgID != nil && *ti.OrgID != orgID {
		return false
	}
	return ti.ProjectID == nil || *ti.ProjectID == projectID
}

// authorizeRoute is authorize for routes that carry {projectID} in the URL but
// whose handler works on a child resource. It returns the parsed project id so
// the caller can verify the resource really belongs to that project.
func (a *authzHolder) authorizeRoute(w http.ResponseWriter, r *http.Request, orgs domain.OrganizationRepository, orgID uuid.UUID, act authz.Action) (uuid.UUID, bool) {
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return uuid.Nil, false
	}
	return projectID, a.authorize(w, r, orgs, orgID, projectID, act)
}

// authorizeOptionalProject serves routes registered both under
// /projects/{projectID}/... and at org level. With a project in the URL it
// enforces act on it; at org level it only requires organization membership
// (the resource's own project, if any, must then be checked by the caller via
// authorizeResourceProject).
func (a *authzHolder) authorizeOptionalProject(w http.ResponseWriter, r *http.Request, orgs domain.OrganizationRepository, orgID uuid.UUID, act authz.Action) (uuid.UUID, bool) {
	if chi.URLParam(r, "projectID") != "" {
		return a.authorizeRoute(w, r, orgs, orgID, act)
	}
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return uuid.Nil, false
	}
	if ok, _ := orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return uuid.Nil, false
	}
	return uuid.Nil, true
}

// authorizeResourceProject enforces act on the project a loaded resource
// belongs to when the request did not name a project (org-level route).
func (a *authzHolder) authorizeResourceProject(w http.ResponseWriter, r *http.Request, orgs domain.OrganizationRepository, orgID uuid.UUID, urlProject uuid.UUID, resourceProject *uuid.UUID, act authz.Action) bool {
	if resourceProject == nil {
		return true // org-level resource: org membership already checked
	}
	if urlProject != uuid.Nil && urlProject != *resourceProject {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "resource not found")
		return false
	}
	if urlProject != uuid.Nil {
		return true // already authorized on the URL project
	}
	return a.authorize(w, r, orgs, orgID, *resourceProject, act)
}
