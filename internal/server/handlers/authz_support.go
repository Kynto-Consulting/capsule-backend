package handlers

import (
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
// and writes the error response when not. Responses:
//   - not an org member:            403 FORBIDDEN "not a member"
//   - member who cannot see it:     404 NOT_FOUND (does not leak existence)
//   - visible but role too low:     403 FORBIDDEN
func (a *authzHolder) authorize(w http.ResponseWriter, r *http.Request, orgs domain.OrganizationRepository, orgID, projectID uuid.UUID, act authz.Action) bool {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return false
	}
	acc, err := a.service(orgs).Access(r.Context(), user.ID, orgID, projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check permissions")
		return false
	}
	switch {
	case !acc.Member:
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return false
	case acc.Hidden:
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return false
	case !authz.RoleAllows(acc.Role, act):
		respondError(w, http.StatusForbidden, "FORBIDDEN", "your project role does not allow this action")
		return false
	}
	return true
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
