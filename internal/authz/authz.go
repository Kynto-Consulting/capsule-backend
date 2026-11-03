// Package authz decides what a user may do inside a project, combining the
// organization role, the organization's project access mode and explicit
// per-project roles. It is pure policy: persistence lives behind Store.
package authz

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

// Action is something a user can do inside a project.
type Action string

const (
	ProjectRead      Action = "project.read"       // project, deployments, logs, masked env list
	ProjectDeploy    Action = "project.deploy"     // create/cancel deployments, rollback
	ProjectEnvWrite  Action = "project.env_write"  // set/delete env vars
	ProjectEnvReveal Action = "project.env_reveal" // see secret values
	ProjectOps       Action = "project.ops"        // workers, crons, domains, project settings, storage, email
	ProjectDatabases Action = "project.databases"  // create/delete databases
	ProjectNetwork   Action = "project.network"    // database access rules, IP allowlist
	ProjectMembers   Action = "project.members"    // manage project members
	ProjectDelete    Action = "project.delete"
)

// AllActions lists every action (used by tests and docs).
var AllActions = []Action{
	ProjectRead, ProjectDeploy, ProjectEnvWrite, ProjectEnvReveal, ProjectOps,
	ProjectDatabases, ProjectNetwork, ProjectMembers, ProjectDelete,
}

// Role is a project-level role. The empty Role means no access.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleDeployer Role = "deployer"
	RoleViewer   Role = "viewer"
)

// Access modes of an organization.
const (
	ModeOpen       = "open"
	ModeRestricted = "restricted"
)

var matrix = map[Role]map[Action]bool{
	RoleViewer: {ProjectRead: true},
	RoleDeployer: {
		ProjectRead: true, ProjectDeploy: true, ProjectEnvWrite: true, ProjectOps: true,
	},
	RoleAdmin: {
		ProjectRead: true, ProjectDeploy: true, ProjectEnvWrite: true, ProjectEnvReveal: true,
		ProjectOps: true, ProjectDatabases: true, ProjectNetwork: true, ProjectMembers: true,
		ProjectDelete: true,
	},
}

// RoleAllows reports whether role may perform a.
func RoleAllows(role Role, a Action) bool { return matrix[role][a] }

// ValidProjectRole reports whether s is a role assignable to a project member.
func ValidProjectRole(s string) bool {
	switch Role(s) {
	case RoleAdmin, RoleDeployer, RoleViewer:
		return true
	}
	return false
}

// ValidMode reports whether s is a valid project_access_mode.
func ValidMode(s string) bool { return s == ModeOpen || s == ModeRestricted }

// Source says where an effective role comes from.
type Source string

const (
	SourceOrg       Source = "org"       // org owner/admin => admin everywhere
	SourceExplicit  Source = "explicit"  // row in project_members
	SourceInherited Source = "inherited" // org default (member => deployer, readonly => viewer)
)

// Access is the outcome of resolving a user against a project.
type Access struct {
	Role   Role
	Source Source
	Member bool // belongs to the organization
	Hidden bool // org member who must not learn the project exists
}

// Resolve is the pure decision function: org role x mode x explicit project role.
func Resolve(orgRole, mode, explicit string) Access {
	if orgRole == "" {
		return Access{}
	}
	a := Access{Member: true}
	switch orgRole {
	case "owner", "admin":
		a.Role, a.Source = RoleAdmin, SourceOrg
		return a
	case "readonly":
		// Never more than viewer. In restricted mode it still needs a row to see the project.
		if mode == ModeRestricted && !ValidProjectRole(explicit) {
			a.Hidden = true
			return a
		}
		a.Role, a.Source = RoleViewer, SourceInherited
		if ValidProjectRole(explicit) {
			a.Source = SourceExplicit
		}
		return a
	case "member":
		if ValidProjectRole(explicit) {
			a.Role, a.Source = Role(explicit), SourceExplicit
			return a
		}
		if mode == ModeRestricted {
			a.Hidden = true
			return a
		}
		a.Role, a.Source = RoleDeployer, SourceInherited
		return a
	}
	// Unknown org role: fail closed without leaking existence.
	a.Hidden = true
	return a
}

// OrgAccess is what the Store knows about a user in an organization.
type OrgAccess struct {
	OrgRole  string               // "" when not a member
	Mode     string               // open | restricted
	Explicit map[uuid.UUID]string // project_id -> explicit role (this org only)
}

// Grant is one (user, project) pair with everything needed to resolve it.
type Grant struct {
	OrgID        uuid.UUID
	OrgSlug      string
	ProjectID    uuid.UUID
	ProjectSlug  string
	OrgRole      string
	Mode         string
	ExplicitRole string
}

// Store is the persistence the Service needs.
type Store interface {
	// LoadOrgAccess returns nil, nil when the user is not an org member.
	LoadOrgAccess(ctx context.Context, orgID, userID uuid.UUID) (*OrgAccess, error)
	UserGrants(ctx context.Context, userID uuid.UUID) ([]Grant, error)
}

// Service evaluates permissions.
type Service struct{ store Store }

// New returns a Service backed by store.
func New(store Store) *Service { return &Service{store: store} }

// Access resolves userID against a project of orgID.
func (s *Service) Access(ctx context.Context, userID, orgID, projectID uuid.UUID) (Access, error) {
	oa, err := s.store.LoadOrgAccess(ctx, orgID, userID)
	if err != nil {
		return Access{}, err
	}
	if oa == nil {
		return Access{}, nil
	}
	return Resolve(oa.OrgRole, oa.Mode, oa.Explicit[projectID]), nil
}

// EffectiveRole returns the user's effective project role ("" if none/hidden).
func (s *Service) EffectiveRole(ctx context.Context, userID, orgID, projectID uuid.UUID) (Role, error) {
	a, err := s.Access(ctx, userID, orgID, projectID)
	return a.Role, err
}

// Can reports whether the user may perform a on the project.
func (s *Service) Can(ctx context.Context, userID, orgID, projectID uuid.UUID, a Action) (bool, error) {
	acc, err := s.Access(ctx, userID, orgID, projectID)
	if err != nil {
		return false, err
	}
	return RoleAllows(acc.Role, a), nil
}

// FilterProjects drops the projects the user cannot see (restricted mode).
func (s *Service) FilterProjects(ctx context.Context, userID, orgID uuid.UUID, projects []*domain.Project) ([]*domain.Project, error) {
	oa, err := s.store.LoadOrgAccess(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Project, 0, len(projects))
	if oa == nil {
		return out, nil
	}
	for _, p := range projects {
		if Resolve(oa.OrgRole, oa.Mode, oa.Explicit[p.ID]).Role != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// Visibility returns a predicate telling which projects of orgID the user can
// see (any effective role). Used to filter org-level listings.
func (s *Service) Visibility(ctx context.Context, userID, orgID uuid.UUID) (func(projectID uuid.UUID) bool, error) {
	oa, err := s.store.LoadOrgAccess(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}
	return func(projectID uuid.UUID) bool {
		if oa == nil {
			return false
		}
		return Resolve(oa.OrgRole, oa.Mode, oa.Explicit[projectID]).Role != ""
	}, nil
}

// ProjectGroups returns "project:<orgSlug>/<projectSlug>:<role>" for every
// project where the user has any effective role (the OIDC groups claim).
func (s *Service) ProjectGroups(ctx context.Context, userID uuid.UUID) ([]string, error) {
	grants, err := s.store.UserGrants(ctx, userID)
	if err != nil {
		return nil, err
	}
	groups := make([]string, 0, len(grants))
	for _, g := range grants {
		a := Resolve(g.OrgRole, g.Mode, g.ExplicitRole)
		if a.Role == "" {
			continue
		}
		groups = append(groups, fmt.Sprintf("project:%s/%s:%s", g.OrgSlug, g.ProjectSlug, a.Role))
	}
	sort.Strings(groups)
	return groups, nil
}

// OrgOnlyStore adapts an OrganizationRepository: open mode, no explicit roles.
// It is the fallback used when no project_members store is wired.
type OrgOnlyStore struct{ Orgs domain.OrganizationRepository }

func (o OrgOnlyStore) LoadOrgAccess(ctx context.Context, orgID, userID uuid.UUID) (*OrgAccess, error) {
	role, err := o.Orgs.GetMemberRole(ctx, orgID, userID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &OrgAccess{OrgRole: role, Mode: ModeOpen}, nil
}

func (o OrgOnlyStore) UserGrants(context.Context, uuid.UUID) ([]Grant, error) { return nil, nil }
