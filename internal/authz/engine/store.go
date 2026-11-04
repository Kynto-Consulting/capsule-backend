// Package engine is the evaluator of the atomic permission engine (docs/permissions/SPEC.md sections 5
// and 12). It is pure policy: everything it knows about a user comes through Store, as plain data, and
// the decision is a function of that data and of the clock.
//
// # What it does
//
// For a (user, organization) pair the engine compiles once an immutable Snapshot (SPEC 12.1): membership
// state, the bitsets of the organization template (permissions, floor, base, ceiling), the union of the
// organization-wide assignments, and maps project/repo/env -> bitset for ONLY the scopes that have own
// assignments. A project without an entry uses the fallback (org-wide assignments plus, when the policy is
// open, the template base) without materialising anything, so memory grows with the number of assignments
// of the user, not with the number of projects. Snapshots live in a bounded in-process cache with a 30 s
// TTL, are evicted by Invalidate and are recompiled at the instant an assignment expires.
//
// # Resolution (SPEC 5.3, normative)
//
//   - not a member: Member=false, empty set. Suspended user or membership: Member=true, empty set.
//     Template that does not resolve: empty set (fail closed).
//   - organization scope: template permissions, cut by the ceiling.
//   - project scope: own := live assignments (user directly, plus the user's groups) at the project;
//     fallback := org-wide assignments + (policy open ? template base : empty); the closest level wins
//     (own replaces the fallback), the same level unions; floor ALWAYS adds; the ceiling cuts last.
//     Without project:view the project is Hidden and the set is empty.
//   - repo and env scope add their own assignments (and the environment approvers) to the project set.
//   - there is no explicit deny.
//   - the ceiling of a template is Ceiling at organization scope and CeilingProject at project, repo and
//     env scope (P0-NOTES D1).
//
// # Store contract (what repository.AccessStore must implement)
//
// See the Store interface below.
package engine

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
)

// Set is the permission bitset of the catalog.
type Set = catalog.Set

// SubjectKind says who an assignment belongs to.
type SubjectKind string

const (
	SubjectUser  SubjectKind = "user"
	SubjectGroup SubjectKind = "group"
)

// Assignment source values (SPEC 5.2). The engine only reads them (Explain, Source of grants).
const (
	AssignManual    = "manual"
	AssignMigrated  = "migrated"
	AssignLegacyAPI = "legacy-api"
	AssignApprover  = "approver"
	AssignOIDC      = "oidc"
	AssignTemporary = "temporary"
)

// OrgTemplate is the resolved organization template of a member: the content of the version in force
// (the pinned one or the latest) with the floor and base project templates already expanded to sets.
type OrgTemplate struct {
	ID      uuid.UUID
	Slug    string // informative (Explain)
	Version int

	Permissions catalog.Set // organization-level permissions

	FloorID, BaseID uuid.UUID // zero when none (informative)
	Floor, Base     catalog.Set

	// HasCeiling is true when the template has a ceiling. Ceiling applies at organization scope and
	// CeilingProject at project, repo and env scope (ceiling_project of systemtemplates, P0-NOTES D1).
	// For custom templates without ceiling_project the store must fill CeilingProject = Ceiling.
	HasCeiling     bool
	Ceiling        catalog.Set
	CeilingProject catalog.Set
}

// Assignment is one LIVE assignment relevant to the user: made to the user or to a group the user belongs
// to. The store must already have discarded: revoked assignments, assignments of a non-active membership,
// assignments of archived groups, and memberships of the user in groups that expired. It MAY include rows
// whose ExpiresAt is already in the past (the engine ignores them at compile time and Explain reports
// them as expired); it must not return rows that do not belong to this organization.
type Assignment struct {
	ID          uuid.UUID
	SubjectKind SubjectKind
	SubjectID   uuid.UUID // user id or group id

	Scope     ScopeType
	ScopeID   uuid.UUID // project, repo or env id; ignored for ScopeOrg
	ProjectID uuid.UUID // project that contains the repo/env; equals ScopeID for ScopeProject; zero for ScopeOrg

	TemplateID      uuid.UUID
	TemplateSlug    string // informative
	TemplateVersion int    // version in force (pinned or latest)

	// Permissions is the content of that template version. For the environment approvers
	// (Source = AssignApprover, Scope = ScopeEnv) the store supplies {promotion:approve}.
	Permissions catalog.Set

	Source string
	// ExpiresAt is zero when it does not expire. For an assignment received through a group the store
	// supplies min(assignment.expires_at, group membership expires_at).
	ExpiresAt time.Time
}

// Epochs are the access epochs of the organization and of the user (SPEC 12.2).
type Epochs struct{ Org, User int64 }

// AccessData is everything the engine needs to compile the snapshot of one (user, organization).
type AccessData struct {
	// Member is false when the user has no membership in the organization (everything else is ignored).
	Member bool
	// UserActive is users.status == active; MemberActive is org_members.status == active.
	UserActive, MemberActive bool

	// Template is nil when the role template of the member does not resolve (the engine then closes).
	Template *OrgTemplate

	// Policy is organizations.project_access_mode. Only "restricted" restricts: "" and any other value
	// behave as "open" (legacy Resolve, P0-NOTES D13).
	Policy string
	// ProjectOverrides is projects.access_override for the projects of the organization that have one
	// ("open" or "restricted"); projects without override are absent. Other values are ignored.
	ProjectOverrides map[uuid.UUID]string

	// Assignments of the user and of the user's groups in this organization, every scope.
	Assignments []Assignment

	// Epochs read BEFORE the rows above (same transaction when possible) so that a concurrent write can
	// only make the snapshot look older than it is, never newer.
	Epochs Epochs
}

// Store is the persistence of the engine. repository.AccessStore implements it.
//
// Both methods must be safe for concurrent use. An error from either makes the decision fail closed
// (Can returns false and the error).
type Store interface {
	// LoadAccess returns the AccessData of (user, org) in one round trip (one query with UNION over
	// (subject_type, subject_id), SPEC 12.1). Data.Member=false for a non-member; that is not an error.
	LoadAccess(ctx context.Context, user, org uuid.UUID) (*AccessData, error)

	// Epochs returns organizations.access_epoch and users.access_epoch (primary-key lookups, <= 1 ms). It
	// backs the strict path for permissions marked sensitive and for token decisions (SPEC 12.2).
	Epochs(ctx context.Context, user, org uuid.UUID) (Epochs, error)
}
