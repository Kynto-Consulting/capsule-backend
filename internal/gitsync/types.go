// Package gitsync is Git Capsule package A2: identity (Capsule user <-> Forgejo login) and the
// projection of Capsule project roles onto Forgejo teams.
//
// Capsule is the source of truth: authz.Resolve decides the effective role of every org member
// and the reconciler makes the three per-project teams (<slug>-viewer/-deployer/-admin) match it,
// removing whoever is in a team without being entitled to it (role changed, left the org,
// restricted mode without a row, a manual add in Forgejo). It talks to Forgejo only through the
// gitcore interfaces and to the database only through the small interfaces declared here.
package gitsync

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

// Identity links a Capsule user to a Forgejo login.
type Identity struct {
	UserID          uuid.UUID  `json:"user_id"`
	ForgejoUsername string     `json:"forgejo_username"`
	ForgejoUserID   *int64     `json:"forgejo_user_id,omitempty"` // nil until it is looked up in Forgejo
	LinkedAt        *time.Time `json:"linked_at,omitempty"`       // nil until the Forgejo user is confirmed to exist
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// IdentityStore persists git_identities.
type IdentityStore interface {
	// Get returns domain-style not found as ErrNoIdentity.
	Get(ctx context.Context, userID uuid.UUID) (*Identity, error)
	// Ensure inserts the identity with that login if the user has none, and returns the stored
	// row either way (the stored login is never changed by Ensure). ErrUsernameTaken when the
	// login already belongs to another user.
	Ensure(ctx context.Context, userID uuid.UUID, login string) (*Identity, error)
	// MarkLinked records that the Forgejo user exists; forgejoUserID 0 means unknown.
	MarkLinked(ctx context.Context, userID uuid.UUID, forgejoUserID int64) error
}

// TeamState is the observed state of one project team after a reconciliation.
type TeamState struct {
	ProjectID        uuid.UUID
	Role             authz.Role
	TeamID           int64
	TeamName         string
	Permission       string
	Members          int
	LastSyncedAt     time.Time
	LastError        string
	DriftEvents      int64
	LastDriftAt      *time.Time
	LastDriftAdded   int
	LastDriftRemoved int
}

// StateStore persists git_team_state and lists the projects to reconcile.
type StateStore interface {
	// PutTeamState upserts the row. When Drift is true DriftEvents is incremented by one and the
	// last_drift_* columns are set from st; otherwise they are kept.
	PutTeamState(ctx context.Context, st TeamState, drift bool) error
	ListTeamStates(ctx context.Context, projectID uuid.UUID) ([]TeamState, error)
	// ListForgejoProjects returns up to limit ids of projects linked to Forgejo with id > after
	// (keyset pagination, ordered by id).
	ListForgejoProjects(ctx context.Context, after uuid.UUID, limit int) ([]uuid.UUID, error)
	// AuditDrift writes an audit_logs row with no acting user (system).
	AuditDrift(ctx context.Context, orgID, projectID uuid.UUID, action string, values map[string]any) error
}

// PendingStore is the git_team_sync queue of 000030 (satisfied by *repository.GitCoreRepository).
type PendingStore interface {
	ReplaceTeamSync(ctx context.Context, projectID uuid.UUID, pending []uuid.UUID, lastErr string, next time.Time) error
}

// Member is an org member with the data needed to resolve a role and a login.
type Member struct {
	UserID  uuid.UUID
	Email   string
	OrgRole string
}

// ProjectInfo describes a Forgejo-linked project.
type ProjectInfo struct {
	ID    uuid.UUID
	OrgID uuid.UUID
	Slug  string          // project slug: team names are <Slug>-<role>
	Repo  gitcore.RepoRef // Forgejo owner/repo of the link
}

// Directory is the read side of Capsule needed to compute desired state.
type Directory interface {
	// Project returns (nil, nil) when the project does not exist or is not linked to Forgejo.
	Project(ctx context.Context, projectID uuid.UUID) (*ProjectInfo, error)
	Members(ctx context.Context, orgID uuid.UUID) ([]Member, error)
	// Access returns the org's project_access_mode and the explicit roles of the project.
	Access(ctx context.Context, orgID, projectID uuid.UUID) (mode string, explicit map[uuid.UUID]string, err error)
}

// Forge is the part of gitcore.Core the reconciler uses. *gitcore.Service satisfies it.
type Forge interface {
	gitcore.Teams
	EnsureOrg(ctx context.Context, slug string) error
	UserExists(ctx context.Context, login string) (bool, error)
	Enabled() bool
}

// TeamPatcher is optional: a Forge that also implements it gets team permission drift corrected
// (gitcore v1 has no such method, so drift is only reported; see the package report).
type TeamPatcher interface {
	PatchTeam(ctx context.Context, org string, teamID int64, spec gitcore.TeamSpec) error
}

// UserResolver is optional: it returns the numeric Forgejo id of a login (0, false if unknown).
type UserResolver interface {
	ForgejoUserID(ctx context.Context, login string) (int64, bool, error)
}

// ReviewJanitor is optional: it discards the pending review requests / pending reviews that
// a user keeps in the open pull requests of a repository after losing access to it. It returns
// how many it discarded. gitcore v1 has no way to do this, so no implementation exists yet.
type ReviewJanitor interface {
	DropPendingReviews(ctx context.Context, repo gitcore.RepoRef, login string) (int, error)
}

// Trigger says why a reconciliation runs. Corrections made by Periodic and Manual passes are
// counted and audited as drift (somebody changed Forgejo behind Capsule's back); Event passes
// are the normal convergence after a role change.
type Trigger string

const (
	TriggerEvent    Trigger = "event"
	TriggerPeriodic Trigger = "periodic"
	TriggerManual   Trigger = "manual"
)

// TeamSpecs returns the spec of the team of each role of a project. Owner decision: admin and
// deployer both map to write; nobody but the Capsule service account is admin of a repo in
// Forgejo, so no team gets "admin" and repo settings never show up for humans. Issues, wiki,
// projects and packages are off.
func TeamSpecs(projectSlug string) map[authz.Role]gitcore.TeamSpec {
	units := []string{"repo.code", "repo.pulls", "repo.releases", "repo.actions"}
	return map[authz.Role]gitcore.TeamSpec{
		authz.RoleAdmin:    {Name: projectSlug + "-admin", Permission: "write", Units: units},
		authz.RoleDeployer: {Name: projectSlug + "-deployer", Permission: "write", Units: units},
		authz.RoleViewer:   {Name: projectSlug + "-viewer", Permission: "read", Units: units},
	}
}

// Roles in a fixed order (deterministic processing and tests).
var Roles = []authz.Role{authz.RoleAdmin, authz.RoleDeployer, authz.RoleViewer}
