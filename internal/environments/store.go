package environments

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

// Patch carries the fields a Transition may set. NotBefore is always written (nil clears it).
type Patch struct {
	Reason     string
	NotBefore  *time.Time
	QuorumAt   *time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
	Health     string
	Required   *int
}

// Decision is one approve/reject. On approval the store counts the approvals that count and, if
// they reach Required, moves the promotion to QuorumStatus (with QuorumNotBefore) in the SAME
// transaction that holds the promotion row lock, so two simultaneous approvals cannot both miss
// the quorum.
type Decision struct {
	PromotionID     uuid.UUID
	Approval        Approval
	Required        int
	AllowSelf       bool
	QuorumStatus    string
	QuorumNotBefore *time.Time
	QuorumAt        time.Time
	RejectReason    string
	RejectedAt      time.Time
}

// PendingRow is a promotion awaiting approval with the environment it targets.
type PendingRow struct {
	Promotion Promotion
	Env       Environment
}

// Store persists environments, promotions and history. internal/repository.EnvironmentRepository
// implements it on Postgres; tests use an in-memory one.
type Store interface {
	Target(ctx context.Context, projectID uuid.UUID) (Target, error) // ErrNotFound

	ListEnvs(ctx context.Context, projectID uuid.UUID) ([]Environment, error)
	GetEnv(ctx context.Context, projectID uuid.UUID, name string) (*Environment, error)
	GetEnvByID(ctx context.Context, id uuid.UUID) (*Environment, error)
	// CreateEnv inserts and writes the audit entry atomically (ErrDuplicate).
	CreateEnv(ctx context.Context, e *Environment, a AuditEntry) error
	UpdateEnv(ctx context.Context, e *Environment, a AuditEntry) error
	DeleteEnv(ctx context.Context, projectID, id uuid.UUID, a AuditEntry) error
	// CurrentDeployment is the newest successful history row of the environment (nil if none).
	CurrentDeployment(ctx context.Context, envID uuid.UUID) (*EnvDeployment, error)
	ListEnvDeployments(ctx context.Context, envID uuid.UUID, cursor string, limit int) ([]EnvDeployment, string, error)
	// HasSuccess reports the successful history row of sha in the environment, if any.
	SuccessfulSHA(ctx context.Context, envID uuid.UUID, sha string) (*EnvDeployment, *Artifact, error)

	// FindArtifact returns the newest successful deployment of sha in the project with a stored source.
	FindArtifact(ctx context.Context, projectID uuid.UUID, sha string) (*Artifact, error)
	ArtifactOf(ctx context.Context, deploymentID uuid.UUID) (*Artifact, error)

	// FindByIdempotency returns the promotion created with that key by that requester (nil if none).
	FindByIdempotency(ctx context.Context, projectID, requestedBy uuid.UUID, key string) (*Promotion, error)
	WriteAudit(ctx context.Context, a AuditEntry) error
	// CreatePromotion inserts the promotion, its history row and the audit entry atomically. A
	// collision with the idempotency key or with an active promotion of the same SHA returns *ExistingError.
	CreatePromotion(ctx context.Context, p *Promotion, a AuditEntry) error
	GetPromotion(ctx context.Context, id uuid.UUID) (*Promotion, error) // with approvals
	ListPromotions(ctx context.Context, envID uuid.UUID, activeOnly bool) ([]Promotion, error)
	// AddDecision: ErrInvalidState, ErrAlreadyDecided. Returns the promotion after the decision.
	AddDecision(ctx context.Context, d Decision, a AuditEntry) (*Promotion, error)
	// Transition moves the promotion from one of from to to atomically (history row and optional
	// audit entry included). ok is false when it was no longer in from, or when the environment
	// already has a deploying promotion (queue).
	Transition(ctx context.Context, id uuid.UUID, from []string, to string, p Patch, a *AuditEntry) (ok bool, err error)
	SetDeployment(ctx context.Context, id, deploymentID uuid.UUID) error
	// ExpireOverdue marks every pending/waiting/approved promotion with expires_at <= now as expired.
	ExpireOverdue(ctx context.Context, now time.Time) ([]Promotion, error)
	// ListActive returns non-final promotions (any state), oldest first.
	ListActive(ctx context.Context, limit int) ([]Promotion, error)
	// PendingForOrg lists promotions in pending_approval of the organization after cursor (a
	// created_at|id key), oldest first.
	PendingForOrg(ctx context.Context, orgID uuid.UUID, cursor string, limit int) ([]PendingRow, error)
}

// Forge is the slice of gitcore.Core this package uses.
type Forge interface {
	Enabled() bool
	ListBranches(ctx context.Context, r gitcore.RepoRef, p gitcore.Page) (gitcore.List[gitcore.Branch], error)
	ListTags(ctx context.Context, r gitcore.RepoRef, p gitcore.Page) (gitcore.List[gitcore.Tag], error)
	Compare(ctx context.Context, r gitcore.RepoRef, base, head string) (*gitcore.Compare, error)
	GetCommit(ctx context.Context, r gitcore.RepoRef, sha string) (*gitcore.Commit, error)
	ListChecks(ctx context.Context, r gitcore.RepoRef, ref string) (*gitcore.CheckSet, error)
	SetCheck(ctx context.Context, r gitcore.RepoRef, sha string, in gitcore.CheckInput) (*gitcore.Check, error)
}

var _ Forge = gitcore.Core(nil)

// Deployer creates and watches deployments. A promotion REUSES the stored source of a successful
// deployment: Deploy never clones, packages or uploads anything; the existing deploy worker then
// processes the queued deployment exactly like a rollback.
type Deployer interface {
	Deploy(ctx context.Context, projectID uuid.UUID, a Artifact, by *uuid.UUID, meta map[string]string) (uuid.UUID, error)
	// Status returns the deployment status and its health result ("" when none).
	Status(ctx context.Context, deploymentID uuid.UUID) (status, health string, err error)
}

// SecurityGate answers the security policy of a SHA (package B7); nil gate = no policy.
type SecurityGate interface {
	Blocked(ctx context.Context, projectID uuid.UUID, sha string) (blocked bool, reason string, err error)
}

// Directory resolves people and project roles.
type Directory interface {
	// Role is the effective project role of the user; "" when not a member or hidden.
	Role(ctx context.Context, userID, orgID, projectID uuid.UUID) (authz.Role, error)
	Person(ctx context.Context, userID uuid.UUID) (Person, error)
	CountAdmins(ctx context.Context, orgID, projectID uuid.UUID) (int, error)
}

// Publisher is the event surface (gitevents.Publisher satisfies it).
type Publisher = gitevents.Publisher
