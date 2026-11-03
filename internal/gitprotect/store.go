package gitprotect

import (
	"context"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// Store persists rules, sync state and audit. internal/repository.BranchProtectionRepository
// implements it on Postgres; tests use an in-memory one.
type Store interface {
	ListRules(ctx context.Context, projectID uuid.UUID) ([]Rule, error) // oldest first
	GetRule(ctx context.Context, projectID, ruleID uuid.UUID) (*Rule, error)
	// CreateRule inserts the rule, an initial pending sync row and the audit entry in ONE
	// transaction. It fills CreatedAt/UpdatedAt. ErrDuplicate when (project, pattern) exists.
	CreateRule(ctx context.Context, r *Rule, a AuditEntry) error
	// UpdateRule replaces the rule and writes the audit entry atomically (ErrNotFound, ErrDuplicate).
	UpdateRule(ctx context.Context, r *Rule, a AuditEntry) error
	// DeleteRule removes the rule (its sync row cascades) and writes the audit entry atomically.
	DeleteRule(ctx context.Context, projectID, ruleID uuid.UUID, a AuditEntry) error
	ListSync(ctx context.Context, projectID uuid.UUID) (map[uuid.UUID]SyncState, error)
	PutSync(ctx context.Context, s SyncState) error
	// ProjectsWithRules lists projects that have rules, whose repository is provisioned.
	ProjectsWithRules(ctx context.Context) ([]Target, error)
	WriteAudit(ctx context.Context, a AuditEntry) error
}

// Forge is the slice of gitcore.Core this package uses (gitcore.Core satisfies it).
type Forge interface {
	ListProtections(ctx context.Context, r gitcore.RepoRef) ([]gitcore.Protection, error)
	UpsertProtection(ctx context.Context, r gitcore.RepoRef, spec gitcore.ProtectionSpec) (*gitcore.Protection, error)
	DeleteProtection(ctx context.Context, r gitcore.RepoRef, rule string) error
	GetRepo(ctx context.Context, r gitcore.RepoRef) (*gitcore.Repository, error)
	PatchRepo(ctx context.Context, r gitcore.RepoRef, p gitcore.RepoPatch) (*gitcore.Repository, error)
	Enabled() bool
}

var _ Forge = gitcore.Core(nil)
