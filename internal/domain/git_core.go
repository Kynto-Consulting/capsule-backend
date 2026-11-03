package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Provision states of a project's repository in the core Git service (Forgejo).
const (
	GitCorePending = "pending"
	GitCoreReady   = "ready"
	GitCoreFailed  = "failed"
)

// GitCoreState tracks the (retried) provisioning of a project's repository.
type GitCoreState struct {
	ProjectID     uuid.UUID `json:"project_id"`
	Status        string    `json:"status"`
	Attempts      int       `json:"attempts"`
	LastError     string    `json:"last_error,omitempty"`
	ImportURL     string    `json:"-"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// GitTeamSync is a project member whose Forgejo team membership is still pending
// (the Forgejo user does not exist until the first OIDC login).
type GitTeamSync struct {
	ProjectID     uuid.UUID
	UserID        uuid.UUID
	Attempts      int
	LastError     string
	NextAttemptAt time.Time
	CreatedAt     time.Time
}

// GitCoreStore persists provisioning state and pending team synchronization.
type GitCoreStore interface {
	GetState(ctx context.Context, projectID uuid.UUID) (*GitCoreState, error)
	// PutState inserts or replaces the state of a project.
	PutState(ctx context.Context, s *GitCoreState) error
	// ListDueStates returns pending states whose next_attempt_at has passed.
	ListDueStates(ctx context.Context, now time.Time, limit int) ([]*GitCoreState, error)
	// ReplaceTeamSync makes pending exactly the given users of the project: rows of other
	// users are deleted, the given ones inserted (or their attempts incremented).
	ReplaceTeamSync(ctx context.Context, projectID uuid.UUID, pending []uuid.UUID, lastErr string, next time.Time) error
	// ListDueTeamSync returns pending rows whose next_attempt_at has passed.
	ListDueTeamSync(ctx context.Context, now time.Time, limit int) ([]*GitTeamSync, error)
}
