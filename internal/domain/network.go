package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// DatabaseAccessRule allows one CIDR to reach a database's published port.
type DatabaseAccessRule struct {
	ID          uuid.UUID  `json:"id"`
	DatabaseID  uuid.UUID  `json:"database_id"`
	CIDR        string     `json:"cidr"`
	Description string     `json:"description"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// DesiredAccess is a rule joined with its database's host port (startup reconcile).
type DesiredAccess struct {
	DatabaseID uuid.UUID
	Port       int
	CIDR       string
}

// DatabaseAccessRepository persists database access rules.
type DatabaseAccessRepository interface {
	List(ctx context.Context, databaseID uuid.UUID) ([]*DatabaseAccessRule, error)
	// ListDesired returns every rule of every live database with a published port.
	ListDesired(ctx context.Context) ([]DesiredAccess, error)
	// Replace makes the stored rules equal to rules (idempotent) and returns the result.
	Replace(ctx context.Context, databaseID uuid.UUID, rules []*DatabaseAccessRule, createdBy uuid.UUID) ([]*DatabaseAccessRule, error)
	// Add inserts a rule; ErrConflict if the CIDR exists, ErrRuleLimit past max.
	Add(ctx context.Context, rule *DatabaseAccessRule, max int) (*DatabaseAccessRule, error)
	Delete(ctx context.Context, databaseID, ruleID uuid.UUID) error
	DeleteAll(ctx context.Context, databaseID uuid.UUID) error
}

// ProjectNetworkRepository stores the per-project application IP allowlist.
type ProjectNetworkRepository interface {
	GetIPAllowlist(ctx context.Context, projectID uuid.UUID) ([]string, error)
	SetIPAllowlist(ctx context.Context, projectID uuid.UUID, cidrs []string) error
}
