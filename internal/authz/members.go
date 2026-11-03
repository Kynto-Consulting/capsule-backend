package authz

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Member is an explicit project_members row.
type Member struct {
	ProjectID uuid.UUID  `json:"project_id"`
	UserID    uuid.UUID  `json:"user_id"`
	Role      string     `json:"role"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// AuditEntry is written to audit_logs.
type AuditEntry struct {
	OrgID        uuid.UUID
	UserID       uuid.UUID
	Action       string
	ResourceType string
	ResourceID   uuid.UUID
	IP           string
	OldValues    map[string]any
	NewValues    map[string]any
}

// MemberStore adds member management on top of Store.
type MemberStore interface {
	Store
	ListExplicit(ctx context.Context, projectID uuid.UUID) ([]Member, error)
	UpsertMember(ctx context.Context, projectID, userID uuid.UUID, role string, createdBy uuid.UUID) error
	// RemoveMember reports whether a row was deleted.
	RemoveMember(ctx context.Context, projectID, userID uuid.UUID) (bool, error)
	// CountEffectiveAdmins counts users who are effective admins of the project:
	// org owners/admins plus org members with an explicit admin row.
	CountEffectiveAdmins(ctx context.Context, orgID, projectID uuid.UUID) (int, error)
	SetOrgAccessMode(ctx context.Context, orgID uuid.UUID, mode string) error
	GetOrgAccessMode(ctx context.Context, orgID uuid.UUID) (string, error)
	Audit(ctx context.Context, e AuditEntry) error
}
