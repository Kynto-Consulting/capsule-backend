package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kynto/capsule/backend/internal/domain"
)

// NewAssignment is the input of Assign.
type NewAssignment struct {
	SubjectType   string // user | group
	SubjectID     uuid.UUID
	ScopeType     string // org | project | repo | env
	ScopeID       uuid.UUID
	TemplateID    uuid.UUID
	PinnedVersion *int
	Source        string // "" = manual
	Reason        string
	ExpiresAt     *time.Time
	CreatedBy     *uuid.UUID
}

// Assign creates a live assignment, or updates pin, expiry and reason of the identical live one (idempotent "change").
// created reports whether a new row was inserted. The organization of scope, subject and template is verified by a trigger
// (confused deputy, SPEC 13.2); the no-escalation rule is the service's job. An archived template cannot be assigned.
func (s *AccessStore) Assign(ctx context.Context, orgID uuid.UUID, in NewAssignment) (a *AccessAssignment, created bool, err error) {
	if in.Source == "" {
		in.Source = "manual"
	}
	var out AccessAssignment
	err = s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		var archived bool
		var cur int
		if err := tx.QueryRow(ctx, `SELECT archived_at IS NOT NULL, current_version FROM role_templates WHERE id = $1 AND (org_id = $2 OR system)`,
			in.TemplateID, orgID).Scan(&archived, &cur); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrNotFound
			}
			return err
		}
		if archived {
			return ErrTemplateArchived
		}
		if in.PinnedVersion != nil && (*in.PinnedVersion < 1 || *in.PinnedVersion > cur) {
			return fmt.Errorf("%w: pinned version %d does not exist", ErrAccessInvalid, *in.PinnedVersion)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM access_assignments WHERE org_id = $1 AND revoked_at IS NULL`, orgID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxAssignmentsPerOrg {
			return fmt.Errorf("%w: %d assignments per organization", ErrAccessLimit, MaxAssignmentsPerOrg)
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO access_assignments (org_id, subject_type, subject_id, scope_type, scope_id, template_id, pinned_version, source, reason, expires_at, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT (subject_type, subject_id, scope_type, scope_id, template_id) WHERE revoked_at IS NULL
			DO UPDATE SET pinned_version = EXCLUDED.pinned_version, expires_at = EXCLUDED.expires_at, reason = EXCLUDED.reason
			RETURNING id, org_id, subject_type, subject_id, scope_type, scope_id, template_id, pinned_version, source, reason, expires_at, created_by, created_at,
			          (xmax = 0)`,
			orgID, in.SubjectType, in.SubjectID, in.ScopeType, in.ScopeID, in.TemplateID, in.PinnedVersion, in.Source, in.Reason, in.ExpiresAt, in.CreatedBy)
		if err := row.Scan(&out.ID, &out.OrgID, &out.SubjectType, &out.SubjectID, &out.ScopeType, &out.ScopeID, &out.TemplateID, &out.PinnedVersion,
			&out.Source, &out.Reason, &out.ExpiresAt, &out.CreatedBy, &out.CreatedAt, &created); err != nil {
			return mapAccessErr(err)
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return &out, created, nil
}

// Revoke revokes a live assignment of the organization (the row stays for the audit trail). ErrNotFound if it is not live.
func (s *AccessStore) Revoke(ctx context.Context, orgID, assignmentID uuid.UUID, by *uuid.UUID) error {
	return s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE access_assignments SET revoked_at = now(), revoked_by = $3 WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`,
			assignmentID, orgID, by)
		if err != nil {
			return mapAccessErr(err)
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

// ListScopeAssignments lists the live assignments on a scope ("who has access to X"), using idx_access_assign_scope.
func (s *AccessStore) ListScopeAssignments(ctx context.Context, orgID uuid.UUID, scopeType string, scopeID uuid.UUID) ([]AccessAssignment, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+assignmentCols+` FROM access_assignments a
		 WHERE a.scope_type = $1 AND a.scope_id = $2 AND a.org_id = $3 AND a.revoked_at IS NULL ORDER BY a.created_at`, scopeType, scopeID, orgID)
	if err != nil {
		return nil, fmt.Errorf("listing scope assignments: %w", err)
	}
	defer rows.Close()
	var out []AccessAssignment
	for rows.Next() {
		var a AccessAssignment
		if err := scanAssignment(rows, &a, false); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
