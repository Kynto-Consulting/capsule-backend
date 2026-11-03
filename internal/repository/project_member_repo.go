package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
)

type rowScanner interface{ Scan(...any) error }

const projectMemberCols = `project_id, user_id, role, created_by, created_at`

func scanProjectMember(row rowScanner, m *authz.Member) error {
	return row.Scan(&m.ProjectID, &m.UserID, &m.Role, &m.CreatedBy, &m.CreatedAt)
}

const explicitRoleCols = `project_id, role`

func scanExplicitRole(row rowScanner, id *uuid.UUID, role *string) error {
	return row.Scan(id, role)
}

const grantCols = `o.id, o.slug, p.id, p.slug, om.role, o.project_access_mode, COALESCE(pm.role, '')`

func scanGrant(row rowScanner, g *authz.Grant) error {
	return row.Scan(&g.OrgID, &g.OrgSlug, &g.ProjectID, &g.ProjectSlug, &g.OrgRole, &g.Mode, &g.ExplicitRole)
}

// ProjectMemberRepository implements authz.MemberStore.
type ProjectMemberRepository struct{ pool *pgxpool.Pool }

func NewProjectMemberRepository(pool *pgxpool.Pool) *ProjectMemberRepository {
	return &ProjectMemberRepository{pool: pool}
}

var _ authz.MemberStore = (*ProjectMemberRepository)(nil)

func (r *ProjectMemberRepository) LoadOrgAccess(ctx context.Context, orgID, userID uuid.UUID) (*authz.OrgAccess, error) {
	var role, mode string
	err := r.pool.QueryRow(ctx, `
		SELECT om.role, o.project_access_mode
		FROM org_members om JOIN organizations o ON o.id = om.org_id
		WHERE om.org_id = $1 AND om.user_id = $2 AND o.deleted_at IS NULL`,
		orgID, userID).Scan(&role, &mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading org access: %w", err)
	}
	oa := &authz.OrgAccess{OrgRole: role, Mode: mode, Explicit: map[uuid.UUID]string{}}
	rows, err := r.pool.Query(ctx, `
		SELECT `+explicitRoleCols+` FROM project_members pm
		WHERE pm.user_id = $1
		  AND pm.project_id IN (SELECT id FROM projects WHERE org_id = $2)`,
		userID, orgID)
	if err != nil {
		return nil, fmt.Errorf("loading explicit roles: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var pr string
		if err := scanExplicitRole(rows, &id, &pr); err != nil {
			return nil, fmt.Errorf("scanning explicit role: %w", err)
		}
		oa.Explicit[id] = pr
	}
	return oa, rows.Err()
}

func (r *ProjectMemberRepository) UserGrants(ctx context.Context, userID uuid.UUID) ([]authz.Grant, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+grantCols+`
		FROM org_members om
		JOIN organizations o ON o.id = om.org_id AND o.deleted_at IS NULL
		JOIN projects p ON p.org_id = o.id AND p.deleted_at IS NULL
		LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = om.user_id
		WHERE om.user_id = $1
		ORDER BY o.slug, p.slug`, userID)
	if err != nil {
		return nil, fmt.Errorf("querying grants: %w", err)
	}
	defer rows.Close()
	var out []authz.Grant
	for rows.Next() {
		var g authz.Grant
		if err := scanGrant(rows, &g); err != nil {
			return nil, fmt.Errorf("scanning grant: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (r *ProjectMemberRepository) ListExplicit(ctx context.Context, projectID uuid.UUID) ([]authz.Member, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+projectMemberCols+` FROM project_members WHERE project_id = $1 ORDER BY created_at`, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing project members: %w", err)
	}
	defer rows.Close()
	var out []authz.Member
	for rows.Next() {
		var m authz.Member
		if err := scanProjectMember(rows, &m); err != nil {
			return nil, fmt.Errorf("scanning project member: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (r *ProjectMemberRepository) UpsertMember(ctx context.Context, projectID, userID uuid.UUID, role string, createdBy uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO project_members (project_id, user_id, role, created_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
		projectID, userID, role, createdBy)
	if err != nil {
		return fmt.Errorf("upserting project member: %w", err)
	}
	return nil
}

func (r *ProjectMemberRepository) RemoveMember(ctx context.Context, projectID, userID uuid.UUID) (bool, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM project_members WHERE project_id = $1 AND user_id = $2`, projectID, userID)
	if err != nil {
		return false, fmt.Errorf("removing project member: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (r *ProjectMemberRepository) CountEffectiveAdmins(ctx context.Context, orgID, projectID uuid.UUID) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM org_members om
		WHERE om.org_id = $1
		  AND (om.role IN ('owner', 'admin')
		       OR (om.role = 'member' AND EXISTS (
		             SELECT 1 FROM project_members pm
		             WHERE pm.project_id = $2 AND pm.user_id = om.user_id AND pm.role = 'admin')))`,
		orgID, projectID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("counting project admins: %w", err)
	}
	return n, nil
}

func (r *ProjectMemberRepository) SetOrgAccessMode(ctx context.Context, orgID uuid.UUID, mode string) error {
	tag, err := r.pool.Exec(ctx, `UPDATE organizations SET project_access_mode = $1, updated_at = now() WHERE id = $2 AND deleted_at IS NULL`, mode, orgID)
	if err != nil {
		return fmt.Errorf("setting project access mode: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *ProjectMemberRepository) GetOrgAccessMode(ctx context.Context, orgID uuid.UUID) (string, error) {
	var mode string
	err := r.pool.QueryRow(ctx, `SELECT project_access_mode FROM organizations WHERE id = $1 AND deleted_at IS NULL`, orgID).Scan(&mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("getting project access mode: %w", err)
	}
	return mode, nil
}

func (r *ProjectMemberRepository) Audit(ctx context.Context, e authz.AuditEntry) error {
	var ip any
	if e.IP != "" {
		ip = e.IP
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO audit_logs (user_id, org_id, action, resource_type, resource_id, ip_address, old_values, new_values)
		VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8)`,
		e.UserID, e.OrgID, e.Action, e.ResourceType, e.ResourceID, ip, e.OldValues, e.NewValues)
	if err != nil {
		return fmt.Errorf("writing audit log: %w", err)
	}
	return nil
}
