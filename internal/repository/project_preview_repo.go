package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

// ListByOrgIncludingPreviews lists projects of the org together with ephemeral
// PR preview projects (the normal ListByOrg hides them).
func (r *ProjectRepository) ListByOrgIncludingPreviews(ctx context.Context, orgID uuid.UUID, page, perPage int) ([]*domain.Project, int, error) {
	const q = `
		SELECT id, org_id, name, slug, repo_url, branch, build_strategy, deploy_type, runtime,
		       serverless, replicas, status, labels, created_at, updated_at
		FROM projects WHERE org_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`
	rows, err := r.pool.Query(ctx, q, orgID, perPage, (page-1)*perPage)
	if err != nil {
		return nil, 0, fmt.Errorf("querying projects: %w", err)
	}
	defer rows.Close()
	var projects []*domain.Project
	for rows.Next() {
		p, err := r.scanRow(rows)
		if err != nil {
			return nil, 0, err
		}
		projects = append(projects, p)
	}
	var total int
	_ = r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM projects WHERE org_id = $1 AND deleted_at IS NULL`, orgID).Scan(&total)
	return projects, total, nil
}
