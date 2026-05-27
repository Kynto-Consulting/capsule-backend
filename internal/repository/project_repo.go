package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
)

type ProjectRepository struct {
	pool *pgxpool.Pool
}

func NewProjectRepository(pool *pgxpool.Pool) *ProjectRepository {
	return &ProjectRepository{pool: pool}
}

func (r *ProjectRepository) Create(ctx context.Context, p *domain.Project) (*domain.Project, error) {
	const q = `
		INSERT INTO projects (org_id, name, slug, repo_url, branch, build_strategy, runtime, serverless, replicas, status, labels)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'created', '{}')
		RETURNING id, org_id, name, slug, repo_url, branch, build_strategy, runtime,
		          serverless, replicas, status, labels, created_at, updated_at`

	var created domain.Project
	err := r.pool.QueryRow(ctx, q,
		p.OrgID, p.Name, p.Slug, p.RepoURL, p.Branch,
		p.BuildStrategy, p.Runtime, p.Serverless, p.Replicas,
	).Scan(
		&created.ID, &created.OrgID, &created.Name, &created.Slug,
		&created.RepoURL, &created.Branch, &created.BuildStrategy, &created.Runtime,
		&created.Serverless, &created.Replicas, &created.Status, &created.Labels,
		&created.CreatedAt, &created.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting project: %w", err)
	}
	return &created, nil
}

func (r *ProjectRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Project, error) {
	const q = `
		SELECT id, org_id, name, slug, repo_url, branch, build_strategy, runtime,
		       serverless, replicas, status, labels, created_at, updated_at
		FROM projects WHERE id = $1 AND deleted_at IS NULL`
	return r.scanOne(ctx, q, id)
}

func (r *ProjectRepository) GetBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*domain.Project, error) {
	const q = `
		SELECT id, org_id, name, slug, repo_url, branch, build_strategy, runtime,
		       serverless, replicas, status, labels, created_at, updated_at
		FROM projects WHERE org_id = $1 AND slug = $2 AND deleted_at IS NULL`
	return r.scanOne(ctx, q, orgID, slug)
}

func (r *ProjectRepository) GetBySlugGlobal(ctx context.Context, slug string) (*domain.Project, error) {
	const q = `
		SELECT id, org_id, name, slug, repo_url, branch, build_strategy, runtime,
		       serverless, replicas, status, labels, created_at, updated_at
		FROM projects WHERE slug = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC LIMIT 1`
	return r.scanOne(ctx, q, slug)
}

func (r *ProjectRepository) ListByOrg(ctx context.Context, orgID uuid.UUID, page, perPage int) ([]*domain.Project, int, error) {
	const q = `
		SELECT id, org_id, name, slug, repo_url, branch, build_strategy, runtime,
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
	_ = r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM projects WHERE org_id = $1 AND deleted_at IS NULL`, orgID,
	).Scan(&total)

	return projects, total, nil
}

func (r *ProjectRepository) Update(ctx context.Context, p *domain.Project) (*domain.Project, error) {
	const q = `
		UPDATE projects
		SET name = $2, repo_url = $3, branch = $4, build_strategy = $5,
		    runtime = $6, serverless = $7, replicas = $8, updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING id, org_id, name, slug, repo_url, branch, build_strategy, runtime,
		          serverless, replicas, status, labels, created_at, updated_at`
	return r.scanOne(ctx, q, p.ID, p.Name, p.RepoURL, p.Branch, p.BuildStrategy, p.Runtime, p.Serverless, p.Replicas)
}

func (r *ProjectRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE projects SET deleted_at = now(), status = 'archived' WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("deleting project: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *ProjectRepository) scanOne(ctx context.Context, q string, args ...any) (*domain.Project, error) {
	row := r.pool.QueryRow(ctx, q, args...)
	p, err := r.scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return p, err
}

func (r *ProjectRepository) scanRow(row interface {
	Scan(...any) error
}) (*domain.Project, error) {
	var p domain.Project
	err := row.Scan(
		&p.ID, &p.OrgID, &p.Name, &p.Slug, &p.RepoURL, &p.Branch,
		&p.BuildStrategy, &p.Runtime, &p.Serverless, &p.Replicas,
		&p.Status, &p.Labels, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning project: %w", err)
	}
	return &p, nil
}
