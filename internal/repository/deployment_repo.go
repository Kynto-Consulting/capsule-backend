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

type DeploymentRepository struct {
	pool *pgxpool.Pool
}

func NewDeploymentRepository(pool *pgxpool.Pool) *DeploymentRepository {
	return &DeploymentRepository{pool: pool}
}

func (r *DeploymentRepository) Create(ctx context.Context, d *domain.Deployment) (*domain.Deployment, error) {
	const q = `
		INSERT INTO deployments
		  (project_id, version, git_sha, status, build_strategy, container_port, trigger, triggered_by, source_key)
		VALUES ($1, $2, $3, 'queued', $4, $5, $6, $7, $8)
		RETURNING id, project_id, server_id, version, git_sha, status, image_tag, build_strategy,
		          container_port, build_duration_ms, deploy_duration_ms, trigger, triggered_by,
		          started_at, completed_at, created_at, source_key, host_port`

	var out domain.Deployment
	var gitSHA, imageTag *string
	err := r.pool.QueryRow(ctx, q,
		d.ProjectID, d.Version, d.GitSHA, d.BuildStrategy, d.ContainerPort, d.Trigger, d.TriggeredBy, d.SourceKey,
	).Scan(
		&out.ID, &out.ProjectID, &out.ServerID, &out.Version, &gitSHA, &out.Status,
		&imageTag, &out.BuildStrategy, &out.ContainerPort, &out.BuildDurationMs,
		&out.DeployDurationMs, &out.Trigger, &out.TriggeredBy, &out.StartedAt, &out.CompletedAt,
		&out.CreatedAt, &out.SourceKey, &out.HostPort,
	)
	if err != nil {
		fmt.Printf("DATABASE ERROR IN CREATE DEPLOYMENT: %v\n", err)
		return nil, fmt.Errorf("creating deployment: %w", err)
	}
	if gitSHA != nil {
		out.GitSHA = *gitSHA
	}
	if imageTag != nil {
		out.ImageTag = *imageTag
	}
	return &out, nil
}

func (r *DeploymentRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Deployment, error) {
	const q = `
		SELECT id, project_id, server_id, version, git_sha, status, image_tag, build_strategy,
		       container_port, build_duration_ms, deploy_duration_ms, trigger, triggered_by,
		       started_at, completed_at, created_at, source_key, host_port
		FROM deployments WHERE id = $1`
	return r.scanOne(ctx, q, id)
}

func (r *DeploymentRepository) ListByProject(ctx context.Context, projectID uuid.UUID, page, perPage int) ([]*domain.Deployment, int, error) {
	const q = `
		SELECT id, project_id, server_id, version, git_sha, status, image_tag, build_strategy,
		       container_port, build_duration_ms, deploy_duration_ms, trigger, triggered_by,
		       started_at, completed_at, created_at, source_key, host_port
		FROM deployments WHERE project_id = $1
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	rows, err := r.pool.Query(ctx, q, projectID, perPage, (page-1)*perPage)
	if err != nil {
		return nil, 0, fmt.Errorf("querying deployments: %w", err)
	}
	defer rows.Close()

	var out []*domain.Deployment
	for rows.Next() {
		d, err := r.scanRow(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}

	var total int
	_ = r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM deployments WHERE project_id = $1`, projectID,
	).Scan(&total)

	return out, total, nil
}

func (r *DeploymentRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	var q string
	switch status {
	case "building", "deploying":
		q = `UPDATE deployments SET status = $2, started_at = COALESCE(started_at, now()) WHERE id = $1`
	case "success", "failed", "cancelled":
		q = `UPDATE deployments SET status = $2, completed_at = now() WHERE id = $1`
	default:
		q = `UPDATE deployments SET status = $2 WHERE id = $1`
	}
	_, err := r.pool.Exec(ctx, q, id, status)
	return err
}

func (r *DeploymentRepository) AppendLog(ctx context.Context, log *domain.BuildLog) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO build_logs (deployment_id, level, message) VALUES ($1, $2, $3)`,
		log.DeploymentID, log.Level, log.Message,
	)
	return err
}

func (r *DeploymentRepository) GetLogs(ctx context.Context, deploymentID uuid.UUID) ([]*domain.BuildLog, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, deployment_id, level, message, created_at FROM build_logs WHERE deployment_id = $1 ORDER BY created_at`,
		deploymentID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying logs: %w", err)
	}
	defer rows.Close()

	var out []*domain.BuildLog
	for rows.Next() {
		var l domain.BuildLog
		if err := rows.Scan(&l.ID, &l.DeploymentID, &l.Level, &l.Message, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning log: %w", err)
		}
		out = append(out, &l)
	}
	return out, nil
}

func (r *DeploymentRepository) scanOne(ctx context.Context, q string, args ...any) (*domain.Deployment, error) {
	row := r.pool.QueryRow(ctx, q, args...)
	d, err := r.scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return d, err
}

func (r *DeploymentRepository) scanRow(row interface{ Scan(...any) error }) (*domain.Deployment, error) {
	var d domain.Deployment
	var gitSHA, imageTag *string
	err := row.Scan(
		&d.ID, &d.ProjectID, &d.ServerID, &d.Version, &gitSHA, &d.Status,
		&imageTag, &d.BuildStrategy, &d.ContainerPort, &d.BuildDurationMs,
		&d.DeployDurationMs, &d.Trigger, &d.TriggeredBy, &d.StartedAt, &d.CompletedAt,
		&d.CreatedAt, &d.SourceKey, &d.HostPort,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning deployment: %w", err)
	}
	if gitSHA != nil {
		d.GitSHA = *gitSHA
	}
	if imageTag != nil {
		d.ImageTag = *imageTag
	}
	return &d, nil
}

func (r *DeploymentRepository) UpdateHostPort(ctx context.Context, id uuid.UUID, hostPort int) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE deployments SET host_port = $1 WHERE id = $2`,
		hostPort, id,
	)
	return err
}

func (r *DeploymentRepository) Cancel(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE deployments SET status = 'cancelled', completed_at = now() WHERE id = $1 AND status IN ('queued','building','deploying')`,
		id,
	)
	return err
}
