package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
)

// CronJobRepository implements domain.CronJobRepository using PostgreSQL.
type CronJobRepository struct{ pool *pgxpool.Pool }

// NewCronJobRepository creates a new CronJobRepository.
func NewCronJobRepository(pool *pgxpool.Pool) *CronJobRepository {
	return &CronJobRepository{pool: pool}
}

// Create inserts a new cron job record.
func (r *CronJobRepository) Create(ctx context.Context, c *domain.CronJob) (*domain.CronJob, error) {
	var out domain.CronJob
	err := r.pool.QueryRow(ctx, `
		INSERT INTO cronjobs (project_id, name, schedule, command, timezone)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, project_id, name, schedule, command, timezone, status, last_run_status, last_run_at, next_run_at, created_at, updated_at`,
		c.ProjectID, c.Name, c.Schedule, c.Command, c.Timezone,
	).Scan(&out.ID, &out.ProjectID, &out.Name, &out.Schedule, &out.Command, &out.Timezone,
		&out.Status, &out.LastRunStatus, &out.LastRunAt, &out.NextRunAt, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating cronjob: %w", err)
	}
	return &out, nil
}

// GetByID fetches a single cron job by ID.
func (r *CronJobRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.CronJob, error) {
	var out domain.CronJob
	err := r.pool.QueryRow(ctx, `
		SELECT id, project_id, name, schedule, command, timezone, status, last_run_status, last_run_at, next_run_at, created_at, updated_at
		FROM cronjobs WHERE id = $1 AND deleted_at IS NULL`, id,
	).Scan(&out.ID, &out.ProjectID, &out.Name, &out.Schedule, &out.Command, &out.Timezone,
		&out.Status, &out.LastRunStatus, &out.LastRunAt, &out.NextRunAt, &out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting cronjob: %w", err)
	}
	return &out, nil
}

// ListByProject returns all cron jobs for a project.
func (r *CronJobRepository) ListByProject(ctx context.Context, projectID uuid.UUID) ([]*domain.CronJob, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, project_id, name, schedule, command, timezone, status, last_run_status, last_run_at, next_run_at, created_at, updated_at
		FROM cronjobs WHERE project_id = $1 AND deleted_at IS NULL ORDER BY created_at`, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing cronjobs: %w", err)
	}
	defer rows.Close()
	var out []*domain.CronJob
	for rows.Next() {
		var c domain.CronJob
		if err := rows.Scan(&c.ID, &c.ProjectID, &c.Name, &c.Schedule, &c.Command, &c.Timezone,
			&c.Status, &c.LastRunStatus, &c.LastRunAt, &c.NextRunAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning cronjob: %w", err)
		}
		out = append(out, &c)
	}
	return out, nil
}

// UpdateStatus updates the status of a cron job.
func (r *CronJobRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE cronjobs SET status = $2, updated_at = now() WHERE id = $1`, id, status)
	return err
}

// UpdateLastRun records the result of the last execution and the next scheduled run time.
func (r *CronJobRepository) UpdateLastRun(ctx context.Context, id uuid.UUID, runStatus string, nextRunAt *time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE cronjobs SET last_run_status = $2, last_run_at = now(), next_run_at = $3, updated_at = now() WHERE id = $1`,
		id, runStatus, nextRunAt)
	return err
}

// Delete soft-deletes a cron job.
func (r *CronJobRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE cronjobs SET deleted_at = now() WHERE id = $1`, id)
	return err
}

// ListActive returns all active cron jobs ordered by next_run_at.
func (r *CronJobRepository) ListActive(ctx context.Context) ([]*domain.CronJob, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, project_id, name, schedule, command, timezone, status, last_run_status, last_run_at, next_run_at, created_at, updated_at
		FROM cronjobs WHERE status = 'active' AND deleted_at IS NULL ORDER BY next_run_at NULLS FIRST`)
	if err != nil {
		return nil, fmt.Errorf("listing active cronjobs: %w", err)
	}
	defer rows.Close()
	var out []*domain.CronJob
	for rows.Next() {
		var c domain.CronJob
		if err := rows.Scan(&c.ID, &c.ProjectID, &c.Name, &c.Schedule, &c.Command, &c.Timezone,
			&c.Status, &c.LastRunStatus, &c.LastRunAt, &c.NextRunAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning cronjob: %w", err)
		}
		out = append(out, &c)
	}
	return out, nil
}

// ensure interface is satisfied at compile time.
var _ domain.CronJobRepository = (*CronJobRepository)(nil)
