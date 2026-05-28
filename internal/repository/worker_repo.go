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

// WorkerRepository implements domain.WorkerRepository using PostgreSQL.
type WorkerRepository struct{ pool *pgxpool.Pool }

// NewWorkerRepository creates a new WorkerRepository.
func NewWorkerRepository(pool *pgxpool.Pool) *WorkerRepository { return &WorkerRepository{pool: pool} }

// Create inserts a new worker record.
func (r *WorkerRepository) Create(ctx context.Context, w *domain.Worker) (*domain.Worker, error) {
	var out domain.Worker
	err := r.pool.QueryRow(ctx, `
		INSERT INTO workers (project_id, name, command, replicas, restart_policy, worker_type, queue_url)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, project_id, name, command, replicas, status, container_id,
		          restart_policy, worker_type, queue_url, created_at, updated_at`,
		w.ProjectID, w.Name, w.Command, w.Replicas, w.RestartPolicy,
		w.WorkerType, w.QueueURL,
	).Scan(&out.ID, &out.ProjectID, &out.Name, &out.Command, &out.Replicas,
		&out.Status, &out.ContainerID, &out.RestartPolicy, &out.WorkerType, &out.QueueURL,
		&out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating worker: %w", err)
	}
	return &out, nil
}

// GetByID fetches a single worker by ID.
func (r *WorkerRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Worker, error) {
	var out domain.Worker
	err := r.pool.QueryRow(ctx, `
		SELECT id, project_id, name, command, replicas, status, container_id,
		       restart_policy, worker_type, queue_url, created_at, updated_at
		FROM workers WHERE id = $1 AND deleted_at IS NULL`, id,
	).Scan(&out.ID, &out.ProjectID, &out.Name, &out.Command, &out.Replicas,
		&out.Status, &out.ContainerID, &out.RestartPolicy, &out.WorkerType, &out.QueueURL,
		&out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting worker: %w", err)
	}
	return &out, nil
}

// ListByProject returns all workers for a project.
func (r *WorkerRepository) ListByProject(ctx context.Context, projectID uuid.UUID) ([]*domain.Worker, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, project_id, name, command, replicas, status, container_id,
		       restart_policy, worker_type, queue_url, created_at, updated_at
		FROM workers WHERE project_id = $1 AND deleted_at IS NULL ORDER BY created_at`, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing workers: %w", err)
	}
	defer rows.Close()
	var out []*domain.Worker
	for rows.Next() {
		var w domain.Worker
		if err := rows.Scan(&w.ID, &w.ProjectID, &w.Name, &w.Command, &w.Replicas,
			&w.Status, &w.ContainerID, &w.RestartPolicy, &w.WorkerType, &w.QueueURL,
			&w.CreatedAt, &w.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning worker: %w", err)
		}
		out = append(out, &w)
	}
	return out, nil
}

// UpdateStatus updates the status and container ID of a worker.
func (r *WorkerRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status, containerID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE workers SET status = $2, container_id = $3, updated_at = now() WHERE id = $1`,
		id, status, containerID)
	return err
}

// Delete soft-deletes a worker.
func (r *WorkerRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE workers SET deleted_at = now() WHERE id = $1`, id)
	return err
}

// ensure interface is satisfied at compile time.
var _ domain.WorkerRepository = (*WorkerRepository)(nil)
