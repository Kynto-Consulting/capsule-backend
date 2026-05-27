package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
)

// ExecutionLogRepository implements domain.ExecutionLogRepository using PostgreSQL.
type ExecutionLogRepository struct{ pool *pgxpool.Pool }

// NewExecutionLogRepository creates a new ExecutionLogRepository.
func NewExecutionLogRepository(pool *pgxpool.Pool) *ExecutionLogRepository {
	return &ExecutionLogRepository{pool: pool}
}

// Append inserts a new execution log entry.
func (r *ExecutionLogRepository) Append(ctx context.Context, log *domain.ExecutionLog) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO execution_logs (project_id, source, source_id, level, message)
		VALUES ($1, $2, $3, $4, $5)`,
		log.ProjectID, log.Source, log.SourceID, log.Level, log.Message,
	)
	if err != nil {
		return fmt.Errorf("appending execution log: %w", err)
	}
	return nil
}

// ListByProject returns recent execution logs for a project, optionally filtered by source.
// Pass source="" to return logs for all sources.
func (r *ExecutionLogRepository) ListByProject(ctx context.Context, projectID uuid.UUID, source string, limit int) ([]*domain.ExecutionLog, error) {
	if limit <= 0 {
		limit = 100
	}
	var (
		rows pgx.Rows
		err  error
	)
	if source == "" {
		rows, err = r.pool.Query(ctx, `
			SELECT id, project_id, source, source_id, level, message, created_at
			FROM execution_logs
			WHERE project_id = $1
			ORDER BY created_at DESC
			LIMIT $2`,
			projectID, limit,
		)
	} else {
		rows, err = r.pool.Query(ctx, `
			SELECT id, project_id, source, source_id, level, message, created_at
			FROM execution_logs
			WHERE project_id = $1 AND source = $2
			ORDER BY created_at DESC
			LIMIT $3`,
			projectID, source, limit,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing execution logs by project: %w", err)
	}
	return scanExecutionLogRows(rows)
}

// ListBySource returns recent execution logs for a specific source within a project.
func (r *ExecutionLogRepository) ListBySource(ctx context.Context, projectID uuid.UUID, source, sourceID string, limit int) ([]*domain.ExecutionLog, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, project_id, source, source_id, level, message, created_at
		FROM execution_logs
		WHERE project_id = $1 AND source = $2 AND source_id = $3
		ORDER BY created_at DESC
		LIMIT $4`,
		projectID, source, sourceID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("listing execution logs by source: %w", err)
	}
	return scanExecutionLogRows(rows)
}

// ListSources returns distinct source_id values for a project+source.
func (r *ExecutionLogRepository) ListSources(ctx context.Context, projectID uuid.UUID, source string) ([]string, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT source_id
		FROM execution_logs
		WHERE project_id = $1 AND source = $2
		ORDER BY source_id`,
		projectID, source,
	)
	if err != nil {
		return nil, fmt.Errorf("listing execution log sources: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scanning source_id: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func scanExecutionLogRows(rows pgx.Rows) ([]*domain.ExecutionLog, error) {
	defer rows.Close()
	var out []*domain.ExecutionLog
	for rows.Next() {
		var l domain.ExecutionLog
		if err := rows.Scan(&l.ID, &l.ProjectID, &l.Source, &l.SourceID, &l.Level, &l.Message, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning execution log: %w", err)
		}
		out = append(out, &l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating execution logs: %w", err)
	}
	return out, nil
}

// ensure interface is satisfied at compile time.
var _ domain.ExecutionLogRepository = (*ExecutionLogRepository)(nil)
