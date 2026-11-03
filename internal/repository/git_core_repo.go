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

// GitCoreRepository persists git_core_state and git_team_sync.
type GitCoreRepository struct{ pool *pgxpool.Pool }

func NewGitCoreRepository(pool *pgxpool.Pool) *GitCoreRepository {
	return &GitCoreRepository{pool: pool}
}

var _ domain.GitCoreStore = (*GitCoreRepository)(nil)

const gitCoreStateCols = `project_id, status, attempts, last_error, import_url, next_attempt_at, created_at, updated_at`

const gitTeamSyncCols = `project_id, user_id, attempts, last_error, next_attempt_at, created_at`

func scanGitCoreState(row interface{ Scan(...any) error }, s *domain.GitCoreState) error {
	return row.Scan(&s.ProjectID, &s.Status, &s.Attempts, &s.LastError, &s.ImportURL, &s.NextAttemptAt, &s.CreatedAt, &s.UpdatedAt)
}

func scanGitTeamSync(row interface{ Scan(...any) error }, s *domain.GitTeamSync) error {
	return row.Scan(&s.ProjectID, &s.UserID, &s.Attempts, &s.LastError, &s.NextAttemptAt, &s.CreatedAt)
}

func (r *GitCoreRepository) GetState(ctx context.Context, projectID uuid.UUID) (*domain.GitCoreState, error) {
	var s domain.GitCoreState
	err := scanGitCoreState(r.pool.QueryRow(ctx, `SELECT `+gitCoreStateCols+` FROM git_core_state WHERE project_id = $1`, projectID), &s)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading git core state: %w", err)
	}
	return &s, nil
}

func (r *GitCoreRepository) PutState(ctx context.Context, s *domain.GitCoreState) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO git_core_state (project_id, status, attempts, last_error, import_url, next_attempt_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (project_id) DO UPDATE SET
			status = EXCLUDED.status, attempts = EXCLUDED.attempts, last_error = EXCLUDED.last_error,
			import_url = EXCLUDED.import_url, next_attempt_at = EXCLUDED.next_attempt_at, updated_at = now()`,
		s.ProjectID, s.Status, s.Attempts, s.LastError, s.ImportURL, s.NextAttemptAt)
	if err != nil {
		return fmt.Errorf("saving git core state: %w", err)
	}
	return nil
}

func (r *GitCoreRepository) ListDueStates(ctx context.Context, now time.Time, limit int) ([]*domain.GitCoreState, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+gitCoreStateCols+` FROM git_core_state
		WHERE status = 'pending' AND next_attempt_at <= $1 ORDER BY next_attempt_at LIMIT $2`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("listing git core states: %w", err)
	}
	defer rows.Close()
	var out []*domain.GitCoreState
	for rows.Next() {
		var s domain.GitCoreState
		if err := scanGitCoreState(rows, &s); err != nil {
			return nil, fmt.Errorf("scanning git core state: %w", err)
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}

func (r *GitCoreRepository) ReplaceTeamSync(ctx context.Context, projectID uuid.UUID, pending []uuid.UUID, lastErr string, next time.Time) error {
	if pending == nil {
		pending = []uuid.UUID{}
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin team sync: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `DELETE FROM git_team_sync WHERE project_id = $1 AND NOT (user_id = ANY($2))`, projectID, pending); err != nil {
		return fmt.Errorf("pruning team sync: %w", err)
	}
	for _, u := range pending {
		if _, err := tx.Exec(ctx, `
			INSERT INTO git_team_sync (project_id, user_id, attempts, last_error, next_attempt_at)
			VALUES ($1, $2, 1, $3, $4)
			ON CONFLICT (project_id, user_id) DO UPDATE SET
				attempts = git_team_sync.attempts + 1, last_error = EXCLUDED.last_error, next_attempt_at = EXCLUDED.next_attempt_at`,
			projectID, u, lastErr, next); err != nil {
			return fmt.Errorf("saving team sync: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (r *GitCoreRepository) ListDueTeamSync(ctx context.Context, now time.Time, limit int) ([]*domain.GitTeamSync, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+gitTeamSyncCols+` FROM git_team_sync
		WHERE next_attempt_at <= $1 ORDER BY next_attempt_at LIMIT $2`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("listing team sync: %w", err)
	}
	defer rows.Close()
	var out []*domain.GitTeamSync
	for rows.Next() {
		var s domain.GitTeamSync
		if err := scanGitTeamSync(rows, &s); err != nil {
			return nil, fmt.Errorf("scanning team sync: %w", err)
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}
