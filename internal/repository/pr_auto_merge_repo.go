package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitreview"
)

// PRAutoMergeRepository persists pr_auto_merge (Git Capsule B8). Every state change is a single
// conditional UPDATE, so two workers racing on the same pull request cannot both win.
type PRAutoMergeRepository struct{ pool *pgxpool.Pool }

func NewPRAutoMergeRepository(pool *pgxpool.Pool) *PRAutoMergeRepository {
	return &PRAutoMergeRepository{pool: pool}
}

var _ gitreview.AutoMergeStore = (*PRAutoMergeRepository)(nil)

const prAutoMergeCols = `project_id, pr_number, head_sha, merge_style, merge_title, merge_message, delete_branch, requested_by,
	requested_login, state, reason, attempts, last_attempt_at, next_attempt_at, claimed_until, last_error, created_at, updated_at`

func scanPRAutoMerge(row interface{ Scan(...any) error }, a *gitreview.AutoMerge) error {
	var style string
	var by *uuid.UUID
	if err := row.Scan(&a.ProjectID, &a.PR, &a.HeadSHA, &style, &a.Title, &a.Message, &a.DeleteBranch, &by,
		&a.RequestedLogin, &a.State, &a.Reason, &a.Attempts, &a.LastAttemptAt, &a.NextAttemptAt, &a.ClaimedUntil, &a.LastError,
		&a.CreatedAt, &a.UpdatedAt); err != nil {
		return err
	}
	a.Style = gitcore.MergeStyle(style)
	if by != nil {
		a.RequestedBy = *by
	}
	return nil
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func (r *PRAutoMergeRepository) Arm(ctx context.Context, a gitreview.AutoMerge) (*gitreview.AutoMerge, error) {
	next := a.NextAttemptAt
	if next.IsZero() {
		next = time.Now()
	}
	var out gitreview.AutoMerge
	err := scanPRAutoMerge(r.pool.QueryRow(ctx, `
		INSERT INTO pr_auto_merge (project_id, pr_number, head_sha, merge_style, merge_title, merge_message, delete_branch,
			requested_by, requested_login, state, next_attempt_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'armed',$10)
		ON CONFLICT (project_id, pr_number) DO UPDATE SET
			head_sha = EXCLUDED.head_sha, merge_style = EXCLUDED.merge_style, merge_title = EXCLUDED.merge_title,
			merge_message = EXCLUDED.merge_message, delete_branch = EXCLUDED.delete_branch,
			requested_by = EXCLUDED.requested_by, requested_login = EXCLUDED.requested_login,
			state = 'armed', reason = '', attempts = 0, last_attempt_at = NULL, claimed_until = NULL, last_error = '',
			next_attempt_at = EXCLUDED.next_attempt_at, created_at = now(), updated_at = now()
		RETURNING `+prAutoMergeCols,
		a.ProjectID, a.PR, a.HeadSHA, string(a.Style), a.Title, a.Message, a.DeleteBranch, nullUUID(a.RequestedBy), a.RequestedLogin, next), &out)
	if err != nil {
		return nil, fmt.Errorf("arming auto-merge: %w", err)
	}
	return &out, nil
}

func (r *PRAutoMergeRepository) Get(ctx context.Context, projectID uuid.UUID, pr int) (*gitreview.AutoMerge, error) {
	var a gitreview.AutoMerge
	err := scanPRAutoMerge(r.pool.QueryRow(ctx, `SELECT `+prAutoMergeCols+` FROM pr_auto_merge WHERE project_id = $1 AND pr_number = $2`, projectID, pr), &a)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, gitreview.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("reading auto-merge: %w", err)
	}
	return &a, nil
}

func (r *PRAutoMergeRepository) Cancel(ctx context.Context, projectID uuid.UUID, pr int, reason string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `UPDATE pr_auto_merge SET state = 'cancelled', reason = $3, claimed_until = NULL, updated_at = now()
		WHERE project_id = $1 AND pr_number = $2 AND state IN ('armed','merging')`, projectID, pr, reason)
	if err != nil {
		return false, fmt.Errorf("cancelling auto-merge: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func collectPRAutoMerge(rows pgx.Rows, err error) ([]gitreview.AutoMerge, error) {
	if err != nil {
		return nil, fmt.Errorf("listing auto-merges: %w", err)
	}
	defer rows.Close()
	var out []gitreview.AutoMerge
	for rows.Next() {
		var a gitreview.AutoMerge
		if err := scanPRAutoMerge(rows, &a); err != nil {
			return nil, fmt.Errorf("scanning auto-merge: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *PRAutoMergeRepository) ListArmedByHead(ctx context.Context, projectID uuid.UUID, sha string) ([]gitreview.AutoMerge, error) {
	return collectPRAutoMerge(r.pool.Query(ctx, `SELECT `+prAutoMergeCols+` FROM pr_auto_merge
		WHERE project_id = $1 AND state = 'armed' AND lower(head_sha) = lower($2) ORDER BY pr_number`, projectID, sha))
}

func (r *PRAutoMergeRepository) ListDue(ctx context.Context, now time.Time, limit int) ([]gitreview.AutoMerge, error) {
	return collectPRAutoMerge(r.pool.Query(ctx, `SELECT `+prAutoMergeCols+` FROM pr_auto_merge
		WHERE (state = 'armed' AND next_attempt_at <= $1) OR (state = 'merging' AND claimed_until <= $1)
		ORDER BY next_attempt_at LIMIT $2`, now, limit))
}

func (r *PRAutoMergeRepository) Claim(ctx context.Context, projectID uuid.UUID, pr int, headSHA string, now, lease time.Time) (*gitreview.AutoMerge, bool, error) {
	var a gitreview.AutoMerge
	err := scanPRAutoMerge(r.pool.QueryRow(ctx, `UPDATE pr_auto_merge SET state = 'merging', claimed_until = $5, last_attempt_at = $4, updated_at = $4
		WHERE project_id = $1 AND pr_number = $2 AND lower(head_sha) = lower($3)
		  AND (state = 'armed' OR (state = 'merging' AND claimed_until <= $4))
		RETURNING `+prAutoMergeCols, projectID, pr, headSHA, now, lease), &a)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("claiming auto-merge: %w", err)
	}
	return &a, true, nil
}

func (r *PRAutoMergeRepository) Release(ctx context.Context, projectID uuid.UUID, pr int, headSHA string, next time.Time, errMsg string, countAttempt bool) error {
	inc := 0
	if countAttempt {
		inc = 1
	}
	_, err := r.pool.Exec(ctx, `UPDATE pr_auto_merge SET state = 'armed', claimed_until = NULL, next_attempt_at = $4, last_error = $5,
		attempts = attempts + $6, updated_at = now()
		WHERE project_id = $1 AND pr_number = $2 AND lower(head_sha) = lower($3) AND state = 'merging'`, projectID, pr, headSHA, next, errMsg, inc)
	if err != nil {
		return fmt.Errorf("releasing auto-merge: %w", err)
	}
	return nil
}

func (r *PRAutoMergeRepository) Defer(ctx context.Context, projectID uuid.UUID, pr int, next time.Time, note string) error {
	_, err := r.pool.Exec(ctx, `UPDATE pr_auto_merge SET next_attempt_at = $3, last_error = $4, updated_at = now()
		WHERE project_id = $1 AND pr_number = $2 AND state = 'armed'`, projectID, pr, next, note)
	if err != nil {
		return fmt.Errorf("deferring auto-merge: %w", err)
	}
	return nil
}

func (r *PRAutoMergeRepository) Finish(ctx context.Context, projectID uuid.UUID, pr int, state, reason string) error {
	if state != gitreview.StateMerged && state != gitreview.StateCancelled {
		return fmt.Errorf("finishing auto-merge: invalid state %q", state)
	}
	_, err := r.pool.Exec(ctx, `UPDATE pr_auto_merge SET state = $3, reason = $4, claimed_until = NULL, updated_at = now()
		WHERE project_id = $1 AND pr_number = $2 AND state IN ('armed','merging')`, projectID, pr, state, reason)
	if err != nil {
		return fmt.Errorf("finishing auto-merge: %w", err)
	}
	return nil
}
