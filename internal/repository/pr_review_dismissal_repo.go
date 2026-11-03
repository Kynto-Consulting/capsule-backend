package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/gitreview"
)

// PRReviewDismissalRepository persists pr_review_dismissals (Git Capsule B8).
type PRReviewDismissalRepository struct{ pool *pgxpool.Pool }

func NewPRReviewDismissalRepository(pool *pgxpool.Pool) *PRReviewDismissalRepository {
	return &PRReviewDismissalRepository{pool: pool}
}

var _ gitreview.DismissalLog = (*PRReviewDismissalRepository)(nil)

const prReviewDismissalCols = `project_id, pr_number, review_id, reviewer, review_state, commit_sha, dismissed_by, reason, created_at`

func scanPRReviewDismissal(row interface{ Scan(...any) error }, d *gitreview.Dismissal) error {
	var by *uuid.UUID
	if err := row.Scan(&d.ProjectID, &d.PR, &d.ReviewID, &d.Reviewer, &d.ReviewState, &d.CommitSHA, &by, &d.Reason, &d.CreatedAt); err != nil {
		return err
	}
	if by != nil {
		d.DismissedBy = *by
	}
	return nil
}

func (r *PRReviewDismissalRepository) Record(ctx context.Context, d gitreview.Dismissal) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO pr_review_dismissals (project_id, pr_number, review_id, reviewer, review_state, commit_sha, dismissed_by, reason)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, d.ProjectID, d.PR, d.ReviewID, d.Reviewer, d.ReviewState, d.CommitSHA, nullUUID(d.DismissedBy), d.Reason)
	if err != nil {
		return fmt.Errorf("recording review dismissal: %w", err)
	}
	return nil
}

func (r *PRReviewDismissalRepository) List(ctx context.Context, projectID uuid.UUID, pr int) ([]gitreview.Dismissal, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+prReviewDismissalCols+` FROM pr_review_dismissals
		WHERE project_id = $1 AND pr_number = $2 ORDER BY created_at, id`, projectID, pr)
	if err != nil {
		return nil, fmt.Errorf("listing review dismissals: %w", err)
	}
	defer rows.Close()
	var out []gitreview.Dismissal
	for rows.Next() {
		var d gitreview.Dismissal
		if err := scanPRReviewDismissal(rows, &d); err != nil {
			return nil, fmt.Errorf("scanning review dismissal: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
