package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/gitinsights"
)

// GitActivityRepository persists git_activity and the notification digest state (Git Capsule C2).
type GitActivityRepository struct{ pool *pgxpool.Pool }

// NewGitActivityRepository returns the repository over pool.
func NewGitActivityRepository(pool *pgxpool.Pool) *GitActivityRepository {
	return &GitActivityRepository{pool: pool}
}

var (
	_ gitinsights.Store       = (*GitActivityRepository)(nil)
	_ gitinsights.DigestStore = (*GitActivityRepository)(nil)
)

const gitActivityCols = `id, org_id, project_id, event_id, type, actor, actor_user_id, ref, summary, branch, pr, data, occurred_at`

func scanGitActivity(row interface{ Scan(...any) error }, a *gitinsights.Activity) error {
	return row.Scan(&a.ID, &a.OrgID, &a.ProjectID, &a.EventID, &a.Type, &a.Actor, &a.ActorUserID, &a.Ref,
		&a.Summary, &a.Branch, &a.PR, &a.Data, &a.OccurredAt)
}

// Insert implements gitinsights.Store.
func (r *GitActivityRepository) Insert(ctx context.Context, a *gitinsights.Activity) (bool, error) {
	data, err := json.Marshal(a.Data)
	if err != nil {
		return false, fmt.Errorf("encoding activity data: %w", err)
	}
	tag, err := r.pool.Exec(ctx, `
		INSERT INTO git_activity (id, org_id, project_id, event_id, type, actor, actor_user_id, ref, summary, branch, pr, data, occurred_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13)
		ON CONFLICT DO NOTHING`,
		a.ID, a.OrgID, a.ProjectID, a.EventID, a.Type, a.Actor, a.ActorUserID, a.Ref, a.Summary, a.Branch, a.PR, string(data), a.OccurredAt)
	if err != nil {
		return false, fmt.Errorf("inserting git activity: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// List implements gitinsights.Store.
func (r *GitActivityRepository) List(ctx context.Context, projectID uuid.UUID, after *gitinsights.Cursor, limit int) ([]gitinsights.Activity, error) {
	var rows pgx.Rows
	var err error
	if after == nil {
		rows, err = r.pool.Query(ctx, `SELECT `+gitActivityCols+` FROM git_activity WHERE project_id = $1
			ORDER BY occurred_at DESC, id DESC LIMIT $2`, projectID, limit)
	} else {
		rows, err = r.pool.Query(ctx, `SELECT `+gitActivityCols+` FROM git_activity WHERE project_id = $1
			AND (occurred_at, id) < ($2, $3) ORDER BY occurred_at DESC, id DESC LIMIT $4`, projectID, after.At, after.ID, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("listing git activity: %w", err)
	}
	defer rows.Close()
	var out []gitinsights.Activity
	for rows.Next() {
		var a gitinsights.Activity
		if err := scanGitActivity(rows, &a); err != nil {
			return nil, fmt.Errorf("scanning git activity: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Counts implements gitinsights.Store.
func (r *GitActivityRepository) Counts(ctx context.Context, projectID uuid.UUID, since, until time.Time) (gitinsights.Counts, error) {
	var c gitinsights.Counts
	err := r.pool.QueryRow(ctx, `
		SELECT
		  COALESCE(SUM(CASE WHEN type = 'push' THEN CASE WHEN data->>'commits' ~ '^[0-9]{1,6}$' THEN (data->>'commits')::int ELSE 1 END ELSE 0 END), 0)::int,
		  COUNT(*) FILTER (WHERE type = 'deployment.succeeded')::int,
		  COUNT(*) FILTER (WHERE type = 'deployment.failed')::int
		FROM git_activity
		WHERE project_id = $1 AND occurred_at >= $2 AND occurred_at <= $3`, projectID, since, until).
		Scan(&c.Commits, &c.DeploysOK, &c.DeploysFailed)
	if err != nil {
		return c, fmt.Errorf("counting git activity: %w", err)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT actor, (array_agg(actor_user_id) FILTER (WHERE actor_user_id IS NOT NULL))[1],
		  SUM(CASE WHEN data->>'commits' ~ '^[0-9]{1,6}$' THEN (data->>'commits')::int ELSE 1 END)::int
		FROM git_activity
		WHERE project_id = $1 AND type = 'push' AND actor <> '' AND occurred_at >= $2 AND occurred_at <= $3
		GROUP BY actor ORDER BY 3 DESC, actor LIMIT 100`, projectID, since, until)
	if err != nil {
		return c, fmt.Errorf("counting contributors: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var k gitinsights.Contributor
		if err := rows.Scan(&k.Login, &k.UserID, &k.Commits); err != nil {
			return c, fmt.Errorf("scanning contributor: %w", err)
		}
		c.Contributors = append(c.Contributors, k)
	}
	return c, rows.Err()
}

const prTimelineMax = 50000

// PRTimeline implements gitinsights.Store.
func (r *GitActivityRepository) PRTimeline(ctx context.Context, projectID uuid.UUID, since, until time.Time) ([]gitinsights.PREvent, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT pr, type, actor, COALESCE(data->>'author', ''), occurred_at
		FROM git_activity
		WHERE project_id = $1 AND pr > 0 AND type IN ('pull_request.opened', 'pull_request.review', 'pull_request.merged')
		  AND pr IN (SELECT pr FROM git_activity WHERE project_id = $1 AND pr > 0
		             AND type IN ('pull_request.opened', 'pull_request.review', 'pull_request.merged')
		             AND occurred_at >= $2 AND occurred_at <= $3)
		ORDER BY occurred_at LIMIT $4`, projectID, since, until, prTimelineMax)
	if err != nil {
		return nil, fmt.Errorf("reading pull request timeline: %w", err)
	}
	defer rows.Close()
	var out []gitinsights.PREvent
	for rows.Next() {
		var e gitinsights.PREvent
		if err := scanPREvent(rows, &e); err != nil {
			return nil, fmt.Errorf("scanning pull request event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const prEventCols = `pr, type, actor, author, occurred_at`

func scanPREvent(row interface{ Scan(...any) error }, e *gitinsights.PREvent) error {
	return row.Scan(&e.PR, &e.Type, &e.Actor, &e.Author, &e.At)
}

// PurgeBefore implements gitinsights.Store (retention).
func (r *GitActivityRepository) PurgeBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	var total int64
	for {
		tag, err := r.pool.Exec(ctx, `DELETE FROM git_activity WHERE id IN (SELECT id FROM git_activity WHERE occurred_at < $1 LIMIT 5000)`, cutoff)
		if err != nil {
			return total, fmt.Errorf("purging git activity: %w", err)
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < 5000 {
			return total, nil
		}
	}
}

// ---- digest ---------------------------------------------------------------------------------

// Candidates implements gitinsights.DigestStore.
func (r *GitActivityRepository) Candidates(ctx context.Context, mode string, boundary time.Time, limit int) ([]gitinsights.DigestCandidate, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT s.user_id, u.email, d.last_sent_at
		FROM notification_settings s
		JOIN users u ON u.id = s.user_id
		LEFT JOIN notification_digest_state d ON d.user_id = s.user_id
		WHERE s.digest = $1 AND (d.last_sent_at IS NULL OR d.last_sent_at < $2)
		ORDER BY s.user_id LIMIT $3`, mode, boundary, limit)
	if err != nil {
		return nil, fmt.Errorf("listing digest candidates: %w", err)
	}
	defer rows.Close()
	var out []gitinsights.DigestCandidate
	for rows.Next() {
		var c gitinsights.DigestCandidate
		if err := scanDigestCandidate(rows, &c); err != nil {
			return nil, fmt.Errorf("scanning digest candidate: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

const digestCandidateCols = `user_id, email, last_sent_at`

func scanDigestCandidate(row interface{ Scan(...any) error }, c *gitinsights.DigestCandidate) error {
	return row.Scan(&c.UserID, &c.Email, &c.LastSent)
}

// Pending implements gitinsights.DigestStore.
func (r *GitActivityRepository) Pending(ctx context.Context, userID uuid.UUID, since time.Time, limit int) ([]gitevents.Notification, int, error) {
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*)::int FROM notifications WHERE user_id = $1 AND read_at IS NULL AND created_at > $2`, userID, since).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting pending notifications: %w", err)
	}
	if total == 0 {
		return nil, 0, nil
	}
	rows, err := r.pool.Query(ctx, `SELECT `+notificationCols+` FROM notifications WHERE user_id = $1 AND read_at IS NULL AND created_at > $2
		ORDER BY created_at DESC, id DESC LIMIT $3`, userID, since, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("listing pending notifications: %w", err)
	}
	defer rows.Close()
	var out []gitevents.Notification
	for rows.Next() {
		var n gitevents.Notification
		if err := scanNotification(rows, &n); err != nil {
			return nil, 0, fmt.Errorf("scanning notification: %w", err)
		}
		out = append(out, n)
	}
	return out, total, rows.Err()
}

// Claim implements gitinsights.DigestStore (compare and set on last_sent_at).
func (r *GitActivityRepository) Claim(ctx context.Context, userID uuid.UUID, prev *time.Time, now time.Time) (bool, error) {
	var tag interface{ RowsAffected() int64 }
	var err error
	if prev == nil {
		tag, err = r.pool.Exec(ctx, `INSERT INTO notification_digest_state (user_id, last_sent_at) VALUES ($1, $2) ON CONFLICT DO NOTHING`, userID, now)
	} else {
		tag, err = r.pool.Exec(ctx, `UPDATE notification_digest_state SET last_sent_at = $2 WHERE user_id = $1 AND last_sent_at = $3`, userID, now, *prev)
	}
	if err != nil {
		return false, fmt.Errorf("claiming digest: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Release implements gitinsights.DigestStore.
func (r *GitActivityRepository) Release(ctx context.Context, userID uuid.UUID, now time.Time, prev *time.Time) error {
	var err error
	if prev == nil {
		_, err = r.pool.Exec(ctx, `DELETE FROM notification_digest_state WHERE user_id = $1 AND last_sent_at = $2`, userID, now)
	} else {
		_, err = r.pool.Exec(ctx, `UPDATE notification_digest_state SET last_sent_at = $3 WHERE user_id = $1 AND last_sent_at = $2`, userID, now, *prev)
	}
	if err != nil {
		return fmt.Errorf("releasing digest claim: %w", err)
	}
	return nil
}

// ---- token expiry notices -------------------------------------------------------------------

// TokenNoticeRepository is the notification store plus the lookup the token expiry notice needs.
type TokenNoticeRepository struct {
	*NotificationRepository
	pool *pgxpool.Pool
}

// NewTokenNoticeRepository returns the repository over pool.
func NewTokenNoticeRepository(pool *pgxpool.Pool) *TokenNoticeRepository {
	return &TokenNoticeRepository{NotificationRepository: NewNotificationRepository(pool), pool: pool}
}

var _ gitinsights.TokenNoticeStore = (*TokenNoticeRepository)(nil)

// UserOrg implements gitinsights.TokenNoticeStore: the first named project when it still exists,
// otherwise the user's oldest organization.
func (r *TokenNoticeRepository) UserOrg(ctx context.Context, userID uuid.UUID, projectIDs []uuid.UUID) (gitinsights.TokenOrgRef, bool, error) {
	var ref gitinsights.TokenOrgRef
	if len(projectIDs) > 0 {
		var pid uuid.UUID
		err := r.pool.QueryRow(ctx, `SELECT o.id, o.slug, p.id, p.slug FROM projects p JOIN organizations o ON o.id = p.org_id
			WHERE p.id = ANY($1::uuid[]) AND p.deleted_at IS NULL AND o.deleted_at IS NULL ORDER BY p.created_at LIMIT 1`, projectIDs).
			Scan(&ref.OrgID, &ref.OrgSlug, &pid, &ref.ProjectSlug)
		if err == nil {
			ref.ProjectID = &pid
			return ref, true, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return ref, false, fmt.Errorf("resolving token project: %w", err)
		}
	}
	err := r.pool.QueryRow(ctx, `SELECT o.id, o.slug FROM org_members m JOIN organizations o ON o.id = m.org_id
		WHERE m.user_id = $1 AND o.deleted_at IS NULL ORDER BY m.joined_at LIMIT 1`, userID).Scan(&ref.OrgID, &ref.OrgSlug)
	if errors.Is(err, pgx.ErrNoRows) {
		return ref, false, nil
	}
	if err != nil {
		return ref, false, fmt.Errorf("resolving token organization: %w", err)
	}
	return ref, true, nil
}
