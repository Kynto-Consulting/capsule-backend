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
	"github.com/kynto/capsule/backend/pkg/crypto"
)

// GitEventRepository persists git_events (Git Capsule A5). It also resolves the project of an
// event (gitevents.ProjectResolver).
type GitEventRepository struct {
	pool      *pgxpool.Pool
	secretKey string
}

func NewGitEventRepository(pool *pgxpool.Pool, secretKey string) *GitEventRepository {
	return &GitEventRepository{pool: pool, secretKey: secretKey}
}

var (
	_ gitevents.Store           = (*GitEventRepository)(nil)
	_ gitevents.ProjectResolver = (*GitEventRepository)(nil)
	_ gitevents.PrevSecretStore = (*GitEventRepository)(nil)
)

// recipients is read as text[] and parsed, which keeps uuid[] handling out of the driver.
const gitEventCols = `id, org_id, project_id, source, delivery_id, raw_event, event, actor, actor_user_id, branch, data, recipients::text[], created_at`

func scanGitEvent(row interface{ Scan(...any) error }, e *gitevents.Event) error {
	var (
		data       []byte
		recipients []string
		actorUser  *uuid.UUID
	)
	if err := row.Scan(&e.ID, &e.OrgID, &e.ProjectID, &e.Source, &e.DeliveryID, &e.RawEvent, &e.Name, &e.Actor,
		&actorUser, &e.Branch, &data, &recipients, &e.CreatedAt); err != nil {
		return err
	}
	if actorUser != nil {
		e.ActorUserID = *actorUser
	}
	e.Data = map[string]any{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &e.Data); err != nil {
			return fmt.Errorf("decoding event data: %w", err)
		}
	}
	e.Recipients = nil
	for _, r := range recipients {
		if id, err := uuid.Parse(r); err == nil {
			e.Recipients = append(e.Recipients, id)
		}
	}
	return nil
}

func (r *GitEventRepository) Insert(ctx context.Context, e *gitevents.Event) (bool, error) {
	data, err := json.Marshal(e.Data)
	if err != nil {
		return false, fmt.Errorf("encoding event data: %w", err)
	}
	var actorUser *uuid.UUID
	if e.ActorUserID != uuid.Nil {
		actorUser = &e.ActorUserID
	}
	recipients := make([]string, 0, len(e.Recipients))
	for _, id := range e.Recipients {
		recipients = append(recipients, id.String())
	}
	tag, err := r.pool.Exec(ctx, `
		INSERT INTO git_events (id, org_id, project_id, source, delivery_id, raw_event, event, actor, actor_user_id, branch, data, recipients, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text::jsonb, $12::text[]::uuid[], $13)
		ON CONFLICT DO NOTHING`,
		e.ID, e.OrgID, e.ProjectID, e.Source, e.DeliveryID, e.RawEvent, e.Name, e.Actor, actorUser, e.Branch,
		string(data), recipients, e.CreatedAt)
	if err != nil {
		return false, fmt.Errorf("inserting git event: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r *GitEventRepository) MarkDispatched(ctx context.Context, id uuid.UUID) error {
	if _, err := r.pool.Exec(ctx, `UPDATE git_events SET dispatched_at = now() WHERE id = $1`, id); err != nil {
		return fmt.Errorf("marking git event dispatched: %w", err)
	}
	return nil
}

func (r *GitEventRepository) RecordDispatchFailure(ctx context.Context, id uuid.UUID) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `UPDATE git_events SET dispatch_attempts = dispatch_attempts + 1 WHERE id = $1 RETURNING dispatch_attempts`, id).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("recording git event dispatch failure: %w", err)
	}
	return n, nil
}

func (r *GitEventRepository) ListUndispatched(ctx context.Context, cutoff time.Time, limit int) ([]gitevents.Event, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+gitEventCols+` FROM git_events
		WHERE dispatched_at IS NULL AND created_at < $1 ORDER BY created_at LIMIT $2`, cutoff, limit)
	if err != nil {
		return nil, fmt.Errorf("listing undispatched git events: %w", err)
	}
	defer rows.Close()
	var out []gitevents.Event
	for rows.Next() {
		var e gitevents.Event
		if err := scanGitEvent(rows, &e); err != nil {
			return nil, fmt.Errorf("scanning git event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Get loads one event by id (tests and tooling).
func (r *GitEventRepository) Get(ctx context.Context, id uuid.UUID) (*gitevents.Event, error) {
	var e gitevents.Event
	err := scanGitEvent(r.pool.QueryRow(ctx, `SELECT `+gitEventCols+` FROM git_events WHERE id = $1`, id), &e)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, gitevents.ErrNoProject
	}
	if err != nil {
		return nil, fmt.Errorf("loading git event: %w", err)
	}
	return &e, nil
}

// ProjectInfo implements gitevents.ProjectResolver.
func (r *GitEventRepository) ProjectInfo(ctx context.Context, projectID uuid.UUID) (gitevents.ProjectInfo, error) {
	var in gitevents.ProjectInfo
	err := r.pool.QueryRow(ctx, `
		SELECT o.id, o.slug, p.slug, p.name
		FROM projects p JOIN organizations o ON o.id = p.org_id
		WHERE p.id = $1 AND p.deleted_at IS NULL AND o.deleted_at IS NULL`, projectID).
		Scan(&in.OrgID, &in.OrgSlug, &in.ProjectSlug, &in.ProjectName)
	if errors.Is(err, pgx.ErrNoRows) {
		return in, gitevents.ErrNoProject
	}
	if err != nil {
		return in, fmt.Errorf("resolving project of event: %w", err)
	}
	return in, nil
}

// OrgSlug resolves an organization slug (used by webhookout for org-level test sends).
func (r *GitEventRepository) OrgSlug(ctx context.Context, orgID uuid.UUID) (string, error) {
	var slug string
	err := r.pool.QueryRow(ctx, `SELECT slug FROM organizations WHERE id = $1 AND deleted_at IS NULL`, orgID).Scan(&slug)
	if err != nil {
		return "", fmt.Errorf("resolving organization slug: %w", err)
	}
	return slug, nil
}

// PreviousWebhookSecret implements gitevents.PrevSecretStore: the inbound secret replaced less
// than 24 h ago (kept by the trigger of migration 000038), or "".
func (r *GitEventRepository) PreviousWebhookSecret(ctx context.Context, projectID uuid.UUID) (string, error) {
	var enc []byte
	err := r.pool.QueryRow(ctx, `SELECT secret_enc FROM git_webhook_previous_secrets WHERE project_id = $1 AND expires_at > now()`, projectID).Scan(&enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("loading previous webhook secret: %w", err)
	}
	plain, err := crypto.Decrypt(enc, r.secretKey)
	if err != nil {
		return "", fmt.Errorf("decrypting previous webhook secret: %w", err)
	}
	return string(plain), nil
}
