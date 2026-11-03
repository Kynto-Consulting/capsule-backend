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

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/webhookout"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

// OutboundWebhookRepository persists outbound_webhooks and webhook_deliveries (Git Capsule A5).
// Destination URLs and signing secrets are encrypted at rest with the platform key.
type OutboundWebhookRepository struct {
	pool      *pgxpool.Pool
	secretKey string
}

func NewOutboundWebhookRepository(pool *pgxpool.Pool, secretKey string) *OutboundWebhookRepository {
	return &OutboundWebhookRepository{pool: pool, secretKey: secretKey}
}

var _ webhookout.Store = (*OutboundWebhookRepository)(nil)

const webhookCols = `id, org_id, project_id, kind, url_enc, email_to, events, branch_filter, active, disabled_reason,
	secret_enc, prev_secret_enc, prev_secret_expires_at, last_delivery_status, last_delivery_at, created_by, created_at, updated_at`

const deliveryCols = `id, webhook_id, event_id, redelivery_of, event, payload, status, attempt, next_attempt_at,
	status_code, duration_ms, error, response_excerpt, request_headers, created_at, delivered_at`

// scanWebhookRow reads the encrypted columns; decrypt turns them into a Webhook.
type webhookEnc struct{ url, secret, prev []byte }

func scanWebhook(row interface{ Scan(...any) error }, w *webhookout.Webhook, enc *webhookEnc) error {
	return row.Scan(&w.ID, &w.OrgID, &w.ProjectID, &w.Kind, &enc.url, &w.EmailTo, &w.Events, &w.BranchFilter,
		&w.Active, &w.DisabledReason, &enc.secret, &enc.prev, &w.PrevSecretExpiresAt, &w.LastDeliveryStatus,
		&w.LastDeliveryAt, &w.CreatedBy, &w.CreatedAt, &w.UpdatedAt)
}

func scanDelivery(row interface{ Scan(...any) error }, d *webhookout.Delivery) error {
	var headers []byte
	if err := row.Scan(&d.ID, &d.WebhookID, &d.EventID, &d.RedeliveryOf, &d.Event, &d.Payload, &d.Status, &d.Attempt,
		&d.NextAttemptAt, &d.StatusCode, &d.DurationMS, &d.Error, &d.ResponseExcerpt, &headers, &d.CreatedAt, &d.DeliveredAt); err != nil {
		return err
	}
	d.RequestHeaders = map[string]string{}
	if len(headers) > 0 {
		_ = json.Unmarshal(headers, &d.RequestHeaders)
	}
	return nil
}

func (r *OutboundWebhookRepository) decrypt(w *webhookout.Webhook, enc webhookEnc) error {
	dec := func(b []byte) (string, error) {
		if len(b) == 0 {
			return "", nil
		}
		p, err := crypto.Decrypt(b, r.secretKey)
		if err != nil {
			return "", err
		}
		return string(p), nil
	}
	var err error
	if w.URL, err = dec(enc.url); err != nil {
		return fmt.Errorf("decrypting webhook url: %w", err)
	}
	if w.Secret, err = dec(enc.secret); err != nil {
		return fmt.Errorf("decrypting webhook secret: %w", err)
	}
	if w.PrevSecret, err = dec(enc.prev); err != nil {
		return fmt.Errorf("decrypting previous webhook secret: %w", err)
	}
	if w.EmailTo == nil {
		w.EmailTo = []string{}
	}
	if w.Events == nil {
		w.Events = []string{}
	}
	return nil
}

func (r *OutboundWebhookRepository) encrypt(plain string) ([]byte, error) {
	if plain == "" {
		return nil, nil
	}
	return crypto.Encrypt([]byte(plain), r.secretKey)
}

func (r *OutboundWebhookRepository) one(ctx context.Context, where string, args ...any) (*webhookout.Webhook, error) {
	var w webhookout.Webhook
	var enc webhookEnc
	err := scanWebhook(r.pool.QueryRow(ctx, `SELECT `+webhookCols+` FROM outbound_webhooks WHERE `+where, args...), &w, &enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading webhook: %w", err)
	}
	if err := r.decrypt(&w, enc); err != nil {
		return nil, err
	}
	return &w, nil
}

func (r *OutboundWebhookRepository) many(ctx context.Context, q string, args ...any) ([]webhookout.Webhook, error) {
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing webhooks: %w", err)
	}
	defer rows.Close()
	out := []webhookout.Webhook{}
	for rows.Next() {
		var w webhookout.Webhook
		var enc webhookEnc
		if err := scanWebhook(rows, &w, &enc); err != nil {
			return nil, fmt.Errorf("scanning webhook: %w", err)
		}
		if err := r.decrypt(&w, enc); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (r *OutboundWebhookRepository) CreateWebhook(ctx context.Context, w *webhookout.Webhook) error {
	urlEnc, err := r.encrypt(w.URL)
	if err != nil {
		return fmt.Errorf("encrypting webhook url: %w", err)
	}
	secEnc, err := r.encrypt(w.Secret)
	if err != nil {
		return fmt.Errorf("encrypting webhook secret: %w", err)
	}
	if w.EmailTo == nil {
		w.EmailTo = []string{}
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO outbound_webhooks (id, org_id, project_id, kind, url_enc, email_to, events, branch_filter, active, secret_enc, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		w.ID, w.OrgID, w.ProjectID, w.Kind, urlEnc, w.EmailTo, w.Events, w.BranchFilter, w.Active, secEnc, w.CreatedBy)
	if err != nil {
		return fmt.Errorf("creating webhook: %w", err)
	}
	return nil
}

func (r *OutboundWebhookRepository) GetWebhook(ctx context.Context, id uuid.UUID) (*webhookout.Webhook, error) {
	return r.one(ctx, `id = $1`, id)
}

func (r *OutboundWebhookRepository) ListWebhooks(ctx context.Context, sc webhookout.Scope) ([]webhookout.Webhook, error) {
	return r.many(ctx, `SELECT `+webhookCols+` FROM outbound_webhooks
		WHERE org_id = $1 AND project_id IS NOT DISTINCT FROM $2 ORDER BY created_at, id`, sc.OrgID, sc.ProjectID)
}

func (r *OutboundWebhookRepository) UpdateWebhook(ctx context.Context, w *webhookout.Webhook) error {
	urlEnc, err := r.encrypt(w.URL)
	if err != nil {
		return fmt.Errorf("encrypting webhook url: %w", err)
	}
	if w.EmailTo == nil {
		w.EmailTo = []string{}
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE outbound_webhooks SET url_enc = $2, email_to = $3, events = $4, branch_filter = $5,
			active = $6, disabled_reason = $7, updated_at = now()
		WHERE id = $1`, w.ID, urlEnc, w.EmailTo, w.Events, w.BranchFilter, w.Active, w.DisabledReason)
	if err != nil {
		return fmt.Errorf("updating webhook: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *OutboundWebhookRepository) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM outbound_webhooks WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting webhook: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *OutboundWebhookRepository) RotateSecret(ctx context.Context, id uuid.UUID, newSecret string, prevExpires time.Time) error {
	enc, err := r.encrypt(newSecret)
	if err != nil {
		return fmt.Errorf("encrypting webhook secret: %w", err)
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE outbound_webhooks SET prev_secret_enc = secret_enc, prev_secret_expires_at = $3,
			secret_enc = $2, updated_at = now()
		WHERE id = $1 AND kind = 'http'`, id, enc, prevExpires)
	if err != nil {
		return fmt.Errorf("rotating webhook secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *OutboundWebhookRepository) DisableWebhook(ctx context.Context, id uuid.UUID, reason string) error {
	_, err := r.pool.Exec(ctx, `UPDATE outbound_webhooks SET active = false, disabled_reason = $2, updated_at = now() WHERE id = $1`, id, reason)
	if err != nil {
		return fmt.Errorf("disabling webhook: %w", err)
	}
	return nil
}

func (r *OutboundWebhookRepository) MatchingWebhooks(ctx context.Context, orgID, projectID uuid.UUID, event string) ([]webhookout.Webhook, error) {
	return r.many(ctx, `SELECT `+webhookCols+` FROM outbound_webhooks
		WHERE active AND $3 = ANY(events) AND org_id = $1 AND (project_id = $2 OR project_id IS NULL)
		ORDER BY created_at, id`, orgID, projectID, event)
}

// ---- deliveries --------------------------------------------------------------------------------

func (r *OutboundWebhookRepository) InsertDelivery(ctx context.Context, d *webhookout.Delivery) (bool, error) {
	headers, _ := json.Marshal(d.RequestHeaders)
	if d.RequestHeaders == nil {
		headers = []byte("{}")
	}
	tag, err := r.pool.Exec(ctx, `
		INSERT INTO webhook_deliveries (id, webhook_id, event_id, redelivery_of, event, payload, status, attempt,
			next_attempt_at, status_code, duration_ms, error, response_excerpt, request_headers, created_at, delivered_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::text::jsonb, $15, $16)
		ON CONFLICT DO NOTHING`,
		d.ID, d.WebhookID, d.EventID, d.RedeliveryOf, d.Event, d.Payload, d.Status, d.Attempt, d.NextAttemptAt,
		d.StatusCode, d.DurationMS, d.Error, d.ResponseExcerpt, string(headers), d.CreatedAt, d.DeliveredAt)
	if err != nil {
		return false, fmt.Errorf("inserting webhook delivery: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r *OutboundWebhookRepository) GetDelivery(ctx context.Context, id uuid.UUID) (*webhookout.Delivery, error) {
	var d webhookout.Delivery
	err := scanDelivery(r.pool.QueryRow(ctx, `SELECT `+deliveryCols+` FROM webhook_deliveries WHERE id = $1`, id), &d)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading webhook delivery: %w", err)
	}
	return &d, nil
}

func (r *OutboundWebhookRepository) ListDeliveries(ctx context.Context, webhookID uuid.UUID, after *gitevents.Cursor, limit int) ([]webhookout.Delivery, error) {
	q := `SELECT ` + deliveryCols + ` FROM webhook_deliveries WHERE webhook_id = $1`
	args := []any{webhookID}
	if after != nil {
		q += ` AND (created_at, id) < ($2, $3)`
		args = append(args, after.At, after.ID)
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT %d`, limit)
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing webhook deliveries: %w", err)
	}
	defer rows.Close()
	out := []webhookout.Delivery{}
	for rows.Next() {
		var d webhookout.Delivery
		if err := scanDelivery(rows, &d); err != nil {
			return nil, fmt.Errorf("scanning webhook delivery: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *OutboundWebhookRepository) ClaimDue(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]webhookout.Delivery, error) {
	rows, err := r.pool.Query(ctx, `
		UPDATE webhook_deliveries SET next_attempt_at = $2
		WHERE id IN (
			SELECT id FROM webhook_deliveries
			WHERE status = 'pending' AND next_attempt_at <= $1
			ORDER BY next_attempt_at LIMIT $3
			FOR UPDATE SKIP LOCKED)
		RETURNING `+deliveryCols, now, now.Add(lease), limit)
	if err != nil {
		return nil, fmt.Errorf("claiming due webhook deliveries: %w", err)
	}
	defer rows.Close()
	var out []webhookout.Delivery
	for rows.Next() {
		var d webhookout.Delivery
		if err := scanDelivery(rows, &d); err != nil {
			return nil, fmt.Errorf("scanning webhook delivery: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RecordAttempt writes the outcome on the delivery and, when a request was actually made
// (RequestHeaders != nil), the last_delivery_* summary of its webhook.
func (r *OutboundWebhookRepository) RecordAttempt(ctx context.Context, d *webhookout.Delivery) error {
	headers := []byte("{}")
	if d.RequestHeaders != nil {
		headers, _ = json.Marshal(d.RequestHeaders)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin recording webhook attempt: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `
		UPDATE webhook_deliveries SET status = $2, attempt = $3, next_attempt_at = $4, status_code = $5,
			duration_ms = $6, error = $7, response_excerpt = $8, request_headers = $9::text::jsonb, delivered_at = $10
		WHERE id = $1`,
		d.ID, d.Status, d.Attempt, d.NextAttemptAt, d.StatusCode, d.DurationMS, d.Error, d.ResponseExcerpt, string(headers), d.DeliveredAt); err != nil {
		return fmt.Errorf("recording webhook attempt: %w", err)
	}
	if d.RequestHeaders != nil {
		if _, err := tx.Exec(ctx, `UPDATE outbound_webhooks SET last_delivery_status = $2, last_delivery_at = now() WHERE id = $1`,
			d.WebhookID, d.StatusCode); err != nil {
			return fmt.Errorf("recording webhook last delivery: %w", err)
		}
	}
	return tx.Commit(ctx)
}
