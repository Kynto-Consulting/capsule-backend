package webhookout

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitevents"
)

// Store persists webhooks and deliveries (implemented in internal/repository: tables
// outbound_webhooks and webhook_deliveries; secrets and URLs are encrypted at rest there).
// Lookups that miss return domain.ErrNotFound.
type Store interface {
	CreateWebhook(ctx context.Context, w *Webhook) error
	GetWebhook(ctx context.Context, id uuid.UUID) (*Webhook, error)
	// ListWebhooks lists the webhooks of exactly one scope (project, or org level when
	// ProjectID is nil).
	ListWebhooks(ctx context.Context, sc Scope) ([]Webhook, error)
	// UpdateWebhook rewrites the mutable fields: kind, url, email_to, events, branch_filter,
	// active, disabled_reason.
	UpdateWebhook(ctx context.Context, w *Webhook) error
	DeleteWebhook(ctx context.Context, id uuid.UUID) error
	// RotateSecret makes newSecret current and keeps the old one as previous until prevExpires.
	RotateSecret(ctx context.Context, id uuid.UUID, newSecret string, prevExpires time.Time) error
	// DisableWebhook sets active=false and disabled_reason.
	DisableWebhook(ctx context.Context, id uuid.UUID, reason string) error
	// MatchingWebhooks returns the ACTIVE webhooks of the project and of its organization (org
	// level) that subscribe to event.
	MatchingWebhooks(ctx context.Context, orgID, projectID uuid.UUID, event string) ([]Webhook, error)

	// InsertDelivery stores d; inserted=false when this (webhook, event) already has its delivery.
	InsertDelivery(ctx context.Context, d *Delivery) (inserted bool, err error)
	GetDelivery(ctx context.Context, id uuid.UUID) (*Delivery, error)
	// ListDeliveries returns up to limit rows of one webhook, newest first, after the cursor.
	ListDeliveries(ctx context.Context, webhookID uuid.UUID, after *gitevents.Cursor, limit int) ([]Delivery, error)
	// ClaimDue returns up to limit pending deliveries due at now and pushes their
	// next_attempt_at to now+lease so concurrent workers (and a restart) never take the same row
	// twice within the lease. It uses FOR UPDATE SKIP LOCKED.
	ClaimDue(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]Delivery, error)
	// RecordAttempt writes the outcome of an attempt on the delivery row and, when the attempt
	// reached the receiver or failed definitively, the last_delivery_* fields of its webhook.
	RecordAttempt(ctx context.Context, d *Delivery) error
}
