// Package webhookout delivers Git Capsule product events to customer systems (package A5):
// signed HTTP webhooks (X-Capsule-* headers), Slack, Discord and email.
//
// Delivery contract (docs/git-capsule/API.openapi.yaml, x-webhook-signing):
//
//	X-Capsule-Event      event name
//	X-Capsule-Delivery   UUID of the delivery, stable across retries (receiver idempotency key)
//	X-Capsule-Timestamp  unix seconds of THIS attempt
//	X-Capsule-Signature  sha256=hex(HMAC-SHA256(secret, timestamp + "." + raw body))
//	X-Capsule-Signature-Previous   same with the previous secret, for 24 h after a rotation
//
// Receivers recompute, compare in constant time and reject |now - timestamp| > 300 s. 2xx means
// delivered; 410 disables the webhook; anything else is retried with backoff. Delivery is
// at-least-once: dedupe on X-Capsule-Delivery. Verification examples (Go, Node, bash) live in
// verify_examples_test.go and docs/git-capsule/WEBHOOKS-VERIFY.md.
package webhookout

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Kind of a webhook destination.
const (
	KindHTTP    = "http"
	KindSlack   = "slack"
	KindDiscord = "discord"
	KindEmail   = "email"
)

// APIVersion is the envelope version (WebhookEnvelope.api_version).
const APIVersion = "2026-11-01"

// Delivery statuses.
const (
	StatusPending   = "pending"   // waiting for (another) attempt
	StatusDelivered = "delivered" // a 2xx answer
	StatusFailed    = "failed"    // retries exhausted
	StatusAbandoned = "abandoned" // webhook disabled (410) or deleted target
)

// Webhook is one outbound destination. project == nil means organization level.
type Webhook struct {
	ID                  uuid.UUID
	OrgID               uuid.UUID
	ProjectID           *uuid.UUID
	Kind                string
	URL                 string // http, slack, discord (secret for slack/discord: never log or return)
	EmailTo             []string
	Events              []string
	BranchFilter        string
	Active              bool
	DisabledReason      string
	Secret              string // http only (secret: never log or return except at create/rotate)
	PrevSecret          string
	PrevSecretExpiresAt *time.Time
	LastDeliveryStatus  int // HTTP status of the last attempt, 0 = none or network error
	LastDeliveryAt      *time.Time
	CreatedBy           *uuid.UUID
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// Delivery is one send (with its retries) of one event to one webhook.
type Delivery struct {
	ID              uuid.UUID
	WebhookID       uuid.UUID
	EventID         *uuid.UUID
	RedeliveryOf    *uuid.UUID
	Event           string
	Payload         string // exactly the body that is signed and sent
	Status          string
	Attempt         int
	NextAttemptAt   time.Time
	StatusCode      int
	DurationMS      int
	Error           string
	ResponseExcerpt string
	RequestHeaders  map[string]string // without signatures
	CreatedAt       time.Time
	DeliveredAt     *time.Time
}

// Backoff is the wait before retry n (n = 1..len): 10 s, 1 min, 5 min, 30 min, 2 h, 6 h
// (x-webhook-signing.delivery). With the first attempt that is len(Backoff)+1 attempts.
var Backoff = []time.Duration{10 * time.Second, time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour}

// MaxAttempts is the total number of attempts of one delivery.
func MaxAttempts() int { return len(Backoff) + 1 }

// RotationWindow is how long the previous secret keeps signing after a rotation.
const RotationWindow = 24 * time.Hour

// MaxWebhooksPerScope caps webhooks per project and per organization.
const MaxWebhooksPerScope = 25

// ValidationError is a rejected input (HTTP 422).
type ValidationError struct{ Field, Msg string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

// ErrNotRotatable is returned when rotating the secret of a webhook that has none.
var ErrNotRotatable = errors.New("only http webhooks have a signing secret")

// Scope identifies where a webhook lives.
type Scope struct {
	OrgID     uuid.UUID
	ProjectID *uuid.UUID // nil = organization level
}
