// Package gitevents is the product event bus of Git Capsule (package A5).
//
// Two things feed it: inbound Forgejo webhooks (pull_request_review, status, workflow_run,
// push, pull_request, branch create/delete), recorded once per X-Forgejo-Delivery, and
// events that other Capsule packages publish (deployments, approvals, security, backups...).
// Every event is persisted in git_events and fanned out to Subscribers: the in-app and email
// notifications of this package and the outbound webhooks of package webhookout.
//
// Other packages (A6 environments, B7 security, B8 review) only need the Publisher interface:
//
//	gitevents.Shared().Publish(ctx, gitevents.Event{
//	    ProjectID: p.ID, Name: gitevents.DeploymentFailed, Actor: "deploy-bot",
//	    Data: map[string]any{"deployment_id": id.String(), "environment": "production"},
//	})
//
// Event data is free-form JSON but must never carry secrets: Publish rejects keys that look like
// credentials (see ErrSecretInEvent).
package gitevents

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Product event names. They are the keys of x-webhook-events in docs/git-capsule/API.openapi.yaml.
const (
	GitPush              = "git.push"
	GitBranchCreated     = "git.branch.created"
	GitBranchDeleted     = "git.branch.deleted"
	PROpened             = "pr.opened"
	PRUpdated            = "pr.updated"
	PRReadyForReview     = "pr.ready_for_review"
	PRReviewSubmitted    = "pr.review_submitted"
	PRReviewRequested    = "pr.review_requested"
	PRMerged             = "pr.merged"
	PRClosed             = "pr.closed"
	PRAutoMergeEnabled   = "pr.auto_merge_enabled"
	CheckCompleted       = "check.completed"
	WorkflowRunCompleted = "workflow.run.completed"
	DeploymentCreated    = "deployment.created"
	DeploymentSucceeded  = "deployment.succeeded"
	DeploymentFailed     = "deployment.failed"
	ApprovalRequested    = "approval.requested"
	ApprovalDecided      = "approval.decided"
	PromotionCompleted   = "promotion.completed"
	PreviewReady         = "preview.ready"
	PreviewDeleted       = "preview.deleted"
	SecurityAlertCreated = "security.alert.created"
	SecurityAlertDismiss = "security.alert.dismissed"
	SecuritySuppExpiring = "security.suppression.expiring"
	SecurityPolicyBlock  = "security.policy.blocked"
	ProtectionChanged    = "protection.changed"
	MemberChanged        = "member.changed"
	BackupCompleted      = "backup.completed"
	RecoveryCompleted    = "recovery.completed"
	DeploymentConnWarn   = "deployment.connection_warning"
)

// WebhookTest is the synthetic event of POST .../webhooks/{id}/test. It is not subscribable.
const WebhookTest = "webhook.test"

// Catalog maps every subscribable event to its description (same text as x-webhook-events).
var Catalog = map[string]string{
	GitPush:              "push a una rama o etiqueta",
	GitBranchCreated:     "rama creada",
	GitBranchDeleted:     "rama eliminada",
	PROpened:             "PR abierto",
	PRUpdated:            "PR actualizado (nuevos commits, titulo)",
	PRReadyForReview:     "draft a listo",
	PRReviewSubmitted:    "revision enviada",
	PRReviewRequested:    "revision solicitada",
	PRMerged:             "PR fusionado",
	PRClosed:             "PR cerrado sin fusionar",
	PRAutoMergeEnabled:   "auto-merge programado",
	CheckCompleted:       "un check cambia a estado final",
	WorkflowRunCompleted: "ejecucion de CI terminada",
	DeploymentCreated:    "despliegue creado",
	DeploymentSucceeded:  "despliegue ok",
	DeploymentFailed:     "despliegue fallido",
	ApprovalRequested:    "promocion espera aprobacion",
	ApprovalDecided:      "aprobada/rechazada",
	PromotionCompleted:   "promocion terminada",
	PreviewReady:         "preview listo",
	PreviewDeleted:       "preview eliminado",
	SecurityAlertCreated: "alerta nueva",
	SecurityAlertDismiss: "alerta suprimida",
	SecuritySuppExpiring: "supresion caduca en 7 dias",
	SecurityPolicyBlock:  "politica bloqueo un merge o despliegue",
	ProtectionChanged:    "cambio de reglas de rama",
	MemberChanged:        "cambio de rol",
	BackupCompleted:      "respaldo terminado",
	RecoveryCompleted:    "recuperacion terminada",
	DeploymentConnWarn:   "despliegue con conexiones internas sin enrutar",
}

// Valid reports whether name is a subscribable product event.
func Valid(name string) bool { _, ok := Catalog[name]; return ok }

// Names returns the catalog sorted.
func Names() []string {
	out := make([]string, 0, len(Catalog))
	for k := range Catalog {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Sources of an event.
const (
	SourceForgejo = "forgejo"
	SourceCapsule = "capsule"
)

// Event is one product event. Fill ProjectID, Name and (optionally) Actor/Branch/Data/Recipients
// when publishing; the rest is completed by the bus.
type Event struct {
	ID          uuid.UUID
	OrgID       uuid.UUID // completed from the project
	ProjectID   uuid.UUID
	OrgSlug     string // completed (not persisted)
	ProjectSlug string // completed (not persisted)
	Source      string // default capsule
	DeliveryID  string // inbound Forgejo delivery id ("" for Capsule events)
	RawEvent    string // inbound X-Forgejo-Event
	Name        string
	Actor       string    // Forgejo login or display name of who did it
	ActorUserID uuid.UUID // Capsule user, when known (never notified about their own action)
	Branch      string    // for branch filters of webhooks
	Data        map[string]any
	// Recipients are Capsule users to notify explicitly (approvers, requester...). When empty the
	// notification policy derives them from the event.
	Recipients []uuid.UUID
	CreatedAt  time.Time
}

// Publisher is the whole surface other packages need.
type Publisher interface {
	// Publish validates, persists and dispatches e asynchronously. It returns quickly and never
	// blocks on webhook receivers. Errors: ErrUnknownEvent, ErrSecretInEvent, ErrNoProject or a
	// storage error.
	Publish(ctx context.Context, e Event) error
}

// Subscriber receives dispatched events. Handle MUST be idempotent: the same event can be
// delivered again after a crash or a failed fan-out.
type Subscriber interface {
	Name() string
	Handle(ctx context.Context, e Event) error
}

// Errors.
var (
	ErrUnknownEvent  = errors.New("gitevents: unknown event name")
	ErrSecretInEvent = errors.New("gitevents: event data must not carry secrets")
	ErrNoProject     = errors.New("gitevents: project not found")
)

var secretKeyHints = []string{"secret", "token", "password", "passwd", "authorization", "api_key", "apikey", "private_key", "credential"}

// CheckNoSecrets walks v and fails if any map key looks like a credential.
func CheckNoSecrets(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			lk := strings.ToLower(k)
			for _, h := range secretKeyHints {
				if strings.Contains(lk, h) {
					return ErrSecretInEvent
				}
			}
			if err := CheckNoSecrets(x); err != nil {
				return err
			}
		}
	case []any:
		for _, x := range t {
			if err := CheckNoSecrets(x); err != nil {
				return err
			}
		}
	case []map[string]any:
		for _, x := range t {
			if err := CheckNoSecrets(x); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---- process-wide publisher ------------------------------------------------------------------

type discard struct{}

func (discard) Publish(context.Context, Event) error { return nil }

// Discard is a Publisher that drops everything (tests and processes without the event bus).
var Discard Publisher = discard{}

var (
	sharedMu sync.RWMutex
	shared   Publisher
)

// SetShared publishes the process-wide Publisher (called once by the wiring).
func SetShared(p Publisher) {
	sharedMu.Lock()
	shared = p
	sharedMu.Unlock()
}

// Shared returns the Publisher published by the wiring, never nil (Discard before that).
func Shared() Publisher {
	sharedMu.RLock()
	p := shared
	sharedMu.RUnlock()
	if p == nil {
		return Discard
	}
	return p
}
