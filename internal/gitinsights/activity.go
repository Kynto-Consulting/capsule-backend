// Package gitinsights is Git Capsule package C2 (activity, insights, digest and expiry notices).
//
// Activity rows (table git_activity) are written by ActivityRecorder, a gitevents.Subscriber: one
// row per product event, idempotent by event id. Insights are computed from those rows (not from
// Forgejo): commits and contributors from push events, pull request timings from opened, review
// and merged events, deployment frequency and failure rate from deployment events.
package gitinsights

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitevents"
)

// Activity types (the "type" of the API Activity schema).
const (
	TypePush           = "push"
	TypeBranchCreated  = "branch.created"
	TypeBranchDeleted  = "branch.deleted"
	TypePROpened       = "pull_request.opened"
	TypePRReopened     = "pull_request.reopened"
	TypePRReview       = "pull_request.review"
	TypePRMerged       = "pull_request.merged"
	TypePRClosed       = "pull_request.closed"
	TypePRReady        = "pull_request.ready"
	TypeWorkflowRun    = "workflow_run"
	TypeDeployCreated  = "deployment.created"
	TypeDeploySuccess  = "deployment.succeeded"
	TypeDeployFailed   = "deployment.failed"
	TypeApprovalReq    = "approval.requested"
	TypeApprovalDecide = "approval.decided"
	TypePromotion      = "promotion.completed"
	TypeAlertCreated   = "security.alert.created"
	TypeAlertDismissed = "security.alert.dismissed"
	TypeProtection     = "protection.changed"
	TypeMember         = "member.changed"
)

// Activity is one git_activity row.
type Activity struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	ProjectID   uuid.UUID
	EventID     *uuid.UUID
	Type        string
	Actor       string
	ActorUserID *uuid.UUID
	Ref         string
	Summary     string
	Branch      string
	PR          int
	Data        map[string]any
	OccurredAt  time.Time
}

// Cursor of the activity list: (occurred_at, id) of the last row of the previous page.
type Cursor struct {
	At time.Time
	ID uuid.UUID
}

// ErrInvalidCursor is returned for a malformed cursor.
var ErrInvalidCursor = errors.New("invalid cursor")

// Encode renders the cursor as an opaque string.
func (c Cursor) Encode() string {
	return base64.RawURLEncoding.EncodeToString([]byte("c2|" + strconv.FormatInt(c.At.UnixMicro(), 10) + "|" + c.ID.String()))
}

// ParseCursor decodes a cursor ("" = nil, nil).
func ParseCursor(s string) (*Cursor, error) {
	if s == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrInvalidCursor
	}
	p := strings.Split(string(raw), "|")
	if len(p) != 3 || p[0] != "c2" {
		return nil, ErrInvalidCursor
	}
	us, err := strconv.ParseInt(p[1], 10, 64)
	if err != nil {
		return nil, ErrInvalidCursor
	}
	id, err := uuid.Parse(p[2])
	if err != nil {
		return nil, ErrInvalidCursor
	}
	return &Cursor{At: time.UnixMicro(us).UTC(), ID: id}, nil
}

// PREvent is the slice of an activity row the pull request timings need.
type PREvent struct {
	PR     int
	Type   string
	Actor  string
	Author string // PR author (data.author)
	At     time.Time
}

// Contributor is a pusher with the commits attributed to them.
type Contributor struct {
	Login   string
	UserID  *uuid.UUID
	Commits int
}

// Counts are the aggregates the store computes in SQL.
type Counts struct {
	Commits       int
	DeploysOK     int
	DeploysFailed int
	Contributors  []Contributor
}

// Store persists and reads git_activity (implemented in internal/repository).
type Store interface {
	// Insert stores a; inserted=false when its event was already recorded.
	Insert(ctx context.Context, a *Activity) (bool, error)
	// List returns up to limit rows newest first strictly after the cursor.
	List(ctx context.Context, projectID uuid.UUID, after *Cursor, limit int) ([]Activity, error)
	Counts(ctx context.Context, projectID uuid.UUID, since, until time.Time) (Counts, error)
	// PRTimeline returns every opened/review/merged event of the pull requests that have any of
	// those events inside [since, until].
	PRTimeline(ctx context.Context, projectID uuid.UUID, since, until time.Time) ([]PREvent, error)
	PurgeBefore(ctx context.Context, cutoff time.Time) (int64, error)
}

func str(d map[string]any, k string) string {
	switch t := d[k].(type) {
	case string:
		return t
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatInt(int64(t), 10)
	}
	return ""
}

func num(d map[string]any, k string) int {
	n, _ := strconv.Atoi(str(d, k))
	return n
}

func firstLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > max {
		s = s[:max]
	}
	return s
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// dataKeys are the only event data keys copied into git_activity.data (no free text bodies).
var dataKeys = []string{"author", "state", "reviewer", "conclusion", "environment", "severity", "commits", "sha", "url", "reopened", "title"}

// FromEvent maps a product event onto an activity row. ok=false for events that are not part of
// the activity (check statuses, previews, PR updates...).
func FromEvent(e gitevents.Event) (Activity, bool) {
	a := Activity{ProjectID: e.ProjectID, OrgID: e.OrgID, Actor: e.Actor, Branch: e.Branch, OccurredAt: e.CreatedAt.UTC(), Data: map[string]any{}}
	if e.ActorUserID != uuid.Nil {
		u := e.ActorUserID
		a.ActorUserID = &u
	}
	if e.ID != uuid.Nil {
		id := e.ID
		a.EventID = &id
	}
	d := e.Data
	pr := num(d, "pr")
	prRef := ""
	if pr > 0 {
		a.PR = pr
		prRef = fmt.Sprintf("#%d", pr)
	}
	title := firstLine(str(d, "title"), 200)
	switch e.Name {
	case gitevents.GitPush:
		a.Type, a.Ref, a.Summary = TypePush, short(str(d, "sha")), firstLine(str(d, "message"), 200)
	case gitevents.GitBranchCreated:
		a.Type, a.Ref, a.Summary = TypeBranchCreated, str(d, "branch"), "Rama creada"
	case gitevents.GitBranchDeleted:
		a.Type, a.Ref, a.Summary = TypeBranchDeleted, str(d, "branch"), "Rama eliminada"
	case gitevents.PROpened:
		a.Type = TypePROpened
		if r, _ := d["reopened"].(bool); r {
			a.Type = TypePRReopened
		}
		a.Ref, a.Summary = prRef, title
	case gitevents.PRReviewSubmitted:
		a.Type, a.Ref, a.Summary = TypePRReview, prRef, strings.TrimSpace(str(d, "state")+" "+title)
		if a.Actor == "" {
			a.Actor = str(d, "reviewer")
		}
	case gitevents.PRMerged:
		a.Type, a.Ref, a.Summary = TypePRMerged, prRef, title
	case gitevents.PRClosed:
		a.Type, a.Ref, a.Summary = TypePRClosed, prRef, title
	case gitevents.PRReadyForReview:
		a.Type, a.Ref, a.Summary = TypePRReady, prRef, title
	case gitevents.WorkflowRunCompleted:
		a.Type, a.Ref = TypeWorkflowRun, str(d, "branch")
		a.Summary = strings.TrimSpace(str(d, "name") + ": " + str(d, "conclusion"))
	case gitevents.DeploymentCreated:
		a.Type, a.Ref, a.Summary = TypeDeployCreated, str(d, "environment"), "Despliegue creado"
	case gitevents.DeploymentSucceeded:
		a.Type, a.Ref, a.Summary = TypeDeploySuccess, str(d, "environment"), "Despliegue correcto"
	case gitevents.DeploymentFailed:
		a.Type, a.Ref, a.Summary = TypeDeployFailed, str(d, "environment"), "Despliegue fallido"
	case gitevents.ApprovalRequested:
		a.Type, a.Ref, a.Summary = TypeApprovalReq, str(d, "environment"), "Aprobacion solicitada"
	case gitevents.ApprovalDecided:
		a.Type, a.Ref, a.Summary = TypeApprovalDecide, str(d, "environment"), "Aprobacion "+str(d, "decision")
	case gitevents.PromotionCompleted:
		a.Type, a.Ref, a.Summary = TypePromotion, str(d, "environment"), "Promocion terminada"
	case gitevents.SecurityAlertCreated:
		a.Type, a.Summary = TypeAlertCreated, firstLine(strings.TrimSpace(str(d, "severity")+" "+title), 200)
	case gitevents.SecurityAlertDismiss:
		a.Type, a.Summary = TypeAlertDismissed, title
	case gitevents.ProtectionChanged:
		a.Type, a.Ref, a.Summary = TypeProtection, str(d, "pattern"), "Reglas de rama cambiadas"
	case gitevents.MemberChanged:
		a.Type, a.Summary = TypeMember, "Rol de miembro cambiado"
	default:
		return Activity{}, false
	}
	for _, k := range dataKeys {
		if v, ok := d[k]; ok {
			if s, isStr := v.(string); isStr {
				v = firstLine(s, 200)
			}
			a.Data[k] = v
		}
	}
	if a.Actor == "" {
		a.Actor = str(d, "author")
	}
	return a, true
}

// ActivityRecorder is the gitevents.Subscriber that fills git_activity.
type ActivityRecorder struct{ Store Store }

// Name implements gitevents.Subscriber.
func (r *ActivityRecorder) Name() string { return "activity" }

// Handle implements gitevents.Subscriber (idempotent: one row per event id).
func (r *ActivityRecorder) Handle(ctx context.Context, e gitevents.Event) error {
	a, ok := FromEvent(e)
	if !ok {
		return nil
	}
	a.ID = uuid.New()
	_, err := r.Store.Insert(ctx, &a)
	return err
}

var _ gitevents.Subscriber = (*ActivityRecorder)(nil)

var (
	sharedMu  sync.RWMutex
	sharedRec *ActivityRecorder
)

// SetSharedRecorder publishes the recorder; the event bus wiring (A5) subscribes it with
// bus.Subscribe(gitinsights.SharedRecorder()).
func SetSharedRecorder(r *ActivityRecorder) {
	sharedMu.Lock()
	sharedRec = r
	sharedMu.Unlock()
}

// SharedRecorder returns the published recorder (nil before the wiring).
func SharedRecorder() *ActivityRecorder {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return sharedRec
}
