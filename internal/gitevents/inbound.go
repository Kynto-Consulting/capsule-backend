package gitevents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

// Invalidator drops cached Forgejo lists of a repository (gitcore.Maintenance satisfies it).
type Invalidator interface {
	InvalidateRepo(ctx context.Context, r gitcore.RepoRef) error
}

// PrevSecretStore returns the inbound webhook secret that was replaced less than 24 h ago ("" when
// there is none or it expired). It lets deliveries signed with the old secret keep working while
// Forgejo is updated after a rotation.
type PrevSecretStore interface {
	PreviousWebhookSecret(ctx context.Context, projectID uuid.UUID) (string, error)
}

// Inbound turns verified Forgejo webhook deliveries into product events. The HTTP handler
// (handlers/git_hooks.go) authenticates the delivery first (HMAC) and then calls Accept.
type Inbound struct {
	bus      *Bus
	projects ProjectResolver
	inv      Invalidator
	prev     PrevSecretStore
	log      *slog.Logger
}

// SetPrevSecretStore enables the 24 h acceptance of the previous inbound secret.
func (in *Inbound) SetPrevSecretStore(p PrevSecretStore) { in.prev = p }

// PreviousSecret returns the previous inbound secret still inside its 24 h window, or "".
func (in *Inbound) PreviousSecret(ctx context.Context, projectID uuid.UUID) string {
	if in.prev == nil {
		return ""
	}
	secret, err := in.prev.PreviousWebhookSecret(ctx, projectID)
	if err != nil {
		in.log.Warn("gitevents: loading previous webhook secret failed", "project_id", projectID)
		return ""
	}
	return secret
}

// NewInbound builds the inbound processor. inv and log may be nil.
func NewInbound(bus *Bus, projects ProjectResolver, inv Invalidator, log *slog.Logger) *Inbound {
	if log == nil {
		log = slog.Default()
	}
	return &Inbound{bus: bus, projects: projects, inv: inv, log: log}
}

// Accept records the delivery once (idempotent by delivery id), invalidates the repo caches and
// publishes the matching product event. duplicate=true means this delivery id was already
// processed: the caller must answer 2xx and do nothing else. Deliveries without a delivery
// header are identified by the hash of the body (an exact replay is a duplicate; an operator
// "redeliver" of the same payload is too). Events that map to no product event (a branch
// deletion push, which also arrives as a delete event) only invalidate the caches.
func (in *Inbound) Accept(ctx context.Context, projectID uuid.UUID, ev *gitsource.Event, rawBody []byte) (duplicate bool, err error) {
	name, branch, data, ok := ProductEvent(ev)
	info, perr := in.projects.ProjectInfo(ctx, projectID)
	if perr != nil {
		return false, perr
	}
	if !ok {
		in.invalidate(ctx, info)
		return false, nil
	}
	id := ev.DeliveryID
	if id == "" {
		sum := sha256.Sum256(rawBody)
		id = "body-" + hex.EncodeToString(sum[:16])
	}
	dup, err := in.bus.Record(ctx, Event{
		ProjectID:  projectID,
		Source:     SourceForgejo,
		DeliveryID: id,
		RawEvent:   ev.RawEvent,
		Name:       name,
		Actor:      ev.Actor,
		Branch:     branch,
		Data:       data,
	})
	if err != nil {
		return false, err
	}
	if !dup {
		in.invalidate(ctx, info)
	}
	return dup, nil
}

func (in *Inbound) invalidate(ctx context.Context, info ProjectInfo) {
	if in.inv == nil {
		return
	}
	if err := in.inv.InvalidateRepo(ctx, gitcore.RepoRef{Owner: info.OrgSlug, Repo: info.ProjectSlug}); err != nil {
		in.log.Warn("gitevents: repo cache invalidation failed", "org", info.OrgSlug, "project", info.ProjectSlug)
	}
}

var wipPrefix = regexp.MustCompile(`(?i)^\s*(\[wip\]|wip:)`)

// ProductEvent maps a parsed Forgejo event onto the product catalog. ok=false when the delivery
// has no product meaning. The Forgejo payload shapes for review, status and run events are (?)
// not confirmed against v15.0.11; see gitsource.ParseEvent.
func ProductEvent(ev *gitsource.Event) (name, branch string, data map[string]any, ok bool) {
	switch ev.Kind {
	case gitsource.EventPush:
		if ev.Deleted {
			return "", "", nil, false
		}
		return GitPush, ev.Branch, clean(map[string]any{
			"branch": ev.Branch, "sha": ev.SHA, "before": ev.Before,
			"message": trunc(ev.Message, 500), "commit_url": ev.CommitURL,
		}), true
	case gitsource.EventBranchCreated:
		return GitBranchCreated, ev.Branch, clean(map[string]any{"branch": ev.Branch}), true
	case gitsource.EventBranchDeleted:
		return GitBranchDeleted, ev.Branch, clean(map[string]any{"branch": ev.Branch}), true
	case gitsource.EventPullRequest:
		d := prData(ev)
		switch ev.Action {
		case "opened":
			return PROpened, ev.Branch, clean(d), true
		case "reopened":
			d["reopened"] = true
			return PROpened, ev.Branch, clean(d), true
		case "synchronize":
			d["reason"] = "commits"
			return PRUpdated, ev.Branch, clean(d), true
		case "edited":
			if wipPrefix.MatchString(ev.TitleFrom) && !wipPrefix.MatchString(ev.Title) {
				return PRReadyForReview, ev.Branch, clean(d), true
			}
			d["reason"] = "edited"
			return PRUpdated, ev.Branch, clean(d), true
		case "closed":
			if ev.Merged {
				return PRMerged, ev.Branch, clean(d), true
			}
			return PRClosed, ev.Branch, clean(d), true
		case "review_requested":
			d["requested_reviewer"] = ev.RequestedReviewer
			return PRReviewRequested, ev.Branch, clean(d), true
		}
	case gitsource.EventReview:
		d := prData(ev)
		d["state"] = ev.ReviewState
		d["reviewer"] = ev.Reviewer
		d["body"] = trunc(ev.ReviewBody, 500)
		return PRReviewSubmitted, ev.Branch, clean(d), true
	case gitsource.EventStatus:
		return CheckCompleted, "", clean(map[string]any{
			"sha": ev.SHA, "context": ev.StatusContext, "state": ev.StatusState,
			"url": ev.StatusURL, "description": trunc(ev.StatusDesc, 300),
		}), true
	case gitsource.EventWorkflowRun:
		return WorkflowRunCompleted, ev.Branch, clean(map[string]any{
			"run_id": ev.RunID, "name": ev.RunName, "workflow": ev.RunWorkflow,
			"conclusion": ev.RunConclusion, "status": ev.RunStatus, "url": ev.RunURL,
			"sha": ev.SHA, "branch": ev.Branch,
		}), true
	}
	return "", "", nil, false
}

func prData(ev *gitsource.Event) map[string]any {
	return map[string]any{
		"pr": ev.PR, "title": trunc(ev.Title, 300), "url": ev.PRURL, "branch": ev.Branch,
		"base": ev.BaseRef, "sha": ev.SHA, "author": ev.PRAuthor,
	}
}

// clean drops empty strings and zero numbers so the payload stays small and stable.
func clean(m map[string]any) map[string]any {
	for k, v := range m {
		switch t := v.(type) {
		case string:
			if t == "" {
				delete(m, k)
			}
		case int:
			if t == 0 {
				delete(m, k)
			}
		}
	}
	return m
}

func trunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s + "..."
}

// ForgejoHookEvents are the event names the repository webhook in Forgejo subscribes to for the
// inbound side of A5. VERIFIED against Forgejo 15.0.11 (hook created with this list and read back;
// real deliveries captured in gitsource/testdata/forgejo_v15.0.11): the swagger enum is a free
// string list, review events are pull_request_review_{approved,rejected,comment} (Forgejo rewrites
// the shorter pull_request_approved/rejected to them), and "pull_request" already brings
// synchronize and conversation comments. Same list as internal/forgejo.HookEvents (a test pins it).
var ForgejoHookEvents = []string{
	"push", "create", "delete",
	"pull_request", "pull_request_review_request",
	"pull_request_review_approved", "pull_request_review_rejected", "pull_request_review_comment",
	"action_run_failure", "action_run_recover", "action_run_success",
}
