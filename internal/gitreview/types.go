// Package gitreview is Git Capsule package B8: CODEOWNERS, required and pending reviews, draft
// handling, Capsule-side auto-merge and the capsule/policy check.
//
// Facts it relies on (verified by A1 against Forgejo, see gitcore/types.go): a draft is the "WIP:"
// title prefix (so no pr_draft_state table exists), Forgejo answers 423 when merging a freshly
// created pull request, and CancelAutoMerge / merge_when_checks_succeed were NOT probed against a
// real Forgejo. For that reason auto-merge lives in Capsule (table pr_auto_merge): a worker retries
// the merge on every status / review / workflow_run event and on a periodic sweep, always passing
// head_sha so a moved head can never be merged by mistake.
package gitreview

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

// PolicyContext is the commit status Capsule publishes on every pull request head.
const PolicyContext = "capsule/policy"

// Project is a Capsule project linked to a Forgejo repository.
type Project struct {
	ID    uuid.UUID
	OrgID uuid.UUID
	Ref   gitcore.RepoRef
}

// Projects resolves projects by id (events) or by Forgejo coordinates (merge blockers).
type Projects interface {
	ByID(ctx context.Context, id uuid.UUID) (*Project, error)
	ByRef(ctx context.Context, ref gitcore.RepoRef) (*Project, error)
}

// Member is a project member with the effective role and the Forgejo login.
type Member struct {
	UserID uuid.UUID
	Login  string // lowercase Forgejo login
	Email  string
	Role   authz.Role
}

// Roster lists who has access to a project (effective roles, from authz.Resolve).
type Roster interface {
	Members(ctx context.Context, p Project) ([]Member, error)
}

// Authorizer re-checks a Capsule permission at the moment the worker acts.
type Authorizer interface {
	Can(ctx context.Context, userID, orgID, projectID uuid.UUID, a authz.Action) (bool, error)
}

// Auto-merge row states.
const (
	StateArmed     = "armed"
	StateMerging   = "merging"
	StateMerged    = "merged"
	StateCancelled = "cancelled"
)

// AutoMerge is one row of pr_auto_merge (one per pull request; re-arming replaces it).
type AutoMerge struct {
	ProjectID      uuid.UUID
	PR             int
	HeadSHA        string
	Style          gitcore.MergeStyle
	Title, Message string
	DeleteBranch   bool
	RequestedBy    uuid.UUID
	RequestedLogin string
	State          string
	Reason         string
	Attempts       int
	LastAttemptAt  *time.Time
	NextAttemptAt  time.Time
	ClaimedUntil   *time.Time
	LastError      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Active reports whether the worker still has to act on the row.
func (a AutoMerge) Active() bool { return a.State == StateArmed || a.State == StateMerging }

// ErrNotFound is returned by stores when there is no row.
var ErrNotFound = errors.New("gitreview: not found")

// AutoMergeStore persists pr_auto_merge. Every method that changes state is atomic.
type AutoMergeStore interface {
	// Arm inserts the row or replaces the one of the PR (state armed, attempts 0).
	Arm(ctx context.Context, a AutoMerge) (*AutoMerge, error)
	Get(ctx context.Context, projectID uuid.UUID, pr int) (*AutoMerge, error) // ErrNotFound
	// Cancel moves an active row to cancelled; false when there was none.
	Cancel(ctx context.Context, projectID uuid.UUID, pr int, reason string) (bool, error)
	ListArmedByHead(ctx context.Context, projectID uuid.UUID, sha string) ([]AutoMerge, error)
	// ListDue returns active rows whose next attempt is due (armed) or whose lease expired (merging).
	ListDue(ctx context.Context, now time.Time, limit int) ([]AutoMerge, error)
	// Claim atomically moves an armed row (or a merging row with an expired lease) with that
	// head_sha to merging until lease. ok=false: nothing to claim (someone else holds it).
	Claim(ctx context.Context, projectID uuid.UUID, pr int, headSHA string, now, lease time.Time) (*AutoMerge, bool, error)
	// Release puts a merging row back to armed. countAttempt adds one failed attempt.
	Release(ctx context.Context, projectID uuid.UUID, pr int, headSHA string, next time.Time, errMsg string, countAttempt bool) error
	// Defer reschedules an armed row without touching attempts.
	Defer(ctx context.Context, projectID uuid.UUID, pr int, next time.Time, note string) error
	// Finish ends an active row as merged or cancelled.
	Finish(ctx context.Context, projectID uuid.UUID, pr int, state, reason string) error
}

// Dismissal is one reviewDismiss recorded in pr_review_dismissals.
type Dismissal struct {
	ProjectID   uuid.UUID
	PR          int
	ReviewID    int64
	Reviewer    string
	ReviewState string
	CommitSHA   string
	DismissedBy uuid.UUID
	Reason      string
	CreatedAt   time.Time
}

// DismissalLog keeps who dismissed what (Forgejo only knows the service account).
type DismissalLog interface {
	Record(ctx context.Context, d Dismissal) error
	List(ctx context.Context, projectID uuid.UUID, pr int) ([]Dismissal, error)
}
