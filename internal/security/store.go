package security

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// ClaimedUpload is a pending upload handed to the worker with its sanitized content.
type ClaimedUpload struct {
	Upload
	Payload UploadPayload
}

// ApplyResult is the outcome of processing one upload.
type ApplyResult struct {
	Created    []Alert // new or reopened alerts
	Fixed      int
	Superseded bool // a newer upload of the same scope was already applied: nothing was written
}

// DismissParams are the validated inputs of alertDismiss (limits were checked by the service).
type DismissParams struct {
	Reason        string
	Justification string
	ExpiresAt     time.Time
	By            uuid.UUID
	CoversHigh    bool
}

// ExpiryResult reports one project whose suppressions or dismissals expired.
type ExpiryResult struct {
	Target         Target
	Suppressions   []uuid.UUID
	AlertsReopened int
}

// Store persists everything of the package. internal/repository.SecurityRepository implements it
// on Postgres (and tests use MemStore). Every method that changes alerts or suppressions writes
// its audit entry in the same transaction.
type Store interface {
	// ---- uploads ----
	// CreateUpload stores the upload and its sanitized payload. When the idempotency key already
	// exists for the project it returns the earlier upload and created=false.
	CreateUpload(ctx context.Context, u *Upload, payload UploadPayload, a AuditEntry) (existing *Upload, created bool, err error)
	GetUpload(ctx context.Context, projectID, id uuid.UUID) (*Upload, error) // ErrNotFound
	// ClaimUploads moves up to limit pending (or processing for longer than stale) uploads to
	// processing and returns them. Safe across processes (FOR UPDATE SKIP LOCKED).
	ClaimUploads(ctx context.Context, limit int, stale time.Duration, now time.Time) ([]ClaimedUpload, error)
	// ApplyUpload runs Reconcile for every scope of the upload inside ONE transaction that holds
	// an advisory lock per (project, branch, tool): two simultaneous uploads of the same tool are
	// serialized, and an upload older than one already applied is marked superseded.
	ApplyUpload(ctx context.Context, cu ClaimedUpload, now time.Time) (*ApplyResult, error)
	// FailUpload records the error; final=false puts it back to pending for a retry.
	FailUpload(ctx context.Context, id uuid.UUID, msg string, final bool, now time.Time) error

	// ---- alerts ----
	ListAlerts(ctx context.Context, projectID uuid.UUID, q AlertQuery) (items []Alert, next string, err error)
	GetAlert(ctx context.Context, projectID, id uuid.UUID) (*Alert, error) // ErrNotFound
	Overview(ctx context.Context, projectID uuid.UUID) (*Overview, error)
	// DismissAlert marks the (open) alert dismissed, creates the alert-sourced suppression of its
	// fingerprint and dismisses the same fingerprint on other branches. ConflictError if the
	// alert is not open.
	DismissAlert(ctx context.Context, projectID, id uuid.UUID, p DismissParams, now time.Time, a AuditEntry) (*Alert, error)
	// ReopenAlert reopens a dismissed alert, revoking the alert-sourced suppression (and reopening
	// the alerts it covered). ConflictError if the alert is not dismissed or is covered by a
	// manual suppression.
	ReopenAlert(ctx context.Context, projectID, id uuid.UUID, now time.Time, a AuditEntry) (*Alert, error)

	// ---- suppressions ----
	ListSuppressions(ctx context.Context, projectID uuid.UUID) ([]Suppression, error)
	// MaxSeverityMatching returns the highest severity among the project's open alerts that the
	// match selects (ok=false when none).
	MaxSeverityMatching(ctx context.Context, projectID uuid.UUID, m SuppressionMatch) (sev Severity, ok bool, err error)
	// CreateSuppression inserts s and dismisses the open alerts it covers; returns how many.
	CreateSuppression(ctx context.Context, s *Suppression, now time.Time, a AuditEntry) (applied int, err error)
	// RevokeSuppression revokes an active suppression and reopens the alerts it covered.
	RevokeSuppression(ctx context.Context, projectID, id, by uuid.UUID, now time.Time, a AuditEntry) (reopened int, err error) // ErrNotFound
	// ExpireDue expires suppressions and dismissals whose time has come (alerts go back to open).
	ExpireDue(ctx context.Context, now time.Time) ([]ExpiryResult, error)
	// DueExpiringNotices returns active suppressions that expire within window and were not
	// notified yet, and MarkExpiringNotified records the notice.
	DueExpiringNotices(ctx context.Context, now time.Time, window time.Duration) ([]Suppression, error)
	MarkExpiringNotified(ctx context.Context, ids []uuid.UUID, now time.Time) error

	// ---- policy ----
	GetPolicy(ctx context.Context, projectID uuid.UUID) (*Policy, error) // ErrNoPolicy when none stored
	PutPolicy(ctx context.Context, projectID uuid.UUID, p Policy, by uuid.UUID, now time.Time, a AuditEntry) error

	// ---- evaluation inputs ----
	// OpenAlertsAtSHA returns the open (not dismissed, not fixed) alerts last seen at sha, any branch.
	OpenAlertsAtSHA(ctx context.Context, projectID uuid.UUID, sha string) ([]Alert, error)
	// KnownFingerprints returns the fingerprints of the open or dismissed alerts of a branch.
	KnownFingerprints(ctx context.Context, projectID uuid.UUID, branch string) (map[string]bool, error)
	// ToolsUploadedAt returns the tool names with a complete upload for sha.
	ToolsUploadedAt(ctx context.Context, projectID uuid.UUID, sha string) (map[string]bool, error)

	// ---- check runs ----
	// EnsureCheckRun inserts the (project, sha) row if absent (first_seen_at = now) and returns it.
	EnsureCheckRun(ctx context.Context, c CheckRun) (*CheckRun, error)
	SaveCheckRun(ctx context.Context, c CheckRun) error
	// OpenCheckRuns returns runs that are not final (waiting for tools or for publication).
	OpenCheckRuns(ctx context.Context, limit int) ([]CheckRun, error)
	// RecentCheckRuns returns the project's runs evaluated or created since the given time.
	RecentCheckRuns(ctx context.Context, projectID uuid.UUID, since time.Time, limit int) ([]CheckRun, error)

	// ---- project ----
	ProjectTarget(ctx context.Context, projectID uuid.UUID) (Target, error) // ErrNotFound
	DefaultBranchOf(ctx context.Context, projectID uuid.UUID) (string, error)

	// ---- renovate ----
	GetRenovate(ctx context.Context, projectID uuid.UUID) (*RenovateState, error) // ErrNotFound
	PutRenovate(ctx context.Context, s RenovateState, by uuid.UUID, a AuditEntry) error
	// UpdateRenovateObserved stores what was observed in Forgejo (onboarding, open PRs, topic).
	UpdateRenovateObserved(ctx context.Context, s RenovateState) error
	RecordRenovateRun(ctx context.Context, projectID uuid.UUID, at time.Time, status string) error
	WriteAudit(ctx context.Context, a AuditEntry) error
}

// Forge is the slice of gitcore.Core this package uses.
type Forge interface {
	GetRepo(ctx context.Context, r gitcore.RepoRef) (*gitcore.Repository, error)
	ListPulls(ctx context.Context, r gitcore.RepoRef, q gitcore.PullQuery, p gitcore.Page) (gitcore.List[gitcore.Pull], error)
	GetFile(ctx context.Context, r gitcore.RepoRef, ref, path string) (*gitcore.Blob, error)
	SetCheck(ctx context.Context, r gitcore.RepoRef, sha string, in gitcore.CheckInput) (*gitcore.Check, error)
	DispatchWorkflow(ctx context.Context, r gitcore.RepoRef, workflow, ref string, inputs map[string]string) error
	Enabled() bool
}

var _ Forge = gitcore.Core(nil)

// TopicSetter is optional: when the Git core can add or remove one repository topic, enabling
// Renovate also marks the repository with the "renovate" topic (the bot autodiscovers by topic).
// gitcore (A1) has no such method today; see Service.RenovatePut.
type TopicSetter interface {
	SetRepoTopic(ctx context.Context, r gitcore.RepoRef, topic string, present bool) error
}

// RenovateRunner starts one Renovate run limited to a repository ("org/repo").
type RenovateRunner interface {
	Run(ctx context.Context, repo string) error
}
