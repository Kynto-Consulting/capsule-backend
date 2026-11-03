// Package gitimport is Git Capsule package C1: importing repositories from GitHub into Forgejo
// (importCreate / importGet) and push mirrors towards a third party (mirror*).
//
// Secrets: the GitHub token of an import is EPHEMERAL. It travels in the request body, lives in the
// memory of the goroutine that runs the import and is handed to Forgejo (POST /repos/migrate); it is
// never stored (no column holds it), never logged and always scrubbed from error text (see
// redact.go). A mirror credential is stored encrypted (AES-GCM, platform key) and is write-only.
//
// Forgejo is only reached through the gitcore interfaces; GitHub only through GitHub (github.go),
// which sits behind the SSRF policy of gitsource.
//
// Forgejo facts verified against a real v15.0.11 (see the C1 report): push mirrors and migrations
// refuse private/loopback targets (push_mirrors answers 401 "Permission denied" for them, which is
// what A1 saw), `[mirror] ENABLED=false` answers 400 "Mirror feature is disabled", and
// branch_filter is a comma-separated list of branch names or globs (not a glob alternation).
package gitimport

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

// Import and repository states (git_imports.status / git_import_repos.status).
const (
	StatusQueued  = "queued"
	StatusRunning = "running"
	StatusPartial = "partial"
	StatusSuccess = "success"
	StatusFailed  = "failed"
)

// Audit actions (audit_logs.action is varchar(50)).
const (
	AuditImportStart  = "git.import.start"
	AuditImportFinish = "git.import.finish"
	AuditMirrorSet    = "git.mirror.set"
	AuditMirrorDelete = "git.mirror.delete"
	AuditMirrorSync   = "git.mirror.sync"
)

// Errors the handlers translate.
var (
	ErrValidation          = errors.New("invalid request")                   // 422 VALIDATION_ERROR (message is safe)
	ErrIdempotencyConflict = errors.New("idempotency key conflict")          // 409 IDEMPOTENCY_CONFLICT
	ErrSlugBusy            = errors.New("another import is using that name") // 409 CONFLICT
	ErrBadToken            = errors.New("the GitHub token was rejected")     // 422 TOKEN_INVALID
	ErrNotConfigured       = errors.New("the Git service is not configured") // 503 GIT_NOT_READY
	ErrNotFound            = domain.ErrNotFound
	ErrBusy                = errors.New("a synchronization is already running") // 409 CONFLICT
	// ErrDuplicateKey is returned by Store.CreateImport when the idempotency key already exists.
	ErrDuplicateKey = errors.New("duplicate idempotency key")
)

// validationError carries a message that is safe to show to the caller.
type validationError struct{ msg string }

func (e validationError) Error() string        { return e.msg }
func (e validationError) Is(target error) bool { return target == ErrValidation }

func invalid(msg string) error { return validationError{msg} }

// ---- import model ---------------------------------------------------------------------------

// CodeOwnersReport is the result of converting a GitHub CODEOWNERS file. The converted text is NOT
// committed to the repository (gitcore has no write-file method on purpose): it is reported so an
// administrator can review it and commit it.
type CodeOwnersReport struct {
	Path      string   `json:"path"`      // where it was found on GitHub
	Converted string   `json:"converted"` // Forgejo syntax (Go regular expressions)
	Warnings  []string `json:"warnings"`  // everything that has no equivalent
}

// RepoState is the state of one repository of an import.
type RepoState struct {
	Name           string            `json:"name"` // owner/repo on GitHub
	Slug           string            `json:"slug"` // project slug = Forgejo repository name
	Status         string            `json:"status"`
	ProjectID      *uuid.UUID        `json:"project_id"`
	CreatedProject bool              `json:"-"` // the project was created by this import
	Error          string            `json:"error"`
	Warnings       []string          `json:"warnings"`
	CodeOwners     *CodeOwnersReport `json:"codeowners,omitempty"`
	Attempts       int               `json:"-"`
	StartedAt      *time.Time        `json:"-"`
	FinishedAt     *time.Time        `json:"-"`
}

// Import is one import job.
type Import struct {
	ID             uuid.UUID
	OrgID          uuid.UUID
	CreatedBy      *uuid.UUID
	Source         string
	Status         string
	Include        []string
	CreateProjects bool
	IdemKey        string
	RequestHash    string
	Attempts       int
	CreatedAt      time.Time
	UpdatedAt      time.Time
	FinishedAt     *time.Time
	Repos          []RepoState
}

// RepoUpdate changes the mutable columns of one repository row.
type RepoUpdate struct {
	Status         string
	ProjectID      *uuid.UUID
	CreatedProject *bool
	Error          string
	Warnings       []string
	CodeOwners     *CodeOwnersReport
	Finished       bool
}

// Store persists imports (git_imports, git_import_repos).
type Store interface {
	// CreateImport inserts the import and its repos; ErrDuplicateKey when (org, idempotency key) exists.
	CreateImport(ctx context.Context, im *Import) error
	// GetImport returns the import with its repos (ErrNotFound if it is not of that org).
	GetImport(ctx context.Context, orgID, id uuid.UUID) (*Import, error)
	FindByIdem(ctx context.Context, orgID uuid.UUID, key string) (*Import, error)
	// BusySlugs returns those of slugs that a queued/running repository of ANOTHER import of the org uses.
	BusySlugs(ctx context.Context, orgID uuid.UUID, slugs []string, except uuid.UUID) ([]string, error)
	// SetStatus sets the import status; finished stamps finished_at.
	SetStatus(ctx context.Context, id uuid.UUID, status string, finished bool) error
	// Resume resets the non-successful repos to queued (clearing their error), bumps attempts and sets
	// the import to queued.
	Resume(ctx context.Context, id uuid.UUID) error
	// BeginRepo marks the repo running (attempts+1) and returns its current row.
	BeginRepo(ctx context.Context, id uuid.UUID, name string) (*RepoState, error)
	UpdateRepo(ctx context.Context, id uuid.UUID, name string, u RepoUpdate) error
	// Touch refreshes updated_at (heartbeat of a live import).
	Touch(ctx context.Context, id uuid.UUID) error
	// FailInterrupted marks queued/running imports whose heartbeat is older than before as partial or
	// failed and their unfinished repos as failed with msg. Returns how many imports changed.
	FailInterrupted(ctx context.Context, before time.Time, msg string) (int, error)
}

// AuditRecord is one audit_logs row. Never put a secret in Values.
type AuditRecord struct {
	OrgID        uuid.UUID
	UserID       *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	IP           string
	Values       map[string]any
}

// Auditor writes audit rows; failures are logged by the caller, never fatal.
type Auditor interface {
	Audit(ctx context.Context, r AuditRecord) error
}

// ---- mirror model ---------------------------------------------------------------------------

// Mirror intervals of the contract (MirrorInput.interval).
const (
	IntervalOnPush = "on_push"
	IntervalHourly = "hourly"
	IntervalDaily  = "daily"
)

// Mirror is the stored configuration of a project's push mirror. The credential is never part of it.
type Mirror struct {
	ProjectID         uuid.UUID
	OrgID             uuid.UUID
	RemoteURL         string
	Branches          []string
	Interval          string
	HasCredential     bool
	ForgejoRemoteName string
	LastSyncAt        *time.Time
	LastError         string
	SyncingSince      *time.Time
	CreatedBy         *uuid.UUID
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// MirrorStore persists git_mirrors; the credential is encrypted by the implementation.
type MirrorStore interface {
	GetMirror(ctx context.Context, projectID uuid.UUID) (*Mirror, error) // ErrNotFound
	// PutMirror upserts the row. credential nil keeps the stored one; a non-nil pointer replaces it
	// ("" removes it).
	PutMirror(ctx context.Context, m *Mirror, credential *string) error
	// Credential returns the decrypted credential ("" if none).
	Credential(ctx context.Context, projectID uuid.UUID) (string, error)
	DeleteMirror(ctx context.Context, projectID uuid.UUID) error
	// RecordSync stores the outcome observed in Forgejo.
	RecordSync(ctx context.Context, projectID uuid.UUID, at *time.Time, lastErr string) error
	// BeginSync claims the "syncing" flag; false when another sync started after staleBefore.
	BeginSync(ctx context.Context, projectID uuid.UUID, staleBefore time.Time) (bool, error)
	EndSync(ctx context.Context, projectID uuid.UUID) error
}
