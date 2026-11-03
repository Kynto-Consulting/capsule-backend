package backup

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrDisabled      = errors.New("backups are disabled on this platform")
	ErrRunInProgress = errors.New("a backup job is already running for this project")
	ErrNotFound      = errors.New("not found")
)

// Config is the platform-level backup configuration (CAPSULE_BACKUPS_*).
type Config struct {
	Enabled              bool
	Bucket               string
	DefaultSchedule      string
	DefaultOn            bool
	DefaultRetentionDays int
	BucketRetentionDays  int // upper bound for retention_days (the bucket lifecycle expiration)
	HelperImage          string
	PlatformDir          string // host dir holding compose, .env and certs
	DockerConfigDir      string // host dir holding daemon.json
	RunTimeout           time.Duration
}

func (c *Config) defaults() {
	if !ValidSchedule(c.DefaultSchedule) {
		c.DefaultSchedule = "daily"
	}
	if c.DefaultRetentionDays <= 0 {
		c.DefaultRetentionDays = 14
	}
	if c.BucketRetentionDays <= 0 {
		c.BucketRetentionDays = 30
	}
	if c.HelperImage == "" {
		c.HelperImage = "debian:bookworm-slim"
	}
	if c.PlatformDir == "" {
		c.PlatformDir = "/opt/capsule"
	}
	if c.DockerConfigDir == "" {
		c.DockerConfigDir = "/etc/docker"
	}
	if c.RunTimeout <= 0 {
		c.RunTimeout = 4 * time.Hour
	}
}

// Settings is the effective per-project configuration.
type Settings struct {
	ProjectID        uuid.UUID
	Enabled          bool
	Schedule         string
	RetentionDays    int
	IncludeDatabases bool
	IncludeVolumes   bool
	Configured       bool // false => platform defaults, no row stored
}

type Run struct {
	ID         uuid.UUID
	ProjectID  *uuid.UUID // nil = platform
	OrgID      *uuid.UUID
	Kind       string // backup | restore | verify
	Trigger    string // manual | schedule
	Status     string // running | success | failed
	StartedAt  time.Time
	FinishedAt *time.Time
	SizeBytes  int64
	Error      string
	UserID     *uuid.UUID
}

type Snapshot struct {
	ID        uuid.UUID
	ProjectID *uuid.UUID
	RunID     uuid.UUID
	Kind      string // database | volume | manifest | platform
	Source    string
	SourceID  string // database id for database snapshots
	Engine    string
	ObjectKey string
	SizeBytes int64  // stored (encrypted) size
	Checksum  string // sha256 hex of the plaintext stream
	CreatedAt time.Time
}

// Candidate is a project (or the platform, ProjectID nil) the scheduler may start a run for.
type Candidate struct {
	ProjectID *uuid.UUID
	OrgID     *uuid.UUID
	Settings  Settings
	LastStart *time.Time
	Running   bool
}

type AuditEntry struct {
	OrgID        *uuid.UUID
	UserID       *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	IP           string
	NewValues    map[string]any
}

// ManifestInput is what only the database knows about a project's last good deployment.
type ManifestInput struct {
	DeploymentID  uuid.UUID
	Version       string
	GitSHA        string
	ImageTag      string
	SourceKey     string
	ContainerPort int
	HostPort      int
	DeployType    string
	EnvVarNames   []string
}

// Repo is the persistence the backup service needs (implemented by repository.BackupRepository).
type Repo interface {
	GetSettings(ctx context.Context, projectID uuid.UUID) (*Settings, error) // nil when never configured
	UpsertSettings(ctx context.Context, s *Settings) error
	// ClaimDue runs under a Postgres advisory lock (one instance at a time): it lists candidates,
	// inserts a 'running' run for every one decide() accepts, and returns those runs.
	ClaimDue(ctx context.Context, includePlatform bool, defaults Settings, decide func(Candidate) bool) ([]Run, error)
	CreateRun(ctx context.Context, r *Run) error // ErrRunInProgress when one is already running
	FinishRun(ctx context.Context, id uuid.UUID, status string, size int64, errMsg string, at time.Time) error
	FailOrphans(ctx context.Context, at time.Time) (int, error)
	ListRuns(ctx context.Context, projectID *uuid.UUID, limit int) ([]Run, error)
	LastBackupStart(ctx context.Context, projectID *uuid.UUID) (*time.Time, error)
	AddSnapshot(ctx context.Context, s *Snapshot) error
	ListSnapshots(ctx context.Context, projectID *uuid.UUID) ([]Snapshot, error) // newest first, not deleted
	GetSnapshot(ctx context.Context, projectID *uuid.UUID, id uuid.UUID) (*Snapshot, error)
	ExpiredSnapshots(ctx context.Context, projectID *uuid.UUID, before time.Time) ([]Snapshot, error)
	MarkSnapshotDeleted(ctx context.Context, id uuid.UUID) error
	LastDeployment(ctx context.Context, projectID uuid.UUID) (*ManifestInput, error) // never nil; DeploymentID is uuid.Nil when none succeeded
	Audit(ctx context.Context, e AuditEntry) error
}
