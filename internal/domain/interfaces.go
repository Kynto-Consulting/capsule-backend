package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// UserRepository handles user persistence.
type UserRepository interface {
	Create(ctx context.Context, user *User) (*User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Update(ctx context.Context, user *User) (*User, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// OrganizationRepository handles org persistence.
type OrganizationRepository interface {
	Create(ctx context.Context, org *Organization) (*Organization, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Organization, error)
	GetBySlug(ctx context.Context, slug string) (*Organization, error)
	ListByUser(ctx context.Context, userID uuid.UUID, page, perPage int) ([]*Organization, int, error)
	Update(ctx context.Context, org *Organization) (*Organization, error)
	Delete(ctx context.Context, id uuid.UUID) error
	AddMember(ctx context.Context, orgID, userID uuid.UUID, role string) error
	RemoveMember(ctx context.Context, orgID, userID uuid.UUID) error
	IsMember(ctx context.Context, orgID, userID uuid.UUID) (bool, error)
	GetMembers(ctx context.Context, orgID uuid.UUID) ([]*OrgMember, error)
	UpdateMemberRole(ctx context.Context, orgID, userID uuid.UUID, role string) error
	GetMemberRole(ctx context.Context, orgID, userID uuid.UUID) (string, error)
}

// ProjectRepository handles project persistence.
type ProjectRepository interface {
	Create(ctx context.Context, project *Project) (*Project, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Project, error)
	GetBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*Project, error)
	GetBySlugGlobal(ctx context.Context, slug string) (*Project, error)
	ListByOrg(ctx context.Context, orgID uuid.UUID, page, perPage int) ([]*Project, int, error)
	Update(ctx context.Context, project *Project) (*Project, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// DeploymentRepository handles deployment persistence.
type DeploymentRepository interface {
	Create(ctx context.Context, d *Deployment) (*Deployment, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Deployment, error)
	ListByProject(ctx context.Context, projectID uuid.UUID, page, perPage int) ([]*Deployment, int, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error
	AppendLog(ctx context.Context, log *BuildLog) error
	GetLogs(ctx context.Context, deploymentID uuid.UUID) ([]*BuildLog, error)
	Cancel(ctx context.Context, id uuid.UUID) error
	UpdateHostPort(ctx context.Context, id uuid.UUID, hostPort int) error
	UpdateFunctionURL(ctx context.Context, id uuid.UUID, functionURL string) error
	GetLatestSuccessfulByProject(ctx context.Context, projectID uuid.UUID) (*Deployment, error)
}

// EnvVarRepository handles environment variable persistence.
type EnvVarRepository interface {
	Upsert(ctx context.Context, e *EnvVar) (*EnvVar, error)
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]*EnvVar, error)
	GetByKey(ctx context.Context, projectID uuid.UUID, key string) (*EnvVar, error)
	Delete(ctx context.Context, projectID uuid.UUID, key string) error
}

// APITokenRepository handles API token persistence.
type APITokenRepository interface {
	Create(ctx context.Context, token *APIToken) (*APIToken, error)
	GetByHash(ctx context.Context, hash string) (*APIToken, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*APIToken, error)
	Revoke(ctx context.Context, id uuid.UUID) error
	TouchLastUsed(ctx context.Context, id uuid.UUID) error
	Update(ctx context.Context, id uuid.UUID, rateLimitRPM int, ipAllowlist string) (*APIToken, error)
	IncrementUsage(ctx context.Context, id uuid.UUID) error
}

// AuditRepository handles audit log persistence.
type AuditRepository interface {
	Append(ctx context.Context, log *AuditLog) error
	ListByOrg(ctx context.Context, orgID uuid.UUID, page, perPage int) ([]*AuditLog, int, error)
}

// DatabaseRepository handles managed database persistence.
type DatabaseRepository interface {
	Create(ctx context.Context, db *Database) (*Database, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Database, error)
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]*Database, error)
	ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*Database, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status, host string, port int) error
	UpdateCredentials(ctx context.Context, id uuid.UUID, credsEnc []byte) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetGlobalStats(ctx context.Context) (projects int, rdsDatabases int, s3Buckets int, domains int, err error)
	GetUserStats(ctx context.Context, userID uuid.UUID) (projects int, rdsDatabases int, s3Buckets int, domains int, err error)
}

// DomainRepository handles domain record persistence.
type DomainRepository interface {
	Create(ctx context.Context, d *Domain) (*Domain, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Domain, error)
	GetByHostname(ctx context.Context, hostname string) (*Domain, error)
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]*Domain, error)
	ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*Domain, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status, recordValue string) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// AuthService handles authentication business logic.
type AuthService interface {
	Register(ctx context.Context, name, email, password, inviteCode, onboardingCode string) (*User, *TokenPair, error)
	Login(ctx context.Context, email, password string) (*User, *TokenPair, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)
	ValidateAccessToken(ctx context.Context, token string) (*User, error)
	GetOnboardingStatus(ctx context.Context) (saved bool, secret string, qrCodeURI string, err error)
	VerifyOnboarding(ctx context.Context, code string) (bool, error)
}

// CacheStore abstracts the Redis cache.
type CacheStore interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, ttlSeconds int) error
	Del(ctx context.Context, key string) error
}

// SettingsRepository handles platform-wide settings persistence.
type SettingsRepository interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// WorkerRepository handles worker process persistence.
type WorkerRepository interface {
	Create(ctx context.Context, w *Worker) (*Worker, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Worker, error)
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]*Worker, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status, containerID string) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// CronJobRepository handles cron job persistence.
type CronJobRepository interface {
	Create(ctx context.Context, c *CronJob) (*CronJob, error)
	GetByID(ctx context.Context, id uuid.UUID) (*CronJob, error)
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]*CronJob, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateLastRun(ctx context.Context, id uuid.UUID, runStatus string, nextRunAt *time.Time) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListActive(ctx context.Context) ([]*CronJob, error)
}

// EmailLogRepository handles email send log persistence.
type EmailLogRepository interface {
	Create(ctx context.Context, log *EmailLog) (*EmailLog, error)
	ListByProject(ctx context.Context, projectID uuid.UUID, limit int) ([]*EmailLog, error)
}

// ExecutionLogRepository handles runtime/lambda/worker/cron execution log persistence.
type ExecutionLogRepository interface {
	Append(ctx context.Context, log *ExecutionLog) error
	ListByProject(ctx context.Context, projectID uuid.UUID, source string, limit int) ([]*ExecutionLog, error)
	ListBySource(ctx context.Context, projectID uuid.UUID, source, sourceID string, limit int) ([]*ExecutionLog, error)
	// ListSources returns distinct source_id values for a project+source combination.
	// Used to populate the resource selector in the UI (which Lambda fn, which cron job, etc.)
	ListSources(ctx context.Context, projectID uuid.UUID, source string) ([]string, error)
}
