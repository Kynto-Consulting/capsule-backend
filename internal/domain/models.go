package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID               uuid.UUID  `json:"id"`
	Email            string     `json:"email"`
	PasswordHash     string     `json:"-"`
	Name             string     `json:"name"`
	AvatarURL        *string    `json:"avatar_url,omitempty"`
	Role             string     `json:"role"`
	EmailVerifiedAt  *time.Time `json:"email_verified_at,omitempty"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	DeletedAt        *time.Time `json:"-"`
	TwoFactorSecret  string     `json:"-"`
	TwoFactorEnabled bool       `json:"two_factor_enabled"`
}

type Organization struct {
	ID        uuid.UUID              `json:"id"`
	Name      string                 `json:"name"`
	Slug      string                 `json:"slug"`
	OwnerID   uuid.UUID              `json:"owner_id"`
	Plan      string                 `json:"plan"`
	Settings  map[string]interface{} `json:"settings"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	DeletedAt *time.Time             `json:"-"`
}

type Project struct {
	ID            uuid.UUID              `json:"id"`
	OrgID         uuid.UUID              `json:"org_id"`
	Name          string                 `json:"name"`
	Slug          string                 `json:"slug"`
	RepoURL       string                 `json:"repo_url,omitempty"`
	Branch        string                 `json:"branch"`
	BuildStrategy string                 `json:"build_strategy"`
	DeployType    string                 `json:"deploy_type"`
	Runtime       string                 `json:"runtime,omitempty"`
	Serverless    bool                   `json:"serverless"`
	Replicas      int                    `json:"replicas"`
	Status        string                 `json:"status"`
	Labels        map[string]interface{} `json:"labels"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	DeletedAt     *time.Time             `json:"-"`
}

type Deployment struct {
	ID               uuid.UUID  `json:"id"`
	ProjectID        uuid.UUID  `json:"project_id"`
	ServerID         *uuid.UUID `json:"server_id,omitempty"`
	Version          string     `json:"version"`
	GitSHA           string     `json:"git_sha,omitempty"`
	Status           string     `json:"status"`
	ImageTag         string     `json:"image_tag,omitempty"`
	BuildStrategy    string     `json:"build_strategy,omitempty"`
	DeployType       string     `json:"deploy_type,omitempty"`
	ContainerPort    int        `json:"container_port,omitempty"`
	BuildDurationMs  *int64     `json:"build_duration_ms,omitempty"`
	DeployDurationMs *int64     `json:"deploy_duration_ms,omitempty"`
	Trigger          string     `json:"trigger"`
	TriggeredBy      *uuid.UUID `json:"triggered_by,omitempty"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	SourceKey        *string    `json:"source_key,omitempty"`
	HostPort         *int       `json:"host_port,omitempty"`
	FunctionURL      *string    `json:"function_url,omitempty"`
}

type BuildLog struct {
	ID           uuid.UUID `json:"id"`
	DeploymentID uuid.UUID `json:"deployment_id"`
	Level        string    `json:"level"`
	Message      string    `json:"message"`
	CreatedAt    time.Time `json:"created_at"`
}

type Database struct {
	ID             uuid.UUID  `json:"id"`
	ProjectID      uuid.UUID  `json:"project_id"`
	Name           string     `json:"name"`
	Engine         string     `json:"engine"`
	Version        string     `json:"version"`
	Host           string     `json:"host"`
	Port           int        `json:"port"`
	DBName         string     `json:"db_name"`
	CredentialsEnc []byte     `json:"-"`
	Status         string     `json:"status"`
	SizeMB         int        `json:"size_mb"`
	ContainerID    string     `json:"container_id,omitempty"`
	VolumeName     string     `json:"volume_name,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DeletedAt      *time.Time `json:"-"`
}

type RedisInstance struct {
	ID          uuid.UUID  `json:"id"`
	ProjectID   uuid.UUID  `json:"project_id"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Host        string     `json:"host"`
	Port        int        `json:"port"`
	PasswordEnc []byte     `json:"-"`
	Status      string     `json:"status"`
	MemoryMB    int        `json:"memory_mb"`
	ContainerID string     `json:"container_id,omitempty"`
	VolumeName  string     `json:"volume_name,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"-"`
}

type Domain struct {
	ID                uuid.UUID  `json:"id"`
	ProjectID         uuid.UUID  `json:"project_id"`
	DomainName        string     `json:"domain_name"`
	RecordType        string     `json:"record_type"`
	RecordValue       string     `json:"record_value,omitempty"`
	VerificationToken string     `json:"verification_token,omitempty"`
	Status            string     `json:"status"`
	SSLEnabled        bool       `json:"ssl_enabled"`
	DNSProvider       string     `json:"dns_provider"`
	VerifiedAt        *time.Time `json:"verified_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type EnvVar struct {
	ID        uuid.UUID `json:"id"`
	ProjectID uuid.UUID `json:"project_id"`
	Key       string    `json:"key"`
	ValueEnc  []byte    `json:"-"`
	IsSecret  bool      `json:"is_secret"`
	Scope     string    `json:"scope"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Server struct {
	ID               uuid.UUID              `json:"id"`
	Name             string                 `json:"name"`
	InstanceID       string                 `json:"instance_id,omitempty"`
	InstanceType     string                 `json:"instance_type,omitempty"`
	AvailabilityZone string                 `json:"availability_zone,omitempty"`
	PublicIP         string                 `json:"public_ip,omitempty"`
	PrivateIP        string                 `json:"private_ip,omitempty"`
	Status           string                 `json:"status"`
	Role             string                 `json:"role"`
	Metadata         map[string]interface{} `json:"metadata"`
	LastHeartbeatAt  *time.Time             `json:"last_heartbeat_at,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
	DeletedAt        *time.Time             `json:"-"`
}

type Worker struct {
	ID            uuid.UUID  `json:"id"`
	ProjectID     uuid.UUID  `json:"project_id"`
	Name          string     `json:"name"`
	Command       string     `json:"command"`
	Replicas      int        `json:"replicas"`
	Status        string     `json:"status"`
	ContainerID   string     `json:"container_id,omitempty"`
	RestartPolicy string     `json:"restart_policy"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `json:"-"`
}

type CronJob struct {
	ID            uuid.UUID  `json:"id"`
	ProjectID     uuid.UUID  `json:"project_id"`
	Name          string     `json:"name"`
	Schedule      string     `json:"schedule"`
	Command       string     `json:"command"`
	Timezone      string     `json:"timezone"`
	Status        string     `json:"status"`
	LastRunStatus *string    `json:"last_run_status,omitempty"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	NextRunAt     *time.Time `json:"next_run_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `json:"-"`
}

type APIToken struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	Name       string     `json:"name"`
	TokenHash  string     `json:"-"`
	Prefix     string     `json:"prefix"`
	Scopes     string     `json:"scopes"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type AuditLog struct {
	ID           uuid.UUID              `json:"id"`
	UserID       *uuid.UUID             `json:"user_id,omitempty"`
	OrgID        *uuid.UUID             `json:"org_id,omitempty"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   *uuid.UUID             `json:"resource_id,omitempty"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	OldValues    map[string]interface{} `json:"old_values,omitempty"`
	NewValues    map[string]interface{} `json:"new_values,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
	CreatedAt    time.Time              `json:"created_at"`
}

type ExecutionLog struct {
	ID        uuid.UUID `json:"id"`
	ProjectID uuid.UUID `json:"project_id"`
	Source    string    `json:"source"`
	SourceID  string    `json:"source_id"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// TokenPair is returned after successful authentication.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// ListMeta is included in paginated list responses.
type ListMeta struct {
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
	Total   int `json:"total"`
}
