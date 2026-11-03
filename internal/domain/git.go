package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// ProjectGit links a project to a Git repository (auto-deploy + PR previews).
// Credential and WebhookSecret hold the DECRYPTED values; they are loaded only
// by the repository for server-side use and are never serialized.
type ProjectGit struct {
	ProjectID       uuid.UUID `json:"project_id"`
	Provider        string    `json:"provider"`
	RepoURL         string    `json:"repo_url"`
	Branch          string    `json:"branch"`
	AuthKind        string    `json:"auth_kind"`
	Credential      string    `json:"-"`
	WebhookSecret   string    `json:"-"`
	AutoDeploy      bool      `json:"auto_deploy"`
	PreviewEnabled  bool      `json:"preview_enabled"`
	PreviewMax      int       `json:"preview_max"`
	PreviewTTLHours int       `json:"preview_ttl_hours"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Preview is an ephemeral project created for a pull request.
type Preview struct {
	ProjectID        uuid.UUID  `json:"project_id"`
	ParentProjectID  uuid.UUID  `json:"parent_project_id"`
	OrgID            uuid.UUID  `json:"org_id"`
	Slug             string     `json:"slug"`
	PR               int        `json:"pr"`
	Status           string     `json:"status"`
	CommentID        int64      `json:"-"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	LatestDeployment *uuid.UUID `json:"latest_deployment_id,omitempty"`
	DeploymentStatus string     `json:"deployment_status,omitempty"`
	URL              string     `json:"url,omitempty"`
}

// GitRepository persists project_git rows and preview metadata.
type GitRepository interface {
	Get(ctx context.Context, projectID uuid.UUID) (*ProjectGit, error)
	Upsert(ctx context.Context, g *ProjectGit) (*ProjectGit, error)
	Delete(ctx context.Context, projectID uuid.UUID) error
	// RotateWebhookSecret stores a new (encrypted) webhook secret.
	RotateWebhookSecret(ctx context.Context, projectID uuid.UUID, secret string) error

	// Previews.
	GetPreview(ctx context.Context, parentID uuid.UUID, pr int) (*Preview, error)
	CreatePreview(ctx context.Context, parent *Project, pr int, slug string, expiresAt time.Time) (*Preview, error)
	TouchPreview(ctx context.Context, previewID uuid.UUID, expiresAt time.Time) error
	SetPreviewComment(ctx context.Context, previewID uuid.UUID, commentID int64) error
	ListPreviews(ctx context.Context, parentID uuid.UUID) ([]*Preview, error)
	// ListExpiredPreviews returns active previews whose expires_at has passed.
	ListExpiredPreviews(ctx context.Context, now time.Time) ([]*Preview, error)
	// DestroyPreview soft-deletes the preview project, frees its slug and removes its domains.
	DestroyPreview(ctx context.Context, previewID uuid.UUID) error
	// IsPreview reports whether the project is an ephemeral PR preview.
	IsPreview(ctx context.Context, projectID uuid.UUID) (bool, error)

	// Deployments of source=git.
	// CancelSupersededGit cancels queued git deployments of the project other than keepID.
	CancelSupersededGit(ctx context.Context, projectID, keepID uuid.UUID) ([]uuid.UUID, error)
	DeploymentStatus(ctx context.Context, deploymentID uuid.UUID) (string, error)
}
