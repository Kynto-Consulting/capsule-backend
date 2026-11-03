package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

// GitRepository persists project_git rows and preview projects.
type GitRepository struct {
	pool      *pgxpool.Pool
	secretKey string
}

func NewGitRepository(pool *pgxpool.Pool, secretKey string) *GitRepository {
	return &GitRepository{pool: pool, secretKey: secretKey}
}

var _ domain.GitRepository = (*GitRepository)(nil)

const gitCols = `project_id, provider, repo_url, branch, auth_kind, auth_enc, webhook_secret_enc,
	auto_deploy, preview_enabled, preview_max, preview_ttl_hours, created_at, updated_at`

func (r *GitRepository) scanGit(row interface{ Scan(...any) error }) (*domain.ProjectGit, error) {
	var g domain.ProjectGit
	var authEnc, secEnc []byte
	if err := row.Scan(&g.ProjectID, &g.Provider, &g.RepoURL, &g.Branch, &g.AuthKind, &authEnc, &secEnc,
		&g.AutoDeploy, &g.PreviewEnabled, &g.PreviewMax, &g.PreviewTTLHours, &g.CreatedAt, &g.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("scanning project git: %w", err)
	}
	if len(authEnc) > 0 {
		plain, err := crypto.Decrypt(authEnc, r.secretKey)
		if err != nil {
			return nil, fmt.Errorf("decrypting git credential: %w", err)
		}
		g.Credential = string(plain)
	}
	if len(secEnc) > 0 {
		plain, err := crypto.Decrypt(secEnc, r.secretKey)
		if err != nil {
			return nil, fmt.Errorf("decrypting webhook secret: %w", err)
		}
		g.WebhookSecret = string(plain)
	}
	return &g, nil
}

func (r *GitRepository) Get(ctx context.Context, projectID uuid.UUID) (*domain.ProjectGit, error) {
	return r.scanGit(r.pool.QueryRow(ctx, `SELECT `+gitCols+` FROM project_git WHERE project_id = $1`, projectID))
}

func (r *GitRepository) Upsert(ctx context.Context, g *domain.ProjectGit) (*domain.ProjectGit, error) {
	var authEnc, secEnc []byte
	var err error
	if g.Credential != "" {
		if authEnc, err = crypto.Encrypt([]byte(g.Credential), r.secretKey); err != nil {
			return nil, fmt.Errorf("encrypting git credential: %w", err)
		}
	}
	if g.WebhookSecret != "" {
		if secEnc, err = crypto.Encrypt([]byte(g.WebhookSecret), r.secretKey); err != nil {
			return nil, fmt.Errorf("encrypting webhook secret: %w", err)
		}
	}
	const q = `
		INSERT INTO project_git (project_id, provider, repo_url, branch, auth_kind, auth_enc, webhook_secret_enc,
		                         auto_deploy, preview_enabled, preview_max, preview_ttl_hours)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (project_id) DO UPDATE SET
		    provider = EXCLUDED.provider, repo_url = EXCLUDED.repo_url, branch = EXCLUDED.branch,
		    auth_kind = EXCLUDED.auth_kind, auth_enc = EXCLUDED.auth_enc,
		    webhook_secret_enc = EXCLUDED.webhook_secret_enc, auto_deploy = EXCLUDED.auto_deploy,
		    preview_enabled = EXCLUDED.preview_enabled, preview_max = EXCLUDED.preview_max,
		    preview_ttl_hours = EXCLUDED.preview_ttl_hours, updated_at = now()
		RETURNING ` + gitCols
	return r.scanGit(r.pool.QueryRow(ctx, q, g.ProjectID, g.Provider, g.RepoURL, g.Branch, g.AuthKind,
		authEnc, secEnc, g.AutoDeploy, g.PreviewEnabled, g.PreviewMax, g.PreviewTTLHours))
}

func (r *GitRepository) Delete(ctx context.Context, projectID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM project_git WHERE project_id = $1`, projectID)
	if err != nil {
		return fmt.Errorf("deleting project git: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *GitRepository) RotateWebhookSecret(ctx context.Context, projectID uuid.UUID, secret string) error {
	enc, err := crypto.Encrypt([]byte(secret), r.secretKey)
	if err != nil {
		return fmt.Errorf("encrypting webhook secret: %w", err)
	}
	tag, err := r.pool.Exec(ctx, `UPDATE project_git SET webhook_secret_enc = $2, updated_at = now() WHERE project_id = $1`, projectID, enc)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// previewCols selects columns of `projects p` plus the latest deployment.
const previewCols = `p.id, p.parent_project_id, p.org_id, p.slug, p.preview_pr, p.status, p.preview_comment_id,
	p.expires_at, p.created_at,
	(SELECT d.id FROM deployments d WHERE d.project_id = p.id ORDER BY d.created_at DESC LIMIT 1),
	(SELECT d.status FROM deployments d WHERE d.project_id = p.id ORDER BY d.created_at DESC LIMIT 1)`

func scanPreview(row interface{ Scan(...any) error }) (*domain.Preview, error) {
	var p domain.Preview
	var comment *int64
	var depStatus *string
	if err := row.Scan(&p.ProjectID, &p.ParentProjectID, &p.OrgID, &p.Slug, &p.PR, &p.Status, &comment,
		&p.ExpiresAt, &p.CreatedAt, &p.LatestDeployment, &depStatus); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("scanning preview: %w", err)
	}
	if comment != nil {
		p.CommentID = *comment
	}
	if depStatus != nil {
		p.DeploymentStatus = *depStatus
	}
	return &p, nil
}

func (r *GitRepository) GetPreview(ctx context.Context, parentID uuid.UUID, pr int) (*domain.Preview, error) {
	return scanPreview(r.pool.QueryRow(ctx, `SELECT `+previewCols+`
		FROM projects p WHERE p.parent_project_id = $1 AND p.preview_pr = $2 AND p.deleted_at IS NULL`, parentID, pr))
}

func (r *GitRepository) CreatePreview(ctx context.Context, parent *domain.Project, pr int, slug string, expiresAt time.Time) (*domain.Preview, error) {
	// Copies runtime / deploy type / strategy from the parent. Databases, domains and
	// storage are NOT copied: previews never get production resources.
	const q = `
		INSERT INTO projects (org_id, name, slug, repo_url, branch, build_strategy, deploy_type, runtime,
		                      serverless, replicas, status, labels, parent_project_id, preview_pr, expires_at)
		SELECT org_id, left(name, 80) || ' (PR #' || $3::int::text || ')', $2, repo_url, branch, build_strategy,
		       deploy_type, runtime, serverless, 1, 'created', '{}', id, $3::int, $4
		FROM projects WHERE id = $1 AND deleted_at IS NULL
		ON CONFLICT (parent_project_id, preview_pr) WHERE parent_project_id IS NOT NULL AND deleted_at IS NULL DO NOTHING`
	if _, err := r.pool.Exec(ctx, q, parent.ID, slug, pr, expiresAt); err != nil {
		return nil, fmt.Errorf("creating preview project: %w", err)
	}
	return r.GetPreview(ctx, parent.ID, pr)
}

func (r *GitRepository) TouchPreview(ctx context.Context, previewID uuid.UUID, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE projects SET expires_at = $2, updated_at = now()
		WHERE id = $1 AND parent_project_id IS NOT NULL AND deleted_at IS NULL`, previewID, expiresAt)
	return err
}

func (r *GitRepository) SetPreviewComment(ctx context.Context, previewID uuid.UUID, commentID int64) error {
	_, err := r.pool.Exec(ctx, `UPDATE projects SET preview_comment_id = $2
		WHERE id = $1 AND parent_project_id IS NOT NULL`, previewID, commentID)
	return err
}

func (r *GitRepository) listPreviews(ctx context.Context, where string, args ...any) ([]*domain.Preview, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+previewCols+` FROM projects p WHERE p.parent_project_id IS NOT NULL
		AND p.deleted_at IS NULL AND `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("querying previews: %w", err)
	}
	defer rows.Close()
	var out []*domain.Preview
	for rows.Next() {
		p, err := scanPreview(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *GitRepository) ListPreviews(ctx context.Context, parentID uuid.UUID) ([]*domain.Preview, error) {
	return r.listPreviews(ctx, `p.parent_project_id = $1 ORDER BY p.created_at ASC`, parentID)
}

func (r *GitRepository) ListExpiredPreviews(ctx context.Context, now time.Time) ([]*domain.Preview, error) {
	return r.listPreviews(ctx, `p.expires_at IS NOT NULL AND p.expires_at < $1 ORDER BY p.expires_at ASC LIMIT 200`, now)
}

func (r *GitRepository) DestroyPreview(ctx context.Context, previewID uuid.UUID) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// The unique (org_id, slug) constraint also covers soft-deleted rows, so free the slug
	// to let the same pull request number get a fresh preview if it is reopened.
	tag, err := tx.Exec(ctx, `UPDATE projects
		SET deleted_at = now(), status = 'archived', expires_at = NULL,
		    slug = left(slug, 80) || '-del-' || substr(id::text, 1, 8)
		WHERE id = $1 AND parent_project_id IS NOT NULL AND deleted_at IS NULL`, previewID)
	if err != nil {
		return fmt.Errorf("archiving preview: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	for _, q := range []string{
		`DELETE FROM domains WHERE project_id = $1`,
		`DELETE FROM env_vars WHERE project_id = $1`,
		`UPDATE deployments SET status = 'cancelled', completed_at = now() WHERE project_id = $1 AND status = 'queued'`,
	} {
		if _, err := tx.Exec(ctx, q, previewID); err != nil {
			return fmt.Errorf("cleaning preview: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (r *GitRepository) CancelSupersededGit(ctx context.Context, projectID, keepID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.pool.Query(ctx, `UPDATE deployments SET status = 'cancelled', completed_at = now()
		WHERE project_id = $1 AND trigger = 'git' AND status = 'queued' AND id <> $2 RETURNING id`, projectID, keepID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (r *GitRepository) DeploymentStatus(ctx context.Context, deploymentID uuid.UUID) (string, error) {
	var s string
	err := r.pool.QueryRow(ctx, `SELECT status FROM deployments WHERE id = $1`, deploymentID).Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrNotFound
	}
	return s, err
}

func (r *GitRepository) IsPreview(ctx context.Context, projectID uuid.UUID) (bool, error) {
	var is bool
	err := r.pool.QueryRow(ctx, `SELECT parent_project_id IS NOT NULL FROM projects WHERE id = $1`, projectID).Scan(&is)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, domain.ErrNotFound
	}
	return is, err
}
