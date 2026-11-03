package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitimport"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

// GitImportRepository persists git_imports / git_import_repos (000053) and git_mirrors (000054, below),
// for Git Capsule C1, writes their audit rows and marks imported projects as
// ready in git_core_state. The GitHub token of an import is never stored: no column holds it.
type GitImportRepository struct {
	pool      *pgxpool.Pool
	secretKey string
}

// NewGitImportRepository returns the repository; secretKey encrypts mirror credentials.
func NewGitImportRepository(pool *pgxpool.Pool, secretKey string) *GitImportRepository {
	return &GitImportRepository{pool: pool, secretKey: secretKey}
}

var (
	_ gitimport.Store       = (*GitImportRepository)(nil)
	_ gitimport.MirrorStore = (*GitImportRepository)(nil)
	_ gitimport.Auditor     = (*GitImportRepository)(nil)
	_ gitimport.Linker      = (*GitImportRepository)(nil)
)

const gitImportCols = `id, org_id, created_by, source, status, include, create_projects, idempotency_key, request_hash, attempts, created_at, updated_at, finished_at`

func scanGitImport(row interface{ Scan(...any) error }, im *gitimport.Import) error {
	var idem *string
	if err := row.Scan(&im.ID, &im.OrgID, &im.CreatedBy, &im.Source, &im.Status, &im.Include, &im.CreateProjects, &idem,
		&im.RequestHash, &im.Attempts, &im.CreatedAt, &im.UpdatedAt, &im.FinishedAt); err != nil {
		return err
	}
	if idem != nil {
		im.IdemKey = *idem
	}
	if im.Include == nil {
		im.Include = []string{}
	}
	return nil
}

const gitImportRepoCols = `name, slug, status, project_id, created_project, error, warnings, codeowners, attempts, started_at, finished_at`

func scanGitImportRepo(row interface{ Scan(...any) error }, r *gitimport.RepoState) error {
	var warnings, owners []byte
	if err := row.Scan(&r.Name, &r.Slug, &r.Status, &r.ProjectID, &r.CreatedProject, &r.Error, &warnings, &owners,
		&r.Attempts, &r.StartedAt, &r.FinishedAt); err != nil {
		return err
	}
	r.Warnings = []string{}
	if len(warnings) > 0 {
		if err := json.Unmarshal(warnings, &r.Warnings); err != nil {
			return fmt.Errorf("decoding import warnings: %w", err)
		}
	}
	r.CodeOwners = nil
	if len(owners) > 0 && string(owners) != "null" {
		var c gitimport.CodeOwnersReport
		if err := json.Unmarshal(owners, &c); err != nil {
			return fmt.Errorf("decoding codeowners report: %w", err)
		}
		r.CodeOwners = &c
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (r *GitImportRepository) CreateImport(ctx context.Context, im *gitimport.Import) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("creating import: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var idem any
	if im.IdemKey != "" {
		idem = im.IdemKey
	}
	inc := im.Include
	if inc == nil {
		inc = []string{}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO git_imports (id, org_id, created_by, source, status, include, create_projects, idempotency_key, request_hash, attempts, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)`,
		im.ID, im.OrgID, im.CreatedBy, im.Source, im.Status, inc, im.CreateProjects, idem, im.RequestHash, im.Attempts, im.CreatedAt); err != nil {
		if isUniqueViolation(err) {
			return gitimport.ErrDuplicateKey
		}
		return fmt.Errorf("creating import: %w", err)
	}
	for _, rp := range im.Repos {
		if _, err := tx.Exec(ctx, `INSERT INTO git_import_repos (import_id, name, slug, status) VALUES ($1, $2, $3, $4)`,
			im.ID, rp.Name, rp.Slug, rp.Status); err != nil {
			return fmt.Errorf("creating import repo: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (r *GitImportRepository) loadRepos(ctx context.Context, im *gitimport.Import) error {
	rows, err := r.pool.Query(ctx, `SELECT `+gitImportRepoCols+` FROM git_import_repos WHERE import_id = $1 ORDER BY name`, im.ID)
	if err != nil {
		return fmt.Errorf("listing import repos: %w", err)
	}
	defer rows.Close()
	im.Repos = []gitimport.RepoState{}
	for rows.Next() {
		var rs gitimport.RepoState
		if err := scanGitImportRepo(rows, &rs); err != nil {
			return fmt.Errorf("scanning import repo: %w", err)
		}
		im.Repos = append(im.Repos, rs)
	}
	return rows.Err()
}

func (r *GitImportRepository) one(ctx context.Context, where string, args ...any) (*gitimport.Import, error) {
	var im gitimport.Import
	err := scanGitImport(r.pool.QueryRow(ctx, `SELECT `+gitImportCols+` FROM git_imports WHERE `+where, args...), &im)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading import: %w", err)
	}
	if err := r.loadRepos(ctx, &im); err != nil {
		return nil, err
	}
	return &im, nil
}

func (r *GitImportRepository) GetImport(ctx context.Context, orgID, id uuid.UUID) (*gitimport.Import, error) {
	return r.one(ctx, `id = $1 AND org_id = $2`, id, orgID)
}

func (r *GitImportRepository) FindByIdem(ctx context.Context, orgID uuid.UUID, key string) (*gitimport.Import, error) {
	return r.one(ctx, `org_id = $1 AND idempotency_key = $2`, orgID, key)
}

func (r *GitImportRepository) BusySlugs(ctx context.Context, orgID uuid.UUID, slugs []string, except uuid.UUID) ([]string, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT r.slug
		FROM git_import_repos r JOIN git_imports i ON i.id = r.import_id
		WHERE i.org_id = $1 AND r.slug = ANY($2) AND i.id <> $3
		  AND r.status IN ('queued', 'running') AND i.status IN ('queued', 'running')
		  AND i.updated_at > now() - interval '2 hours'`, orgID, slugs, except)
	if err != nil {
		return nil, fmt.Errorf("checking busy import names: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scanning busy import name: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *GitImportRepository) SetStatus(ctx context.Context, id uuid.UUID, status string, finished bool) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE git_imports SET status = $2, updated_at = now(),
			finished_at = CASE WHEN $3 THEN now() ELSE finished_at END
		WHERE id = $1`, id, status, finished)
	if err != nil {
		return fmt.Errorf("setting import status: %w", err)
	}
	return nil
}

func (r *GitImportRepository) Resume(ctx context.Context, id uuid.UUID) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("resuming import: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `
		UPDATE git_import_repos SET status = 'queued', error = '', finished_at = NULL, updated_at = now()
		WHERE import_id = $1 AND status <> 'success'`, id); err != nil {
		return fmt.Errorf("resuming import repos: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE git_imports SET status = 'queued', attempts = attempts + 1, finished_at = NULL, updated_at = now()
		WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("resuming import: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return tx.Commit(ctx)
}

func (r *GitImportRepository) BeginRepo(ctx context.Context, id uuid.UUID, name string) (*gitimport.RepoState, error) {
	var rs gitimport.RepoState
	err := scanGitImportRepo(r.pool.QueryRow(ctx, `
		UPDATE git_import_repos SET status = 'running', attempts = attempts + 1, started_at = now(), finished_at = NULL, updated_at = now()
		WHERE import_id = $1 AND name = $2
		RETURNING `+gitImportRepoCols, id, name), &rs)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("starting import repo: %w", err)
	}
	return &rs, nil
}

func (r *GitImportRepository) UpdateRepo(ctx context.Context, id uuid.UUID, name string, u gitimport.RepoUpdate) error {
	var warnings, owners any
	if u.Warnings != nil {
		b, err := json.Marshal(u.Warnings)
		if err != nil {
			return fmt.Errorf("encoding import warnings: %w", err)
		}
		warnings = string(b)
	}
	if u.CodeOwners != nil {
		b, err := json.Marshal(u.CodeOwners)
		if err != nil {
			return fmt.Errorf("encoding codeowners report: %w", err)
		}
		owners = string(b)
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE git_import_repos SET
			status = COALESCE(NULLIF($3, ''), status),
			project_id = COALESCE($4, project_id),
			created_project = COALESCE($5, created_project),
			error = $6,
			warnings = COALESCE($7::jsonb, warnings),
			codeowners = COALESCE($8::jsonb, codeowners),
			finished_at = CASE WHEN $9 THEN now() ELSE finished_at END,
			updated_at = now()
		WHERE import_id = $1 AND name = $2`,
		id, name, u.Status, u.ProjectID, u.CreatedProject, u.Error, warnings, owners, u.Finished)
	if err != nil {
		return fmt.Errorf("updating import repo: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *GitImportRepository) Touch(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE git_imports SET updated_at = now() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("touching import: %w", err)
	}
	return nil
}

func (r *GitImportRepository) FailInterrupted(ctx context.Context, before time.Time, msg string) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("recovering imports: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	rows, err := tx.Query(ctx, `
		UPDATE git_imports SET
			status = CASE WHEN EXISTS (SELECT 1 FROM git_import_repos r WHERE r.import_id = git_imports.id AND r.status = 'success')
			              THEN 'partial' ELSE 'failed' END,
			finished_at = now(), updated_at = now()
		WHERE status IN ('queued', 'running') AND updated_at < $1
		RETURNING id`, before)
	if err != nil {
		return 0, fmt.Errorf("recovering imports: %w", err)
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scanning recovered import: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("recovering imports: %w", err)
	}
	if len(ids) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE git_import_repos SET status = 'failed', error = $2, finished_at = now(), updated_at = now()
			WHERE import_id = ANY($1) AND status <> 'success'`, ids, msg); err != nil {
			return 0, fmt.Errorf("recovering import repos: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("recovering imports: %w", err)
	}
	return len(ids), nil
}

// Audit writes an audit_logs row (T17: imports and mirrors are audited). Values must not hold secrets.
func (r *GitImportRepository) Audit(ctx context.Context, a gitimport.AuditRecord) error {
	var ip any
	if net.ParseIP(a.IP) != nil {
		ip = a.IP
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO audit_logs (user_id, org_id, action, resource_type, resource_id, ip_address, new_values)
		VALUES ($1, $2, $3, $4, $5, $6::inet, $7)`,
		a.UserID, a.OrgID, a.Action, a.ResourceType, a.ResourceID, ip, a.Values)
	if err != nil {
		return fmt.Errorf("writing audit log: %w", err)
	}
	return nil
}

// MarkReady records that the project's repository exists in Forgejo, so the provisioning retry loop
// of 000030 does not create an empty one.
func (r *GitImportRepository) MarkReady(ctx context.Context, projectID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO git_core_state (project_id, status) VALUES ($1, 'ready')
		ON CONFLICT (project_id) DO UPDATE SET status = 'ready', last_error = '', import_url = '', updated_at = now()`, projectID)
	if err != nil {
		return fmt.Errorf("marking project ready: %w", err)
	}
	return nil
}

// ---- mirrors --------------------------------------------------------------------------------

const gitMirrorCols = `project_id, org_id, remote_url, branches, sync_interval, has_cred, forgejo_remote_name, last_sync_at, last_error, syncing_since, created_by, created_at, updated_at`

const gitMirrorSelect = `SELECT project_id, org_id, remote_url, branches, sync_interval, (credential_enc IS NOT NULL AND length(credential_enc) > 0) AS has_cred,
	forgejo_remote_name, last_sync_at, last_error, syncing_since, created_by, created_at, updated_at FROM git_mirrors`

func scanGitMirror(row interface{ Scan(...any) error }, m *gitimport.Mirror) error {
	if err := row.Scan(&m.ProjectID, &m.OrgID, &m.RemoteURL, &m.Branches, &m.Interval, &m.HasCredential, &m.ForgejoRemoteName,
		&m.LastSyncAt, &m.LastError, &m.SyncingSince, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return err
	}
	if m.Branches == nil {
		m.Branches = []string{}
	}
	return nil
}

func (r *GitImportRepository) GetMirror(ctx context.Context, projectID uuid.UUID) (*gitimport.Mirror, error) {
	var m gitimport.Mirror
	err := scanGitMirror(r.pool.QueryRow(ctx, gitMirrorSelect+` WHERE project_id = $1`, projectID), &m)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading mirror: %w", err)
	}
	return &m, nil
}

func (r *GitImportRepository) PutMirror(ctx context.Context, m *gitimport.Mirror, credential *string) error {
	var enc []byte
	replace := credential != nil
	if replace && *credential != "" {
		var err error
		if enc, err = crypto.Encrypt([]byte(*credential), r.secretKey); err != nil {
			return fmt.Errorf("encrypting mirror credential: %w", err)
		}
	}
	br := m.Branches
	if br == nil {
		br = []string{}
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO git_mirrors (project_id, org_id, remote_url, branches, sync_interval, credential_enc, forgejo_remote_name, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (project_id) DO UPDATE SET
			remote_url = EXCLUDED.remote_url, branches = EXCLUDED.branches, sync_interval = EXCLUDED.sync_interval,
			credential_enc = CASE WHEN $9 THEN EXCLUDED.credential_enc ELSE git_mirrors.credential_enc END,
			forgejo_remote_name = EXCLUDED.forgejo_remote_name,
			last_sync_at = NULL, last_error = '', updated_at = now()`,
		m.ProjectID, m.OrgID, m.RemoteURL, br, m.Interval, enc, m.ForgejoRemoteName, m.CreatedBy, replace)
	if err != nil {
		return fmt.Errorf("saving mirror: %w", err)
	}
	return nil
}

func (r *GitImportRepository) Credential(ctx context.Context, projectID uuid.UUID) (string, error) {
	var enc []byte
	err := r.pool.QueryRow(ctx, `SELECT credential_enc FROM git_mirrors WHERE project_id = $1`, projectID).Scan(&enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", domain.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("loading mirror credential: %w", err)
	}
	if len(enc) == 0 {
		return "", nil
	}
	p, err := crypto.Decrypt(enc, r.secretKey)
	if err != nil {
		return "", fmt.Errorf("decrypting mirror credential: %w", err)
	}
	return string(p), nil
}

func (r *GitImportRepository) DeleteMirror(ctx context.Context, projectID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM git_mirrors WHERE project_id = $1`, projectID)
	if err != nil {
		return fmt.Errorf("deleting mirror: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *GitImportRepository) RecordSync(ctx context.Context, projectID uuid.UUID, at *time.Time, lastErr string) error {
	_, err := r.pool.Exec(ctx, `UPDATE git_mirrors SET last_sync_at = $2, last_error = $3, updated_at = now() WHERE project_id = $1`, projectID, at, lastErr)
	if err != nil {
		return fmt.Errorf("recording mirror sync: %w", err)
	}
	return nil
}

func (r *GitImportRepository) BeginSync(ctx context.Context, projectID uuid.UUID, staleBefore time.Time) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE git_mirrors SET syncing_since = now()
		WHERE project_id = $1 AND (syncing_since IS NULL OR syncing_since < $2)`, projectID, staleBefore)
	if err != nil {
		return false, fmt.Errorf("claiming mirror sync: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	var one int
	if err := r.pool.QueryRow(ctx, `SELECT 1 FROM git_mirrors WHERE project_id = $1`, projectID).Scan(&one); errors.Is(err, pgx.ErrNoRows) {
		return false, domain.ErrNotFound
	} else if err != nil {
		return false, fmt.Errorf("claiming mirror sync: %w", err)
	}
	return false, nil
}

func (r *GitImportRepository) EndSync(ctx context.Context, projectID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE git_mirrors SET syncing_since = NULL WHERE project_id = $1`, projectID)
	if err != nil {
		return fmt.Errorf("releasing mirror sync: %w", err)
	}
	return nil
}
