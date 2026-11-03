package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/backup"
)

// backupSchedulerLock is the Postgres advisory lock key: only the instance holding it claims work.
const backupSchedulerLock int64 = 7270032

type BackupRepository struct{ pool *pgxpool.Pool }

func NewBackupRepository(pool *pgxpool.Pool) *BackupRepository { return &BackupRepository{pool: pool} }

var _ backup.Repo = (*BackupRepository)(nil)

type backupRowScanner interface{ Scan(dest ...any) error }

const (
	backupSettingsCols = `project_id, enabled, schedule, retention_days, include_databases, include_volumes`
	backupRunCols      = `id, project_id, org_id, kind, trigger, status, started_at, finished_at, size_bytes, error, created_by`
	backupSnapCols     = `id, project_id, run_id, kind, source, source_id, engine, object_key, size_bytes, checksum, created_at`
	backupDeployCols   = `id, version, COALESCE(git_sha,''), COALESCE(image_tag,''), COALESCE(source_key,''), COALESCE(container_port,0), COALESCE(host_port,0), COALESCE(deploy_type,'')`
	// candidates: every project with a settings row, or (when defaults are on) with databases.
	backupCandidateCols = `p.id, p.org_id, COALESCE(s.enabled, $1), COALESCE(s.schedule, $2), COALESCE(s.retention_days, $3),
		COALESCE(s.include_databases, $4), COALESCE(s.include_volumes, $5),
		(SELECT max(r.started_at) FROM backup_runs r WHERE r.project_id = p.id AND r.kind = 'backup'),
		EXISTS (SELECT 1 FROM backup_runs r WHERE r.project_id = p.id AND r.status = 'running')`
)

func scanBackupSettings(row backupRowScanner) (*backup.Settings, error) {
	var s backup.Settings
	if err := row.Scan(&s.ProjectID, &s.Enabled, &s.Schedule, &s.RetentionDays, &s.IncludeDatabases, &s.IncludeVolumes); err != nil {
		return nil, err
	}
	s.Configured = true
	return &s, nil
}

func scanBackupRun(row backupRowScanner) (backup.Run, error) {
	var r backup.Run
	err := row.Scan(&r.ID, &r.ProjectID, &r.OrgID, &r.Kind, &r.Trigger, &r.Status, &r.StartedAt, &r.FinishedAt, &r.SizeBytes, &r.Error, &r.UserID)
	return r, err
}

func scanBackupSnapshot(row backupRowScanner) (backup.Snapshot, error) {
	var s backup.Snapshot
	err := row.Scan(&s.ID, &s.ProjectID, &s.RunID, &s.Kind, &s.Source, &s.SourceID, &s.Engine, &s.ObjectKey, &s.SizeBytes, &s.Checksum, &s.CreatedAt)
	return s, err
}

func scanBackupDeploy(row backupRowScanner) (*backup.ManifestInput, error) {
	var m backup.ManifestInput
	if err := row.Scan(&m.DeploymentID, &m.Version, &m.GitSHA, &m.ImageTag, &m.SourceKey, &m.ContainerPort, &m.HostPort, &m.DeployType); err != nil {
		return nil, err
	}
	return &m, nil
}

func scanBackupCandidate(row backupRowScanner) (backup.Candidate, error) {
	var c backup.Candidate
	var pid, oid uuid.UUID
	if err := row.Scan(&pid, &oid, &c.Settings.Enabled, &c.Settings.Schedule, &c.Settings.RetentionDays,
		&c.Settings.IncludeDatabases, &c.Settings.IncludeVolumes, &c.LastStart, &c.Running); err != nil {
		return c, err
	}
	c.ProjectID, c.OrgID = &pid, &oid
	c.Settings.ProjectID = pid
	return c, nil
}

func (r *BackupRepository) GetSettings(ctx context.Context, projectID uuid.UUID) (*backup.Settings, error) {
	s, err := scanBackupSettings(r.pool.QueryRow(ctx, `SELECT `+backupSettingsCols+` FROM backup_settings WHERE project_id = $1`, projectID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting backup settings: %w", err)
	}
	return s, nil
}

func (r *BackupRepository) UpsertSettings(ctx context.Context, s *backup.Settings) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO backup_settings (project_id, enabled, schedule, retention_days, include_databases, include_volumes, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, now())
		ON CONFLICT (project_id) DO UPDATE SET enabled = EXCLUDED.enabled, schedule = EXCLUDED.schedule,
			retention_days = EXCLUDED.retention_days, include_databases = EXCLUDED.include_databases,
			include_volumes = EXCLUDED.include_volumes, updated_at = now()`,
		s.ProjectID, s.Enabled, s.Schedule, s.RetentionDays, s.IncludeDatabases, s.IncludeVolumes)
	if err != nil {
		return fmt.Errorf("saving backup settings: %w", err)
	}
	return nil
}

func insertBackupRun(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, run *backup.Run) error {
	_, err := q.Exec(ctx, `
		INSERT INTO backup_runs (id, project_id, org_id, kind, trigger, status, started_at, created_by)
		VALUES ($1, $2, $3, $4, $5, 'running', $6, $7)`,
		run.ID, run.ProjectID, run.OrgID, run.Kind, run.Trigger, run.StartedAt, run.UserID)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return backup.ErrRunInProgress
	}
	if err != nil {
		return fmt.Errorf("creating backup run: %w", err)
	}
	return nil
}

func (r *BackupRepository) CreateRun(ctx context.Context, run *backup.Run) error {
	return insertBackupRun(ctx, r.pool, run)
}

func (r *BackupRepository) ClaimDue(ctx context.Context, includePlatform bool, d backup.Settings, decide func(backup.Candidate) bool) ([]backup.Run, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var got bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, backupSchedulerLock).Scan(&got); err != nil {
		return nil, fmt.Errorf("scheduler lock: %w", err)
	}
	if !got {
		return nil, nil // another instance is claiming work
	}
	rows, err := tx.Query(ctx, `SELECT `+backupCandidateCols+`
		FROM projects p LEFT JOIN backup_settings s ON s.project_id = p.id
		WHERE p.deleted_at IS NULL AND (s.project_id IS NOT NULL OR ($1 AND EXISTS
			(SELECT 1 FROM databases d WHERE d.project_id = p.id AND d.deleted_at IS NULL)))`,
		d.Enabled, d.Schedule, d.RetentionDays, d.IncludeDatabases, d.IncludeVolumes)
	if err != nil {
		return nil, fmt.Errorf("listing backup candidates: %w", err)
	}
	var cands []backup.Candidate
	for rows.Next() {
		c, err := scanBackupCandidate(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		cands = append(cands, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if includePlatform {
		pc := backup.Candidate{Settings: backup.Settings{Enabled: true, Schedule: d.Schedule, RetentionDays: d.RetentionDays}}
		if err := tx.QueryRow(ctx, `SELECT (SELECT max(started_at) FROM backup_runs WHERE project_id IS NULL AND kind = 'backup'),
			EXISTS (SELECT 1 FROM backup_runs WHERE project_id IS NULL AND status = 'running')`).Scan(&pc.LastStart, &pc.Running); err != nil {
			return nil, err
		}
		cands = append(cands, pc)
	}
	var runs []backup.Run
	for _, c := range cands {
		if !decide(c) {
			continue
		}
		run := backup.Run{ID: uuid.New(), ProjectID: c.ProjectID, OrgID: c.OrgID, Kind: "backup", Trigger: "schedule",
			Status: "running", StartedAt: time.Now().UTC()}
		if err := insertBackupRun(ctx, tx, &run); err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return runs, nil
}

func (r *BackupRepository) FinishRun(ctx context.Context, id uuid.UUID, status string, size int64, errMsg string, at time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE backup_runs SET status = $2, size_bytes = $3, error = $4, finished_at = $5 WHERE id = $1`,
		id, status, size, errMsg, at)
	return err
}

func (r *BackupRepository) FailOrphans(ctx context.Context, at time.Time) (int, error) {
	tag, err := r.pool.Exec(ctx, `UPDATE backup_runs SET status = 'failed', error = 'interrupted: the server restarted while this job was running', finished_at = $1
		WHERE status = 'running'`, at)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (r *BackupRepository) ListRuns(ctx context.Context, projectID *uuid.UUID, limit int) ([]backup.Run, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+backupRunCols+` FROM backup_runs
		WHERE project_id IS NOT DISTINCT FROM $1::uuid ORDER BY started_at DESC LIMIT $2`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []backup.Run
	for rows.Next() {
		run, err := scanBackupRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

func (r *BackupRepository) LastBackupStart(ctx context.Context, projectID *uuid.UUID) (*time.Time, error) {
	var t *time.Time
	err := r.pool.QueryRow(ctx, `SELECT max(started_at) FROM backup_runs
		WHERE project_id IS NOT DISTINCT FROM $1::uuid AND kind = 'backup'`, projectID).Scan(&t)
	return t, err
}

func (r *BackupRepository) AddSnapshot(ctx context.Context, s *backup.Snapshot) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO backup_snapshots (`+backupSnapCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		s.ID, s.ProjectID, s.RunID, s.Kind, s.Source, s.SourceID, s.Engine, s.ObjectKey, s.SizeBytes, s.Checksum, s.CreatedAt)
	return err
}

func (r *BackupRepository) ListSnapshots(ctx context.Context, projectID *uuid.UUID) ([]backup.Snapshot, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+backupSnapCols+` FROM backup_snapshots
		WHERE project_id IS NOT DISTINCT FROM $1::uuid AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 500`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []backup.Snapshot
	for rows.Next() {
		s, err := scanBackupSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *BackupRepository) GetSnapshot(ctx context.Context, projectID *uuid.UUID, id uuid.UUID) (*backup.Snapshot, error) {
	s, err := scanBackupSnapshot(r.pool.QueryRow(ctx, `SELECT `+backupSnapCols+` FROM backup_snapshots
		WHERE id = $1 AND project_id IS NOT DISTINCT FROM $2::uuid AND deleted_at IS NULL`, id, projectID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, backup.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *BackupRepository) ExpiredSnapshots(ctx context.Context, projectID *uuid.UUID, before time.Time) ([]backup.Snapshot, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+backupSnapCols+` FROM backup_snapshots
		WHERE project_id IS NOT DISTINCT FROM $1::uuid AND deleted_at IS NULL AND created_at < $2`, projectID, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []backup.Snapshot
	for rows.Next() {
		s, err := scanBackupSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *BackupRepository) MarkSnapshotDeleted(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE backup_snapshots SET deleted_at = now() WHERE id = $1`, id)
	return err
}

func (r *BackupRepository) LastDeployment(ctx context.Context, projectID uuid.UUID) (*backup.ManifestInput, error) {
	in, err := scanBackupDeploy(r.pool.QueryRow(ctx, `SELECT `+backupDeployCols+` FROM deployments
		WHERE project_id = $1 AND status = 'success' ORDER BY created_at DESC LIMIT 1`, projectID))
	if errors.Is(err, pgx.ErrNoRows) {
		in = &backup.ManifestInput{}
	} else if err != nil {
		return nil, fmt.Errorf("getting last deployment: %w", err)
	}
	rows, err := r.pool.Query(ctx, `SELECT key FROM env_vars WHERE project_id = $1 ORDER BY key`, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing env var names: %w", err)
	}
	defer rows.Close()
	in.EnvVarNames = []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		in.EnvVarNames = append(in.EnvVarNames, k)
	}
	return in, rows.Err()
}

func (r *BackupRepository) Audit(ctx context.Context, e backup.AuditEntry) error {
	var ip any
	if e.IP != "" {
		ip = e.IP
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO audit_logs (user_id, org_id, action, resource_type, resource_id, ip_address, new_values)
		VALUES ($1, $2, $3, $4, $5, $6::inet, $7)`,
		e.UserID, e.OrgID, e.Action, e.ResourceType, e.ResourceID, ip, e.NewValues)
	if err != nil {
		return fmt.Errorf("writing audit log: %w", err)
	}
	return nil
}
