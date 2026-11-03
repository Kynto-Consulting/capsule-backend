package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/backup"
	"github.com/kynto/capsule/backend/internal/recovery"
)

// RecoveryRepository is the Postgres side of package C3: the catalog source (projects and backup
// snapshots) and the run journal (recovery_runs, migration 000057).
type RecoveryRepository struct{ pool *pgxpool.Pool }

func NewRecoveryRepository(pool *pgxpool.Pool) *RecoveryRepository {
	return &RecoveryRepository{pool: pool}
}

var _ recovery.Store = (*RecoveryRepository)(nil)

const (
	recoveryRunCols  = `id, mode, status, requested_by, idempotency_key, plan_id, request, steps, report_key, error, started_at, finished_at`
	recoveryProjCols = `p.id, p.slug, COALESCE(g.status = 'ready', false)`
)

func scanRecoveryProject(row backupRowScanner) (recovery.ProjectInfo, error) {
	var p recovery.ProjectInfo
	err := row.Scan(&p.ID, &p.Slug, &p.GitReady)
	return p, err
}

func scanRecoveryRun(row backupRowScanner) (*recovery.Run, error) {
	var (
		r            recovery.Run
		mode, status string
		idem         *string
		reqJSON      []byte
		stepsJSON    []byte
	)
	if err := row.Scan(&r.ID, &mode, &status, &r.RequestedBy, &idem, &r.PlanID, &reqJSON, &stepsJSON, &r.ReportURL, &r.Error, &r.StartedAt, &r.FinishedAt); err != nil {
		return nil, err
	}
	r.Mode, r.Status = recovery.Mode(mode), recovery.RunStatus(status)
	if idem != nil {
		r.IdempotencyKey = *idem
	}
	if err := json.Unmarshal(reqJSON, &r.Request); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(stepsJSON, &r.Steps); err != nil {
		return nil, err
	}
	return &r, nil
}

// Projects lists live projects with whether their Git repository is provisioned.
func (r *RecoveryRepository) Projects(ctx context.Context) ([]recovery.ProjectInfo, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+recoveryProjCols+` FROM projects p
		LEFT JOIN git_core_state g ON g.project_id = p.id WHERE p.deleted_at IS NULL ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []recovery.ProjectInfo
	for rows.Next() {
		p, err := scanRecoveryProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Snapshots lists every non-deleted snapshot, project or platform, newest first.
func (r *RecoveryRepository) Snapshots(ctx context.Context) ([]backup.Snapshot, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+backupSnapCols+` FROM backup_snapshots WHERE deleted_at IS NULL ORDER BY created_at DESC, id`)
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

func (r *RecoveryRepository) findIdem(ctx context.Context, key string, user *uuid.UUID) (*recovery.Run, error) {
	run, err := scanRecoveryRun(r.pool.QueryRow(ctx, `SELECT `+recoveryRunCols+` FROM recovery_runs
		WHERE idempotency_key = $1 AND requested_by IS NOT DISTINCT FROM $2::uuid`, key, user))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return run, err
}

// Begin stores the run. Same Idempotency-Key and requester returns the stored run (created=false);
// a second running apply fails with ErrActive (unique partial index uq_recovery_runs_active).
func (r *RecoveryRepository) Begin(ctx context.Context, run *recovery.Run) (*recovery.Run, bool, error) {
	if run.IdempotencyKey != "" {
		if ex, err := r.findIdem(ctx, run.IdempotencyKey, run.RequestedBy); err != nil || ex != nil {
			return ex, false, err
		}
	}
	reqJSON, _ := json.Marshal(run.Request)
	stepsJSON, _ := json.Marshal(run.Steps)
	var idem *string
	if run.IdempotencyKey != "" {
		idem = &run.IdempotencyKey
	}
	_, err := r.pool.Exec(ctx, `INSERT INTO recovery_runs (id, mode, status, project_id, requested_by, idempotency_key, plan_id, request, steps, started_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		run.ID, string(run.Mode), string(run.Status), run.Request.ProjectID, run.RequestedBy, idem, run.PlanID, reqJSON, stepsJSON, run.StartedAt)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		if pe.ConstraintName == "uq_recovery_runs_idem" {
			ex, ferr := r.findIdem(ctx, run.IdempotencyKey, run.RequestedBy)
			return ex, false, ferr
		}
		return nil, false, recovery.ErrActive
	}
	if err != nil {
		return nil, false, err
	}
	return nil, true, nil
}

func (r *RecoveryRepository) Save(ctx context.Context, run *recovery.Run) error {
	stepsJSON, _ := json.Marshal(run.Steps)
	tag, err := r.pool.Exec(ctx, `UPDATE recovery_runs SET status = $2, plan_id = $3, steps = $4, report_key = $5, error = $6, finished_at = $7 WHERE id = $1`,
		run.ID, string(run.Status), run.PlanID, stepsJSON, run.ReportURL, run.Error, run.FinishedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return recovery.ErrNotFound
	}
	return nil
}

func (r *RecoveryRepository) Get(ctx context.Context, id uuid.UUID) (*recovery.Run, error) {
	run, err := scanRecoveryRun(r.pool.QueryRow(ctx, `SELECT `+recoveryRunCols+` FROM recovery_runs WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, recovery.ErrNotFound
	}
	return run, err
}

// FailOrphans marks runs left 'running' by a crashed process as failed so they stop blocking new
// applies; `--resume` can still pick them up through their journal.
func (r *RecoveryRepository) FailOrphans(ctx context.Context) (int, error) {
	tag, err := r.pool.Exec(ctx, `UPDATE recovery_runs SET status = 'failed', error = 'interrupted by a restart; resume with --resume', finished_at = $1 WHERE status = 'running'`, time.Now().UTC())
	return int(tag.RowsAffected()), err
}
