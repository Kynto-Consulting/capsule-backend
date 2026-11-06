package fn

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStore is the PostgreSQL Store.
type PGStore struct{ Pool *pgxpool.Pool }

const fnCols = `id, org_id, project_id, name, image, entry, vpn_id, cron, memory_mb, cpus, timeout_seconds, max_concurrency, scopes, enabled, last_cron_at, created_by, created_at`

func scanFn(row pgx.Row) (*Function, error) {
	var f Function
	var cpus float32
	err := row.Scan(&f.ID, &f.OrgID, &f.ProjectID, &f.Name, &f.Image, &f.Entry, &f.VPNID, &f.Cron, &f.MemoryMB, &cpus, &f.TimeoutSeconds,
		&f.MaxConcurrency, &f.Scopes, &f.Enabled, &f.LastCronAt, &f.CreatedBy, &f.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	f.CPUs = float64(cpus)
	return &f, err
}

func (s *PGStore) CreateFunction(ctx context.Context, f *Function) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO fn_functions (id, org_id, project_id, name, image, entry, vpn_id, cron, memory_mb, cpus, timeout_seconds,
		max_concurrency, scopes, enabled, last_cron_at, created_by, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		f.ID, f.OrgID, f.ProjectID, f.Name, f.Image, f.Entry, f.VPNID, f.Cron, f.MemoryMB, f.CPUs, f.TimeoutSeconds, f.MaxConcurrency, f.Scopes, f.Enabled, f.LastCronAt, f.CreatedBy, f.CreatedAt)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return ErrConflict
	}
	return err
}

func (s *PGStore) GetFunction(ctx context.Context, p uuid.UUID, name string) (*Function, error) {
	return scanFn(s.Pool.QueryRow(ctx, `SELECT `+fnCols+` FROM fn_functions WHERE project_id=$1 AND name=$2`, p, name))
}

func (s *PGStore) GetFunctionByID(ctx context.Context, id uuid.UUID) (*Function, error) {
	return scanFn(s.Pool.QueryRow(ctx, `SELECT `+fnCols+` FROM fn_functions WHERE id=$1`, id))
}

func (s *PGStore) queryFns(ctx context.Context, q string, args ...any) ([]*Function, error) {
	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Function
	for rows.Next() {
		f, err := scanFn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *PGStore) ListFunctions(ctx context.Context, p uuid.UUID) ([]*Function, error) {
	return s.queryFns(ctx, `SELECT `+fnCols+` FROM fn_functions WHERE project_id=$1 ORDER BY name`, p)
}

func (s *PGStore) CronFunctions(ctx context.Context) ([]*Function, error) {
	return s.queryFns(ctx, `SELECT `+fnCols+` FROM fn_functions WHERE cron <> '' AND enabled`)
}

func (s *PGStore) DeleteFunction(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM fn_functions WHERE id=$1`, id)
	return err
}

func (s *PGStore) CASLastCron(ctx context.Context, id uuid.UUID, old *time.Time, now time.Time) (bool, error) {
	ct, err := s.Pool.Exec(ctx, `UPDATE fn_functions SET last_cron_at=$3 WHERE id=$1 AND last_cron_at IS NOT DISTINCT FROM $2`, id, old, now)
	return ct.RowsAffected() == 1, err
}

const runCols = `id, function_id, project_id, trigger, triggered_by, status, queued_at, started_at, finished_at, exit_code, scopes, bytes_in, bytes_out, node_id, payload, log_tail`

func scanRun(row pgx.Row) (*Run, error) {
	var r Run
	var payload []byte
	err := row.Scan(&r.ID, &r.FunctionID, &r.ProjectID, &r.Trigger, &r.TriggeredBy, &r.Status, &r.QueuedAt, &r.StartedAt, &r.FinishedAt,
		&r.ExitCode, &r.Scopes, &r.BytesIn, &r.BytesOut, &r.NodeID, &payload, &r.LogTail)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	r.Payload = payload
	return &r, err
}

func (s *PGStore) queryRuns(ctx context.Context, q string, args ...any) ([]*Run, error) {
	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PGStore) EnqueueRun(ctx context.Context, r *Run) error {
	var payload any
	if len(r.Payload) > 0 {
		payload = []byte(r.Payload)
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO fn_runs (id, function_id, project_id, trigger, triggered_by, status, queued_at, scopes, payload)
		VALUES ($1,$2,$3,$4,$5,'queued',$6,$7,$8)`, r.ID, r.FunctionID, r.ProjectID, r.Trigger, r.TriggeredBy, r.QueuedAt, r.Scopes, payload)
	return err
}

func (s *PGStore) QueuedRuns(ctx context.Context, limit int) ([]*Run, error) {
	return s.queryRuns(ctx, `SELECT `+runCols+` FROM fn_runs WHERE status='queued' ORDER BY queued_at LIMIT $1`, limit)
}

func (s *PGStore) RunningRuns(ctx context.Context) ([]*Run, error) {
	return s.queryRuns(ctx, `SELECT `+runCols+` FROM fn_runs WHERE status='running' ORDER BY started_at`)
}

// TryStart serializes starts per function with a row lock on the function, so max_concurrency holds with several claimers.
func (s *PGStore) TryStart(ctx context.Context, runID uuid.UUID, node string, now time.Time) (bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var maxc int
	var fid uuid.UUID
	err = tx.QueryRow(ctx, `SELECT f.max_concurrency, f.id FROM fn_runs r JOIN fn_functions f ON f.id = r.function_id
		WHERE r.id=$1 AND r.status='queued' FOR UPDATE OF f`, runID).Scan(&maxc, &fid)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var running int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM fn_runs WHERE function_id=$1 AND status='running'`, fid).Scan(&running); err != nil {
		return false, err
	}
	if running >= maxc {
		return false, nil
	}
	ct, err := tx.Exec(ctx, `UPDATE fn_runs SET status='running', node_id=$2, started_at=$3 WHERE id=$1 AND status='queued'`, runID, node, now)
	if err != nil || ct.RowsAffected() != 1 {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func (s *PGStore) FinishRun(ctx context.Context, id uuid.UUID, status string, exit *int, in, out int64, tail string, now time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE fn_runs SET status=$2, exit_code=$3, bytes_in=$4, bytes_out=$5, log_tail=$6, finished_at=$7 WHERE id=$1`,
		id, status, exit, in, out, tail, now)
	return err
}

func (s *PGStore) GetRun(ctx context.Context, id uuid.UUID) (*Run, error) {
	return scanRun(s.Pool.QueryRow(ctx, `SELECT `+runCols+` FROM fn_runs WHERE id=$1`, id))
}

func (s *PGStore) ListRuns(ctx context.Context, fid uuid.UUID, limit int) ([]*Run, error) {
	return s.queryRuns(ctx, `SELECT `+runCols+` FROM fn_runs WHERE function_id=$1 ORDER BY queued_at DESC LIMIT $2`, fid, limit)
}

func (s *PGStore) PutToken(ctx context.Context, t RunToken) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO fn_run_tokens (token_hash, run_id, project_id, scopes, expires_at) VALUES ($1,$2,$3,$4,$5)`,
		t.Hash, t.RunID, t.ProjectID, t.Scopes, t.ExpiresAt)
	return err
}

func (s *PGStore) GetToken(ctx context.Context, hash string) (*RunToken, error) {
	var t RunToken
	err := s.Pool.QueryRow(ctx, `SELECT token_hash, run_id, project_id, scopes, expires_at, revoked_at FROM fn_run_tokens WHERE token_hash=$1`, hash).
		Scan(&t.Hash, &t.RunID, &t.ProjectID, &t.Scopes, &t.ExpiresAt, &t.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &t, err
}

func (s *PGStore) RevokeRunTokens(ctx context.Context, run uuid.UUID, now time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE fn_run_tokens SET revoked_at=$2 WHERE run_id=$1 AND revoked_at IS NULL`, run, now)
	return err
}

func (s *PGStore) NodeByHash(ctx context.Context, hash string) (string, error) {
	var name string
	err := s.Pool.QueryRow(ctx, `UPDATE fn_nodes SET last_seen_at=now() WHERE token_hash=$1 RETURNING name`, hash).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return name, err
}

// CreateNode registers a work node and returns its token (shown once).
func (s *PGStore) CreateNode(ctx context.Context, name string) (string, error) {
	plain, hash := NewToken(NodeTokPrefix)
	_, err := s.Pool.Exec(ctx, `INSERT INTO fn_nodes (name, token_hash) VALUES ($1,$2) ON CONFLICT (name) DO UPDATE SET token_hash=EXCLUDED.token_hash`, name, hash)
	return plain, err
}
