package fn

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// maxBuildLog is how much of a build's log is kept (the tail): docker output of a large build is long.
const maxBuildLog = 256 << 10

// ---- PostgreSQL (table fn_builds, migration 000077) ----

const buildCols = `id, function_id, project_id, org_id, function, runtime, status, source_key, image, error, attempts, created_by, created_at, started_at, finished_at`

func scanBuild(row pgx.Row, withLog bool) (*Build, error) {
	var b Build
	dst := []any{&b.ID, &b.FunctionID, &b.ProjectID, &b.OrgID, &b.Function, &b.Runtime, &b.Status, &b.SourceKey, &b.Image, &b.Error, &b.Attempts,
		&b.CreatedBy, &b.CreatedAt, &b.StartedAt, &b.FinishedAt}
	if withLog {
		dst = append(dst, &b.Log)
	}
	err := row.Scan(dst...)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &b, err
}

func (s *PGStore) CreateBuild(ctx context.Context, b *Build) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO fn_builds (id, function_id, project_id, org_id, function, runtime, status, source_key, created_by, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, b.ID, b.FunctionID, b.ProjectID, b.OrgID, b.Function, b.Runtime, b.Status, b.SourceKey, b.CreatedBy, b.CreatedAt)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return ErrConflict
	}
	return err
}

func (s *PGStore) GetBuild(ctx context.Context, id uuid.UUID) (*Build, error) {
	return scanBuild(s.Pool.QueryRow(ctx, `SELECT `+buildCols+`, log FROM fn_builds WHERE id=$1`, id), true)
}

func (s *PGStore) ListBuilds(ctx context.Context, functionID uuid.UUID, limit int) ([]*Build, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+buildCols+` FROM fn_builds WHERE function_id=$1 ORDER BY created_at DESC LIMIT $2`, functionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Build
	for rows.Next() {
		b, err := scanBuild(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *PGStore) ClaimBuild(ctx context.Context, now time.Time) (*Build, error) {
	return scanBuild(s.Pool.QueryRow(ctx, `UPDATE fn_builds SET status='building', started_at=$1, attempts=attempts+1
		WHERE id = (SELECT id FROM fn_builds WHERE status='queued' ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING `+buildCols, now), false)
}

func (s *PGStore) AppendBuildLog(ctx context.Context, id uuid.UUID, text string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE fn_builds SET log = right(log || $2, $3) WHERE id=$1`, id, text, maxBuildLog)
	return err
}

func (s *PGStore) FinishBuild(ctx context.Context, id uuid.UUID, status, image, msg string, now time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE fn_builds SET status=$2, image=$3, error=$4, finished_at=$5 WHERE id=$1`, id, status, image, msg, now)
	return err
}

func (s *PGStore) ReapBuilds(ctx context.Context, before, now time.Time) (int, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE fn_builds SET
			status = CASE WHEN attempts >= $3 THEN 'failed' ELSE 'queued' END,
			error = CASE WHEN attempts >= $3 THEN 'the build was interrupted (backend restart) too many times' ELSE error END,
			finished_at = CASE WHEN attempts >= $3 THEN $2 ELSE NULL END,
			log = right(log || $4, $5)
		WHERE status='building' AND started_at < $1`, before, now, MaxBuildAttempts, "-- the build was interrupted (backend restart); it is picked up again --\n", maxBuildLog)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *PGStore) SetFunctionImage(ctx context.Context, functionID uuid.UUID, image string) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE fn_functions SET image=$2 WHERE id=$1`, functionID, image)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// Audit writes an audit_logs row (Service.Audit); failures are ignored: an audit row never fails the operation.
func (s *PGStore) Audit(ctx context.Context, e AuditEntry) {
	var ip any
	if e.IP != "" {
		ip = e.IP
	}
	_, _ = s.Pool.Exec(ctx, `INSERT INTO audit_logs (user_id, org_id, project_id, action, resource_type, resource_id, ip_address, new_values)
		VALUES ($1, $2, $3, $4, 'function', $5, $6::inet, $7)`, e.UserID, e.OrgID, e.ProjectID, e.Action, e.ResourceID, ip, e.Values)
}

// ---- in memory (tests and local use) ----

func (m *MemStore) buildsMap() map[uuid.UUID]*Build {
	if m.builds == nil {
		m.builds = map[uuid.UUID]*Build{}
	}
	return m.builds
}

func (m *MemStore) CreateBuild(_ context.Context, b *Build) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.buildsMap() {
		if o.FunctionID == b.FunctionID && (o.Status == BuildQueued || o.Status == BuildBuilding) {
			return ErrConflict
		}
	}
	c := *b
	m.buildsMap()[b.ID] = &c
	return nil
}

func (m *MemStore) GetBuild(_ context.Context, id uuid.UUID) (*Build, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.buildsMap()[id]; ok {
		c := *b
		return &c, nil
	}
	return nil, ErrNotFound
}

func (m *MemStore) ListBuilds(_ context.Context, functionID uuid.UUID, limit int) ([]*Build, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Build
	for _, b := range m.buildsMap() {
		if b.FunctionID == functionID {
			c := *b
			c.Log = ""
			out = append(out, &c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemStore) ClaimBuild(_ context.Context, now time.Time) (*Build, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var best *Build
	for _, b := range m.buildsMap() {
		if b.Status == BuildQueued && (best == nil || b.CreatedAt.Before(best.CreatedAt)) {
			best = b
		}
	}
	if best == nil {
		return nil, ErrNotFound
	}
	best.Status, best.StartedAt = BuildBuilding, &now
	best.Attempts++
	c := *best
	return &c, nil
}

func (m *MemStore) AppendBuildLog(_ context.Context, id uuid.UUID, text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.buildsMap()[id]
	if !ok {
		return ErrNotFound
	}
	b.Log += text
	if len(b.Log) > maxBuildLog {
		b.Log = b.Log[len(b.Log)-maxBuildLog:]
	}
	return nil
}

func (m *MemStore) FinishBuild(_ context.Context, id uuid.UUID, status, image, msg string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.buildsMap()[id]
	if !ok {
		return ErrNotFound
	}
	b.Status, b.Image, b.Error, b.FinishedAt = status, image, msg, &now
	return nil
}

func (m *MemStore) ReapBuilds(_ context.Context, before, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, b := range m.buildsMap() {
		if b.Status != BuildBuilding || b.StartedAt == nil || !b.StartedAt.Before(before) {
			continue
		}
		n++
		b.Log += "-- the build was interrupted (backend restart); it is picked up again --\n"
		if b.Attempts >= MaxBuildAttempts {
			b.Status, b.Error, b.FinishedAt = BuildFailed, "the build was interrupted (backend restart) too many times", &now
		} else {
			b.Status = BuildQueued
		}
	}
	return n, nil
}

func (m *MemStore) SetFunctionImage(_ context.Context, functionID uuid.UUID, image string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.fns[functionID]
	if !ok {
		return ErrNotFound
	}
	f.Image = image
	return nil
}

var (
	_ BuildStore = (*PGStore)(nil)
	_ BuildStore = (*MemStore)(nil)
)
