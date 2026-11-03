package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/connaudit"
)

// ConnAuditRepository persists the deploy connection audit (connaudit.Store).
// It reads/writes its own columns so the shared deployment SELECTs stay untouched.
type ConnAuditRepository struct{ pool *pgxpool.Pool }

func NewConnAuditRepository(pool *pgxpool.Pool) *ConnAuditRepository {
	return &ConnAuditRepository{pool: pool}
}

var _ connaudit.Store = (*ConnAuditRepository)(nil)

const connSuppSelect = `SELECT finding_id, reason, expires_at, created_by, created_at
		FROM connection_audit_suppressions WHERE project_id = $1 ORDER BY created_at`

func scanConnSuppression(row interface{ Scan(...any) error }) (connaudit.Suppression, error) {
	var s connaudit.Suppression
	var exp *time.Time
	err := row.Scan(&s.FindingID, &s.Reason, &exp, &s.CreatedBy, &s.CreatedAt)
	s.ExpiresAt = exp
	return s, err
}

const connWarnSelect = `SELECT id, connection_warnings FROM deployments WHERE id = ANY($1)`

func scanConnWarnings(row interface{ Scan(...any) error }) (uuid.UUID, []connaudit.Finding, error) {
	var id uuid.UUID
	var raw []byte
	if err := row.Scan(&id, &raw); err != nil {
		return id, nil, err
	}
	var fs []connaudit.Finding
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &fs)
	}
	return id, fs, nil
}

func (r *ConnAuditRepository) Mode(ctx context.Context, projectID uuid.UUID) (connaudit.Mode, error) {
	var m string
	if err := r.pool.QueryRow(ctx, `SELECT connection_audit_mode FROM projects WHERE id = $1`, projectID).Scan(&m); err != nil {
		return connaudit.ModeWarn, err
	}
	mode, _ := connaudit.ParseMode(m)
	return mode, nil
}

func (r *ConnAuditRepository) SetMode(ctx context.Context, projectID uuid.UUID, m connaudit.Mode) error {
	_, err := r.pool.Exec(ctx, `UPDATE projects SET connection_audit_mode = $2 WHERE id = $1`, projectID, string(m))
	return err
}

func (r *ConnAuditRepository) Suppressions(ctx context.Context, projectID uuid.UUID) ([]connaudit.Suppression, error) {
	rows, err := r.pool.Query(ctx, connSuppSelect, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []connaudit.Suppression
	for rows.Next() {
		s, err := scanConnSuppression(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *ConnAuditRepository) PutSuppression(ctx context.Context, projectID uuid.UUID, s connaudit.Suppression) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO connection_audit_suppressions (project_id, finding_id, reason, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (project_id, finding_id) DO UPDATE SET reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at,
		  created_by = EXCLUDED.created_by, created_at = now()`,
		projectID, s.FindingID, s.Reason, s.ExpiresAt, s.CreatedBy)
	return err
}

func (r *ConnAuditRepository) DeleteSuppression(ctx context.Context, projectID uuid.UUID, findingID string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM connection_audit_suppressions WHERE project_id = $1 AND finding_id = $2`, projectID, findingID)
	return err
}

func (r *ConnAuditRepository) SaveFindings(ctx context.Context, deploymentID uuid.UUID, f []connaudit.Finding) error {
	if f == nil {
		f = []connaudit.Finding{}
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `UPDATE deployments SET connection_warnings = $2 WHERE id = $1`, deploymentID, raw)
	return err
}

func (r *ConnAuditRepository) FindingsFor(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]connaudit.Finding, error) {
	out := map[uuid.UUID][]connaudit.Finding{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.pool.Query(ctx, connWarnSelect, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		id, fs, err := scanConnWarnings(rows)
		if err != nil {
			return nil, err
		}
		out[id] = fs
	}
	return out, rows.Err()
}
