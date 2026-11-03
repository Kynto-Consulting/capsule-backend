package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/gitaudit"
)

// AuditRepository reads and appends audit_logs (Git Capsule C2). It exposes no update or delete;
// PurgeBefore (retention, never reachable from the API) is the only removal.
type AuditRepository struct{ pool *pgxpool.Pool }

// NewAuditRepository returns the repository over pool.
func NewAuditRepository(pool *pgxpool.Pool) *AuditRepository { return &AuditRepository{pool: pool} }

var (
	_ gitaudit.Writer   = (*AuditRepository)(nil)
	_ gitaudit.Reader   = (*AuditRepository)(nil)
	_ gitaudit.Retainer = (*AuditRepository)(nil)
)

const auditCols = `a.id, a.org_id, a.project_id, a.user_id, COALESCE(u.name, ''), COALESCE(u.email, ''), a.actor_label,
	a.action, a.resource_type, a.resource_id, COALESCE(host(a.ip_address), ''), COALESCE(a.user_agent, ''),
	a.old_values, a.new_values, a.metadata, a.created_at`

func scanAudit(row interface{ Scan(...any) error }, e *gitaudit.Entry) error {
	return row.Scan(&e.ID, &e.OrgID, &e.ProjectID, &e.UserID, &e.ActorName, &e.ActorEmail, &e.ActorLabel,
		&e.Action, &e.ResourceType, &e.ResourceID, &e.IP, &e.UserAgent,
		&e.OldValues, &e.NewValues, &e.Metadata, &e.CreatedAt)
}

func jsonOrNil(m map[string]any) (any, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// Append implements gitaudit.Writer.
func (r *AuditRepository) Append(ctx context.Context, e gitaudit.Entry) error {
	oldV, err := jsonOrNil(e.OldValues)
	if err != nil {
		return fmt.Errorf("encoding audit values: %w", err)
	}
	newV, err := jsonOrNil(e.NewValues)
	if err != nil {
		return fmt.Errorf("encoding audit values: %w", err)
	}
	meta := e.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	metaV, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("encoding audit metadata: %w", err)
	}
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO audit_logs (id, user_id, org_id, project_id, actor_label, action, resource_type, resource_id,
			ip_address, user_agent, old_values, new_values, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, '')::inet, NULLIF($10, ''), $11::jsonb, $12::jsonb, $13::jsonb, $14)`,
		e.ID, e.UserID, e.OrgID, e.ProjectID, e.ActorLabel, e.Action, e.ResourceType, e.ResourceID,
		e.IP, e.UserAgent, oldV, newV, string(metaV), e.CreatedAt)
	if err != nil {
		return fmt.Errorf("writing audit log: %w", err)
	}
	return nil
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// List implements gitaudit.Reader. Order: created_at DESC, id DESC; the cursor is the (created_at,
// id) of the previous page's last row, compared as a row value so ties never skip or repeat rows.
func (r *AuditRepository) List(ctx context.Context, orgID uuid.UUID, f gitaudit.Filter, after *gitaudit.Cursor, limit int) ([]gitaudit.Entry, error) {
	where := []string{"a.org_id = $1"}
	args := []any{orgID}
	add := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if a := f.Action; a != "" {
		if strings.HasSuffix(a, "*") {
			where = append(where, "a.action LIKE "+add(escapeLike(strings.TrimSuffix(a, "*"))+"%"))
		} else {
			where = append(where, "a.action = "+add(a))
		}
	}
	if f.Actor != "" {
		if id, ok := f.ActorID(); ok {
			where = append(where, "a.user_id = "+add(id))
		} else {
			p := add(f.Actor)
			where = append(where, fmt.Sprintf("(lower(u.email) = lower(%s) OR a.actor_label = %s)", p, p))
		}
	}
	if f.ProjectID != nil {
		p := add(*f.ProjectID)
		where = append(where, fmt.Sprintf("(a.project_id = %s OR (a.resource_type = 'project' AND a.resource_id = %s))", p, p))
	}
	if f.Since != nil {
		where = append(where, "a.created_at >= "+add(*f.Since))
	}
	if f.Until != nil {
		where = append(where, "a.created_at <= "+add(*f.Until))
	}
	if after != nil {
		t, id := add(after.At), add(after.ID)
		where = append(where, fmt.Sprintf("(a.created_at, a.id) < (%s, %s)", t, id))
	}
	q := `SELECT ` + auditCols + ` FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id
		WHERE ` + strings.Join(where, " AND ") + ` ORDER BY a.created_at DESC, a.id DESC LIMIT ` + add(limit)
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing audit log: %w", err)
	}
	defer rows.Close()
	var out []gitaudit.Entry
	for rows.Next() {
		var e gitaudit.Entry
		if err := scanAudit(rows, &e); err != nil {
			return nil, fmt.Errorf("scanning audit log: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ProjectID implements gitaudit.Reader: ref is a project id or slug of the organization.
func (r *AuditRepository) ProjectID(ctx context.Context, orgID uuid.UUID, ref string) (uuid.UUID, bool, error) {
	var id uuid.UUID
	var err error
	if u, perr := uuid.Parse(ref); perr == nil {
		// a deleted project still has history: look it up regardless of deleted_at
		err = r.pool.QueryRow(ctx, `SELECT id FROM projects WHERE id = $1 AND org_id = $2`, u, orgID).Scan(&id)
	} else {
		err = r.pool.QueryRow(ctx, `SELECT id FROM projects WHERE org_id = $1 AND slug = $2 ORDER BY deleted_at NULLS FIRST LIMIT 1`, orgID, ref).Scan(&id)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("resolving audit project: %w", err)
	}
	return id, true, nil
}

// PurgeBefore implements gitaudit.Retainer, in batches so it never holds a long lock.
func (r *AuditRepository) PurgeBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	var total int64
	for {
		tag, err := r.pool.Exec(ctx, `DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs WHERE created_at < $1 LIMIT 5000)`, cutoff)
		if err != nil {
			return total, fmt.Errorf("purging audit log: %w", err)
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < 5000 {
			return total, nil
		}
	}
}
