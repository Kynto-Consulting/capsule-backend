package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
)

const accessRuleCols = `id, database_id, cidr, description, created_by, created_at`

func scanAccessRule(row interface{ Scan(...any) error }, r *domain.DatabaseAccessRule) error {
	return row.Scan(&r.ID, &r.DatabaseID, &r.CIDR, &r.Description, &r.CreatedBy, &r.CreatedAt)
}

const desiredAccessCols = `r.database_id, d.port, r.cidr`

func scanDesiredAccess(row interface{ Scan(...any) error }, d *domain.DesiredAccess) error {
	return row.Scan(&d.DatabaseID, &d.Port, &d.CIDR)
}

const ipAllowlistCols = `ip_allowlist`

func scanIPAllowlist(row interface{ Scan(...any) error }, out *[]string) error {
	return row.Scan(out)
}

// DatabaseAccessRepository implements domain.DatabaseAccessRepository.
type DatabaseAccessRepository struct{ pool *pgxpool.Pool }

func NewDatabaseAccessRepository(pool *pgxpool.Pool) *DatabaseAccessRepository {
	return &DatabaseAccessRepository{pool: pool}
}

func (r *DatabaseAccessRepository) List(ctx context.Context, databaseID uuid.UUID) ([]*domain.DatabaseAccessRule, error) {
	return listAccessRules(ctx, r.pool, databaseID)
}

type queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func listAccessRules(ctx context.Context, q queryer, databaseID uuid.UUID) ([]*domain.DatabaseAccessRule, error) {
	rows, err := q.Query(ctx,
		`SELECT `+accessRuleCols+` FROM database_access_rules WHERE database_id = $1 ORDER BY created_at, cidr`, databaseID)
	if err != nil {
		return nil, fmt.Errorf("listing access rules: %w", err)
	}
	defer rows.Close()
	out := []*domain.DatabaseAccessRule{}
	for rows.Next() {
		var rule domain.DatabaseAccessRule
		if err := scanAccessRule(rows, &rule); err != nil {
			return nil, fmt.Errorf("scanning access rule: %w", err)
		}
		out = append(out, &rule)
	}
	return out, rows.Err()
}

func (r *DatabaseAccessRepository) ListDesired(ctx context.Context) ([]domain.DesiredAccess, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+desiredAccessCols+`
		FROM database_access_rules r
		JOIN databases d ON d.id = r.database_id
		WHERE d.deleted_at IS NULL AND d.port > 0`)
	if err != nil {
		return nil, fmt.Errorf("listing desired access: %w", err)
	}
	defer rows.Close()
	var out []domain.DesiredAccess
	for rows.Next() {
		var d domain.DesiredAccess
		if err := scanDesiredAccess(rows, &d); err != nil {
			return nil, fmt.Errorf("scanning desired access: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *DatabaseAccessRepository) Replace(ctx context.Context, databaseID uuid.UUID, rules []*domain.DatabaseAccessRule, createdBy uuid.UUID) ([]*domain.DatabaseAccessRule, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	cidrs := make([]string, 0, len(rules))
	for _, rule := range rules {
		cidrs = append(cidrs, rule.CIDR)
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM database_access_rules WHERE database_id = $1 AND NOT (cidr = ANY($2))`, databaseID, cidrs); err != nil {
		return nil, fmt.Errorf("pruning access rules: %w", err)
	}
	for _, rule := range rules {
		if _, err := tx.Exec(ctx, `
			INSERT INTO database_access_rules (database_id, cidr, description, created_by)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (database_id, cidr) DO UPDATE SET description = EXCLUDED.description`,
			databaseID, rule.CIDR, rule.Description, createdBy); err != nil {
			return nil, fmt.Errorf("upserting access rule: %w", err)
		}
	}
	out, err := listAccessRules(ctx, tx, databaseID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}

func (r *DatabaseAccessRepository) Add(ctx context.Context, rule *domain.DatabaseAccessRule, max int) (*domain.DatabaseAccessRule, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Serialise concurrent adds for the same database so the limit is exact.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM databases WHERE id = $1 FOR UPDATE`, rule.DatabaseID); err != nil {
		return nil, fmt.Errorf("locking database: %w", err)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM database_access_rules WHERE database_id = $1`, rule.DatabaseID).Scan(&n); err != nil {
		return nil, fmt.Errorf("counting access rules: %w", err)
	}
	if n >= max {
		return nil, domain.ErrRuleLimit
	}
	var out domain.DatabaseAccessRule
	err = scanAccessRule(tx.QueryRow(ctx, `
		INSERT INTO database_access_rules (database_id, cidr, description, created_by)
		VALUES ($1, $2, $3, $4)
		RETURNING `+accessRuleCols, rule.DatabaseID, rule.CIDR, rule.Description, rule.CreatedBy), &out)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, domain.ErrConflict
		}
		return nil, fmt.Errorf("adding access rule: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return &out, nil
}

func (r *DatabaseAccessRepository) Delete(ctx context.Context, databaseID, ruleID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM database_access_rules WHERE id = $1 AND database_id = $2`, ruleID, databaseID)
	if err != nil {
		return fmt.Errorf("deleting access rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *DatabaseAccessRepository) DeleteAll(ctx context.Context, databaseID uuid.UUID) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM database_access_rules WHERE database_id = $1`, databaseID); err != nil {
		return fmt.Errorf("deleting access rules: %w", err)
	}
	return nil
}

// ProjectNetworkRepository implements domain.ProjectNetworkRepository.
type ProjectNetworkRepository struct{ pool *pgxpool.Pool }

func NewProjectNetworkRepository(pool *pgxpool.Pool) *ProjectNetworkRepository {
	return &ProjectNetworkRepository{pool: pool}
}

func (r *ProjectNetworkRepository) GetIPAllowlist(ctx context.Context, projectID uuid.UUID) ([]string, error) {
	var out []string
	err := scanIPAllowlist(r.pool.QueryRow(ctx,
		`SELECT `+ipAllowlistCols+` FROM projects WHERE id = $1 AND deleted_at IS NULL`, projectID), &out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting ip allowlist: %w", err)
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

func (r *ProjectNetworkRepository) SetIPAllowlist(ctx context.Context, projectID uuid.UUID, cidrs []string) error {
	if cidrs == nil {
		cidrs = []string{}
	}
	tag, err := r.pool.Exec(ctx,
		`UPDATE projects SET ip_allowlist = $2, updated_at = now() WHERE id = $1 AND deleted_at IS NULL`, projectID, cidrs)
	if err != nil {
		return fmt.Errorf("setting ip allowlist: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
