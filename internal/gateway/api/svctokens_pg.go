package api

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgServiceTokens is the Postgres ServiceTokenStore (table gateway_service_tokens, migration 000063).
type PgServiceTokens struct{ pool *pgxpool.Pool }

// NewPgServiceTokens returns the store.
func NewPgServiceTokens(pool *pgxpool.Pool) *PgServiceTokens { return &PgServiceTokens{pool: pool} }

const svcTokCols = `id, org_id, project_id, service_id, name, token_hash, prefix, created_by, created_at, expires_at, revoked_at, last_used_at`

func scanSvcToken(row pgx.Row, t *ServiceToken) error {
	return row.Scan(&t.ID, &t.OrgID, &t.ProjectID, &t.ServiceID, &t.Name, &t.Hash, &t.Prefix, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt)
}

// Create inserts the token (the value is not here: only its hash).
func (s *PgServiceTokens) Create(ctx context.Context, t *ServiceToken) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO gateway_service_tokens (id, org_id, project_id, service_id, name, token_hash, prefix, created_by, created_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		t.ID, t.OrgID, t.ProjectID, t.ServiceID, t.Name, t.Hash, t.Prefix, t.CreatedBy, t.CreatedAt, t.ExpiresAt)
	return err
}

// GetByHash returns the token with that hash (ErrNoRows-style: nil, error when none).
func (s *PgServiceTokens) GetByHash(ctx context.Context, hash string) (*ServiceToken, error) {
	var t ServiceToken
	if err := scanSvcToken(s.pool.QueryRow(ctx, `SELECT `+svcTokCols+` FROM gateway_service_tokens WHERE token_hash = $1`, hash), &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// List returns the project's tokens, newest first.
func (s *PgServiceTokens) List(ctx context.Context, projectID uuid.UUID) ([]*ServiceToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+svcTokCols+` FROM gateway_service_tokens WHERE project_id = $1 ORDER BY created_at DESC, id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ServiceToken
	for rows.Next() {
		t := &ServiceToken{}
		if err := scanSvcToken(rows, t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CountActive counts the project's unexpired, unrevoked tokens.
func (s *PgServiceTokens) CountActive(ctx context.Context, projectID uuid.UUID, now time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM gateway_service_tokens WHERE project_id = $1 AND revoked_at IS NULL AND expires_at > $2`, projectID, now).Scan(&n)
	return n, err
}

// Revoke marks the token revoked; false when it does not exist in that project or was already revoked.
func (s *PgServiceTokens) Revoke(ctx context.Context, projectID, id uuid.UUID) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE gateway_service_tokens SET revoked_at = now() WHERE id = $1 AND project_id = $2 AND revoked_at IS NULL`, id, projectID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// TouchUsed records the use (at most one write per minute per token).
func (s *PgServiceTokens) TouchUsed(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE gateway_service_tokens SET last_used_at = now() WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, id)
	return err
}
