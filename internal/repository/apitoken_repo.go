package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
)

type APITokenRepository struct {
	pool *pgxpool.Pool
}

func NewAPITokenRepository(pool *pgxpool.Pool) *APITokenRepository {
	return &APITokenRepository{pool: pool}
}

const tokenCols = `id, user_id, name, token_hash, prefix, scopes,
	rate_limit_rpm, ip_allowlist, request_count, last_count_reset,
	last_used_at, expires_at, created_at, revoked_at`

func scanToken(row interface{ Scan(...any) error }, t *domain.APIToken) error {
	return row.Scan(
		&t.ID, &t.UserID, &t.Name, &t.TokenHash, &t.Prefix, &t.Scopes,
		&t.RateLimitRPM, &t.IPAllowlist, &t.RequestCount, &t.LastCountReset,
		&t.LastUsedAt, &t.ExpiresAt, &t.CreatedAt, &t.RevokedAt,
	)
}

func (r *APITokenRepository) Create(ctx context.Context, token *domain.APIToken) (*domain.APIToken, error) {
	const q = `
		INSERT INTO api_tokens (user_id, name, token_hash, prefix, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING ` + tokenCols

	var out domain.APIToken
	if err := scanToken(r.pool.QueryRow(ctx, q,
		token.UserID, token.Name, token.TokenHash, token.Prefix, token.Scopes, token.ExpiresAt,
	), &out); err != nil {
		return nil, fmt.Errorf("creating api token: %w", err)
	}
	return &out, nil
}

func (r *APITokenRepository) GetByHash(ctx context.Context, hash string) (*domain.APIToken, error) {
	q := `SELECT ` + tokenCols + ` FROM api_tokens WHERE token_hash = $1 AND revoked_at IS NULL`
	var out domain.APIToken
	err := scanToken(r.pool.QueryRow(ctx, q, hash), &out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting api token by hash: %w", err)
	}
	return &out, nil
}

func (r *APITokenRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*domain.APIToken, error) {
	q := `SELECT ` + tokenCols + ` FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC`
	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("listing api tokens: %w", err)
	}
	defer rows.Close()

	var out []*domain.APIToken
	for rows.Next() {
		var token domain.APIToken
		if err := scanToken(rows, &token); err != nil {
			return nil, fmt.Errorf("scanning api token: %w", err)
		}
		out = append(out, &token)
	}
	return out, nil
}

func (r *APITokenRepository) Update(ctx context.Context, id uuid.UUID, rateLimitRPM int, ipAllowlist string) (*domain.APIToken, error) {
	q := `UPDATE api_tokens SET rate_limit_rpm=$2, ip_allowlist=$3 WHERE id=$1 AND revoked_at IS NULL RETURNING ` + tokenCols
	var out domain.APIToken
	if err := scanToken(r.pool.QueryRow(ctx, q, id, rateLimitRPM, ipAllowlist), &out); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("updating api token: %w", err)
	}
	return &out, nil
}

func (r *APITokenRepository) IncrementUsage(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE api_tokens SET request_count = request_count+1, last_used_at=now() WHERE id=$1`, id)
	return err
}

func (r *APITokenRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("revoking api token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *APITokenRepository) TouchLastUsed(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE api_tokens SET last_used_at = now() WHERE id = $1`, id)
	return err
}
