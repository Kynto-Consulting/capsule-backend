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

func (r *APITokenRepository) Create(ctx context.Context, token *domain.APIToken) (*domain.APIToken, error) {
	const q = `
		INSERT INTO api_tokens (user_id, name, token_hash, prefix, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, user_id, name, token_hash, prefix, scopes, last_used_at, expires_at, created_at, revoked_at`

	var out domain.APIToken
	err := r.pool.QueryRow(ctx, q,
		token.UserID, token.Name, token.TokenHash, token.Prefix, token.Scopes, token.ExpiresAt,
	).Scan(
		&out.ID, &out.UserID, &out.Name, &out.TokenHash, &out.Prefix, &out.Scopes,
		&out.LastUsedAt, &out.ExpiresAt, &out.CreatedAt, &out.RevokedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating api token: %w", err)
	}
	return &out, nil
}

func (r *APITokenRepository) GetByHash(ctx context.Context, hash string) (*domain.APIToken, error) {
	const q = `
		SELECT id, user_id, name, token_hash, prefix, scopes, last_used_at, expires_at, created_at, revoked_at
		FROM api_tokens
		WHERE token_hash = $1 AND revoked_at IS NULL`

	var out domain.APIToken
	err := r.pool.QueryRow(ctx, q, hash).Scan(
		&out.ID, &out.UserID, &out.Name, &out.TokenHash, &out.Prefix, &out.Scopes,
		&out.LastUsedAt, &out.ExpiresAt, &out.CreatedAt, &out.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting api token by hash: %w", err)
	}
	return &out, nil
}

func (r *APITokenRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*domain.APIToken, error) {
	const q = `
		SELECT id, user_id, name, token_hash, prefix, scopes, last_used_at, expires_at, created_at, revoked_at
		FROM api_tokens
		WHERE user_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("listing api tokens: %w", err)
	}
	defer rows.Close()

	var out []*domain.APIToken
	for rows.Next() {
		var token domain.APIToken
		err := rows.Scan(
			&token.ID, &token.UserID, &token.Name, &token.TokenHash, &token.Prefix, &token.Scopes,
			&token.LastUsedAt, &token.ExpiresAt, &token.CreatedAt, &token.RevokedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning api token: %w", err)
		}
		out = append(out, &token)
	}
	return out, nil
}

func (r *APITokenRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	const q = `
		UPDATE api_tokens
		SET revoked_at = now()
		WHERE id = $1 AND revoked_at IS NULL`

	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("revoking api token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *APITokenRepository) TouchLastUsed(ctx context.Context, id uuid.UUID) error {
	const q = `
		UPDATE api_tokens
		SET last_used_at = now()
		WHERE id = $1`

	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("touching api token last used: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
