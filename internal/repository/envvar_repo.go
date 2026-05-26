package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

type EnvVarRepository struct {
	pool      *pgxpool.Pool
	secretKey string
}

func NewEnvVarRepository(pool *pgxpool.Pool, secretKey string) *EnvVarRepository {
	return &EnvVarRepository{pool: pool, secretKey: secretKey}
}

func (r *EnvVarRepository) Upsert(ctx context.Context, e *domain.EnvVar) (*domain.EnvVar, error) {
	enc, err := crypto.Encrypt([]byte(e.Key+":"+string(e.ValueEnc)), r.secretKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting env var: %w", err)
	}

	const q = `
		INSERT INTO env_vars (project_id, key, value_enc, is_secret, scope)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (project_id, key) DO UPDATE
		SET value_enc = EXCLUDED.value_enc, is_secret = EXCLUDED.is_secret,
		    scope = EXCLUDED.scope, updated_at = now()
		RETURNING id, project_id, key, value_enc, is_secret, scope, created_at, updated_at`

	var out domain.EnvVar
	err = r.pool.QueryRow(ctx, q, e.ProjectID, e.Key, enc, e.IsSecret, e.Scope).Scan(
		&out.ID, &out.ProjectID, &out.Key, &out.ValueEnc, &out.IsSecret, &out.Scope,
		&out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("upserting env var: %w", err)
	}
	out.ValueEnc = e.ValueEnc // return plaintext bytes for the response
	return &out, nil
}

func (r *EnvVarRepository) ListByProject(ctx context.Context, projectID uuid.UUID) ([]*domain.EnvVar, error) {
	const q = `
		SELECT id, project_id, key, value_enc, is_secret, scope, created_at, updated_at
		FROM env_vars WHERE project_id = $1 ORDER BY key`

	rows, err := r.pool.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("querying env vars: %w", err)
	}
	defer rows.Close()

	var out []*domain.EnvVar
	for rows.Next() {
		var e domain.EnvVar
		if err := rows.Scan(&e.ID, &e.ProjectID, &e.Key, &e.ValueEnc, &e.IsSecret, &e.Scope, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning env var: %w", err)
		}
		e.ValueEnc = r.decryptValue(e.Key, e.ValueEnc)
		out = append(out, &e)
	}
	return out, nil
}

func (r *EnvVarRepository) GetByKey(ctx context.Context, projectID uuid.UUID, key string) (*domain.EnvVar, error) {
	const q = `
		SELECT id, project_id, key, value_enc, is_secret, scope, created_at, updated_at
		FROM env_vars WHERE project_id = $1 AND key = $2`

	var e domain.EnvVar
	err := r.pool.QueryRow(ctx, q, projectID, key).Scan(
		&e.ID, &e.ProjectID, &e.Key, &e.ValueEnc, &e.IsSecret, &e.Scope, &e.CreatedAt, &e.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting env var: %w", err)
	}
	e.ValueEnc = r.decryptValue(e.Key, e.ValueEnc)
	return &e, nil
}

func (r *EnvVarRepository) Delete(ctx context.Context, projectID uuid.UUID, key string) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM env_vars WHERE project_id = $1 AND key = $2`, projectID, key)
	if err != nil {
		return fmt.Errorf("deleting env var: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *EnvVarRepository) decryptValue(key string, enc []byte) []byte {
	plain, err := crypto.Decrypt(enc, r.secretKey)
	if err != nil {
		return enc
	}
	// strip the "key:" prefix we added on encrypt
	prefix := []byte(key + ":")
	if len(plain) > len(prefix) {
		return plain[len(prefix):]
	}
	return plain
}
