package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

// OrgEnvVarRepository stores account-level variables, encrypted exactly like
// project env_vars (AES-GCM over "KEY:value").
type OrgEnvVarRepository struct {
	pool      *pgxpool.Pool
	secretKey string
}

func NewOrgEnvVarRepository(pool *pgxpool.Pool, secretKey string) *OrgEnvVarRepository {
	return &OrgEnvVarRepository{pool: pool, secretKey: secretKey}
}

func (r *OrgEnvVarRepository) Upsert(ctx context.Context, e *domain.OrgEnvVar) (*domain.OrgEnvVar, error) {
	enc, err := crypto.Encrypt([]byte(e.Key+":"+string(e.ValueEnc)), r.secretKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting org env var: %w", err)
	}
	const q = `
		INSERT INTO org_env_vars (org_id, key, value_enc, is_secret, scope)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (org_id, key) DO UPDATE
		SET value_enc = EXCLUDED.value_enc, is_secret = EXCLUDED.is_secret,
		    scope = EXCLUDED.scope, updated_at = now()
		RETURNING id, org_id, key, is_secret, scope, created_at, updated_at`
	var out domain.OrgEnvVar
	if err := r.pool.QueryRow(ctx, q, e.OrgID, e.Key, enc, e.IsSecret, e.Scope).Scan(
		&out.ID, &out.OrgID, &out.Key, &out.IsSecret, &out.Scope, &out.CreatedAt, &out.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("upserting org env var: %w", err)
	}
	out.ValueEnc = e.ValueEnc
	return &out, nil
}

func (r *OrgEnvVarRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*domain.OrgEnvVar, error) {
	const q = `
		SELECT id, org_id, key, value_enc, is_secret, scope, created_at, updated_at
		FROM org_env_vars WHERE org_id = $1 ORDER BY key`
	rows, err := r.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("querying org env vars: %w", err)
	}
	defer rows.Close()
	var out []*domain.OrgEnvVar
	for rows.Next() {
		var e domain.OrgEnvVar
		if err := rows.Scan(&e.ID, &e.OrgID, &e.Key, &e.ValueEnc, &e.IsSecret, &e.Scope, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning org env var: %w", err)
		}
		e.ValueEnc = []byte(DecryptEnvValue(e.Key, e.ValueEnc, r.secretKey))
		out = append(out, &e)
	}
	return out, rows.Err()
}

func (r *OrgEnvVarRepository) Delete(ctx context.Context, orgID uuid.UUID, key string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM org_env_vars WHERE org_id = $1 AND key = $2`, orgID, key)
	if err != nil {
		return fmt.Errorf("deleting org env var: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// DecryptEnvValue reverses the "KEY:value" AES-GCM encoding used by env_vars
// and org_env_vars; falls back to the raw bytes if decryption fails.
func DecryptEnvValue(key string, enc []byte, secretKey string) string {
	plain, err := crypto.Decrypt(enc, secretKey)
	if err != nil {
		return string(enc)
	}
	prefix := []byte(key + ":")
	if len(plain) > len(prefix) {
		return string(plain[len(prefix):])
	}
	return string(plain)
}
