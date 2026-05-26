package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SettingsRepository struct {
	pool *pgxpool.Pool
}

func NewSettingsRepository(pool *pgxpool.Pool) *SettingsRepository {
	return &SettingsRepository{pool: pool}
}

func (r *SettingsRepository) Get(ctx context.Context, key string) (string, error) {
	var val string
	err := r.pool.QueryRow(ctx, "SELECT value FROM platform_settings WHERE key = $1", key).Scan(&val)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return val, nil
}

func (r *SettingsRepository) Set(ctx context.Context, key, value string) error {
	now := time.Now()
	_, err := r.pool.Exec(ctx, `
		INSERT INTO platform_settings (key, value, created_at, updated_at)
		VALUES ($1, $2, $3, $3)
		ON CONFLICT (key) DO UPDATE
		SET value = $2, updated_at = $3
	`, key, value, now)
	return err
}
