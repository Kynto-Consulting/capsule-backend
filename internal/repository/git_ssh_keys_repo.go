package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gittokens"
)

// gitSSHKeyColumns are the SELECT expressions of git_ssh_keys, in scan order.
var gitSSHKeyColumns = []string{
	"id", "user_id", "title", "public_key", "key_type", "fingerprint", "forgejo_key_id",
	"synced_at", "sync_error", "sync_attempts", "next_sync_at", "last_used_at", "deleted_at", "created_at",
}

var gitSSHKeyCols = strings.Join(gitSSHKeyColumns, ", ")

func scanGitSSHKey(row interface{ Scan(...any) error }, k *gittokens.SSHKey) error {
	return row.Scan(
		&k.ID, &k.UserID, &k.Title, &k.PublicKey, &k.KeyType, &k.Fingerprint, &k.ForgejoKeyID,
		&k.SyncedAt, &k.SyncError, &k.SyncAttempts, &k.NextSyncAt, &k.LastUsedAt, &k.DeletedAt, &k.CreatedAt,
	)
}

func (r *GitAccessRepository) CreateKey(ctx context.Context, k *gittokens.SSHKey) (*gittokens.SSHKey, error) {
	var out gittokens.SSHKey
	err := scanGitSSHKey(r.pool.QueryRow(ctx, `
		INSERT INTO git_ssh_keys (user_id, title, public_key, key_type, fingerprint, next_sync_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING `+gitSSHKeyCols,
		k.UserID, k.Title, k.PublicKey, k.KeyType, k.Fingerprint, k.NextSyncAt), &out)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, domain.ErrConflict
	}
	if err != nil {
		return nil, fmt.Errorf("creating git ssh key: %w", err)
	}
	return &out, nil
}

func (r *GitAccessRepository) GetKey(ctx context.Context, id uuid.UUID) (*gittokens.SSHKey, error) {
	var k gittokens.SSHKey
	err := scanGitSSHKey(r.pool.QueryRow(ctx, `SELECT `+gitSSHKeyCols+` FROM git_ssh_keys WHERE id = $1`, id), &k)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading git ssh key: %w", err)
	}
	return &k, nil
}

func (r *GitAccessRepository) listKeys(ctx context.Context, q string, args ...any) ([]*gittokens.SSHKey, error) {
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing git ssh keys: %w", err)
	}
	defer rows.Close()
	out := []*gittokens.SSHKey{}
	for rows.Next() {
		var k gittokens.SSHKey
		if err := scanGitSSHKey(rows, &k); err != nil {
			return nil, fmt.Errorf("scanning git ssh key: %w", err)
		}
		out = append(out, &k)
	}
	return out, rows.Err()
}

func (r *GitAccessRepository) ListKeys(ctx context.Context, userID uuid.UUID) ([]*gittokens.SSHKey, error) {
	return r.listKeys(ctx, `SELECT `+gitSSHKeyCols+` FROM git_ssh_keys
		WHERE user_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 200`, userID)
}

func (r *GitAccessRepository) MarkKeySynced(ctx context.Context, id uuid.UUID, forgejoKeyID int64) error {
	_, err := r.pool.Exec(ctx, `UPDATE git_ssh_keys
		SET forgejo_key_id = $2, synced_at = now(), sync_error = '', sync_attempts = 0 WHERE id = $1`, id, forgejoKeyID)
	if err != nil {
		return fmt.Errorf("marking git ssh key synced: %w", err)
	}
	return nil
}

func (r *GitAccessRepository) MarkKeySyncFailed(ctx context.Context, id uuid.UUID, msg string, next time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE git_ssh_keys
		SET sync_error = $2, sync_attempts = sync_attempts + 1, next_sync_at = $3 WHERE id = $1`, id, msg, next)
	if err != nil {
		return fmt.Errorf("marking git ssh key sync failure: %w", err)
	}
	return nil
}

func (r *GitAccessRepository) SoftDeleteKey(ctx context.Context, id uuid.UUID, next time.Time) error {
	tag, err := r.pool.Exec(ctx, `UPDATE git_ssh_keys
		SET deleted_at = now(), next_sync_at = $2, sync_attempts = 0, sync_error = ''
		WHERE id = $1 AND deleted_at IS NULL`, id, next)
	if err != nil {
		return fmt.Errorf("deleting git ssh key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *GitAccessRepository) MarkKeyRemoved(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE git_ssh_keys
		SET forgejo_key_id = NULL, synced_at = NULL, sync_error = '', sync_attempts = 0 WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("marking git ssh key removed: %w", err)
	}
	return nil
}

func (r *GitAccessRepository) ListPendingKeys(ctx context.Context, now time.Time, limit int) ([]*gittokens.SSHKey, error) {
	return r.listKeys(ctx, `SELECT `+gitSSHKeyCols+` FROM git_ssh_keys
		WHERE next_sync_at <= $1
		  AND ((synced_at IS NULL AND deleted_at IS NULL) OR (deleted_at IS NOT NULL AND forgejo_key_id IS NOT NULL))
		ORDER BY next_sync_at LIMIT $2`, now, limit)
}
