package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/gitsync"
)

// GitIdentityRepository persists git_identities (Git Capsule A2).
type GitIdentityRepository struct{ pool *pgxpool.Pool }

func NewGitIdentityRepository(pool *pgxpool.Pool) *GitIdentityRepository {
	return &GitIdentityRepository{pool: pool}
}

var _ gitsync.IdentityStore = (*GitIdentityRepository)(nil)

const gitIdentityCols = `user_id, forgejo_username, forgejo_user_id, linked_at, created_at, updated_at`

func scanGitIdentity(row interface{ Scan(...any) error }, i *gitsync.Identity) error {
	return row.Scan(&i.UserID, &i.ForgejoUsername, &i.ForgejoUserID, &i.LinkedAt, &i.CreatedAt, &i.UpdatedAt)
}

func (r *GitIdentityRepository) Get(ctx context.Context, userID uuid.UUID) (*gitsync.Identity, error) {
	var i gitsync.Identity
	err := scanGitIdentity(r.pool.QueryRow(ctx, `SELECT `+gitIdentityCols+` FROM git_identities WHERE user_id = $1`, userID), &i)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, gitsync.ErrNoIdentity
	}
	if err != nil {
		return nil, fmt.Errorf("loading git identity: %w", err)
	}
	return &i, nil
}

func (r *GitIdentityRepository) Ensure(ctx context.Context, userID uuid.UUID, login string) (*gitsync.Identity, error) {
	var i gitsync.Identity
	// DO UPDATE SET user_id = user_id is a no-op that makes RETURNING yield the stored row.
	err := scanGitIdentity(r.pool.QueryRow(ctx, `
		INSERT INTO git_identities (user_id, forgejo_username) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET user_id = git_identities.user_id
		RETURNING `+gitIdentityCols, userID, login), &i)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, gitsync.ErrUsernameTaken
	}
	if err != nil {
		return nil, fmt.Errorf("saving git identity: %w", err)
	}
	return &i, nil
}

func (r *GitIdentityRepository) MarkLinked(ctx context.Context, userID uuid.UUID, forgejoUserID int64) error {
	var fid any
	if forgejoUserID > 0 {
		fid = forgejoUserID
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE git_identities SET
			linked_at = COALESCE(linked_at, now()),
			forgejo_user_id = COALESCE($2, forgejo_user_id),
			updated_at = now()
		WHERE user_id = $1`, userID, fid)
	if err != nil {
		return fmt.Errorf("marking git identity linked: %w", err)
	}
	return nil
}
