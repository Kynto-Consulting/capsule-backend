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

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	const q = `
		INSERT INTO users (email, password_hash, name, avatar_url, role)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, email, password_hash, name, avatar_url, role,
		          email_verified_at, last_login_at, created_at, updated_at`

	var created domain.User
	err := r.pool.QueryRow(ctx, q,
		user.Email, user.PasswordHash, user.Name, user.AvatarURL, user.Role,
	).Scan(
		&created.ID, &created.Email, &created.PasswordHash, &created.Name,
		&created.AvatarURL, &created.Role, &created.EmailVerifiedAt,
		&created.LastLoginAt, &created.CreatedAt, &created.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting user: %w", err)
	}
	return &created, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	const q = `
		SELECT id, email, password_hash, name, avatar_url, role,
		       email_verified_at, last_login_at, created_at, updated_at
		FROM users WHERE id = $1 AND deleted_at IS NULL`

	var u domain.User
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.AvatarURL, &u.Role,
		&u.EmailVerifiedAt, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying user by id: %w", err)
	}
	return &u, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	const q = `
		SELECT id, email, password_hash, name, avatar_url, role,
		       email_verified_at, last_login_at, created_at, updated_at
		FROM users WHERE email = $1 AND deleted_at IS NULL`

	var u domain.User
	err := r.pool.QueryRow(ctx, q, email).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.AvatarURL, &u.Role,
		&u.EmailVerifiedAt, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("querying user by email: %w", err)
	}
	return &u, nil
}

func (r *UserRepository) Update(ctx context.Context, user *domain.User) (*domain.User, error) {
	const q = `
		UPDATE users SET name = $2, avatar_url = $3, updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING id, email, password_hash, name, avatar_url, role,
		          email_verified_at, last_login_at, created_at, updated_at`

	var u domain.User
	err := r.pool.QueryRow(ctx, q, user.ID, user.Name, user.AvatarURL).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.AvatarURL, &u.Role,
		&u.EmailVerifiedAt, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("updating user: %w", err)
	}
	return &u, nil
}

func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	const q = `UPDATE users SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`
	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("soft-deleting user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// ListAll returns all users (including suspended) ordered by created_at, excluding hard-deleted.
func (r *UserRepository) ListAll(ctx context.Context, page, perPage int) ([]*domain.User, int, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		perPage = 50
	}
	offset := (page - 1) * perPage

	var total int
	if err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE deleted_at IS NULL`,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting users: %w", err)
	}

	rows, err := r.pool.Query(ctx, `
		SELECT id, email, password_hash, name, avatar_url, role,
		       email_verified_at, last_login_at, created_at, updated_at
		FROM users WHERE deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`, perPage, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()

	var out []*domain.User
	for rows.Next() {
		var u domain.User
		if err := rows.Scan(
			&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.AvatarURL, &u.Role,
			&u.EmailVerifiedAt, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning user: %w", err)
		}
		out = append(out, &u)
	}
	return out, total, nil
}

// SetRole updates a user's role (used by admin to suspend/restore/promote users).
func (r *UserRepository) SetRole(ctx context.Context, id uuid.UUID, role string) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE users SET role = $2, updated_at = now() WHERE id = $1 AND deleted_at IS NULL`,
		id, role)
	if err != nil {
		return fmt.Errorf("setting user role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
