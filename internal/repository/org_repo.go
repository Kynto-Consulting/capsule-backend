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

type OrgRepository struct {
	pool *pgxpool.Pool
}

func NewOrgRepository(pool *pgxpool.Pool) *OrgRepository {
	return &OrgRepository{pool: pool}
}

func (r *OrgRepository) Create(ctx context.Context, org *domain.Organization) (*domain.Organization, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning tx: %w", err)
	}
	defer tx.Rollback(ctx)

	const q = `
		INSERT INTO organizations (name, slug, owner_id, plan, settings)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, name, slug, owner_id, plan, settings, created_at, updated_at`

	var created domain.Organization
	err = tx.QueryRow(ctx, q,
		org.Name, org.Slug, org.OwnerID, "free", "{}",
	).Scan(
		&created.ID, &created.Name, &created.Slug, &created.OwnerID,
		&created.Plan, &created.Settings, &created.CreatedAt, &created.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting org: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, 'owner')`,
		created.ID, org.OwnerID,
	)
	if err != nil {
		return nil, fmt.Errorf("adding owner member: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing tx: %w", err)
	}
	return &created, nil
}

func (r *OrgRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Organization, error) {
	const q = `
		SELECT id, name, slug, owner_id, plan, settings, created_at, updated_at
		FROM organizations WHERE id = $1 AND deleted_at IS NULL`
	return r.scanOne(ctx, q, id)
}

func (r *OrgRepository) GetBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	const q = `
		SELECT id, name, slug, owner_id, plan, settings, created_at, updated_at
		FROM organizations WHERE slug = $1 AND deleted_at IS NULL`
	return r.scanOne(ctx, q, slug)
}

func (r *OrgRepository) ListByUser(ctx context.Context, userID uuid.UUID, page, perPage int) ([]*domain.Organization, int, error) {
	const q = `
		SELECT o.id, o.name, o.slug, o.owner_id, o.plan, o.settings, o.created_at, o.updated_at
		FROM organizations o
		JOIN org_members m ON m.org_id = o.id
		WHERE m.user_id = $1 AND o.deleted_at IS NULL
		ORDER BY o.created_at DESC
		LIMIT $2 OFFSET $3`

	offset := (page - 1) * perPage
	rows, err := r.pool.Query(ctx, q, userID, perPage, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("querying orgs: %w", err)
	}
	defer rows.Close()

	var orgs []*domain.Organization
	for rows.Next() {
		var o domain.Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.OwnerID, &o.Plan, &o.Settings, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("scanning org: %w", err)
		}
		orgs = append(orgs, &o)
	}

	var total int
	_ = r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM organizations o JOIN org_members m ON m.org_id = o.id WHERE m.user_id = $1 AND o.deleted_at IS NULL`,
		userID,
	).Scan(&total)

	return orgs, total, nil
}

func (r *OrgRepository) Update(ctx context.Context, org *domain.Organization) (*domain.Organization, error) {
	const q = `
		UPDATE organizations SET name = $2, settings = $3, updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING id, name, slug, owner_id, plan, settings, created_at, updated_at`
	return r.scanOne(ctx, q, org.ID, org.Name, org.Settings)
}

func (r *OrgRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `UPDATE organizations SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("deleting org: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *OrgRepository) AddMember(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		orgID, userID, role,
	)
	return err
}

func (r *OrgRepository) RemoveMember(ctx context.Context, orgID, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM org_members WHERE org_id = $1 AND user_id = $2`, orgID, userID)
	return err
}

func (r *OrgRepository) IsMember(ctx context.Context, orgID, userID uuid.UUID) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2)`,
		orgID, userID,
	).Scan(&exists)
	return exists, err
}

func (r *OrgRepository) scanOne(ctx context.Context, q string, args ...any) (*domain.Organization, error) {
	var o domain.Organization
	err := r.pool.QueryRow(ctx, q, args...).Scan(
		&o.ID, &o.Name, &o.Slug, &o.OwnerID, &o.Plan, &o.Settings, &o.CreatedAt, &o.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scanning org: %w", err)
	}
	return &o, nil
}
