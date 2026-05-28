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

type DomainRepository struct {
	pool *pgxpool.Pool
}

func NewDomainRepository(pool *pgxpool.Pool) *DomainRepository {
	return &DomainRepository{pool: pool}
}

func (r *DomainRepository) Create(ctx context.Context, d *domain.Domain) (*domain.Domain, error) {
	const q = `
		INSERT INTO domains
			(org_id, project_id, domain_name, record_type, record_value, verification_token, status, ssl_enabled, dns_provider)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, org_id, project_id, domain_name, record_type, record_value, verification_token,
		          status, ssl_enabled, dns_provider, verified_at, created_at, updated_at`

	var out domain.Domain
	err := r.pool.QueryRow(ctx, q,
		d.OrgID, d.ProjectID, d.DomainName, d.RecordType, d.RecordValue,
		d.VerificationToken, d.Status, d.SSLEnabled, d.DNSProvider,
	).Scan(
		&out.ID, &out.OrgID, &out.ProjectID, &out.DomainName, &out.RecordType, &out.RecordValue,
		&out.VerificationToken, &out.Status, &out.SSLEnabled, &out.DNSProvider,
		&out.VerifiedAt, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating domain: %w", err)
	}
	return &out, nil
}

func (r *DomainRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Domain, error) {
	const q = `
		SELECT id, org_id, project_id, domain_name, record_type, record_value, verification_token,
		       status, ssl_enabled, dns_provider, verified_at, created_at, updated_at
		FROM domains
		WHERE id = $1`

	var out domain.Domain
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&out.ID, &out.OrgID, &out.ProjectID, &out.DomainName, &out.RecordType, &out.RecordValue,
		&out.VerificationToken, &out.Status, &out.SSLEnabled, &out.DNSProvider,
		&out.VerifiedAt, &out.CreatedAt, &out.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting domain: %w", err)
	}
	return &out, nil
}

func (r *DomainRepository) GetByHostname(ctx context.Context, hostname string) (*domain.Domain, error) {
	const q = `
		SELECT id, org_id, project_id, domain_name, record_type, record_value, verification_token,
		       status, ssl_enabled, dns_provider, verified_at, created_at, updated_at
		FROM domains
		WHERE domain_name = $1 AND status = 'verified'
		LIMIT 1`
	var out domain.Domain
	err := r.pool.QueryRow(ctx, q, hostname).Scan(
		&out.ID, &out.OrgID, &out.ProjectID, &out.DomainName, &out.RecordType, &out.RecordValue,
		&out.VerificationToken, &out.Status, &out.SSLEnabled, &out.DNSProvider,
		&out.VerifiedAt, &out.CreatedAt, &out.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting domain by hostname: %w", err)
	}
	return &out, nil
}

func (r *DomainRepository) ListByProject(ctx context.Context, projectID uuid.UUID) ([]*domain.Domain, error) {
	const q = `
		SELECT id, org_id, project_id, domain_name, record_type, record_value, verification_token,
		       status, ssl_enabled, dns_provider, verified_at, created_at, updated_at
		FROM domains
		WHERE project_id = $1
		ORDER BY created_at DESC`
	return r.scanDomains(ctx, q, projectID)
}

func (r *DomainRepository) ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*domain.Domain, error) {
	const q = `
		SELECT id, org_id, project_id, domain_name, record_type, record_value, verification_token,
		       status, ssl_enabled, dns_provider, verified_at, created_at, updated_at
		FROM domains
		WHERE org_id = $1
		ORDER BY created_at DESC`
	return r.scanDomains(ctx, q, orgID)
}

func (r *DomainRepository) scanDomains(ctx context.Context, q string, arg any) ([]*domain.Domain, error) {
	rows, err := r.pool.Query(ctx, q, arg)
	if err != nil {
		return nil, fmt.Errorf("listing domains: %w", err)
	}
	defer rows.Close()

	var out []*domain.Domain
	for rows.Next() {
		var d domain.Domain
		if err := rows.Scan(
			&d.ID, &d.OrgID, &d.ProjectID, &d.DomainName, &d.RecordType, &d.RecordValue,
			&d.VerificationToken, &d.Status, &d.SSLEnabled, &d.DNSProvider,
			&d.VerifiedAt, &d.CreatedAt, &d.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning domain: %w", err)
		}
		out = append(out, &d)
	}
	return out, nil
}

func (r *DomainRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status, recordValue string) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE domains SET status = $2, record_value = $3, updated_at = now() WHERE id = $1`,
		id, status, recordValue,
	)
	if err != nil {
		return fmt.Errorf("updating domain status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *DomainRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM domains WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("deleting domain: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}
