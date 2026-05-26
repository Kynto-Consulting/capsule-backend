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

type DatabaseRepository struct {
	pool *pgxpool.Pool
}

func NewDatabaseRepository(pool *pgxpool.Pool) *DatabaseRepository {
	return &DatabaseRepository{pool: pool}
}

func (r *DatabaseRepository) Create(ctx context.Context, db *domain.Database) (*domain.Database, error) {
	const q = `
		INSERT INTO databases
			(project_id, name, engine, version, host, port, db_name, credentials_enc, status, size_mb, container_id, volume_name)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, project_id, name, engine, version, host, port, db_name, credentials_enc, status, size_mb,
		          container_id, volume_name, created_at, updated_at`

	var out domain.Database
	err := r.pool.QueryRow(ctx, q,
		db.ProjectID, db.Name, db.Engine, db.Version,
		db.Host, db.Port, db.DBName, db.CredentialsEnc,
		db.Status, db.SizeMB, db.ContainerID, db.VolumeName,
	).Scan(
		&out.ID, &out.ProjectID, &out.Name, &out.Engine, &out.Version,
		&out.Host, &out.Port, &out.DBName, &out.CredentialsEnc,
		&out.Status, &out.SizeMB, &out.ContainerID, &out.VolumeName,
		&out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating database: %w", err)
	}
	return &out, nil
}

func (r *DatabaseRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Database, error) {
	const q = `
		SELECT id, project_id, name, engine, version, host, port, db_name, credentials_enc, status, size_mb,
		       container_id, volume_name, created_at, updated_at
		FROM databases
		WHERE id = $1 AND deleted_at IS NULL`

	var out domain.Database
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&out.ID, &out.ProjectID, &out.Name, &out.Engine, &out.Version,
		&out.Host, &out.Port, &out.DBName, &out.CredentialsEnc,
		&out.Status, &out.SizeMB, &out.ContainerID, &out.VolumeName,
		&out.CreatedAt, &out.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting database: %w", err)
	}
	return &out, nil
}

func (r *DatabaseRepository) ListByProject(ctx context.Context, projectID uuid.UUID) ([]*domain.Database, error) {
	const q = `
		SELECT id, project_id, name, engine, version, host, port, db_name, credentials_enc, status, size_mb,
		       container_id, volume_name, created_at, updated_at
		FROM databases
		WHERE project_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing databases: %w", err)
	}
	defer rows.Close()

	var out []*domain.Database
	for rows.Next() {
		var db domain.Database
		if err := rows.Scan(
			&db.ID, &db.ProjectID, &db.Name, &db.Engine, &db.Version,
			&db.Host, &db.Port, &db.DBName, &db.CredentialsEnc,
			&db.Status, &db.SizeMB, &db.ContainerID, &db.VolumeName,
			&db.CreatedAt, &db.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning database: %w", err)
		}
		out = append(out, &db)
	}
	return out, nil
}

func (r *DatabaseRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status, host string, port int) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE databases SET status = $2, host = $3, port = $4, updated_at = now() WHERE id = $1`,
		id, status, host, port,
	)
	if err != nil {
		return fmt.Errorf("updating database status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *DatabaseRepository) UpdateCredentials(ctx context.Context, id uuid.UUID, credsEnc []byte) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE databases SET credentials_enc = $2, updated_at = now() WHERE id = $1`,
		id, credsEnc,
	)
	if err != nil {
		return fmt.Errorf("updating database credentials: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *DatabaseRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE databases SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL`,
		id,
	)
	if err != nil {
		return fmt.Errorf("deleting database: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *DatabaseRepository) GetGlobalStats(ctx context.Context) (projects int, rdsDatabases int, s3Buckets int, domains int, err error) {
	err = r.pool.QueryRow(ctx, "SELECT COUNT(*) FROM projects WHERE deleted_at IS NULL").Scan(&projects)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	err = r.pool.QueryRow(ctx, "SELECT COUNT(*) FROM databases WHERE engine != 's3' AND deleted_at IS NULL").Scan(&rdsDatabases)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	err = r.pool.QueryRow(ctx, "SELECT COUNT(*) FROM databases WHERE engine = 's3' AND deleted_at IS NULL").Scan(&s3Buckets)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	err = r.pool.QueryRow(ctx, "SELECT COUNT(*) FROM domains").Scan(&domains)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	return projects, rdsDatabases, s3Buckets, domains, nil
}
