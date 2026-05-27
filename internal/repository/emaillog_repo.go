package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
)

type EmailLogRepository struct {
	pool *pgxpool.Pool
}

func NewEmailLogRepository(pool *pgxpool.Pool) *EmailLogRepository {
	return &EmailLogRepository{pool: pool}
}

func (r *EmailLogRepository) Create(ctx context.Context, log *domain.EmailLog) (*domain.EmailLog, error) {
	const q = `
		INSERT INTO email_logs (project_id, domain, from_addr, to_addr, subject, status, message_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, project_id, domain, from_addr, to_addr, subject, status, message_id, created_at`

	var out domain.EmailLog
	err := r.pool.QueryRow(ctx, q,
		log.ProjectID, log.Domain, log.FromAddr, log.ToAddr,
		log.Subject, log.Status, log.MessageID,
	).Scan(
		&out.ID, &out.ProjectID, &out.Domain, &out.FromAddr, &out.ToAddr,
		&out.Subject, &out.Status, &out.MessageID, &out.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating email log: %w", err)
	}
	return &out, nil
}

func (r *EmailLogRepository) ListByProject(ctx context.Context, projectID uuid.UUID, limit int) ([]*domain.EmailLog, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `
		SELECT id, project_id, domain, from_addr, to_addr, subject, status, message_id, created_at
		FROM email_logs
		WHERE project_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := r.pool.Query(ctx, q, projectID, limit)
	if err != nil {
		return nil, fmt.Errorf("listing email logs: %w", err)
	}
	defer rows.Close()

	var out []*domain.EmailLog
	for rows.Next() {
		var el domain.EmailLog
		if err := rows.Scan(
			&el.ID, &el.ProjectID, &el.Domain, &el.FromAddr, &el.ToAddr,
			&el.Subject, &el.Status, &el.MessageID, &el.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning email log: %w", err)
		}
		out = append(out, &el)
	}
	return out, nil
}
