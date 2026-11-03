package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kynto/capsule/backend/internal/domain"
)

// deploymentHealthCols receives the health_* / error_message columns appended to
// every deployment SELECT (see deployment_repo.go). Keep in sync with the queries:
// deployment_scan_test.go checks the column count against the scan destinations.
type deploymentHealthCols struct {
	status    string
	path      string
	checkedAt *time.Time
	detail    string
	errMsg    string
}

// apply copies the columns into the deployment. health is omitted entirely when
// no check ever ran (status empty).
func (h *deploymentHealthCols) apply(d *domain.Deployment) {
	d.ErrorMessage = h.errMsg
	if h.status == "" {
		return
	}
	d.Health = &domain.DeploymentHealth{
		Status:    h.status,
		Path:      h.path,
		LastCheck: h.checkedAt,
		Detail:    h.detail,
	}
}

// SetHealth records the health state of a deployment (domain.DeploymentHealthStore).
func (r *DeploymentRepository) SetHealth(ctx context.Context, id uuid.UUID, h domain.DeploymentHealth) error {
	checked := time.Now().UTC()
	if h.LastCheck != nil {
		checked = *h.LastCheck
	}
	detail := h.Detail
	if len(detail) > 2000 {
		detail = detail[:2000]
	}
	_, err := r.pool.Exec(ctx,
		`UPDATE deployments SET health_status = $2, health_path = $3, health_checked_at = $4, health_detail = $5 WHERE id = $1`,
		id, h.Status, h.Path, checked, detail)
	return err
}

// SetErrorMessage records why a deployment failed (domain.DeploymentHealthStore).
func (r *DeploymentRepository) SetErrorMessage(ctx context.Context, id uuid.UUID, msg string) error {
	if len(msg) > 4000 {
		msg = msg[:4000]
	}
	_, err := r.pool.Exec(ctx, `UPDATE deployments SET error_message = $2 WHERE id = $1`, id, msg)
	return err
}

var _ domain.DeploymentHealthStore = (*DeploymentRepository)(nil)

const projectHealthSelect = `SELECT health_path, health_timeout_seconds, health_interval_seconds, health_expected_status
		FROM projects WHERE id = $1 AND deleted_at IS NULL`

func scanProjectHealth(row interface{ Scan(...any) error }) (domain.ProjectHealthConfig, error) {
	var c domain.ProjectHealthConfig
	err := row.Scan(&c.Path, &c.TimeoutSeconds, &c.IntervalSeconds, &c.ExpectedStatus)
	return c, err
}

// GetHealthConfig reads the project's health settings (domain.ProjectHealthStore).
func (r *ProjectRepository) GetHealthConfig(ctx context.Context, projectID uuid.UUID) (domain.ProjectHealthConfig, error) {
	c, err := scanProjectHealth(r.pool.QueryRow(ctx, projectHealthSelect, projectID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProjectHealthConfig{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.ProjectHealthConfig{}, fmt.Errorf("reading project health config: %w", err)
	}
	return c, nil
}

// SetHealthConfig writes the project's health settings (already validated).
func (r *ProjectRepository) SetHealthConfig(ctx context.Context, projectID uuid.UUID, c domain.ProjectHealthConfig) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE projects
		SET health_path = $2, health_timeout_seconds = $3, health_interval_seconds = $4,
		    health_expected_status = $5, updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL`,
		projectID, c.Path, c.TimeoutSeconds, c.IntervalSeconds, c.ExpectedStatus)
	if err != nil {
		return fmt.Errorf("updating project health config: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

var _ domain.ProjectHealthStore = (*ProjectRepository)(nil)
