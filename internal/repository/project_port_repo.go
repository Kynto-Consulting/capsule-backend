package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
)

const projectPortCols = `id, project_id, name, container_port, protocol, host_port, created_at`

func scanProjectPort(row interface{ Scan(...any) error }, p *domain.ProjectPort) error {
	return row.Scan(&p.ID, &p.ProjectID, &p.Name, &p.ContainerPort, &p.Protocol, &p.HostPort, &p.CreatedAt)
}

const portRuleCols = `id, port_id, cidr, description, created_by, created_at`

func scanPortRule(row interface{ Scan(...any) error }, r *domain.PortRule) error {
	return row.Scan(&r.ID, &r.PortID, &r.CIDR, &r.Description, &r.CreatedBy, &r.CreatedAt)
}

const desiredPortRuleCols = `p.project_id, p.host_port, r.cidr`

func scanDesiredPortRule(row interface{ Scan(...any) error }, d *domain.DesiredPortRule) error {
	return row.Scan(&d.ProjectID, &d.HostPort, &d.CIDR)
}

const usedPortCols = `host_port`

func scanUsedPort(row interface{ Scan(...any) error }, port *int) error {
	return row.Scan(port)
}

// portsLockKey serialises every port-allocation transaction (pg_advisory_xact_lock).
const portsLockKey int64 = 0x43415053504f5254 // "CAPSPORT"

// ProjectPortRepository implements domain.ProjectPortRepository.
type ProjectPortRepository struct{ pool *pgxpool.Pool }

func NewProjectPortRepository(pool *pgxpool.Pool) *ProjectPortRepository {
	return &ProjectPortRepository{pool: pool}
}

func listProjectPorts(ctx context.Context, q queryer, projectID uuid.UUID) ([]*domain.ProjectPort, error) {
	rows, err := q.Query(ctx,
		`SELECT `+projectPortCols+` FROM project_ports WHERE project_id = $1 ORDER BY container_port`, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing project ports: %w", err)
	}
	var ports []*domain.ProjectPort
	byID := map[uuid.UUID]*domain.ProjectPort{}
	for rows.Next() {
		var p domain.ProjectPort
		if err := scanProjectPort(rows, &p); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scanning project port: %w", err)
		}
		p.Rules = []*domain.PortRule{}
		ports = append(ports, &p)
		byID[p.ID] = &p
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return []*domain.ProjectPort{}, nil
	}
	rrows, err := q.Query(ctx, `SELECT `+portRuleCols+` FROM project_port_rules
		WHERE port_id IN (SELECT id FROM project_ports WHERE project_id = $1)
		ORDER BY created_at, cidr`, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing port rules: %w", err)
	}
	defer rrows.Close()
	for rrows.Next() {
		var r domain.PortRule
		if err := scanPortRule(rrows, &r); err != nil {
			return nil, fmt.Errorf("scanning port rule: %w", err)
		}
		if p := byID[r.PortID]; p != nil {
			p.Rules = append(p.Rules, &r)
		}
	}
	return ports, rrows.Err()
}

func (r *ProjectPortRepository) List(ctx context.Context, projectID uuid.UUID) ([]*domain.ProjectPort, error) {
	return listProjectPorts(ctx, r.pool, projectID)
}

func (r *ProjectPortRepository) UsedHostPorts(ctx context.Context, from, to int) (map[int]bool, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+usedPortCols+` FROM project_ports WHERE host_port BETWEEN $1 AND $2
		UNION SELECT port FROM databases WHERE deleted_at IS NULL AND port BETWEEN $1 AND $2
		UNION SELECT host_port FROM deployments WHERE host_port BETWEEN $1 AND $2`, from, to)
	if err != nil {
		return nil, fmt.Errorf("listing used ports: %w", err)
	}
	defer rows.Close()
	out := map[int]bool{}
	for rows.Next() {
		var p int
		if err := scanUsedPort(rows, &p); err != nil {
			return nil, fmt.Errorf("scanning used port: %w", err)
		}
		out[p] = true
	}
	return out, rows.Err()
}

func (r *ProjectPortRepository) Replace(ctx context.Context, projectID uuid.UUID, ports []*domain.ProjectPort) ([]*domain.ProjectPort, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, portsLockKey); err != nil {
		return nil, fmt.Errorf("locking ports: %w", err)
	}
	keep := make([]int32, 0, len(ports))
	for _, p := range ports {
		keep = append(keep, int32(p.ContainerPort))
	}
	// Delete first so freed host ports are reusable by the inserts below.
	if _, err := tx.Exec(ctx,
		`DELETE FROM project_ports WHERE project_id = $1 AND NOT (container_port = ANY($2))`, projectID, keep); err != nil {
		return nil, fmt.Errorf("pruning project ports: %w", err)
	}
	for _, p := range ports {
		// A kept port keeps its stored host_port (the DO UPDATE does not touch it).
		if _, err := tx.Exec(ctx, `
			INSERT INTO project_ports (project_id, name, container_port, protocol, host_port)
			VALUES ($1, $2, $3, 'tcp', $4)
			ON CONFLICT (project_id, container_port) DO UPDATE SET name = EXCLUDED.name`,
			projectID, p.Name, p.ContainerPort, p.HostPort); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return nil, domain.ErrConflict
			}
			return nil, fmt.Errorf("upserting project port: %w", err)
		}
	}
	out, err := listProjectPorts(ctx, tx, projectID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}

func (r *ProjectPortRepository) AddRule(ctx context.Context, projectID uuid.UUID, containerPort int, rule *domain.PortRule, max int) (*domain.PortRule, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Lock the port row so concurrent adds keep the limit exact.
	var portID uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT id FROM project_ports WHERE project_id = $1 AND container_port = $2 FOR UPDATE`,
		projectID, containerPort).Scan(&portID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("locking port: %w", err)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM project_port_rules WHERE port_id = $1`, portID).Scan(&n); err != nil {
		return nil, fmt.Errorf("counting port rules: %w", err)
	}
	if n >= max {
		return nil, domain.ErrRuleLimit
	}
	var out domain.PortRule
	err = scanPortRule(tx.QueryRow(ctx, `
		INSERT INTO project_port_rules (port_id, cidr, description, created_by)
		VALUES ($1, $2, $3, $4)
		RETURNING `+portRuleCols, portID, rule.CIDR, rule.Description, rule.CreatedBy), &out)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, domain.ErrConflict
		}
		return nil, fmt.Errorf("adding port rule: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return &out, nil
}

func (r *ProjectPortRepository) DeleteRule(ctx context.Context, projectID, ruleID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM project_port_rules WHERE id = $1
		AND port_id IN (SELECT id FROM project_ports WHERE project_id = $2)`, ruleID, projectID)
	if err != nil {
		return fmt.Errorf("deleting port rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *ProjectPortRepository) ListDesired(ctx context.Context) ([]domain.DesiredPortRule, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+desiredPortRuleCols+`
		FROM project_port_rules r
		JOIN project_ports p ON p.id = r.port_id
		JOIN projects pr ON pr.id = p.project_id
		WHERE pr.deleted_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("listing desired port rules: %w", err)
	}
	defer rows.Close()
	var out []domain.DesiredPortRule
	for rows.Next() {
		var d domain.DesiredPortRule
		if err := scanDesiredPortRule(rows, &d); err != nil {
			return nil, fmt.Errorf("scanning desired port rule: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *ProjectPortRepository) DeleteAll(ctx context.Context, projectID uuid.UUID) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM project_ports WHERE project_id = $1`, projectID); err != nil {
		return fmt.Errorf("deleting project ports: %w", err)
	}
	return nil
}
