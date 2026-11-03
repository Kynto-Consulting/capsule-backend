package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// poolLockKey serialises every port-pool mutation (pg_advisory_xact_lock), so quota counts and the
// "leased port without lease" reclaim cannot race.
const poolLockKey int64 = 0x4341504750504f4c // "CAPGPPOL"

type scanner interface{ Scan(...any) error }

type dbq interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const (
	serviceCols = `id, org_id, project_id, name, protocol, container_port, default_access, project_port_id, database_id, created_at, updated_at`
	accessCols  = `id, service_id, kind, enabled, port`
	routeCols   = `id, service_id, host, transport, protocol, dest_host, dest_port, mode, enabled, rev`
	// routeViewCols: route columns (r.) + org, project and service name.
	routeViewCols = `r.id, r.service_id, r.host, r.transport, r.protocol, r.dest_host, r.dest_port, r.mode, r.enabled, r.rev, s.org_id, s.project_id, s.name`
	leaseCols     = `id, port, service_id, project_id, org_id, state, leased_at, released_at, last_conn_at`
	leaseViewCols = `port, service_id, project_id, org_id`
)

func scanService(row scanner, s *Service) error {
	var project *uuid.UUID
	if err := row.Scan(&s.ID, &s.OrgID, &project, &s.Name, &s.Protocol, &s.ContainerPort, &s.DefaultAccess,
		&s.ProjectPortID, &s.DatabaseID, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return err
	}
	s.ProjectID = uuid.Nil
	if project != nil {
		s.ProjectID = *project
	}
	return nil
}

func scanAccess(row scanner, a *Access) error {
	return row.Scan(&a.ID, &a.ServiceID, &a.Kind, &a.Enabled, &a.Port)
}

func scanRoute(row scanner, r *Route) error {
	return row.Scan(&r.ID, &r.ServiceID, &r.Host, &r.Transport, &r.Protocol, &r.DestHost, &r.DestPort, &r.Mode, &r.Enabled, &r.Rev)
}

func scanRouteView(row scanner, v *RouteView) error {
	var project *uuid.UUID
	if err := row.Scan(&v.ID, &v.ServiceID, &v.Host, &v.Transport, &v.Protocol, &v.DestHost, &v.DestPort, &v.Mode,
		&v.Enabled, &v.Rev, &v.OrgID, &project, &v.ServiceName); err != nil {
		return err
	}
	v.ProjectID = uuid.Nil
	if project != nil {
		v.ProjectID = *project
	}
	return nil
}

func scanLease(row scanner, l *Lease) error {
	var project *uuid.UUID
	if err := row.Scan(&l.ID, &l.Port, &l.ServiceID, &project, &l.OrgID, &l.State, &l.LeasedAt, &l.ReleasedAt, &l.LastConnAt); err != nil {
		return err
	}
	l.ProjectID = uuid.Nil
	if project != nil {
		l.ProjectID = *project
	}
	return nil
}

func scanLeaseView(row scanner, v *LeaseView) error {
	var project *uuid.UUID
	if err := row.Scan(&v.Port, &v.ServiceID, &project, &v.OrgID); err != nil {
		return err
	}
	v.ProjectID = uuid.Nil
	if project != nil {
		v.ProjectID = *project
	}
	return nil
}

// PgStore implements RouteStore on pgx.
type PgStore struct{ pool *pgxpool.Pool }

var _ RouteStore = (*PgStore)(nil)

func NewPgStore(pool *pgxpool.Pool) *PgStore { return &PgStore{pool: pool} }

func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// mapErr turns Postgres integrity errors into the typed errors of this package.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "23505":
			return fmt.Errorf("%w: %s", ErrConflict, pe.ConstraintName)
		case "23514", "22001":
			return fmt.Errorf("%w: %s", ErrInvalid, pe.ConstraintName)
		case "23503":
			return fmt.Errorf("%w: %s", ErrNotFound, pe.ConstraintName)
		}
	}
	return err
}

func (s *PgStore) inTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// bumpRev increments the global revision inside tx and returns the new value.
func bumpRev(ctx context.Context, q dbq) (int64, error) {
	var rev int64
	err := q.QueryRow(ctx, `UPDATE gateway_revision SET rev = rev + 1 WHERE id RETURNING rev`).Scan(&rev)
	if err != nil {
		return 0, fmt.Errorf("bumping gateway revision: %w", err)
	}
	return rev, nil
}

func lockPool(ctx context.Context, q dbq) error {
	_, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, poolLockKey)
	return err
}

// ---- resolution --------------------------------------------------------------

// gatewayOnly restricts to enabled routes whose service has an enabled gateway access.
const routeJoin = ` FROM gateway_routes r
	JOIN gateway_services s ON s.id = r.service_id
	JOIN gateway_accesses a ON a.service_id = s.id AND a.kind = 'gateway' AND a.enabled
	WHERE r.enabled`

func (s *PgStore) ResolveRoute(ctx context.Context, transport, host string) (*RouteView, error) {
	if transport == "" {
		transport = TransportTCP
	}
	var v RouteView
	err := scanRouteView(s.pool.QueryRow(ctx,
		`SELECT `+routeViewCols+routeJoin+` AND r.transport = $1 AND r.host = $2`,
		transport, strings.ToLower(host)), &v)
	if err != nil {
		return nil, mapErr(err)
	}
	return &v, nil
}

func (s *PgStore) ResolveService(ctx context.Context, projectID uuid.UUID, name, transport string) (*RouteView, error) {
	if transport == "" {
		transport = TransportTCP
	}
	var v RouteView
	err := scanRouteView(s.pool.QueryRow(ctx,
		`SELECT `+routeViewCols+routeJoin+` AND r.transport = $3
		   AND s.project_id IS NOT DISTINCT FROM $1 AND s.name = $2
		 ORDER BY r.host LIMIT 1`,
		nullUUID(projectID), strings.ToLower(name), transport), &v)
	if err != nil {
		return nil, mapErr(err)
	}
	return &v, nil
}

func (s *PgStore) Revision(ctx context.Context) (int64, error) {
	var rev int64
	if err := s.pool.QueryRow(ctx, `SELECT rev FROM gateway_revision WHERE id`).Scan(&rev); err != nil {
		return 0, mapErr(err)
	}
	return rev, nil
}

func (s *PgStore) Snapshot(ctx context.Context, since int64) (*Snapshot, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	snap := &Snapshot{Routes: []RouteView{}, Leases: []LeaseView{}}
	if err := tx.QueryRow(ctx, `SELECT rev FROM gateway_revision WHERE id`).Scan(&snap.Rev); err != nil {
		return nil, mapErr(err)
	}
	if since == snap.Rev {
		snap.Unchanged = true
		return snap, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+routeViewCols+routeJoin+` ORDER BY r.transport, r.host`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v RouteView
		if err := scanRouteView(rows, &v); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scanning route: %w", err)
		}
		snap.Routes = append(snap.Routes, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	lrows, err := tx.Query(ctx, `SELECT `+leaseViewCols+` FROM gateway_port_leases WHERE state = 'active' ORDER BY port`)
	if err != nil {
		return nil, err
	}
	for lrows.Next() {
		var v LeaseView
		if err := scanLeaseView(lrows, &v); err != nil {
			lrows.Close()
			return nil, fmt.Errorf("scanning lease: %w", err)
		}
		snap.Leases = append(snap.Leases, v)
	}
	lrows.Close()
	if err := lrows.Err(); err != nil {
		return nil, err
	}
	return snap, tx.Commit(ctx)
}

// ---- services, accesses, routes -----------------------------------------------

func (s *PgStore) CreateService(ctx context.Context, in NewService) (*Service, error) {
	if !ValidServiceName(in.Name) || in.OrgID == uuid.Nil {
		return nil, fmt.Errorf("%w: service name must be a DNS label", ErrInvalid)
	}
	if in.Protocol == "" {
		in.Protocol = "tcp"
	}
	if !ValidProtocol(in.Protocol) {
		return nil, fmt.Errorf("%w: protocol %q", ErrInvalid, in.Protocol)
	}
	if in.DefaultAccess == "" {
		in.DefaultAccess = AccessGateway
	}
	if in.DefaultAccess != AccessGateway && in.DefaultAccess != AccessDirectPort {
		return nil, fmt.Errorf("%w: default_access %q", ErrInvalid, in.DefaultAccess)
	}
	if in.DefaultAccess == AccessDirectPort && in.DirectPort == nil {
		return nil, fmt.Errorf("%w: direct_port default needs a direct port", ErrInvalid)
	}
	var out *Service
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var svc Service
		if err := scanService(tx.QueryRow(ctx,
			`INSERT INTO gateway_services (org_id, project_id, name, protocol, container_port, default_access, project_port_id, database_id)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+serviceCols,
			in.OrgID, nullUUID(in.ProjectID), in.Name, in.Protocol, in.ContainerPort, in.DefaultAccess, in.ProjectPortID, in.DatabaseID), &svc); err != nil {
			return mapErr(err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO gateway_accesses (service_id, kind, enabled) VALUES ($1,'gateway',true)`, svc.ID); err != nil {
			return mapErr(err)
		}
		if in.DirectPort != nil {
			if _, err := tx.Exec(ctx,
				`INSERT INTO gateway_accesses (service_id, kind, enabled, port) VALUES ($1,'direct_port',true,$2)`,
				svc.ID, *in.DirectPort); err != nil {
				return mapErr(err)
			}
		}
		if _, err := bumpRev(ctx, tx); err != nil {
			return err
		}
		acc, err := listAccesses(ctx, tx, svc.ID)
		if err != nil {
			return err
		}
		svc.Accesses = acc
		out = &svc
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func listAccesses(ctx context.Context, q dbq, serviceID uuid.UUID) ([]Access, error) {
	rows, err := q.Query(ctx, `SELECT `+accessCols+` FROM gateway_accesses WHERE service_id = $1 ORDER BY kind`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Access{}
	for rows.Next() {
		var a Access
		if err := scanAccess(rows, &a); err != nil {
			return nil, fmt.Errorf("scanning access: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PgStore) GetService(ctx context.Context, id uuid.UUID) (*Service, error) {
	var svc Service
	if err := scanService(s.pool.QueryRow(ctx, `SELECT `+serviceCols+` FROM gateway_services WHERE id = $1`, id), &svc); err != nil {
		return nil, mapErr(err)
	}
	acc, err := listAccesses(ctx, s.pool, svc.ID)
	if err != nil {
		return nil, err
	}
	svc.Accesses = acc
	return &svc, nil
}

func (s *PgStore) ListServices(ctx context.Context, projectID uuid.UUID) ([]*Service, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+serviceCols+` FROM gateway_services WHERE project_id IS NOT DISTINCT FROM $1 ORDER BY name`, nullUUID(projectID))
	if err != nil {
		return nil, err
	}
	out := []*Service{}
	for rows.Next() {
		var svc Service
		if err := scanService(rows, &svc); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scanning service: %w", err)
		}
		out = append(out, &svc)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, svc := range out {
		if svc.Accesses, err = listAccesses(ctx, s.pool, svc.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DeleteService removes the service (accesses and routes cascade) and releases its random-port lease
// into quarantine so the port is never handed to another tenant right away.
func (s *PgStore) DeleteService(ctx context.Context, id uuid.UUID, quarantine time.Duration) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockPool(ctx, tx); err != nil {
			return err
		}
		if err := releaseLeaseTx(ctx, tx, id, quarantine); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM gateway_services WHERE id = $1`, id)
		if err != nil {
			return mapErr(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = bumpRev(ctx, tx)
		return err
	})
}

func (s *PgStore) SetAccess(ctx context.Context, serviceID uuid.UUID, kind string, enabled bool, port *int) (*Access, error) {
	if kind != AccessGateway && kind != AccessDirectPort {
		return nil, fmt.Errorf("%w: access kind %q", ErrInvalid, kind)
	}
	if kind == AccessDirectPort && port == nil {
		// Allowed only if the access already has a port (enable/disable of an existing direct access).
		var has bool
		if err := s.pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM gateway_accesses WHERE service_id = $1 AND kind = 'direct_port' AND port IS NOT NULL)`,
			serviceID).Scan(&has); err != nil {
			return nil, err
		}
		if !has {
			return nil, fmt.Errorf("%w: direct_port needs a port", ErrInvalid)
		}
	}
	var out Access
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := scanAccess(tx.QueryRow(ctx,
			`INSERT INTO gateway_accesses (service_id, kind, enabled, port) VALUES ($1,$2,$3,$4)
			 ON CONFLICT (service_id, kind) DO UPDATE
			   SET enabled = EXCLUDED.enabled, port = COALESCE(EXCLUDED.port, gateway_accesses.port), updated_at = now()
			 RETURNING `+accessCols, serviceID, kind, enabled, port), &out); err != nil {
			return mapErr(err)
		}
		_, err := bumpRev(ctx, tx)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *PgStore) SetDefaultAccess(ctx context.Context, serviceID uuid.UUID, kind string) error {
	if kind != AccessGateway && kind != AccessDirectPort {
		return fmt.Errorf("%w: access kind %q", ErrInvalid, kind)
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM gateway_accesses WHERE service_id = $1 AND kind = $2)`, serviceID, kind).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: service has no %s access", ErrInvalid, kind)
		}
		tag, err := tx.Exec(ctx, `UPDATE gateway_services SET default_access = $2, updated_at = now() WHERE id = $1`, serviceID, kind)
		if err != nil {
			return mapErr(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = bumpRev(ctx, tx)
		return err
	})
}

func (s *PgStore) UpsertRoute(ctx context.Context, in NewRoute) (*Route, error) {
	in.Host = strings.ToLower(strings.TrimSpace(in.Host))
	if in.Host == "" || len(in.Host) > 253 || in.DestHost == "" || in.DestPort < 1 || in.DestPort > 65535 {
		return nil, fmt.Errorf("%w: route host/destination", ErrInvalid)
	}
	if in.Transport == "" {
		in.Transport = TransportTCP
	}
	if in.Mode == "" {
		in.Mode = ModePassthrough
	}
	var out Route
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var svcProto string
		if err := tx.QueryRow(ctx, `SELECT protocol FROM gateway_services WHERE id = $1`, in.ServiceID).Scan(&svcProto); err != nil {
			return mapErr(err)
		}
		if in.Protocol == "" {
			in.Protocol = svcProto
		}
		rev, err := bumpRev(ctx, tx)
		if err != nil {
			return err
		}
		err = scanRoute(tx.QueryRow(ctx,
			`INSERT INTO gateway_routes (service_id, host, transport, protocol, dest_host, dest_port, mode, enabled, rev)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			 ON CONFLICT (transport, host) DO UPDATE
			   SET protocol = EXCLUDED.protocol, dest_host = EXCLUDED.dest_host, dest_port = EXCLUDED.dest_port,
			       mode = EXCLUDED.mode, enabled = EXCLUDED.enabled, rev = EXCLUDED.rev, updated_at = now()
			   WHERE gateway_routes.service_id = EXCLUDED.service_id
			 RETURNING `+routeCols,
			in.ServiceID, in.Host, in.Transport, in.Protocol, in.DestHost, in.DestPort, in.Mode, in.Enabled, rev), &out)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: host belongs to another service", ErrConflict)
		}
		return mapErr(err)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *PgStore) DeleteRoute(ctx context.Context, id uuid.UUID) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM gateway_routes WHERE id = $1`, id)
		if err != nil {
			return mapErr(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = bumpRev(ctx, tx)
		return err
	})
}

// ---- random-port pool ---------------------------------------------------------

func (s *PgStore) SeedPortPool(ctx context.Context, lo, hi int) (int, error) {
	if lo < 1024 || hi > 65535 || lo > hi {
		return 0, fmt.Errorf("%w: pool range %d-%d", ErrInvalid, lo, hi)
	}
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO gateway_port_pool (port) SELECT g FROM generate_series($1::int, $2::int) g ON CONFLICT (port) DO NOTHING`, lo, hi)
	if err != nil {
		return 0, mapErr(err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *PgStore) GetQuotas(ctx context.Context, orgID uuid.UUID) (Quotas, error) {
	return getQuotas(ctx, s.pool, orgID)
}

func getQuotas(ctx context.Context, q dbq, orgID uuid.UUID) (Quotas, error) {
	out := Quotas{MaxRandomPorts: DefaultMaxRandomPortsOrg, MaxRandomPortsPerProject: DefaultMaxRandomPortsProject}
	err := q.QueryRow(ctx, `SELECT max_random_ports, max_random_ports_proj FROM gateway_org_quotas WHERE org_id = $1`, orgID).
		Scan(&out.MaxRandomPorts, &out.MaxRandomPortsPerProject)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	return out, nil
}

func (s *PgStore) SetQuotas(ctx context.Context, orgID uuid.UUID, q Quotas) error {
	if q.MaxRandomPorts < 0 || q.MaxRandomPortsPerProject < 0 {
		return fmt.Errorf("%w: negative quota", ErrInvalid)
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO gateway_org_quotas (org_id, max_random_ports, max_random_ports_proj) VALUES ($1,$2,$3)
		 ON CONFLICT (org_id) DO UPDATE SET max_random_ports = EXCLUDED.max_random_ports,
		   max_random_ports_proj = EXCLUDED.max_random_ports_proj, updated_at = now()`,
		orgID, q.MaxRandomPorts, q.MaxRandomPortsPerProject)
	return mapErr(err)
}

// LeasePort assigns a random free port to the service (idempotent: an active lease is returned as is).
// Free means state 'free' or a quarantine that has expired. Exhaustion -> ErrPortPoolExhausted.
func (s *PgStore) LeasePort(ctx context.Context, serviceID uuid.UUID) (*Lease, error) {
	var out Lease
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockPool(ctx, tx); err != nil {
			return err
		}
		var orgID uuid.UUID
		var project *uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT org_id, project_id FROM gateway_services WHERE id = $1`, serviceID).Scan(&orgID, &project); err != nil {
			return mapErr(err)
		}
		err := scanLease(tx.QueryRow(ctx, `SELECT `+leaseCols+` FROM gateway_port_leases WHERE service_id = $1 AND state = 'active'`, serviceID), &out)
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		q, err := getQuotas(ctx, tx, orgID)
		if err != nil {
			return err
		}
		var orgN, projN int
		if err := tx.QueryRow(ctx,
			`SELECT count(*), count(*) FILTER (WHERE project_id IS NOT DISTINCT FROM $2)
			   FROM gateway_port_leases WHERE org_id = $1 AND state = 'active'`, orgID, project).Scan(&orgN, &projN); err != nil {
			return err
		}
		if orgN >= q.MaxRandomPorts {
			return &QuotaError{Scope: "org", Limit: q.MaxRandomPorts}
		}
		if project != nil && projN >= q.MaxRandomPortsPerProject {
			return &QuotaError{Scope: "project", Limit: q.MaxRandomPortsPerProject}
		}
		var port int
		err = tx.QueryRow(ctx,
			`UPDATE gateway_port_pool SET state = 'leased', last_org_id = $1, quarantine_until = NULL
			  WHERE port = (SELECT port FROM gateway_port_pool
			                 WHERE state = 'free' OR (state = 'quarantine' AND quarantine_until <= now())
			                 ORDER BY random() LIMIT 1 FOR UPDATE SKIP LOCKED)
			  RETURNING port`, orgID).Scan(&port)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPortPoolExhausted
		}
		if err != nil {
			return err
		}
		if err := scanLease(tx.QueryRow(ctx,
			`INSERT INTO gateway_port_leases (port, service_id, project_id, org_id) VALUES ($1,$2,$3,$4) RETURNING `+leaseCols,
			port, serviceID, project, orgID), &out); err != nil {
			return mapErr(err)
		}
		_, err = bumpRev(ctx, tx)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// releaseLeaseTx releases the service's active lease into quarantine. The pool lock must be held.
func releaseLeaseTx(ctx context.Context, tx pgx.Tx, serviceID uuid.UUID, quarantine time.Duration) error {
	var port int
	err := tx.QueryRow(ctx,
		`UPDATE gateway_port_leases SET state = 'released', released_at = now()
		  WHERE service_id = $1 AND state = 'active' RETURNING port`, serviceID).Scan(&port)
	if err != nil {
		return mapErr(err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE gateway_port_pool SET state = 'quarantine', quarantine_until = now() + make_interval(secs => $2) WHERE port = $1`,
		port, quarantine.Seconds()); err != nil {
		return err
	}
	_, err = bumpRev(ctx, tx)
	return err
}

func (s *PgStore) ReleaseLease(ctx context.Context, serviceID uuid.UUID, quarantine time.Duration) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockPool(ctx, tx); err != nil {
			return err
		}
		return releaseLeaseTx(ctx, tx, serviceID, quarantine)
	})
}

func (s *PgStore) TouchLease(ctx context.Context, port int) error {
	_, err := s.pool.Exec(ctx, `UPDATE gateway_port_leases SET last_conn_at = now() WHERE port = $1 AND state = 'active'`, port)
	return err
}

// ReleaseIdle releases active leases with no connection since idleBefore (never connected: since leased_at).
func (s *PgStore) ReleaseIdle(ctx context.Context, idleBefore time.Time, quarantine time.Duration) (int, error) {
	n := 0
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockPool(ctx, tx); err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`SELECT service_id FROM gateway_port_leases WHERE state = 'active' AND COALESCE(last_conn_at, leased_at) < $1`, idleBefore)
		if err != nil {
			return err
		}
		var ids []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			if err := releaseLeaseTx(ctx, tx, id, quarantine); err != nil {
				return err
			}
		}
		n = len(ids)
		return nil
	})
	return n, err
}

func (s *PgStore) SweepPool(ctx context.Context) (int, error) {
	n := 0
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := lockPool(ctx, tx); err != nil {
			return err
		}
		t1, err := tx.Exec(ctx, `UPDATE gateway_port_pool SET state = 'free', quarantine_until = NULL
			WHERE state = 'quarantine' AND quarantine_until <= now()`)
		if err != nil {
			return err
		}
		// A leased port whose lease vanished (organisation deleted, manual cleanup) goes to a 24 h quarantine.
		t2, err := tx.Exec(ctx, `UPDATE gateway_port_pool p SET state = 'quarantine', quarantine_until = now() + interval '24 hours'
			WHERE p.state = 'leased' AND NOT EXISTS (SELECT 1 FROM gateway_port_leases l WHERE l.port = p.port AND l.state = 'active')`)
		if err != nil {
			return err
		}
		n = int(t1.RowsAffected())
		if t2.RowsAffected() > 0 {
			_, err = bumpRev(ctx, tx)
		}
		return err
	})
	return n, err
}

func (s *PgStore) PoolStats(ctx context.Context) (PoolStats, error) {
	var st PoolStats
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE state='free'), count(*) FILTER (WHERE state='leased'),
		        count(*) FILTER (WHERE state='quarantine'), count(*) FROM gateway_port_pool`).
		Scan(&st.Free, &st.Leased, &st.Quarantine, &st.Total)
	return st, err
}

// ---- organisation policy --------------------------------------------------------

func (s *PgStore) GetOrgPolicy(ctx context.Context, orgID uuid.UUID) (string, error) {
	var p string
	if err := s.pool.QueryRow(ctx, `SELECT gateway_policy FROM organizations WHERE id = $1`, orgID).Scan(&p); err != nil {
		return "", mapErr(err)
	}
	return p, nil
}

func (s *PgStore) SetOrgPolicy(ctx context.Context, orgID uuid.UUID, policy string) error {
	if policy != PolicyWarn && policy != PolicyError {
		return fmt.Errorf("%w: gateway_policy %q", ErrInvalid, policy)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE organizations SET gateway_policy = $2 WHERE id = $1`, orgID, policy)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
