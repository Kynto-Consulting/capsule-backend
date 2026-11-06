package vpn

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStore is the PostgreSQL Store.
type PGStore struct{ Pool *pgxpool.Pool }

const tunnelCols = `id, org_id, project_id, name, provider, host, cidrs, cert_pin, config, secret_enc, enabled, max_conns,
	bandwidth_bps, status, last_handshake_at, last_error, created_by, created_at, updated_at`

func scanTunnel(row pgx.Row) (*Tunnel, error) {
	var t Tunnel
	var cfg []byte
	err := row.Scan(&t.ID, &t.OrgID, &t.ProjectID, &t.Name, &t.Provider, &t.Host, &t.CIDRs, &t.CertPin, &cfg, &t.SecretEnc, &t.Enabled,
		&t.MaxConns, &t.BandwidthBps, &t.Status, &t.LastHandshakeAt, &t.LastError, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.Config = cfg
	t.HasSecret = len(t.SecretEnc) > 0
	return &t, nil
}

func (s *PGStore) Create(ctx context.Context, t *Tunnel) error {
	var cfg any
	if len(t.Config) > 0 {
		cfg = []byte(t.Config)
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO vpn_tunnels (id, org_id, project_id, name, provider, host, cidrs, cert_pin, config, secret_enc,
		enabled, max_conns, bandwidth_bps, status, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		t.ID, t.OrgID, t.ProjectID, t.Name, t.Provider, t.Host, t.CIDRs, t.CertPin, cfg, t.SecretEnc, t.Enabled, t.MaxConns, t.BandwidthBps, t.Status, t.CreatedBy)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return ErrConflict
	}
	return err
}

func (s *PGStore) GetByName(ctx context.Context, p uuid.UUID, name string) (*Tunnel, error) {
	return scanTunnel(s.Pool.QueryRow(ctx, `SELECT `+tunnelCols+` FROM vpn_tunnels WHERE project_id=$1 AND name=$2`, p, name))
}

func (s *PGStore) GetByID(ctx context.Context, id uuid.UUID) (*Tunnel, error) {
	return scanTunnel(s.Pool.QueryRow(ctx, `SELECT `+tunnelCols+` FROM vpn_tunnels WHERE id=$1`, id))
}

func (s *PGStore) List(ctx context.Context, p uuid.UUID) ([]*Tunnel, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+tunnelCols+` FROM vpn_tunnels WHERE project_id=$1 ORDER BY created_at`, p)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Tunnel
	for rows.Next() {
		t, err := scanTunnel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *PGStore) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM vpn_tunnels WHERE id=$1`, id)
	return err
}

func (s *PGStore) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	ct, err := s.Pool.Exec(ctx, `UPDATE vpn_tunnels SET enabled=$2, updated_at=now() WHERE id=$1`, id, enabled)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *PGStore) SetStatus(ctx context.Context, id uuid.UUID, status string, hs *time.Time, lastErr string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE vpn_tunnels SET status=$2, last_error=$4, last_handshake_at=COALESCE($3, last_handshake_at) WHERE id=$1`, id, status, hs, lastErr)
	return err
}

func (s *PGStore) AddEvent(ctx context.Context, e Event) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO vpn_events (tunnel_id, project_id, at, kind, message, actor) VALUES ($1,$2,$3,$4,$5,$6)`,
		e.TunnelID, e.ProjectID, e.At, e.Kind, e.Message, e.Actor)
	return err
}

func (s *PGStore) Events(ctx context.Context, id uuid.UUID, limit int) ([]Event, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, tunnel_id, project_id, at, kind, message, actor FROM vpn_events WHERE tunnel_id=$1 ORDER BY id DESC LIMIT $2`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TunnelID, &e.ProjectID, &e.At, &e.Kind, &e.Message, &e.Actor); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
