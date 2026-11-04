package store

import "context"

// PurgeOrphans removes the services whose source (project, database or published port) no longer exists or is
// soft-deleted, with their routes, accesses and leases (a leased port goes to a 24 h quarantine) and bumps the route
// revision. Triggers (migration 000065) do this at delete time; this is the periodic safety net. It returns how many
// services were removed.
func (s *PgStore) PurgeOrphans(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT gateway_purge_orphans()`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
