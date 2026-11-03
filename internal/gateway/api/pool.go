package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/kynto/capsule/backend/internal/gateway/store"
)

// SeedPool inserts the configured range into the pool (idempotent: only missing ports are added; leased and
// quarantined ports are untouched). It opens nothing in AWS: the single security-group rule for the range is
// managed by Terraform (deploy/terraform/gateway.tf). Returns how many ports were added.
func SeedPool(ctx context.Context, st store.RouteStore, cfg Config) (int, error) {
	cfg = cfg.WithDefaults()
	if cfg.PoolOff || cfg.PoolHi == 0 {
		return 0, nil
	}
	return st.SeedPortPool(ctx, cfg.PoolLo, cfg.PoolHi)
}

// RunSweeper returns expired quarantine ports to the pool and releases leases idle for IdleRelease, every
// SweepInterval, until ctx is cancelled. It runs once at start. Errors are logged and never stop the loop.
func RunSweeper(ctx context.Context, st store.RouteStore, cfg Config, logger *slog.Logger, wake func()) {
	cfg = cfg.WithDefaults()
	if logger == nil {
		logger = slog.Default()
	}
	once := func() {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		freed, err := st.SweepPool(sctx)
		if err != nil {
			logger.Warn("gateway: pool sweep failed", "error", err.Error())
		}
		released, err2 := st.ReleaseIdle(sctx, time.Now().Add(-cfg.IdleRelease), cfg.Quarantine)
		if err2 != nil {
			logger.Warn("gateway: idle lease release failed", "error", err2.Error())
		}
		if released > 0 && wake != nil {
			wake()
		}
		if freed > 0 || released > 0 {
			logger.Info("gateway: pool swept", "returned_to_pool", freed, "idle_released", released)
		}
	}
	once()
	t := time.NewTicker(cfg.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			once()
		}
	}
}
