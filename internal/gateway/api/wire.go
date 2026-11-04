package api

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

var (
	sharedMu sync.RWMutex
	shared   *Service
)

// Shared returns the Service published by Wire (nil before Wire runs or when it failed).
func Shared() *Service {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return shared
}

// SetShared publishes s (tests and Wire).
func SetShared(s *Service) {
	sharedMu.Lock()
	shared = s
	sharedMu.Unlock()
}

// Wire builds the control plane, seeds the random-port pool, starts the lease/quarantine sweeper (cancelled with ctx)
// and publishes the Service for MountInternal / MountAPI. A configuration error disables the feature and is logged: the
// rest of Capsule keeps working. It never opens anything in AWS.
func Wire(ctx context.Context, logger *slog.Logger, d Deps) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	d.Logger = logger
	svc, err := New(d)
	if err != nil {
		logger.Error("gateway control plane disabled", "error", err.Error())
		return nil
	}
	cfg := svc.Config()
	if cfg.Secret == "" {
		logger.Info("gateway internal endpoints closed (CAPSULE_GW_SECRET not set)")
	}
	if svc.Signer() == nil {
		logger.Info("gateway connection tokens disabled (" + EnvSigningKey + " not set)")
	}
	if !cfg.PoolOff {
		sctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		n, err := SeedPool(sctx, d.Store, cfg)
		cancel()
		if err != nil {
			logger.Warn("gateway port pool seeding failed", "error", err.Error())
		} else {
			logger.Info("gateway port pool ready", "range", poolRange(cfg), "added", n)
		}
	} else {
		logger.Info("gateway random-port pool disabled")
	}
	// Sweeper always runs: besides the pool it removes services whose project/database/port is gone.
	go RunSweeper(ctx, d.Store, cfg, logger, svc.notify)
	SetShared(svc)
	return svc
}

func poolRange(c Config) string {
	return itoa(c.PoolLo) + "-" + itoa(c.PoolHi)
}

// MountInternal registers the data-plane endpoints on the root router (no-op when Wire did not publish a Service).
func MountInternal(root chi.Router) {
	if s := Shared(); s != nil {
		s.MountInternal(root)
	}
}

// MountAPI registers the user API inside the authenticated group (no-op when Wire did not publish a Service).
func MountAPI(r chi.Router) {
	if s := Shared(); s != nil {
		s.MountAPI(r)
	}
}
