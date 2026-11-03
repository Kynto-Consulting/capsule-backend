package security

import (
	"context"
	"log/slog"
	"sync"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

var (
	sharedMu sync.RWMutex
	shared   *Service
)

// Shared returns the Service published by WireSecurity (nil before wiring).
func Shared() *Service {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return shared
}

// SetShared publishes the process-wide Service (tests and WireSecurity).
func SetShared(s *Service) {
	sharedMu.Lock()
	shared = s
	sharedMu.Unlock()
}

// WireSecurity builds the Service on the shared gitcore Core, subscribes it to the A5 event bus
// (pull request events create the capsule/security check), publishes it and starts the upload
// worker and the sweeps. Called from the git-capsule:wiring block of cmd/server/main.go with the
// Postgres-backed store; secretKey (the platform key) keys secret fingerprints unless
// SECURITY_FINGERPRINT_KEY is set.
func WireSecurity(ctx context.Context, logger *slog.Logger, store Store, secretKey string) *Service {
	cfg := ConfigFromEnv()
	if cfg.FingerprintKey == "" {
		cfg.FingerprintKey = "security-fingerprint:" + secretKey
	}
	svc := New(store, gitcore.Shared(), cfg, logger)
	if r := NewExecRunner(cfg); r != nil {
		svc.SetRunner(r)
	}
	if bus, ok := gitevents.Shared().(interface{ Subscribe(gitevents.Subscriber) }); ok {
		bus.Subscribe(svc.Subscriber())
	} else if logger != nil {
		logger.Warn("security: the event bus is not wired yet; pull request checks are created on SARIF upload only")
	}
	SetShared(svc)
	if logger != nil {
		logger.Info("security ready", "check_timeout", cfg.CheckTimeout.String(), "renovate_runs", svc.runner != nil)
	}
	go svc.RunLoop(ctx)
	return svc
}
