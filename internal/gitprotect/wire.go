package gitprotect

import (
	"context"
	"log/slog"
	"sync"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

var (
	sharedMu sync.RWMutex
	shared   *Service
)

// Shared returns the Service published by WireGitProtect (nil before wiring).
func Shared() *Service {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return shared
}

// SetShared publishes the process-wide Service (tests and WireGitProtect).
func SetShared(s *Service) {
	sharedMu.Lock()
	shared = s
	sharedMu.Unlock()
}

// WireGitProtect builds the Service on the shared gitcore Core, publishes it and starts the
// drift reconciler (cfg from GITPROTECT_*). Called from the git-capsule:wiring block of
// cmd/server/main.go with the Postgres-backed store.
func WireGitProtect(ctx context.Context, logger *slog.Logger, store Store) *Service {
	svc := New(store, gitcore.Shared(), ConfigFromEnv(), logger)
	SetShared(svc)
	if logger != nil {
		logger.Info("gitprotect ready", "reconcile_every", svc.cfg.ReconcileEvery.String(), "prune_unmanaged", svc.cfg.PruneUnmanaged, "tag_patterns", svc.cfg.TagPatterns)
	}
	go svc.RunLoop(ctx)
	return svc
}
