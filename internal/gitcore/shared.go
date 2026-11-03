package gitcore

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// MountDeps is what a package's Mount<Pkg>(r, deps) receives from router.go.
type MountDeps struct {
	Core Core
}

var (
	sharedMu sync.RWMutex
	shared   Core
)

// SetShared publishes the process-wide Core (called once, by Wire).
func SetShared(c Core) {
	sharedMu.Lock()
	shared = c
	sharedMu.Unlock()
}

// Shared returns the Core published by Wire. If Wire was never called it builds one from the
// environment WITHOUT cache, so mounts never see nil. Always non-nil; check Enabled().
func Shared() Core {
	sharedMu.RLock()
	c := shared
	sharedMu.RUnlock()
	if c != nil {
		return c
	}
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if shared == nil {
		shared = New(ConfigFromEnv(), nil, nil)
	}
	return shared
}

// Mounts is the convenience value for Mount<Pkg>(r, gitcore.Mounts()).
func Mounts() MountDeps { return MountDeps{Core: Shared()} }

// Wire builds the Core from CAPSULE_GIT_* with the Redis-backed cache (nil = no cache),
// publishes it with SetShared and returns it. It never fails: with the integration off
// every call answers GIT_NOT_READY.
func Wire(ctx context.Context, logger *slog.Logger, cache Cache) *Service {
	cfg := ConfigFromEnv()
	var lg Logger
	if logger != nil {
		lg = slogAdapter{logger}
	}
	svc := New(cfg, cache, lg)
	SetShared(svc)
	if logger != nil {
		logger.Info("gitcore ready", "enabled", cfg.Enabled(), "cache", cache != nil)
		if cfg.Enabled() {
			go func() {
				pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				if err := svc.Ping(pctx); err != nil {
					logger.Warn("gitcore: Forgejo did not answer the first ping", "code", errCode(err))
				}
			}()
		}
	}
	return svc
}

type slogAdapter struct{ l *slog.Logger }

func (a slogAdapter) Warn(msg string, args ...any) { a.l.Warn(msg, args...) }

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
