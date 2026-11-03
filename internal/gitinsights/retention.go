package gitinsights

import (
	"context"
	"log/slog"
	"time"
)

// ActivityRetention removes git_activity rows older than the configured period (daily).
type ActivityRetention struct {
	Store Store
	Cfg   Config
	Log   *slog.Logger
}

// Purge removes the rows past retention.
func (r *ActivityRetention) Purge(ctx context.Context) (int64, error) {
	days := r.Cfg.ActivityRetentionDays
	if days < 90 {
		days = 90
	}
	return r.Store.PurgeBefore(ctx, time.Now().UTC().Add(-time.Duration(days)*24*time.Hour))
}

// Run purges once a day until ctx is done.
func (r *ActivityRetention) Run(ctx context.Context) {
	log := r.Log
	if log == nil {
		log = slog.Default()
	}
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if n, err := r.Purge(ctx); err != nil {
			log.Warn("activity retention failed", "error", err.Error())
		} else if n > 0 {
			log.Info("activity retention purged rows", "rows", n)
		}
	}
}
