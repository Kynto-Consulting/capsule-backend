package gitaudit

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Retention limits (SPEC 5.9: retention >= 400 days).
const (
	MinRetentionDays     = 400
	DefaultRetentionDays = 730
)

// Config of the audit package.
type Config struct {
	// RetentionDays is how long audit rows are kept (CAPSULE_AUDIT_RETENTION_DAYS). Values below
	// MinRetentionDays are raised to it: audit can be kept longer, never shorter.
	RetentionDays int
}

// ConfigFromEnv reads CAPSULE_AUDIT_RETENTION_DAYS.
func ConfigFromEnv() Config {
	c := Config{RetentionDays: DefaultRetentionDays}
	if v := strings.TrimSpace(os.Getenv("CAPSULE_AUDIT_RETENTION_DAYS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.RetentionDays = n
		}
	}
	return c.Normalized()
}

// Normalized raises RetentionDays to the minimum.
func (c Config) Normalized() Config {
	if c.RetentionDays < MinRetentionDays {
		c.RetentionDays = MinRetentionDays
	}
	return c
}

// Retention is the only code that ever deletes audit rows, and only past the retention period.
type Retention struct {
	R   Retainer
	Cfg Config
	Log *slog.Logger
	Now func() time.Time
}

// Cutoff is the instant before which rows may be purged.
func (r *Retention) Cutoff() time.Time {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	return now().UTC().Add(-time.Duration(r.Cfg.Normalized().RetentionDays) * 24 * time.Hour)
}

// Purge removes the rows past retention and returns how many.
func (r *Retention) Purge(ctx context.Context) (int64, error) {
	return r.R.PurgeBefore(ctx, r.Cutoff())
}

// Run purges once a day until ctx is done.
func (r *Retention) Run(ctx context.Context) {
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
			log.Warn("audit retention failed", "error", err.Error())
		} else if n > 0 {
			log.Info("audit retention purged rows", "rows", n)
		}
	}
}
