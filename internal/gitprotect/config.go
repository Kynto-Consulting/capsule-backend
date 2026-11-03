package gitprotect

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is read from the package's own environment (rule 0.2: not in config.go).
//
//	GITPROTECT_RECONCILE_MINUTES   period of the drift reconciler (default 10, 0 = off)
//	GITPROTECT_PRUNE_UNMANAGED     "true" removes Forgejo rules Capsule does not know (default false:
//	                               they are only audited, so a reconciliation never lowers protection)
//	GITPROTECT_TAG_PATTERNS        comma separated globs of protected tags (default "v*", "-" = none)
type Config struct {
	ReconcileEvery time.Duration
	PruneUnmanaged bool
	TagPatterns    []string
}

// DefaultConfig is what ConfigFromEnv returns with an empty environment.
func DefaultConfig() Config {
	return Config{ReconcileEvery: 10 * time.Minute, TagPatterns: []string{"v*"}}
}

// ConfigFromEnv reads the GITPROTECT_* variables.
func ConfigFromEnv() Config {
	c := DefaultConfig()
	if v := strings.TrimSpace(os.Getenv("GITPROTECT_RECONCILE_MINUTES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			c.ReconcileEvery = time.Duration(n) * time.Minute
		}
	}
	c.PruneUnmanaged = strings.EqualFold(strings.TrimSpace(os.Getenv("GITPROTECT_PRUNE_UNMANAGED")), "true")
	if v := strings.TrimSpace(os.Getenv("GITPROTECT_TAG_PATTERNS")); v != "" {
		c.TagPatterns = nil
		if v != "-" {
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					c.TagPatterns = append(c.TagPatterns, p)
				}
			}
		}
	}
	return c
}
