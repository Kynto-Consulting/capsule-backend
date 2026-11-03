package recovery

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/kynto/capsule/backend/internal/backup"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

// Store is what the repository implements: the catalog source plus the run journal.
type Store interface {
	Source
	Journal
}

var (
	sharedMu  sync.RWMutex
	sharedSvc *Service
)

// Shared returns the service built by WireRecovery (nil when recovery is disabled).
func Shared() *Service {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return sharedSvc
}

// WireRecovery builds the service from CAPSULE_RECOVERY_* and publishes it (Shared). It does
// nothing, and logs why, unless CAPSULE_RECOVERY_ENABLED=true, the backups bucket and the S3
// client exist. Called from the git-capsule:wiring block of cmd/server/main.go.
func WireRecovery(ctx context.Context, logger *slog.Logger, st Store, secret string, aws *awsclient.Clients) {
	cfg := ConfigFromEnv()
	bucket := strings.TrimSpace(os.Getenv("CAPSULE_BACKUPS_BUCKET"))
	if !cfg.Enabled || bucket == "" || aws == nil || aws.S3 == nil || st == nil {
		logger.Info("recovery disabled (CAPSULE_RECOVERY_ENABLED / CAPSULE_BACKUPS_BUCKET / S3 client)")
		return
	}
	data := backup.NewS3Store(aws.S3, bucket)
	var forgejo backup.Store = data
	if cfg.ForgejoBucket != "" && cfg.ForgejoBucket != bucket {
		forgejo = backup.NewS3Store(aws.S3, cfg.ForgejoBucket)
	}
	if o, ok := st.(interface {
		FailOrphans(context.Context) (int, error)
	}); ok {
		if n, err := o.FailOrphans(ctx); err == nil && n > 0 {
			logger.Warn("recovery runs interrupted by a restart were marked failed", "count", n)
		}
	}
	svc := New(cfg, st, &Verifier{Store: data, Secret: secret}, forgejo, st, logger)
	svc.SetContext(ctx)
	sharedMu.Lock()
	sharedSvc = svc
	sharedMu.Unlock()
	logger.Info("recovery enabled", "workdir", cfg.WorkDir, "scripts", cfg.ScriptsOn)
}
