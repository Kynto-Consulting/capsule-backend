package main

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/backup"
	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server/handlers"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

// wireBackups builds the data-backup service, registers the "backups" capability and starts
// the scheduler. The service always exists (GET answers even when disabled); it only runs and
// accepts writes when CAPSULE_BACKUPS_ENABLED is on and an S3 client + bucket are available.
func wireBackups(ctx context.Context, cfg *config.Config, logger *slog.Logger, pool *pgxpool.Pool,
	aws *awsclient.Clients, projects domain.ProjectRepository, dbs domain.DatabaseRepository) *backup.Service {
	bc := config.LoadBackups()
	var store backup.Store
	if bc.Enabled && aws != nil && aws.S3 != nil {
		store = backup.NewS3Store(aws.S3, bc.Bucket)
	} else if bc.Enabled {
		logger.Warn("backups disabled: AWS S3 client unavailable")
	}
	svc := backup.New(backup.Config{
		Enabled: bc.Enabled && store != nil, Bucket: bc.Bucket, DefaultSchedule: bc.DefaultSchedule, DefaultOn: bc.DefaultOn,
		DefaultRetentionDays: bc.DefaultRetentionDays, BucketRetentionDays: bc.BucketRetentionDays,
		HelperImage: bc.HelperImage, PlatformDir: bc.PlatformDir, DockerConfigDir: bc.DockerConfigDir, RunTimeout: bc.RunTimeout,
	}, repository.NewBackupRepository(pool), store, backup.CLIDocker{}, projects, dbs, cfg.SecretKey, logger)
	handlers.RegisterCapability("backups", svc.Capability)
	if svc.Enabled() {
		logger.Info("data backups enabled", "bucket", bc.Bucket, "default_schedule", bc.DefaultSchedule)
		go svc.Run(ctx)
	} else {
		logger.Info("data backups disabled (CAPSULE_BACKUPS_ENABLED / CAPSULE_BACKUPS_BUCKET)")
	}
	return svc
}
