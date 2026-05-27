package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server"
	"github.com/kynto/capsule/backend/internal/service"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	if cfg.LogLevel == "debug" {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}

	logger.Info("starting capsule server",
		"version", version,
		"commit", commit,
		"build_date", buildDate,
		"env", cfg.Env,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := repository.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	userRepo       := repository.NewUserRepository(pool)
	orgRepo        := repository.NewOrgRepository(pool)
	projRepo       := repository.NewProjectRepository(pool)
	envVarRepo     := repository.NewEnvVarRepository(pool, cfg.SecretKey)
	deploymentRepo := repository.NewDeploymentRepository(pool)
	dbRepo         := repository.NewDatabaseRepository(pool)
	domainRepo     := repository.NewDomainRepository(pool)
	apiTokenRepo   := repository.NewAPITokenRepository(pool)
	settingsRepo   := repository.NewSettingsRepository(pool)
	workerRepo     := repository.NewWorkerRepository(pool)
	cronJobRepo    := repository.NewCronJobRepository(pool)
	execLogRepo    := repository.NewExecutionLogRepository(pool)
	authSvc        := service.NewAuthService(userRepo, settingsRepo, cfg.SecretKey, cfg.JWTAccessTTL, cfg.JWTRefreshTTL, logger)

	var cacheStore domain.CacheStore
	redisCache, err := repository.NewRedisCache(cfg.RedisURL)
	if err != nil {
		logger.Warn("redis unavailable; cache features disabled", "error", err)
	} else {
		cacheStore = redisCache
	}

	awsCtx, awsCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer awsCancel()
	awsClients, err := awsclient.New(awsCtx, cfg.AWSRegion,
		os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), cfg.AWSAccountID)
	if err != nil {
		logger.Warn("AWS clients unavailable", "error", err)
		awsClients = nil
	}

	worker := service.NewDeployWorker(deploymentRepo, pool, awsClients, cfg.ArtifactsBucket, logger)
	go worker.Run(context.Background())

	srv := server.New(cfg, logger, version, server.Deps{
		AuthSvc:            authSvc,
		OrgRepo:            orgRepo,
		ProjRepo:           projRepo,
		EnvVarRepo:         envVarRepo,
		DeploymentRepo:     deploymentRepo,
		CacheStore:         cacheStore,
		DatabaseRepo:       dbRepo,
		DomainRepo:         domainRepo,
		APITokenRepo:       apiTokenRepo,
		AWSClients:         awsClients,
		ALBDNSName:         cfg.ALBDNSName,
		DBSubnetGroup:      cfg.DBSubnetGroup,
		RDSSecurityGroupID: cfg.RDSSecurityGroupID,
		SecretKey:          cfg.SecretKey,
		ArtifactsBucket:    cfg.ArtifactsBucket,
		WorkerRepo:         workerRepo,
		CronJobRepo:        cronJobRepo,
		ExecLogRepo:        execLogRepo,
	})
	if err := srv.Run(); err != nil {
		logger.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}
