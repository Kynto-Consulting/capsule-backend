package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	goredis "github.com/redis/go-redis/v9"
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

	if dsn := os.Getenv("SENTRY_DSN"); dsn != "" {
		if err := sentry.Init(sentry.ClientOptions{
			Dsn:              dsn,
			Release:          version,
			Environment:      cfg.Env,
			TracesSampleRate: 0.1,
		}); err != nil {
			logger.Warn("sentry init failed", "error", err)
		} else {
			logger.Info("sentry initialized")
			defer sentry.Flush(2 * time.Second)
		}
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
	emailLogRepo   := repository.NewEmailLogRepository(pool)
	authSvc        := service.NewAuthService(userRepo, settingsRepo, cfg.SecretKey, cfg.JWTAccessTTL, cfg.JWTRefreshTTL, logger)

	var cacheStore domain.CacheStore
	var redisRawClient *goredis.Client
	redisCache, err := repository.NewRedisCache(cfg.RedisURL)
	if err != nil {
		logger.Warn("redis unavailable; cache + distributed rate limiting disabled", "error", err)
	} else {
		cacheStore = redisCache
		redisRawClient = redisCache.Client()
	}

	awsCtx, awsCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer awsCancel()
	awsClients, err := awsclient.New(awsCtx, cfg.AWSRegion,
		os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), cfg.AWSAccountID)
	if err != nil {
		logger.Warn("AWS clients unavailable", "error", err)
		awsClients = nil
	}

	// Worker runs with a cancellable context so graceful shutdown waits for
	// in-flight deployments to finish before the process exits.
	workerCtx, workerCancel := context.WithCancel(context.Background())
	fargateConfig := service.FargateConfig{
		Cluster:          cfg.ECSCluster,
		Subnets:          splitComma(cfg.ECSSubnets),
		SecurityGroup:    cfg.ECSSecurityGroup,
		ExecutionRoleARN: cfg.ECSExecutionRoleARN,
		ALBListenerARN:   cfg.ALBListenerARN,
		VpcID:            cfg.VpcID,
		AppsDomain:       cfg.AppsDomain,
		ECRRegistry:      cfg.ECRRegistry,
	}
	deployWorker := service.NewDeployWorker(deploymentRepo, pool, awsClients, cfg.ArtifactsBucket, fargateConfig, logger)
	workerDone := make(chan struct{})
	go func() {
		deployWorker.Run(workerCtx)
		close(workerDone)
	}()

	// Catch OS signals so we cancel the worker before the process exits.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("shutdown signal received, stopping worker")
		workerCancel()
		select {
		case <-workerDone:
		case <-time.After(30 * time.Second):
			logger.Warn("worker did not finish in time, forcing shutdown")
		}
	}()

	srv := server.New(cfg, logger, version, server.Deps{
		AuthSvc:            authSvc,
		OrgRepo:            orgRepo,
		UserRepo:           userRepo,
		ProjRepo:           projRepo,
		EnvVarRepo:         envVarRepo,
		DeploymentRepo:     deploymentRepo,
		CacheStore:         cacheStore,
		RedisClient:        redisRawClient,
		DatabaseRepo:       dbRepo,
		DomainRepo:         domainRepo,
		APITokenRepo:       apiTokenRepo,
		AWSClients:         awsClients,
		ALBDNSName:         cfg.ALBDNSName,
		DBSubnetGroup:      cfg.DBSubnetGroup,
		RDSSecurityGroupID: cfg.RDSSecurityGroupID,
		PublicHost:         cfg.PublicHost,
		SecretKey:          cfg.SecretKey,
		ArtifactsBucket:    cfg.ArtifactsBucket,
		WorkerRepo:         workerRepo,
		CronJobRepo:        cronJobRepo,
		ExecLogRepo:        execLogRepo,
		EmailLogRepo:       emailLogRepo,
	})
	if err := srv.Run(); err != nil {
		logger.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}
