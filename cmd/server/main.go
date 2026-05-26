package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server"
	"github.com/kynto/capsule/backend/internal/service"
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

	userRepo := repository.NewUserRepository(pool)
	authSvc := service.NewAuthService(userRepo, cfg.SecretKey, cfg.JWTAccessTTL, cfg.JWTRefreshTTL, logger)

	srv := server.New(cfg, logger, version, authSvc)
	if err := srv.Run(); err != nil {
		logger.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}
