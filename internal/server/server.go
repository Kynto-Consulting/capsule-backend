package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/domain"
)

type Server struct {
	http    *http.Server
	logger  *slog.Logger
	version string
}

func New(cfg *config.Config, logger *slog.Logger, version string, authSvc domain.AuthService) *Server {
	router := newRouter(cfg, logger, version, authSvc)
	return &Server{
		http: &http.Server{
			Addr:         fmt.Sprintf(":%d", cfg.Port),
			Handler:      router,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		logger:  logger,
		version: version,
	}
}

func (s *Server) Run() error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("server started", "addr", s.http.Addr, "version", s.version)
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case sig := <-quit:
		s.logger.Info("shutting down", "signal", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.http.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	s.logger.Info("server stopped")
	return nil
}
