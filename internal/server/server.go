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
)

type Server struct {
	http    *http.Server
	logger  *slog.Logger
	version string
	cancel  context.CancelFunc
	s3      *http.Server // dedicated object-store listener (nil when disabled)
}

func New(cfg *config.Config, logger *slog.Logger, version string, deps Deps) *Server {
	router := newRouter(cfg, logger, version, deps)

	ctx, cancel := context.WithCancel(context.Background())

	// Start mock builder ONLY when explicitly requested (local dev / demo).
	// Never auto-activate based on AWS client state — real deploy worker handles
	// all production builds.
	if os.Getenv("CAPSULE_MOCK_BUILDER") == "true" {
		StartMockBuilder(ctx, deps.DeploymentRepo, logger)
	}

	var s3 *http.Server
	if deps.Objstore != nil && deps.Objstore.Addr != "" {
		s3 = s3Listener(deps.Objstore, logger)
	}
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
		cancel:  cancel,
		s3:      s3,
	}
}

// Handler returns the HTTP handler (router) configured for the server.
func (s *Server) Handler() http.Handler {
	return s.http.Handler
}

func (s *Server) Run() error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	if s.s3 != nil {
		go runS3(s.s3, s.logger, errCh)
	}
	go func() {
		s.logger.Info("server started", "addr", s.http.Addr, "version", s.version)
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		s.cancel()
		return fmt.Errorf("server error: %w", err)
	case sig := <-quit:
		s.logger.Info("shutting down", "signal", sig)
	}

	s.cancel() // stop background workers

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	shutdownS3(s.s3, ctx)
	if err := s.http.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	s.logger.Info("server stopped")
	return nil
}
