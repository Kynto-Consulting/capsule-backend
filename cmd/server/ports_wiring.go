package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server/handlers"
	"github.com/kynto/capsule/backend/internal/service"
)

// wirePorts builds the extra-TCP-ports service, makes new deployments publish
// the stored ports and starts the firewall sweep. It returns a service that
// answers 501 when the firewall (APP_SECURITY_GROUP_ID) is not configured.
func wirePorts(cfg *config.Config, logger *slog.Logger, pool *pgxpool.Pool, worker *service.DeployWorker, fw service.PortsFirewall) *service.PortsService {
	from, to, err := service.ParsePortRange(cfg.PortRange)
	if err != nil {
		logger.Warn("CAPSULE_PORT_RANGE invalid, using default", "error", err)
		from, to, _ = service.ParsePortRange("")
	}
	avoid := [][2]int{{cfg.Port, cfg.Port}}
	if dbFrom, dbTo := handlers.DBPortRange(); dbTo > 0 {
		avoid = append(avoid, [2]int{dbFrom, dbTo})
	}
	repo := repository.NewProjectPortRepository(pool)
	svc := service.NewPortsService(repo, fw, worker.PortsRestarter(), service.PortsConfig{
		From: from, To: to, Host: cfg.TCPHost,
		Reserved:  []int{cfg.Port},
		AvoidHost: avoid,
		InUse:     service.PortFree,
	}, logger)
	worker.SetExtraPorts(svc.ExtraPorts)
	handlers.RegisterCapability("ports", func() any {
		return map[string]any{"enabled": svc.Enabled(), "range": svc.Range(), "host": svc.Host()}
	})
	if !svc.Enabled() {
		logger.Info("project TCP ports API disabled (APP_SECURITY_GROUP_ID not set)")
		return svc
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := svc.Sweep(ctx); err != nil {
			logger.Warn("project port rules startup sweep failed", "error", err)
		}
	}()
	return svc
}
