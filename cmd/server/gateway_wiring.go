package main

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	gwapi "github.com/kynto/capsule/backend/internal/gateway/api"
	gwstore "github.com/kynto/capsule/backend/internal/gateway/store"
	"github.com/kynto/capsule/backend/internal/repository"
)

// wireGateway is the gateway control plane (docs/gateway/PLAN.md 5): internal routes/authorize for the data plane and the
// user API. Configuration comes from CAPSULE_GW_*; the internal endpoints stay closed while CAPSULE_GW_SECRET is empty.
// It seeds the random-port pool in the database (CAPSULE_GW_POOL, default 20000-29999) and sweeps leases and quarantine
// until ctx is cancelled. It opens nothing in AWS: the single rule for the range is managed by Terraform.
func wireGateway(ctx context.Context, logger *slog.Logger, pool *pgxpool.Pool, tcpHost string, orgRepo domain.OrganizationRepository,
	projRepo domain.ProjectRepository, userRepo domain.UserRepository, apiTokens domain.APITokenRepository, dbRepo domain.DatabaseRepository,
	accessRepo domain.DatabaseAccessRepository, networkRepo domain.ProjectNetworkRepository, authzSvc *authz.Service) {
	if pool == nil {
		return
	}
	cfg, err := gwapi.ConfigFromEnv()
	if err != nil {
		logger.Error("gateway configuration invalid: random-port pool disabled", "error", err.Error())
		cfg.PoolOff = true
	}
	cfg.TCPHost = tcpHost
	portRepo := repository.NewProjectPortRepository(pool)
	gwapi.Wire(ctx, logger, gwapi.Deps{
		Store:     gwstore.NewPgStore(pool),
		Projects:  projRepo,
		Orgs:      orgRepo,
		Users:     userRepo,
		Authz:     authzSvc,
		APITokens: apiTokens,
		SvcTokens: gwapi.NewPgServiceTokens(pool),
		IPLists:   gwapi.RepoIPLists{Databases: accessRepo, Ports: portRepo, Network: networkRepo},
		Sources:   gwapi.RepoSources{PortRepo: portRepo, DBRepo: dbRepo},
		Audit:     repository.NewAuditRepository(pool),
		Config:    cfg,
	})
}
