package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitsource"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server/handlers"
	"github.com/kynto/capsule/backend/internal/service"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

// wireGit builds the git auto-deploy / PR preview module and starts its
// expired-preview reaper (stops with ctx).
func wireGit(ctx context.Context, cfg *config.Config, logger *slog.Logger, pool *pgxpool.Pool,
	projRepo domain.ProjectRepository, orgRepo domain.OrganizationRepository, deployRepo domain.DeploymentRepository,
	awsClients *awsclient.Clients, fargate service.FargateConfig) *handlers.GitHandler {

	policy := gitsource.PolicyFromEnv()
	fetcher := &gitsource.GitFetcher{Policy: policy, Limits: gitsource.LimitsFromEnv()}
	gitRepo := repository.NewGitRepository(pool, cfg.SecretKey)
	apiClient := policy.NewHTTPClient(20 * time.Second)

	svc := &service.GitService{
		Git:         gitRepo,
		Projects:    projRepo,
		Deployments: deployRepo,
		Uploader:    service.S3Uploader{AWS: awsClients, Bucket: cfg.ArtifactsBucket},
		Fetcher:     fetcher,
		Provider: func(g *domain.ProjectGit) (service.StatusClient, error) {
			if g.AuthKind != "token" {
				return nil, gitsource.ErrUnsupported
			}
			return gitsource.NewProviderClient(g.Provider, g.RepoURL, g.Credential, apiClient)
		},
		Runtime:    service.AppRemover{AWS: awsClients, Fargate: fargate, Logger: logger},
		Logger:     logger,
		AppsDomain: cfg.AppsDomain,
		ConsoleURL: os.Getenv("CAPSULE_CONSOLE_URL"),
	}
	go svc.RunReaper(ctx, 0)

	return handlers.NewGitHandler(handlers.GitDeps{
		Git:        gitRepo,
		Projects:   projRepo,
		Orgs:       orgRepo,
		Policy:     policy,
		Fetcher:    fetcher,
		Service:    svc,
		PublicHost: cfg.PublicHost,
		Logger:     logger,
	})
}
