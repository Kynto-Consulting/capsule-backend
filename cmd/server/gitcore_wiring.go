package main

import (
	"context"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/forgejo"
	"github.com/kynto/capsule/backend/internal/gitsource"
	"github.com/kynto/capsule/backend/internal/oidc"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server/handlers"
)

// wireGitCore builds the core Git (Forgejo) integration: provisioning on project
// creation, team synchronization, the dashboard views and API previews. With
// CAPSULE_GIT_URL / CAPSULE_GIT_TOKEN unset it does nothing (the capabilities
// endpoint reports git.enabled=false and the routes answer 501).
func wireGitCore(ctx context.Context, cfg *config.Config, logger *slog.Logger, pool *pgxpool.Pool,
	gitHandler *handlers.GitHandler, projRepo domain.ProjectRepository, orgRepo domain.OrganizationRepository,
	deployRepo domain.DeploymentRepository, members authz.MemberStore, oidcEnabled bool) *handlers.GitCoreHandler {

	if gitHandler == nil {
		return nil
	}
	gcfg := forgejo.ConfigFromEnv()
	publicURL := strings.TrimRight(os.Getenv("CAPSULE_PUBLIC_URL"), "/")
	if publicURL == "" && cfg.PublicHost != "" {
		publicURL = "https://" + strings.TrimPrefix(strings.TrimPrefix(cfg.PublicHost, "https://"), "http://")
	}
	oidcRepo := repository.NewOIDCRepository(pool)

	core := &forgejo.Core{
		Client:    forgejo.NewClient(gcfg),
		PublicURL: publicURL,
		Git:       repository.NewGitRepository(pool, cfg.SecretKey),
		Projects:  projRepo,
		Orgs:      orgRepo,
		Members:   members,
		Store:     repository.NewGitCoreRepository(pool),
		// The Forgejo login is the OIDC preferred_username (same derivation as oidc.Service).
		Username: func(ctx context.Context, userID uuid.UUID, email string) (string, error) {
			base := oidc.SanitizeUsername(email)
			taken, err := oidcRepo.UsernameTaken(ctx, userID, base)
			if err != nil {
				return "", err
			}
			if taken {
				return base + "-" + hex.EncodeToString(userID[:3]), nil
			}
			return base, nil
		},
		Policy: gitsource.PolicyFromEnv(),
		Logger: logger,
	}

	handlers.SetGitCoreHooks(handlers.GitCoreHooks{
		ProjectCreated: core.OnProjectCreated,
		MembersChanged: core.OnMembersChanged,
		OrgChanged:     core.OnOrgChanged,
	})
	gitHandler.CoreLinks = core.Links

	handlers.RegisterCapability("git", func() any {
		if !core.Enabled() {
			return map[string]any{"enabled": false, "url": "", "ssh_host": ""}
		}
		return map[string]any{"enabled": true, "url": gcfg.URL, "ssh_host": gcfg.SSHAddress()}
	})
	handlers.RegisterCapability("oidc", func() any {
		if !oidcEnabled {
			return map[string]any{"enabled": false, "issuer": ""}
		}
		return map[string]any{"enabled": true, "issuer": cfg.OIDCIssuer}
	})

	if core.Enabled() {
		logger.Info("core Git integration enabled", "url", gcfg.URL)
		go core.RunRetry(ctx, time.Minute)
	} else {
		logger.Info("core Git integration disabled (CAPSULE_GIT_URL / CAPSULE_GIT_TOKEN not set)")
	}
	return handlers.NewGitCoreHandler(gitHandler, core, deployRepo)
}
