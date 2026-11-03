package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitimport"
	"github.com/kynto/capsule/backend/internal/gitsource"
	"github.com/kynto/capsule/backend/internal/gitsync"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server/handlers"
)

// wireGitImport is Git Capsule package C1: import from GitHub and push mirrors.
//
//   - POST /git/migrate answers when the whole clone is done, so imports use a DEDICATED gitcore client
//     whose per-call timeout is CAPSULE_GIT_IMPORT_REPO_MINUTES (default 30); mirror CRUD uses the
//     shared client and only the manual synchronization uses a client with
//     CAPSULE_GIT_MIRROR_SYNC_MINUTES (default 10);
//   - GitHub is reached with the SSRF-checked HTTP client of gitsource (public destinations only);
//   - imports interrupted by a restart are marked so the same request can resume them.
//
// Without a database or with the Forgejo integration off it does nothing and the routes are absent.
func wireGitImport(ctx context.Context, logger *slog.Logger, pool *pgxpool.Pool, secretKey string, projRepo domain.ProjectRepository) {
	shared := gitcore.Shared()
	if pool == nil || !shared.Enabled() {
		return
	}
	cfg := gitimport.ConfigFromEnv()
	repo := repository.NewGitImportRepository(pool, secretKey)
	policy := gitsource.PolicyFromEnv()

	slow := gitcore.ConfigFromEnv()
	slow.Timeout = cfg.RepoTimeout
	importForge := gitcore.New(slow, nil, nil)
	syncCfg := gitcore.ConfigFromEnv()
	syncCfg.Timeout = cfg.SyncTimeout
	syncForge := gitcore.New(syncCfg, nil, nil)

	imp := gitimport.New(ctx, cfg, gitimport.Deps{
		Store:    repo,
		Forge:    importForge,
		GitHub:   &gitimport.GitHub{BaseURL: cfg.GitHubAPI, HTTP: policy.NewHTTPClient(30 * time.Second)},
		Projects: projRepo,
		Linker:   repo,
		Audit:    repo,
		Policy:   policy,
		AfterImport: func(c context.Context, projectID uuid.UUID) error {
			if d := gitsync.Shared(); d != nil && d.Rec != nil {
				return d.Rec.SyncProject(c, projectID) // teams of the new project (A2)
			}
			return nil
		},
		Logger: logger,
	})
	imp.Recover(ctx)
	mir := gitimport.NewMirrors(ctx, cfg, gitimport.MirrorDeps{Store: repo, Forge: shared, SyncForge: syncForge, Policy: policy, Audit: repo, Logger: logger})
	handlers.WireGitImport(handlers.GitImportWiring{Import: imp, Mirror: mir, Logger: logger})
}
