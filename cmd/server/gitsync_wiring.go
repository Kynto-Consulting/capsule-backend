package main

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/forgejo"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitsync"
	"github.com/kynto/capsule/backend/internal/oidc"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server/handlers"
)

// wireGitSync is Git Capsule package A2: identity + team projection + git.* authorization.
//
//   - the Git handler decides with the project role matrix (authz) instead of the org role;
//   - when the Forgejo integration is configured, the reconciler replaces the built-in team sync
//     of forgejo.Core (provisioning, member hooks and the pending-user retry all call it), runs
//     periodically (CAPSULE_GIT_RECONCILE_MINUTES, default 15) and backs POST /git/admin/reconcile;
//   - the first OIDC token issued to a user records the Forgejo login (git_identities).
//
// CAPSULE_GIT_BOT_LOGIN (default capsule-bot) is the service account: never removed from a team.
func wireGitSync(ctx context.Context, logger *slog.Logger, pool *pgxpool.Pool, secretKey string, orgRepo domain.OrganizationRepository,
	projRepo domain.ProjectRepository, members authz.MemberStore, userRepo domain.UserRepository,
	oidcSvc *oidc.Service, authzSvc *authz.Service, gitHandler *handlers.GitHandler) {

	if gitHandler != nil && authzSvc != nil {
		gitHandler.SetAuthorizer(handlers.AuthzAuthorizer{Svc: authzSvc})
	}

	core := gitcore.Shared()
	if !core.Enabled() {
		logger.Info("git sync disabled (CAPSULE_GIT_URL / CAPSULE_GIT_TOKEN not set)")
		return
	}
	forge, ok := core.(gitsync.Forge)
	if !ok {
		logger.Error("git sync disabled: the shared gitcore does not implement gitsync.Forge")
		return
	}

	forge = gitsync.WithExt(forge) // PatchTeam and GetUser from gitcore: permission drift is corrected, forgejo_user_id filled

	ids := &gitsync.Identities{
		Store: repository.NewGitIdentityRepository(pool),
		Taken: repository.NewOIDCRepository(pool).UsernameTaken,
	}
	bot := strings.TrimSpace(os.Getenv("CAPSULE_GIT_BOT_LOGIN"))
	if bot == "" {
		bot = "capsule-bot"
	}
	rec := &gitsync.Reconciler{
		Forge: forge,
		Dir: gitsync.DomainDirectory{
			Projects: projRepo, Orgs: orgRepo, Git: repository.NewGitRepository(pool, secretKey), Roles: members,
		},
		IDs:     ids,
		States:  repository.NewGitTeamStateRepository(pool),
		Pending: repository.NewGitCoreRepository(pool),
		Keep:    []string{bot},
		Logger:  logger,
	}

	forgejo.SetTeamSyncDelegate(rec.SyncProject)
	gitsync.Publish(&gitsync.Deps{Rec: rec})

	every := 15 * time.Minute
	if n, err := strconv.Atoi(os.Getenv("CAPSULE_GIT_RECONCILE_MINUTES")); err == nil && n > 0 {
		every = time.Duration(n) * time.Minute
	}
	go rec.Run(ctx, every)

	if oidcSvc != nil && userRepo != nil {
		prev := oidcSvc.ExtraGroups
		oidcSvc.ExtraGroups = func(c context.Context, userID uuid.UUID) ([]string, error) {
			if u, err := userRepo.GetByID(c, userID); err == nil && u != nil {
				if err := ids.OnLogin(c, userID, u.Email); err != nil {
					logger.Warn("git identity: recording the login failed", "user_id", userID, "error", err)
				}
			}
			if prev != nil {
				return prev(c, userID)
			}
			return nil, nil
		}
	}
	logger.Info("git sync enabled", "reconcile_every", every.String(), "bot", bot)
}

// sharedGitIdentities exposes A2's identity resolver (nil while git sync is off) to A7.
func sharedGitIdentities() *gitsync.Identities {
	if d := gitsync.Shared(); d != nil && d.Rec != nil {
		return d.Rec.IDs
	}
	return nil
}
