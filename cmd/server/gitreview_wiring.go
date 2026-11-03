package main

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitreview"
	"github.com/kynto/capsule/backend/internal/gitsync"
	"github.com/kynto/capsule/backend/internal/repository"
)

// wireGitReview is Git Capsule package B8: CODEOWNERS, required reviews, capsule/policy, the
// auto-merge worker and the janitor that withdraws review requests from users who lost access.
// It must run AFTER the A5 event bus wiring (it subscribes to it) and after wireGitSync (it plugs
// its janitor into the reconciler). Without a database or with the Forgejo integration off it does
// nothing; the routes then answer 501/503.
func wireGitReview(ctx context.Context, logger *slog.Logger, pool *pgxpool.Pool, secretKey string, orgRepo domain.OrganizationRepository,
	projRepo domain.ProjectRepository, members authz.MemberStore, authzSvc *authz.Service) {
	if pool == nil || !gitcore.Shared().Enabled() {
		return
	}
	dir := gitsync.DomainDirectory{Projects: projRepo, Orgs: orgRepo, Git: repository.NewGitRepository(pool, secretKey), Roles: members}
	ids := &gitsync.Identities{Store: repository.NewGitIdentityRepository(pool), Taken: repository.NewOIDCRepository(pool).UsernameTaken}
	_, janitor := gitreview.WireGitReview(ctx, logger,
		gitreview.DomainProjects{Projects: projRepo, Orgs: orgRepo},
		gitreview.DirectoryRoster{Dir: dir, IDs: ids},
		repository.NewPRAutoMergeRepository(pool), authzSvc, repository.NewPRReviewDismissalRepository(pool))
	if d := gitsync.Shared(); d != nil && d.Rec != nil && d.Rec.Janitor == nil {
		d.Rec.Janitor = janitor
	}
}
