package main

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/gitaudit"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/gitinsights"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server/handlers"
	"github.com/kynto/capsule/backend/internal/webhookout"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

// wireGitC2 is Git Capsule package C2: audit log read side and retention, git_activity (fed by
// the event bus), insights, the notification digest, suppression expiry notices and the token
// expiry notifier (gittokens: pass gitinsights.SharedTokenNotifier() as Notifier).
//
// It must run after the A5 wiring (the activity recorder subscribes to the shared bus).
func wireGitC2(ctx context.Context, logger *slog.Logger, pool *pgxpool.Pool, frontendURL string, aws *awsclient.Clients) {
	if pool == nil {
		return
	}
	auditRepo := repository.NewAuditRepository(pool)
	rec := gitaudit.NewRecorder(auditRepo)
	gitaudit.SetShared(rec)

	actRepo := repository.NewGitActivityRepository(pool)
	recorder := &gitinsights.ActivityRecorder{Store: actRepo}
	gitinsights.SetSharedRecorder(recorder)
	if bus, ok := gitevents.Shared().(interface{ Subscribe(gitevents.Subscriber) }); ok {
		bus.Subscribe(recorder)
	} else {
		logger.Warn("git activity: the event bus is not wired; the activity feed and insights stay empty")
	}
	handlers.WireC2(gitaudit.NewService(auditRepo), rec, &gitinsights.Service{Store: actRepo})

	var ses webhookout.SESAPI
	if aws != nil && aws.SES != nil {
		ses = aws.SES
	}
	mailer := webhookout.MailerFromEnv(ses)

	gcfg := gitinsights.ConfigFromEnv()
	gitinsights.SetTokenNotifier(&gitinsights.TokenExpiryNotifier{
		Store: repository.NewTokenNoticeRepository(pool), Mailer: mailer, BaseURL: frontendURL, Log: logger,
	})

	go (&gitaudit.Retention{R: auditRepo, Cfg: gitaudit.ConfigFromEnv(), Log: logger}).Run(ctx)
	go (&gitinsights.ActivityRetention{Store: actRepo, Cfg: gcfg, Log: logger}).Run(ctx)
	go (&gitinsights.Digester{Store: actRepo, Mailer: mailer, Cfg: gcfg, Log: logger}).Run(ctx)
	go (&gitinsights.SuppressionExpiryScanner{Source: gitinsights.SharedSuppressionSource(), Publisher: gitevents.Shared(), Cfg: gcfg, Log: logger}).Run(ctx)
}
