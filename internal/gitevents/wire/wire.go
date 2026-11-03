// Package wire builds and connects package A5 (event bus, notifications, outbound webhooks,
// inbound webhook sink). It is a separate package so that internal/repository (which implements
// the stores) and internal/gitevents / internal/webhookout never import each other.
//
// main.go calls Wire once, inside the git-capsule:wiring block.
package wire

import (
	"context"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/gitsource"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server/handlers"
	"github.com/kynto/capsule/backend/internal/webhookout"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

// Wire creates the event bus, subscribes the notifier and the outbound webhooks to it, starts the
// background loops (redispatch sweeper, webhook delivery worker) and publishes the shared
// instances:
//
//	gitevents.Shared()            Publisher for A6, B7, B8...
//	gitevents.SharedNotifier()    /user/notifications
//	webhookout.Shared()           /webhooks routes
//	handlers.SetInboundSink(...)  POST /hooks/git/{projectID}
//
// With a nil pool nothing is wired (the routes are absent and Publish drops events).
// secretKey encrypts webhook URLs and secrets (same platform key as the rest of the backend).
// aws may be nil: then the email channel reports "not configured".
func Wire(ctx context.Context, logger *slog.Logger, pool *pgxpool.Pool, secretKey, frontendURL string, aws *awsclient.Clients) {
	if pool == nil {
		return
	}
	events := repository.NewGitEventRepository(pool, secretKey)
	hooks := repository.NewOutboundWebhookRepository(pool, secretKey)
	inbox := repository.NewNotificationRepository(pool)

	var mailer = webhookout.MailerFromEnv(nil)
	if aws != nil && aws.SES != nil {
		mailer = webhookout.MailerFromEnv(aws.SES)
	}

	bus := gitevents.NewBus(events, events, logger)
	notifier := gitevents.NewNotifier(inbox, mailer, frontendURL, logger)
	out := webhookout.New(webhookout.Config{
		Store: hooks, Projects: events, OrgSlug: events.OrgSlug,
		Policy: gitsource.Policy{}, // any public host; private ranges are blocked at dial time
		Mailer: mailer, BaseURL: strings.TrimRight(frontendURL, "/"), Logger: logger,
	})
	bus.Subscribe(notifier)
	bus.Subscribe(out)

	inbound := gitevents.NewInbound(bus, events, gitcore.Shared(), logger)
	inbound.SetPrevSecretStore(events)

	gitevents.SetShared(bus)
	gitevents.SetSharedNotifier(notifier)
	webhookout.SetShared(out)
	handlers.SetInboundSink(inbound)

	go bus.Run(ctx)
	go out.Run(ctx)
	if logger != nil {
		logger.Info("git events ready", "email", mailer != nil)
	}
}
