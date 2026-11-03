package gitreview

import (
	"context"
	"log/slog"
	"sync"

	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

var (
	sharedMu sync.RWMutex
	shared   *Service
)

// Shared returns the Service published by WireGitReview (nil before wiring).
func Shared() *Service {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return shared
}

// SetShared publishes the process-wide Service (tests and WireGitReview).
func SetShared(s *Service) {
	sharedMu.Lock()
	shared = s
	sharedMu.Unlock()
}

// WireGitReview builds the Service on the shared gitcore Core, publishes it, plugs it into the
// pull request document (auto_merge decorator, CODEOWNER_REQUIRED blocker, code_owner_pending),
// subscribes it to the event bus when there is one and starts the sweep. Call it from the
// git-capsule:wiring block of cmd/server/main.go AFTER the gitevents wiring. It returns the
// Janitor for gitsync.Reconciler.Janitor.
func WireGitReview(ctx context.Context, logger *slog.Logger, projects Projects, roster Roster, store AutoMergeStore, az Authorizer, dismissals DismissalLog) (*Service, Janitor) {
	svc := New(gitcore.Shared(), projects, roster, store, ConfigFromEnv(), logger)
	svc.Authz = az
	svc.Dismissals = dismissals
	SetShared(svc)
	gitapi.RegisterBlockerSource(svc.BlockerSource)
	gitapi.RegisterCodeownerSource(svc.CodeownersPending)
	gitapi.RegisterPullDecorator(svc.decorate)
	if bus, ok := gitevents.Shared().(interface{ Subscribe(gitevents.Subscriber) }); ok {
		bus.Subscribe(svc)
	} else if logger != nil {
		logger.Warn("gitreview: no event bus, auto-merge relies on the periodic sweep only")
	}
	go svc.Run(ctx)
	if logger != nil {
		logger.Info("gitreview ready", "sweep_every", svc.cfg().SweepEvery.String())
	}
	return svc, Janitor{Svc: svc}
}
