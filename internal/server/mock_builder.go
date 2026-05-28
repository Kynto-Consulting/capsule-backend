package server

// mockBuilder simulates a Docker/container build pipeline for deployments that
// would normally require ECS + ECR infrastructure. It is only active when
// CAPSULE_MOCK_BUILDER=true or when AWS clients are not fully configured
// (i.e. dev/staging environments without real ECS access).
//
// State machine per deployment:
//   queued → building (2s delay) → deploying (4s delay) → running

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

type mockBuilderWorker struct {
	deployments domain.DeploymentRepository
	logger      *slog.Logger
}

// StartMockBuilder launches the background mock-builder goroutine and returns
// immediately. The goroutine runs until ctx is cancelled.
func StartMockBuilder(ctx context.Context, deployments domain.DeploymentRepository, logger *slog.Logger) {
	w := &mockBuilderWorker{deployments: deployments, logger: logger}
	go w.run(ctx)
	logger.Info("mock builder started — docker deployments will be simulated")
}

func (w *mockBuilderWorker) run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Track deployments already in-flight so we don't double-advance them.
	inFlight := map[uuid.UUID]bool{}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tick(ctx, inFlight)
		}
	}
}

func (w *mockBuilderWorker) tick(ctx context.Context, inFlight map[uuid.UUID]bool) {
	// List queued deployments (page 1, up to 50)
	deps, _, err := w.deployments.ListQueued(ctx, 1, 50)
	if err != nil {
		w.logger.Warn("mock builder: ListQueued error", "err", err)
		return
	}

	for _, d := range deps {
		if inFlight[d.ID] {
			continue
		}
		inFlight[d.ID] = true
		go w.advance(ctx, d.ID, inFlight)
	}
}

func (w *mockBuilderWorker) advance(ctx context.Context, id uuid.UUID, inFlight map[uuid.UUID]bool) {
	defer func() { delete(inFlight, id) }()

	steps := []struct {
		status string
		delay  time.Duration
		msg    string
	}{
		{"building", 2 * time.Second, "Building Docker image..."},
		{"deploying", 4 * time.Second, "Pushing image and starting container..."},
		{"running", 0, "Deployment is live."},
	}

	for _, step := range steps {
		select {
		case <-ctx.Done():
			return
		case <-time.After(step.delay):
		}

		if err := w.deployments.UpdateStatus(ctx, id, step.status); err != nil {
			w.logger.Warn("mock builder: UpdateStatus error", "id", id, "status", step.status, "err", err)
			return
		}
		if err := w.deployments.AppendLog(ctx, &domain.BuildLog{
			DeploymentID: id,
			Level:        "info",
			Message:      step.msg,
		}); err != nil {
			w.logger.Warn("mock builder: AppendLog error", "err", err)
		}
	}
}
