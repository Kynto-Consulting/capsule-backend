package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"

	"github.com/kynto/capsule/backend/internal/domain"
)

// The in-process cron scheduler.
//
// A cron job used to be saved and then handed to EventBridge Scheduler, which needs a Lambda and a role that
// a self-hosted Capsule does not have: nothing ever fired, and only `crons trigger` ran a job. The scheduler
// below fires every active job from the server itself, once per minute, by the same path as a manual trigger
// (docker exec inside the project's app container).
//
// Rules:
//   - a job fires when its expression (5 fields, in the job's timezone) matches the current minute;
//   - a job that is still running is not started again (the missed tick is skipped, never queued);
//   - at most cronConcurrency() commands run at once, so a burst of jobs cannot starve the host;
//   - a command is killed after cronTimeout().
//
// CAPSULE_CRON_SCHEDULER=off disables it (manual triggers keep working).

// cronDue reports whether expr, read in timezone tz, fires at the minute that contains now.
func cronDue(expr, tz string, now time.Time) (bool, error) {
	loc := time.UTC
	if tz != "" {
		l, err := time.LoadLocation(tz)
		if err != nil {
			return false, fmt.Errorf("timezone %q: %w", tz, err)
		}
		loc = l
	}
	sched, err := cron.ParseStandard(strings.TrimSpace(expr))
	if err != nil {
		return false, err
	}
	minute := now.In(loc).Truncate(time.Minute)
	return sched.Next(minute.Add(-time.Second)).Equal(minute), nil
}

// cronNext is the next time expr fires after now (nil if the expression or timezone is invalid).
func cronNext(expr, tz string, now time.Time) *time.Time {
	loc := time.UTC
	if tz != "" {
		l, err := time.LoadLocation(tz)
		if err != nil {
			return nil
		}
		loc = l
	}
	sched, err := cron.ParseStandard(strings.TrimSpace(expr))
	if err != nil {
		return nil
	}
	n := sched.Next(now.In(loc)).UTC()
	return &n
}

func cronConcurrency() int {
	if n, err := strconv.Atoi(os.Getenv("CAPSULE_CRON_CONCURRENCY")); err == nil && n > 0 {
		return n
	}
	return 4
}

func cronTimeout() time.Duration {
	if n, err := strconv.Atoi(os.Getenv("CAPSULE_CRON_TIMEOUT_MINUTES")); err == nil && n > 0 {
		return time.Duration(n) * time.Minute
	}
	return 30 * time.Minute
}

// cronRunning is the set of jobs with a command in flight, shared by the scheduler and the manual trigger.
var cronRunning = struct {
	sync.Mutex
	ids map[uuid.UUID]struct{}
}{ids: map[uuid.UUID]struct{}{}}

func cronAcquire(id uuid.UUID) bool {
	cronRunning.Lock()
	defer cronRunning.Unlock()
	if _, busy := cronRunning.ids[id]; busy {
		return false
	}
	cronRunning.ids[id] = struct{}{}
	return true
}

func cronRelease(id uuid.UUID) {
	cronRunning.Lock()
	delete(cronRunning.ids, id)
	cronRunning.Unlock()
}

// cronExec is how a command reaches the app container; a test replaces it.
var cronExec = func(ctx context.Context, container, command string) ([]byte, error) {
	_ = wakeApp(ctx, container, 0) // the app may be asleep (idle sleep)
	return exec.CommandContext(ctx, "docker", "exec", container, "sh", "-c", command).CombinedOutput()
}

// runCronJob runs the job's command INSIDE the project's app container via docker exec: that gives it the
// app's working dir, its env vars (DATABASE_URL etc.) and keeps user commands off the platform host. The
// container name matches the deploy worker: capsule-app-<first12ofUUID>. It records the result and the log.
func runCronJob(ctx context.Context, crons domain.CronJobRepository, exLogs domain.ExecutionLogRepository, logger *slog.Logger, c *domain.CronJob) {
	start := time.Now()
	shortID := strings.ReplaceAll(c.ProjectID.String(), "-", "")[:12]
	containerName := "capsule-app-" + shortID

	runCtx, cancel := context.WithTimeout(ctx, cronTimeout())
	out, runErr := cronExec(runCtx, containerName, c.Command)
	cancel()
	dur := time.Since(start)
	runStatus := "success"
	level := "info"
	if runErr != nil {
		logger.Error("cron run failed", "cron_id", c.ID, "container", containerName, "error", runErr)
		runStatus = "failed"
		level = "error"
	}
	// The result is recorded even when the server is shutting down.
	recCtx, recCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer recCancel()
	_ = crons.UpdateLastRun(recCtx, c.ID, runStatus, cronNext(c.Schedule, c.Timezone, time.Now()))

	if exLogs != nil {
		msg := fmt.Sprintf("cron %q (%s) → %s in %s", c.Name, c.Command, runStatus, dur.Round(time.Millisecond))
		if len(out) > 0 {
			msg += "\n" + string(out)
		}
		_ = exLogs.Append(recCtx, &domain.ExecutionLog{
			ProjectID: c.ProjectID,
			Source:    "cron",
			SourceID:  c.ID.String(),
			Level:     level,
			Message:   msg,
		})
	}
}

// cronTick starts every active job due at the minute of now and returns how many it started.
func cronTick(ctx context.Context, crons domain.CronJobRepository, exLogs domain.ExecutionLogRepository, logger *slog.Logger, sem chan struct{}, now time.Time, wg *sync.WaitGroup) int {
	jobs, err := crons.ListActive(ctx)
	if err != nil {
		logger.Warn("cron scheduler: listing jobs failed", "error", err)
		return 0
	}
	started := 0
	for _, c := range jobs {
		due, err := cronDue(c.Schedule, c.Timezone, now)
		if err != nil {
			logger.Warn("cron scheduler: invalid schedule", "cron_id", c.ID, "error", err)
			continue
		}
		if !due {
			continue
		}
		if !cronAcquire(c.ID) {
			logger.Info("cron scheduler: previous run still in flight, tick skipped", "cron_id", c.ID, "name", c.Name)
			continue
		}
		started++
		wg.Add(1)
		go func(c *domain.CronJob) {
			defer wg.Done()
			defer cronRelease(c.ID)
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			runCronJob(ctx, crons, exLogs, logger, c)
		}(c)
	}
	return started
}

// RunCronScheduler fires the active cron jobs every minute until ctx ends.
func RunCronScheduler(ctx context.Context, crons domain.CronJobRepository, exLogs domain.ExecutionLogRepository, logger *slog.Logger) {
	if strings.EqualFold(os.Getenv("CAPSULE_CRON_SCHEDULER"), "off") {
		logger.Info("cron scheduler disabled (CAPSULE_CRON_SCHEDULER=off)")
		return
	}
	logger.Info("cron scheduler started", "concurrency", cronConcurrency(), "timeout", cronTimeout().String())
	sem := make(chan struct{}, cronConcurrency())
	var wg sync.WaitGroup
	for {
		next := time.Now().Truncate(time.Minute).Add(time.Minute)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
		cronTick(ctx, crons, exLogs, logger, sem, next, &wg)
	}
}
