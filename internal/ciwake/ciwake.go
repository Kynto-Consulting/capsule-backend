// Package ciwake turns the CI runner EC2 instance on when there is CI work for it.
//
// The runner (Forgejo Actions, deploy/forgejo/README.md section 8) stops itself after N idle
// minutes (deploy/forgejo/runner-idle-stop). This package is the other half: it subscribes to
// the git event bus and, on a push or a pull request of a project with a repository in Git
// Capsule, starts the instance if (and only if) it is stopped.
//
// Guarantees: StartInstances is only called for a `stopped` instance (idempotent); at most one
// check per Debounce window; at most MaxPerHour starts per rolling hour (loop/cost guard); the
// feature is off when no instance id is configured; logs and counters never carry credentials.
package ciwake

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

// Defaults.
const (
	DefaultDebounce   = 60 * time.Second
	DefaultMaxPerHour = 6
)

// EC2API is the subset of *ec2.Client used here (fake in tests).
type EC2API interface {
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	StartInstances(ctx context.Context, in *ec2.StartInstancesInput, optFns ...func(*ec2.Options)) (*ec2.StartInstancesOutput, error)
}

// RepoChecker says whether a project has a repository in Git Capsule. Optional: when nil, every
// event with a project id counts (the bus only carries events of git-enabled projects).
type RepoChecker interface {
	HasRepo(ctx context.Context, projectID uuid.UUID) (bool, error)
}

// Config of the waker.
type Config struct {
	InstanceID string
	MaxPerHour int           // starts per rolling hour; <= 0 = DefaultMaxPerHour
	Debounce   time.Duration // <= 0 = DefaultDebounce
}

// Outcome of one wake attempt.
type Outcome string

const (
	OutcomeStarted     Outcome = "started"
	OutcomeAlready     Outcome = "already_on"   // running or pending
	OutcomeDebounced   Outcome = "debounced"    // checked less than Debounce ago
	OutcomeRateLimited Outcome = "rate_limited" // MaxPerHour reached
	OutcomeStopping    Outcome = "stopping"     // shutting down: the next event starts it
	OutcomeUnusable    Outcome = "unusable"     // terminated / shutting-down / not found
	OutcomeError       Outcome = "error"
)

// Stats are cumulative counters since process start.
type Stats struct {
	Events, Ignored, Started, Already, Debounced, RateLimited, Stopping, Unusable, Errors int64
}

// Waker implements gitevents.Subscriber.
type Waker struct {
	api   EC2API
	cfg   Config
	repos RepoChecker
	log   *slog.Logger
	now   func() time.Time

	mu        sync.Mutex
	lastCheck time.Time
	starts    []time.Time
	stats     Stats
}

// New builds a Waker. It returns nil when cfg.InstanceID is empty or api is nil (feature off).
func New(api EC2API, cfg Config, repos RepoChecker, log *slog.Logger) *Waker {
	cfg.InstanceID = strings.TrimSpace(cfg.InstanceID)
	if cfg.InstanceID == "" || api == nil {
		return nil
	}
	if cfg.MaxPerHour <= 0 {
		cfg.MaxPerHour = DefaultMaxPerHour
	}
	if cfg.Debounce <= 0 {
		cfg.Debounce = DefaultDebounce
	}
	if log == nil {
		log = slog.Default()
	}
	return &Waker{api: api, cfg: cfg, repos: repos, log: log, now: time.Now}
}

// Name implements gitevents.Subscriber.
func (w *Waker) Name() string { return "ciwake" }

// wakes lists the events that can create CI work. workflow.run.completed does not: a finished run
// needs no runner.
var wakes = map[string]bool{
	gitevents.GitPush:          true,
	gitevents.PROpened:         true,
	gitevents.PRUpdated:        true,
	gitevents.PRReadyForReview: true,
}

// Handle implements gitevents.Subscriber. It never returns an error: waking the runner is best
// effort and a failure must not make the bus redeliver the event (the next push retries).
func (w *Waker) Handle(ctx context.Context, e gitevents.Event) error {
	w.bump(func(s *Stats) { s.Events++ })
	if !wakes[e.Name] || e.ProjectID == uuid.Nil {
		w.bump(func(s *Stats) { s.Ignored++ })
		return nil
	}
	if w.repos != nil {
		ok, err := w.repos.HasRepo(ctx, e.ProjectID)
		if err != nil {
			w.log.Warn("ciwake: repo lookup failed", "error", err)
		}
		if err != nil || !ok {
			w.bump(func(s *Stats) { s.Ignored++ })
			return nil
		}
	}
	w.Wake(ctx, e.Name)
	return nil
}

func (w *Waker) bump(f func(*Stats)) { w.mu.Lock(); f(&w.stats); w.mu.Unlock() }

// Stats returns a snapshot of the counters.
func (w *Waker) Stats() Stats { w.mu.Lock(); defer w.mu.Unlock(); return w.stats }

// Wake checks the instance and starts it when stopped. reason is only logged.
func (w *Waker) Wake(ctx context.Context, reason string) Outcome {
	w.mu.Lock()
	defer w.mu.Unlock() // serialises: concurrent events cannot double-start
	now := w.now()
	if !w.lastCheck.IsZero() && now.Sub(w.lastCheck) < w.cfg.Debounce {
		w.stats.Debounced++
		return OutcomeDebounced
	}

	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := w.api.DescribeInstances(cctx, &ec2.DescribeInstancesInput{InstanceIds: []string{w.cfg.InstanceID}})
	if err != nil {
		w.stats.Errors++
		w.log.Warn("ciwake: describe failed", "instance", w.cfg.InstanceID, "error", err)
		return OutcomeError
	}
	state, found := instanceState(out)
	switch {
	case !found:
		w.stats.Unusable++
		w.log.Warn("ciwake: instance not found", "instance", w.cfg.InstanceID)
		return OutcomeUnusable
	case state == ec2types.InstanceStateNameRunning || state == ec2types.InstanceStateNamePending:
		w.lastCheck = now
		w.stats.Already++
		return OutcomeAlready
	case state == ec2types.InstanceStateNameStopping:
		w.stats.Stopping++ // no debounce: the next event must retry once it is stopped
		w.log.Info("ciwake: runner is stopping; the next event will start it", "instance", w.cfg.InstanceID)
		return OutcomeStopping
	case state != ec2types.InstanceStateNameStopped:
		w.stats.Unusable++
		w.log.Warn("ciwake: instance cannot be started", "instance", w.cfg.InstanceID, "state", string(state))
		return OutcomeUnusable
	}

	// stopped: apply the hourly cap.
	cut := now.Add(-time.Hour)
	kept := w.starts[:0]
	for _, t := range w.starts {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	w.starts = kept
	if len(w.starts) >= w.cfg.MaxPerHour {
		w.lastCheck = now
		w.stats.RateLimited++
		w.log.Warn("ciwake: hourly start limit reached; not starting", "instance", w.cfg.InstanceID, "max_per_hour", w.cfg.MaxPerHour)
		return OutcomeRateLimited
	}
	if _, err := w.api.StartInstances(cctx, &ec2.StartInstancesInput{InstanceIds: []string{w.cfg.InstanceID}}); err != nil {
		w.stats.Errors++
		w.log.Warn("ciwake: start failed", "instance", w.cfg.InstanceID, "error", err)
		return OutcomeError
	}
	w.lastCheck = now
	w.starts = append(w.starts, now)
	w.stats.Started++
	w.log.Info("ciwake: runner starting", "instance", w.cfg.InstanceID, "reason", reason, "starts_last_hour", len(w.starts))
	return OutcomeStarted
}

func instanceState(out *ec2.DescribeInstancesOutput) (ec2types.InstanceStateName, bool) {
	if out == nil {
		return "", false
	}
	for _, r := range out.Reservations {
		for _, i := range r.Instances {
			if i.State != nil {
				return i.State.Name, true
			}
		}
	}
	return "", false
}

// ConfigFromEnv reads CAPSULE_CI_RUNNER_INSTANCE_ID, CAPSULE_CI_WAKE_MAX_PER_HOUR and
// CAPSULE_CI_RUNNER_REGION (empty = the backend's AWS region).
func ConfigFromEnv() (cfg Config, region string) {
	cfg.InstanceID = strings.TrimSpace(os.Getenv("CAPSULE_CI_RUNNER_INSTANCE_ID"))
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("CAPSULE_CI_WAKE_MAX_PER_HOUR"))); err == nil {
		cfg.MaxPerHour = v
	}
	return cfg, strings.TrimSpace(os.Getenv("CAPSULE_CI_RUNNER_REGION"))
}

// subscribable is what *gitevents.Bus offers beyond Publisher.
type subscribable interface{ Subscribe(gitevents.Subscriber) }

// ErrNoBus is returned by Wire when the event bus is not wired (call after the A5 wiring).
var ErrNoBus = errors.New("ciwake: event bus not available")

// Wire subscribes a Waker to the shared event bus. It does nothing (nil, nil) when
// CAPSULE_CI_RUNNER_INSTANCE_ID is empty or AWS is unavailable. Call after eventswire.Wire.
// The runner must live in the backend's region (one shared EC2 client): another
// CAPSULE_CI_RUNNER_REGION disables the feature with a warning.
func Wire(logger *slog.Logger, clients *awsclient.Clients) (*Waker, error) {
	cfg, region := ConfigFromEnv()
	if cfg.InstanceID == "" {
		return nil, nil
	}
	if clients == nil || clients.EC2 == nil {
		if logger != nil {
			logger.Warn("ciwake: AWS EC2 client unavailable; CI wake disabled")
		}
		return nil, nil
	}
	if region != "" && region != clients.Region {
		if logger != nil {
			logger.Warn("ciwake: CAPSULE_CI_RUNNER_REGION differs from the backend region; CI wake disabled", "runner_region", region, "backend_region", clients.Region)
		}
		return nil, nil
	}
	sub, ok := gitevents.Shared().(subscribable)
	if !ok {
		return nil, ErrNoBus
	}
	w := New(clients.EC2, cfg, nil, logger)
	sub.Subscribe(w)
	if logger != nil {
		logger.Info("ciwake: CI wake enabled", "instance", cfg.InstanceID, "max_per_hour", w.cfg.MaxPerHour)
	}
	return w, nil
}

var _ gitevents.Subscriber = (*Waker)(nil)
