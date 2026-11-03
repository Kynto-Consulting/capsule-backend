package gitevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ProjectInfo is what the bus needs to know about a project to complete an event.
type ProjectInfo struct {
	OrgID       uuid.UUID
	OrgSlug     string
	ProjectSlug string
	ProjectName string
}

// ProjectResolver loads ProjectInfo. It returns ErrNoProject when the project does not exist
// (or was deleted).
type ProjectResolver interface {
	ProjectInfo(ctx context.Context, projectID uuid.UUID) (ProjectInfo, error)
}

// Store persists events (table git_events, implemented in internal/repository).
type Store interface {
	// Insert stores e (e.ID must be set). inserted is false when another row with the same
	// (project_id, delivery_id) exists: the delivery was already processed (idempotency).
	Insert(ctx context.Context, e *Event) (inserted bool, err error)
	MarkDispatched(ctx context.Context, id uuid.UUID) error
	// RecordDispatchFailure increments the dispatch attempt counter and returns it.
	RecordDispatchFailure(ctx context.Context, id uuid.UUID) (attempts int, err error)
	// ListUndispatched returns events not yet fully fanned out and created before cutoff.
	ListUndispatched(ctx context.Context, cutoff time.Time, limit int) ([]Event, error)
}

// Bus persists events and fans them out to subscribers.
type Bus struct {
	store    Store
	projects ProjectResolver
	log      *slog.Logger
	now      func() time.Time

	mu   sync.RWMutex
	subs []Subscriber

	sem         chan struct{}
	wg          sync.WaitGroup
	maxAttempts int
	// SweepEvery / SweepAge tune the redispatch loop (defaults 30 s / 30 s).
	SweepEvery time.Duration
	SweepAge   time.Duration
}

// NewBus builds a bus. log may be nil.
func NewBus(store Store, projects ProjectResolver, log *slog.Logger) *Bus {
	if log == nil {
		log = slog.Default()
	}
	return &Bus{
		store: store, projects: projects, log: log, now: time.Now,
		sem: make(chan struct{}, 32), maxAttempts: 10,
		SweepEvery: 30 * time.Second, SweepAge: 30 * time.Second,
	}
}

// Subscribe registers a subscriber (call before publishing).
func (b *Bus) Subscribe(s Subscriber) {
	b.mu.Lock()
	b.subs = append(b.subs, s)
	b.mu.Unlock()
}

var _ Publisher = (*Bus)(nil)

// Publish implements Publisher.
func (b *Bus) Publish(ctx context.Context, e Event) error {
	if e.Source == "" {
		e.Source = SourceCapsule
	}
	_, err := b.Record(ctx, e)
	return err
}

// Record validates, completes and persists e and starts its asynchronous dispatch. duplicate is
// true (and nothing is dispatched) when e.DeliveryID was already recorded for the project.
func (b *Bus) Record(ctx context.Context, e Event) (duplicate bool, err error) {
	if !Valid(e.Name) {
		return false, fmt.Errorf("%w: %q", ErrUnknownEvent, e.Name)
	}
	if err := CheckNoSecrets(e.Data); err != nil {
		return false, err
	}
	if e.Source == "" {
		e.Source = SourceCapsule
	}
	info, err := b.projects.ProjectInfo(ctx, e.ProjectID)
	if err != nil {
		return false, err
	}
	e.OrgID, e.OrgSlug, e.ProjectSlug = info.OrgID, info.OrgSlug, info.ProjectSlug
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = b.now().UTC()
	}
	if e.Data == nil {
		e.Data = map[string]any{}
	}
	// Data must survive a JSON round trip (it is stored as jsonb and replayed by the sweeper).
	if _, err := json.Marshal(e.Data); err != nil {
		return false, fmt.Errorf("gitevents: event data is not JSON: %w", err)
	}
	inserted, err := b.store.Insert(ctx, &e)
	if err != nil {
		return false, err
	}
	if !inserted {
		return true, nil
	}
	b.dispatchAsync(e)
	return false, nil
}

func (b *Bus) dispatchAsync(e Event) {
	select {
	case b.sem <- struct{}{}:
	default:
		return // saturated: the sweeper will pick it up
	}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		defer func() { <-b.sem }()
		b.dispatch(e)
	}()
}

// dispatch fans e out to every subscriber. Nothing here may panic the process.
func (b *Bus) dispatch(e Event) {
	defer func() {
		if r := recover(); r != nil {
			b.log.Error("gitevents: subscriber panicked", "event", e.Name, "event_id", e.ID, "panic", fmt.Sprint(r))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if e.OrgSlug == "" {
		if info, err := b.projects.ProjectInfo(ctx, e.ProjectID); err == nil {
			e.OrgID, e.OrgSlug, e.ProjectSlug = info.OrgID, info.OrgSlug, info.ProjectSlug
		} else if errors.Is(err, ErrNoProject) {
			_ = b.store.MarkDispatched(ctx, e.ID) // project is gone: nothing to deliver
			return
		}
	}
	b.mu.RLock()
	subs := append([]Subscriber(nil), b.subs...)
	b.mu.RUnlock()
	ok := true
	for _, s := range subs {
		if err := s.Handle(ctx, e); err != nil {
			ok = false
			b.log.Warn("gitevents: subscriber failed", "subscriber", s.Name(), "event", e.Name, "event_id", e.ID, "error", err)
		}
	}
	if ok {
		if err := b.store.MarkDispatched(ctx, e.ID); err != nil {
			b.log.Warn("gitevents: marking event dispatched failed", "event_id", e.ID, "error", err)
		}
		return
	}
	n, err := b.store.RecordDispatchFailure(ctx, e.ID)
	if err != nil {
		b.log.Warn("gitevents: recording dispatch failure failed", "event_id", e.ID, "error", err)
		return
	}
	if n >= b.maxAttempts {
		b.log.Error("gitevents: giving up dispatching event", "event", e.Name, "event_id", e.ID, "attempts", n)
		_ = b.store.MarkDispatched(ctx, e.ID)
	}
}

// Sweep redispatches events whose fan-out did not complete (crash, subscriber error). It
// returns how many it handled. Subscribers are idempotent, so repeating is safe.
func (b *Bus) Sweep(ctx context.Context) int {
	evs, err := b.store.ListUndispatched(ctx, b.now().Add(-b.SweepAge), 50)
	if err != nil {
		b.log.Warn("gitevents: listing undispatched events failed", "error", err)
		return 0
	}
	for _, e := range evs {
		b.dispatch(e)
	}
	return len(evs)
}

// Run sweeps until ctx ends.
func (b *Bus) Run(ctx context.Context) {
	t := time.NewTicker(b.SweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.Sweep(ctx)
		}
	}
}

// Wait blocks until the in-flight dispatches finish (tests).
func (b *Bus) Wait() { b.wg.Wait() }
