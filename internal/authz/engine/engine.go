package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/domain"
)

// Options configures an Engine. Zero values take the defaults.
type Options struct {
	TTL      time.Duration    // snapshot lifetime; default 30 s
	MaxBytes int64            // cache budget; default 64 MB
	Now      func() time.Time // clock; default time.Now (tests inject a fake)
}

// Stats are cumulative counters (tests and metrics).
type Stats struct {
	Hits, Misses  uint64 // cache lookups
	Compiles      uint64 // snapshots built from the Store
	StrictReloads uint64 // strict path found a different epoch and recompiled
	StrictChecks  uint64 // strict path epoch comparisons
	Entries       int
	Bytes         int64
}

// Engine evaluates permissions. It is safe for concurrent use.
type Engine struct {
	store Store
	ttl   time.Duration
	now   func() time.Time
	cache *cache

	invGen atomic.Uint64 // bumped by every Invalidate; a compile that overlaps one is not cached

	mu       sync.Mutex
	inflight map[cacheKey]*flight

	hits, misses, compiles, strictReloads, strictChecks atomic.Uint64
}

type flight struct {
	done chan struct{}
	snap *snapshot
	err  error
}

// New returns an Engine reading from store.
func New(store Store, opts Options) *Engine {
	e := &Engine{store: store, ttl: opts.TTL, now: opts.Now, cache: newCache(opts.MaxBytes),
		inflight: map[cacheKey]*flight{}}
	if e.ttl <= 0 {
		e.ttl = DefaultTTL
	}
	if e.now == nil {
		e.now = time.Now
	}
	return e
}

// Stats returns the counters.
func (e *Engine) Stats() Stats {
	n, b := e.cache.len()
	return Stats{e.hits.Load(), e.misses.Load(), e.compiles.Load(), e.strictReloads.Load(),
		e.strictChecks.Load(), n, b}
}

// Target selects the snapshots Invalidate evicts. A non-zero Org selects every snapshot of that
// organization; a non-zero User selects every snapshot of that user (all their organizations); both
// zero selects everything.
type Target struct{ Org, User uuid.UUID }

// Invalidate evicts the snapshots selected by t. It is what the NOTIFY listener and the writers call
// (SPEC 12.2): the writer evicts locally before answering so its own reads are consistent.
func (e *Engine) Invalidate(t Target) {
	e.invGen.Add(1)
	e.mu.Lock()
	e.inflight = map[cacheKey]*flight{} // late callers must not join a load that started before the write
	e.mu.Unlock()
	switch {
	case t.Org != uuid.Nil && t.User != uuid.Nil:
		e.cache.evictIf(func(k cacheKey) bool { return k.org == t.Org || k.user == t.User })
	case t.Org != uuid.Nil:
		e.cache.evictIf(func(k cacheKey) bool { return k.org == t.Org })
	case t.User != uuid.Nil:
		e.cache.evictIf(func(k cacheKey) bool { return k.user == t.User })
	default:
		e.cache.evictIf(func(cacheKey) bool { return true })
	}
}

// InvalidateOrg evicts the snapshots of an organization.
func (e *Engine) InvalidateOrg(org uuid.UUID) { e.Invalidate(Target{Org: org}) }

// InvalidateUser evicts the snapshots of a user.
func (e *Engine) InvalidateUser(user uuid.UUID) { e.Invalidate(Target{User: user}) }

// snapshot returns the snapshot of (user, org). strict compares the access epochs with the store and
// recompiles on any difference (SPEC 12.2 strict path).
func (e *Engine) snapshot(ctx context.Context, user, org uuid.UUID, strict bool) (*snapshot, error) {
	k := cacheKey{user, org}
	now := e.now()
	if s := e.cache.get(k, now); s != nil {
		e.hits.Add(1)
		if !strict {
			return s, nil
		}
		e.strictChecks.Add(1)
		ep, err := e.store.Epochs(ctx, user, org)
		if err != nil {
			return nil, err
		}
		if ep == s.epochs {
			return s, nil
		}
		e.strictReloads.Add(1)
		return e.compileNow(ctx, k, now)
	}
	e.misses.Add(1)
	if strict {
		// a fresh compile already reads the current epochs
		return e.compileNow(ctx, k, now)
	}
	return e.loadShared(ctx, k, now)
}

// loadShared compiles once for any number of concurrent callers of the same key.
func (e *Engine) loadShared(ctx context.Context, k cacheKey, now time.Time) (*snapshot, error) {
	e.mu.Lock()
	if f, ok := e.inflight[k]; ok {
		e.mu.Unlock()
		select {
		case <-f.done:
			return f.snap, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	e.inflight[k] = f
	e.mu.Unlock()

	f.snap, f.err = e.compileNow(ctx, k, now)

	e.mu.Lock()
	if e.inflight[k] == f {
		delete(e.inflight, k)
	}
	e.mu.Unlock()
	close(f.done)
	return f.snap, f.err
}

func (e *Engine) compileNow(ctx context.Context, k cacheKey, now time.Time) (*snapshot, error) {
	gen := e.invGen.Load()
	d, err := e.store.LoadAccess(ctx, k.user, k.org)
	if err != nil {
		return nil, err
	}
	if d == nil {
		d = &AccessData{}
	}
	e.compiles.Add(1)
	s := compile(k.user, k.org, d, now, e.ttl)
	if e.invGen.Load() == gen { // no invalidation overlapped the load: safe to share
		e.cache.put(k, s, now)
	}
	return s, nil
}

// Effective resolves user against scope in org (SPEC 5.3). It returns the Access outcome and the effective
// permission set (empty when not a member, suspended, hidden or unresolved). The scope's project must
// belong to org (the caller verifies it, as handlers do today).
func (e *Engine) Effective(ctx context.Context, user, org uuid.UUID, sc Scope) (Access, Set, error) {
	return e.effective(ctx, user, org, sc, false)
}

// EffectiveStrict is Effective on the strict path: epochs are compared with the store first (token
// decisions, SPEC 12.2).
func (e *Engine) EffectiveStrict(ctx context.Context, user, org uuid.UUID, sc Scope) (Access, Set, error) {
	return e.effective(ctx, user, org, sc, true)
}

func (e *Engine) effective(ctx context.Context, user, org uuid.UUID, sc Scope, strict bool) (Access, Set, error) {
	s, err := e.snapshot(ctx, user, org, strict)
	if err != nil {
		return Access{}, Set{}, err
	}
	set, own, hidden := s.scopeSet(sc)
	return s.access(sc, set, own, hidden), set, nil
}

// Can reports whether user holds perm at scope in org. A permission marked sensitive in the catalog takes
// the strict path. An unknown permission is never granted. Errors fail closed (false).
func (e *Engine) Can(ctx context.Context, user, org uuid.UUID, sc Scope, perm string) (bool, error) {
	bit, ok := catalog.Bit(perm)
	if !ok {
		return false, nil
	}
	s, err := e.snapshot(ctx, user, org, sensitives[bit])
	if err != nil {
		return false, err
	}
	return s.has(sc, bit), nil
}

// CanStrict is Can on the strict path whatever the permission (used for tokens "cap_").
func (e *Engine) CanStrict(ctx context.Context, user, org uuid.UUID, sc Scope, perm string) (bool, error) {
	bit, ok := catalog.Bit(perm)
	if !ok {
		return false, nil
	}
	s, err := e.snapshot(ctx, user, org, true)
	if err != nil {
		return false, err
	}
	return s.has(sc, bit), nil
}

// CanAll reports whether user holds every permission of perms. An empty list and an unknown permission
// are both false (fail closed). The strict path is taken if any permission is sensitive.
func (e *Engine) CanAll(ctx context.Context, user, org uuid.UUID, sc Scope, perms ...string) (bool, error) {
	if len(perms) == 0 {
		return false, nil
	}
	var want Set
	strict := false
	for _, p := range perms {
		bit, ok := catalog.Bit(p)
		if !ok {
			return false, nil
		}
		want = want.Union(catalog.NewSet(p))
		strict = strict || sensitives[bit]
	}
	s, err := e.snapshot(ctx, user, org, strict)
	if err != nil {
		return false, err
	}
	set, _, _ := s.scopeSet(sc)
	return set.ContainsAll(want), nil
}

// FilterProjects drops the projects the user cannot see: one pass of bit tests over the list the handler
// already has, no per-project query.
func (e *Engine) FilterProjects(ctx context.Context, user, org uuid.UUID, projects []*domain.Project) ([]*domain.Project, error) {
	s, err := e.snapshot(ctx, user, org, false)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Project, 0, len(projects))
	for _, p := range projects {
		if s.visible(p.ID) {
			out = append(out, p)
		}
	}
	return out, nil
}

// Visibility returns a predicate telling which projects of org the user can see. It is bound to the
// snapshot current at the call: use it for the listing being built, not across requests.
func (e *Engine) Visibility(ctx context.Context, user, org uuid.UUID) (func(project uuid.UUID) bool, error) {
	s, err := e.snapshot(ctx, user, org, false)
	if err != nil {
		return nil, err
	}
	return s.visible, nil
}
