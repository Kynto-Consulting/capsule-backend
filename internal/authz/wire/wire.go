// Package wire connects the new permission engine (authz/engine over repository.AccessStore) to authz.Service and the token gate:
// the V2 adapter with the shapes of package authz, the per-organization mode cache, and the start-up sequence (seed of the system
// templates, NOTIFY listener, invalidation).
package wire

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/authz/engine"
	"github.com/kynto/capsule/backend/internal/authz/v2adapter"
	"github.com/kynto/capsule/backend/internal/metrics"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// PolicySource is what OrgModes reads.
type PolicySource interface {
	LoadOrgPolicy(ctx context.Context, orgID uuid.UUID) (*repository.AccessOrgPolicy, error)
}

// OrgModes resolves organizations.access_settings.engine with a short cache (the mode is read on every decision).
type OrgModes struct {
	src PolicySource
	ttl time.Duration
	mu  sync.Mutex
	m   map[uuid.UUID]modeEntry
}

type modeEntry struct {
	mode authz.Mode
	exp  time.Time
}

// NewOrgModes returns a resolver reading src with the given cache lifetime (default 10 s).
func NewOrgModes(src PolicySource, ttl time.Duration) *OrgModes {
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	return &OrgModes{src: src, ttl: ttl, m: map[uuid.UUID]modeEntry{}}
}

// Mode returns the override of the organization ("" when none or unreadable).
func (o *OrgModes) Mode(ctx context.Context, org uuid.UUID) authz.Mode {
	now := time.Now()
	o.mu.Lock()
	if e, ok := o.m[org]; ok && now.Before(e.exp) {
		o.mu.Unlock()
		return e.mode
	}
	o.mu.Unlock()
	var mode authz.Mode
	pol, err := o.src.LoadOrgPolicy(ctx, org)
	if err != nil {
		return "" // failures are not cached: the global mode applies
	}
	var s struct {
		Engine string `json:"engine"`
	}
	if pol != nil && json.Unmarshal(pol.Settings, &s) == nil && s.Engine != "" {
		if m, ok := authz.ParseMode(s.Engine); ok {
			mode = m
		}
	}
	o.mu.Lock()
	if len(o.m) > 4096 {
		o.m = map[uuid.UUID]modeEntry{}
	}
	o.m[org] = modeEntry{mode, now.Add(o.ttl)}
	o.mu.Unlock()
	return mode
}

// Invalidate forgets the cached mode of an organization (uuid.Nil: all).
func (o *OrgModes) Invalidate(org uuid.UUID) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if org == uuid.Nil {
		o.m = map[uuid.UUID]modeEntry{}
		return
	}
	delete(o.m, org)
}

// Runtime is the running engine of the process.
type Runtime struct {
	Engine *engine.Engine
	Store  *repository.AccessStore
	V2     *v2adapter.Adapter
	Modes  *OrgModes
	Global authz.Mode
	Log    *slog.Logger
}

// GlobalModeFromEnv reads CAPSULE_AUTHZ_MODE (v1 | shadow | v2; default v1). An invalid value is v1 and reported by ok=false.
func GlobalModeFromEnv() (authz.Mode, bool) { return authz.ParseMode(os.Getenv("CAPSULE_AUTHZ_MODE")) }

// Start seeds the system templates (after migrations), builds the engine over the real store and starts the NOTIFY listener, which
// evicts snapshots and cached modes. Cancel ctx to stop the listener. Without the seed the engine closes on every decision.
func Start(ctx context.Context, log *slog.Logger, pool *pgxpool.Pool) (*Runtime, error) {
	if _, err := repository.SeedSystemTemplates(ctx, pool); err != nil {
		return nil, fmt.Errorf("seeding system templates: %w", err)
	}
	store := repository.NewAccessStore(pool)
	eng := engine.New(store.EngineStore(), engine.Options{})
	global, ok := GlobalModeFromEnv()
	if !ok {
		log.Warn("CAPSULE_AUTHZ_MODE is not v1|shadow|v2; using v1")
	}
	rt := &Runtime{Engine: eng, Store: store, V2: &v2adapter.Adapter{E: eng}, Modes: NewOrgModes(store, 0), Global: global, Log: log}
	go func() {
		err := store.Listen(ctx, func(org uuid.UUID) {
			if org == uuid.Nil {
				eng.Invalidate(engine.Target{})
			} else {
				eng.Invalidate(engine.Target{Org: org})
			}
			rt.Modes.Invalidate(org)
		})
		if err != nil && ctx.Err() == nil {
			log.Error("access listener stopped", "error", err)
		}
	}()
	return rt, nil
}

// Attach puts the engine behind svc using the global mode, the per-organization override and the shadow settings of the
// environment: CAPSULE_AUTHZ_SHADOW_SAMPLE (0..1, default 1), CAPSULE_AUTHZ_SHADOW_TIMEOUT_MS (default 500) and
// CAPSULE_AUTHZ_SHADOW_MAX_INFLIGHT (default 64).
func (rt *Runtime) Attach(svc *authz.Service) {
	svc.EnableEngine(authz.EngineConfig{
		V2: rt.V2, Global: rt.Global, OrgMode: rt.Modes.Mode, Observer: metrics.AuthzShadow{}, Log: rt.Log,
		SampleRate:  envFloat("CAPSULE_AUTHZ_SHADOW_SAMPLE", 1),
		Timeout:     time.Duration(envFloat("CAPSULE_AUTHZ_SHADOW_TIMEOUT_MS", 500)) * time.Millisecond,
		MaxInFlight: int(envFloat("CAPSULE_AUTHZ_SHADOW_MAX_INFLIGHT", 64)),
	})
}

func envFloat(name string, def float64) float64 {
	if v, err := strconv.ParseFloat(os.Getenv(name), 64); err == nil {
		return v
	}
	return def
}

// Gate builds the token gate for routes: the mode of the token's organization (override, then global) decides how tokens are
// judged, and shadow differences go to the shadow metrics (kind "token") and the log.
func (rt *Runtime) Gate(routes middleware.RouteTable) *middleware.TokenGate {
	return &middleware.TokenGate{
		Routes: routes,
		Mode: func(ctx context.Context, org uuid.UUID) string {
			if org != uuid.Nil {
				if m := rt.Modes.Mode(ctx, org); m != "" {
					return string(m)
				}
			}
			return string(rt.Global)
		},
		Observe: metrics.AuthzShadow{}.ObserveShadow,
		Log:     rt.Log,
	}
}
