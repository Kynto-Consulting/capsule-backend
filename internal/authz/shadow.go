package authz

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/domain"
)

// Mode says which engine decides (docs/permissions/MIGRATION.md F2-F3).
//
//	v1      the legacy decision (Resolve over project_members). Default. The new engine is not consulted.
//	shadow  the legacy decision answers; the new engine computes the same decision in parallel (asynchronously, sampled, bounded in
//	        time and concurrency) and differences are counted and logged. It never changes a response nor makes one slower.
//	v2      the new engine decides.
//
// The mode is global (CAPSULE_AUTHZ_MODE) and can be overridden per organization (organizations.access_settings.engine).
type Mode string

const (
	ModeV1     Mode = "v1"
	ModeShadow Mode = "shadow"
	ModeV2     Mode = "v2"
)

// ParseMode validates a mode name; the empty string is v1.
func ParseMode(s string) (Mode, bool) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case "", ModeV1:
		return ModeV1, true
	case ModeShadow:
		return ModeShadow, true
	case ModeV2:
		return ModeV2, true
	}
	return ModeV1, false
}

// Outcome is one decision: how the user relates to the project and whether the action is allowed.
type Outcome struct {
	Access  Access
	Allowed bool
}

// V2 is the new engine seen with the shapes of this package (the adapter lives in authz/wire; the engine itself cannot be imported
// here because it depends on this package). act may be an old action ("project.read") or an atom ("deployment:create").
type V2 interface {
	Check(ctx context.Context, user, org, project uuid.UUID, act Action) (Outcome, error)
	Access(ctx context.Context, user, org, project uuid.UUID) (Access, error)
	FilterProjects(ctx context.Context, user, org uuid.UUID, projects []*domain.Project) ([]*domain.Project, error)
	Visibility(ctx context.Context, user, org uuid.UUID) (func(uuid.UUID) bool, error)
	// Explain is a short, non sensitive description of why the engine decided what it did (cause, scopes and template slugs).
	Explain(ctx context.Context, user, org, project uuid.UUID, act Action) string
}

// ShadowObserver receives the shadow measurements (metrics authz_shadow_total, authz_shadow_mismatch_total, authz_shadow_seconds).
type ShadowObserver interface {
	ObserveShadow(kind string, d time.Duration, mismatch bool)
	ObserveShadowSkipped(kind, reason string)
}

// EngineConfig wires the new engine behind a Service.
type EngineConfig struct {
	V2     V2
	Global Mode
	// OrgMode returns the per-organization override ("" = none). It must be cheap (cached) and may be nil.
	OrgMode func(ctx context.Context, org uuid.UUID) Mode
	// Observer and Log receive shadow results; both may be nil.
	Observer ShadowObserver
	Log      *slog.Logger
	// SampleRate is the fraction of decisions compared in shadow mode (0..1, default 1).
	SampleRate float64
	// Timeout bounds one shadow computation (default 500 ms); MaxInFlight bounds concurrent ones (default 64): beyond it the
	// comparison is dropped, never queued.
	Timeout     time.Duration
	MaxInFlight int
}

type engineWiring struct {
	cfg EngineConfig
	sem chan struct{}
}

// EnableEngine puts the new engine behind the Service. Without it every decision is legacy (v1).
func (s *Service) EnableEngine(cfg EngineConfig) {
	if cfg.Global == "" {
		cfg.Global = ModeV1
	}
	if cfg.SampleRate <= 0 || cfg.SampleRate > 1 {
		cfg.SampleRate = 1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 500 * time.Millisecond
	}
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = 64
	}
	s.x = &engineWiring{cfg: cfg, sem: make(chan struct{}, cfg.MaxInFlight)}
}

// ModeFor returns the mode in force for an organization.
func (s *Service) ModeFor(ctx context.Context, org uuid.UUID) Mode {
	if s.x == nil {
		return ModeV1
	}
	return s.x.modeFor(ctx, org)
}

func (w *engineWiring) modeFor(ctx context.Context, org uuid.UUID) (m Mode) {
	m = w.cfg.Global
	if w.cfg.OrgMode == nil || org == uuid.Nil {
		return m
	}
	defer func() {
		if recover() != nil {
			m = w.cfg.Global
		}
	}()
	if o := w.cfg.OrgMode(ctx, org); o == ModeV1 || o == ModeShadow || o == ModeV2 {
		return o
	}
	return m
}

type routeKey struct{}

// WithRoute records the route pattern in the context so shadow logs can name it.
func WithRoute(ctx context.Context, route string) context.Context {
	return context.WithValue(ctx, routeKey{}, route)
}

func routeOf(ctx context.Context) string {
	r, _ := ctx.Value(routeKey{}).(string)
	return r
}

// IsAtom reports whether a is an atomic permission ("deployment:create") rather than an old action ("project.read").
func IsAtom(a Action) bool { return strings.Contains(string(a), ":") }

// Atoms returns the atoms a must hold: itself, or the expansion of the old action (nil for an unknown action).
func Atoms(a Action) []string {
	if IsAtom(a) {
		if catalog.Has(string(a)) {
			return []string{string(a)}
		}
		return nil
	}
	return catalog.Expand(a)
}

// allowV1 is the legacy decision of an action, extended to atoms: an atom is allowed when some old action the role holds contains it.
// For the system roles this equals the engine (TestSystemTemplatesMatchLegacyMatrix proves the exact union).
var (
	atomOnce sync.Once
	atomOld  map[string][]Action // atom -> old actions that contain it
)

func allowV1(role Role, a Action) bool {
	if !IsAtom(a) {
		return RoleAllows(role, a)
	}
	atomOnce.Do(func() {
		atomOld = map[string][]Action{}
		for _, old := range catalog.OldActions() {
			for _, at := range catalog.Expand(Action(old)) {
				atomOld[at] = append(atomOld[at], Action(old))
			}
		}
	})
	for _, old := range atomOld[string(a)] {
		if RoleAllows(role, old) {
			return true
		}
	}
	return false
}

// Check resolves the user against the project and decides act in ONE evaluation (what handlers need). Access.Member false means
// "not a member", Access.Hidden means the project must not be revealed; otherwise Allowed says whether act is permitted.
func (s *Service) Check(ctx context.Context, userID, orgID, projectID uuid.UUID, act Action) (Outcome, error) {
	if s.x == nil {
		return s.checkV1(ctx, userID, orgID, projectID, act)
	}
	switch s.x.modeFor(ctx, orgID) {
	case ModeV2:
		return s.x.cfg.V2.Check(ctx, userID, orgID, projectID, act)
	case ModeShadow:
		o, err := s.checkV1(ctx, userID, orgID, projectID, act)
		if err == nil {
			s.shadow(ctx, "check", userID, orgID, projectID, act, func(c context.Context) (bool, string, string) {
				n, err := s.x.cfg.V2.Check(c, userID, orgID, projectID, act)
				if err != nil {
					return false, "", "error"
				}
				if n.Access.Member != o.Access.Member || n.Access.Hidden != o.Access.Hidden || n.Allowed != o.Allowed {
					return true, fmt.Sprintf("member=%t hidden=%t allowed=%t", o.Access.Member, o.Access.Hidden, o.Allowed) + " -> " +
						fmt.Sprintf("member=%t hidden=%t allowed=%t", n.Access.Member, n.Access.Hidden, n.Allowed), ""
				}
				return false, "", ""
			})
		}
		return o, err
	}
	return s.checkV1(ctx, userID, orgID, projectID, act)
}

func (s *Service) checkV1(ctx context.Context, userID, orgID, projectID uuid.UUID, act Action) (Outcome, error) {
	acc, err := s.accessV1(ctx, userID, orgID, projectID)
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Access: acc, Allowed: acc.Member && !acc.Hidden && allowV1(acc.Role, act)}, nil
}

// Access resolves userID against a project of orgID.
func (s *Service) Access(ctx context.Context, userID, orgID, projectID uuid.UUID) (Access, error) {
	if s.x == nil {
		return s.accessV1(ctx, userID, orgID, projectID)
	}
	switch s.x.modeFor(ctx, orgID) {
	case ModeV2:
		return s.x.cfg.V2.Access(ctx, userID, orgID, projectID)
	case ModeShadow:
		a, err := s.accessV1(ctx, userID, orgID, projectID)
		if err == nil {
			s.shadow(ctx, "access", userID, orgID, projectID, "", func(c context.Context) (bool, string, string) {
				n, err := s.x.cfg.V2.Access(c, userID, orgID, projectID)
				if err != nil {
					return false, "", "error"
				}
				if n != a {
					return true, fmt.Sprintf("%+v -> %+v", a, n), ""
				}
				return false, "", ""
			})
		}
		return a, err
	}
	return s.accessV1(ctx, userID, orgID, projectID)
}

// FilterProjects drops the projects the user cannot see.
func (s *Service) FilterProjects(ctx context.Context, userID, orgID uuid.UUID, projects []*domain.Project) ([]*domain.Project, error) {
	if s.x == nil {
		return s.filterProjectsV1(ctx, userID, orgID, projects)
	}
	switch s.x.modeFor(ctx, orgID) {
	case ModeV2:
		return s.x.cfg.V2.FilterProjects(ctx, userID, orgID, projects)
	case ModeShadow:
		out, err := s.filterProjectsV1(ctx, userID, orgID, projects)
		if err == nil {
			s.shadow(ctx, "filter", userID, orgID, uuid.Nil, "", func(c context.Context) (bool, string, string) {
				n, err := s.x.cfg.V2.FilterProjects(c, userID, orgID, projects)
				if err != nil {
					return false, "", "error"
				}
				if !sameProjects(out, n) {
					return true, fmt.Sprintf("visible %d -> %d", len(out), len(n)), ""
				}
				return false, "", ""
			})
		}
		return out, err
	}
	return s.filterProjectsV1(ctx, userID, orgID, projects)
}

func sameProjects(a, b []*domain.Project) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			return false
		}
	}
	return true
}

// Visibility returns a predicate telling which projects of orgID the user can see. In shadow mode the legacy predicate answers and
// the new one is compared on the first projects it is asked about.
func (s *Service) Visibility(ctx context.Context, userID, orgID uuid.UUID) (func(projectID uuid.UUID) bool, error) {
	if s.x == nil {
		return s.visibilityV1(ctx, userID, orgID)
	}
	switch s.x.modeFor(ctx, orgID) {
	case ModeV2:
		return s.x.cfg.V2.Visibility(ctx, userID, orgID)
	case ModeShadow:
		old, err := s.visibilityV1(ctx, userID, orgID)
		if err != nil {
			return nil, err
		}
		asked := make(chan uuid.UUID, 8)
		wrapped := func(p uuid.UUID) bool {
			v := old(p)
			select {
			case asked <- p:
				s.shadow(ctx, "visibility", userID, orgID, p, "", func(c context.Context) (bool, string, string) {
					nv, err := s.x.cfg.V2.Visibility(c, userID, orgID)
					if err != nil {
						return false, "", "error"
					}
					if nv(p) != v {
						return true, fmt.Sprintf("visible=%t -> %t", v, !v), ""
					}
					return false, "", ""
				})
			default:
			}
			return v
		}
		return wrapped, nil
	}
	return s.visibilityV1(ctx, userID, orgID)
}

// shadow runs cmp asynchronously: sampled, with its own timeout (not the request's context, which ends with the response), a bound
// on concurrent comparisons (excess is dropped), and recovery from panics. cmp returns (mismatch, "old -> new", skipReason); a
// non-empty skipReason means the comparison could not be made (engine error) and is only counted as skipped.
func (s *Service) shadow(ctx context.Context, kind string, user, org, project uuid.UUID, act Action, cmp func(context.Context) (bool, string, string)) {
	w := s.x
	if w.cfg.SampleRate < 1 && rand.Float64() >= w.cfg.SampleRate {
		return
	}
	select {
	case w.sem <- struct{}{}:
	default:
		if w.cfg.Observer != nil {
			w.cfg.Observer.ObserveShadowSkipped(kind, "busy")
		}
		return
	}
	route := routeOf(ctx)
	go func() {
		defer func() { <-w.sem }()
		defer func() {
			if r := recover(); r != nil {
				if w.cfg.Observer != nil {
					w.cfg.Observer.ObserveShadowSkipped(kind, "panic")
				}
			}
		}()
		c, cancel := context.WithTimeout(context.Background(), w.cfg.Timeout)
		defer cancel()
		start := time.Now()
		mismatch, detail, skip := cmp(c)
		d := time.Since(start)
		if skip != "" {
			if w.cfg.Observer != nil {
				w.cfg.Observer.ObserveShadowSkipped(kind, skip)
			}
			return
		}
		if w.cfg.Observer != nil {
			w.cfg.Observer.ObserveShadow(kind, d, mismatch)
		}
		if mismatch && w.cfg.Log != nil {
			explain := w.cfg.V2.Explain(c, user, org, project, act)
			w.cfg.Log.Warn("authz shadow mismatch", "kind", kind, "route", route, "permission", string(act),
				"user", user, "org", org, "project", project, "decision", detail, "explain", explain)
		}
	}()
}

var legacyFactory func(Store) V2

// RegisterLegacyFactory registers the builder of the new engine over a legacy Store (authz/wire/legacyv2, test binaries only).
// With it registered and CAPSULE_AUTHZ_MODE=v2|shadow, New wires the engine behind every Service it returns.
func RegisterLegacyFactory(f func(Store) V2) { legacyFactory = f }

func envMode() Mode {
	m, _ := ParseMode(os.Getenv("CAPSULE_AUTHZ_MODE"))
	return m
}
