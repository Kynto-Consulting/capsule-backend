package wire

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/v2adapter"
	"github.com/kynto/capsule/backend/internal/domain"
)

type fakeOld struct {
	oa     *authz.OrgAccess
	grants []authz.Grant
}

func (f fakeOld) LoadOrgAccess(context.Context, uuid.UUID, uuid.UUID) (*authz.OrgAccess, error) {
	return f.oa, nil
}
func (f fakeOld) UserGrants(context.Context, uuid.UUID) ([]authz.Grant, error) { return f.grants, nil }

type recObs struct {
	mu                       sync.Mutex
	total, mismatch, skipped int
}

func (r *recObs) ObserveShadow(_ string, _ time.Duration, mm bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.total++
	if mm {
		r.mismatch++
	}
}
func (r *recObs) ObserveShadowSkipped(string, string) { r.mu.Lock(); r.skipped++; r.mu.Unlock() }
func (r *recObs) snap() (int, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total, r.mismatch, r.skipped
}

// The exhaustive matrix of MIGRATION 5.1 at Service level: org role x mode x explicit row x EVERY action (the 23 old ones and
// every atom of the catalog), old Service vs the Service with the new engine deciding (v2). 0 differences.
func TestServiceV1VersusV2Exhaustive(t *testing.T) {
	ctx := context.Background()
	user, org, project := uuid.New(), uuid.New(), uuid.New()
	var actions []authz.Action
	for _, a := range authz.AllActions {
		actions = append(actions, a)
	}
	actions = append(actions, authz.GitActions...)
	actions = append(actions, authz.ProjectConnect)
	for _, p := range catalog.All() {
		actions = append(actions, authz.Action(p.ID))
	}
	roles := []string{"owner", "admin", "member", "readonly", "", "bogus"}
	modes := []string{"open", "restricted", ""}
	explicit := []string{"", "viewer", "deployer", "admin", "bogus"}
	cases := 0
	for _, role := range roles {
		for _, mode := range modes {
			for _, ex := range explicit {
				var oa *authz.OrgAccess
				if role != "" {
					oa = &authz.OrgAccess{OrgRole: role, Mode: mode, Explicit: map[uuid.UUID]string{}}
					if ex != "" {
						oa.Explicit[project] = ex
					}
				}
				old := authz.New(fakeOld{oa: oa})
				nw := authz.New(fakeOld{oa: oa})
				nw.EnableEngine(authz.EngineConfig{V2: v2adapter.NewLegacyV2(fakeOld{oa: oa}), Global: authz.ModeV2})
				ao, _ := old.Access(ctx, user, org, project)
				an, _ := nw.Access(ctx, user, org, project)
				if ao != an {
					t.Errorf("role=%q mode=%q explicit=%q: Access old %+v new %+v", role, mode, ex, ao, an)
				}
				for _, a := range actions {
					if authz.IsAtom(a) {
						// the new Check is the reference for atoms; the old side extends the legacy matrix (allowV1)
					}
					oo, _ := old.Check(ctx, user, org, project, a)
					on, _ := nw.Check(ctx, user, org, project, a)
					cases++
					if oo.Allowed != on.Allowed || oo.Access.Member != on.Access.Member || oo.Access.Hidden != on.Access.Hidden {
						t.Errorf("role=%q mode=%q explicit=%q action=%s: old %+v new %+v", role, mode, ex, a, oo, on)
					}
					bo, _ := old.Can(ctx, user, org, project, a)
					bn, _ := nw.Can(ctx, user, org, project, a)
					if bo != bn {
						t.Errorf("Can role=%q mode=%q explicit=%q action=%s: old %t new %t", role, mode, ex, a, bo, bn)
					}
				}
				ps := []*domain.Project{{ID: project}, {ID: uuid.New()}}
				fo, _ := old.FilterProjects(ctx, user, org, ps)
				fn, _ := nw.FilterProjects(ctx, user, org, ps)
				if len(fo) != len(fn) {
					t.Errorf("FilterProjects role=%q mode=%q explicit=%q: old %d new %d", role, mode, ex, len(fo), len(fn))
				}
				vo, _ := old.Visibility(ctx, user, org)
				vn, _ := nw.Visibility(ctx, user, org)
				for _, p := range ps {
					if vo(p.ID) != vn(p.ID) {
						t.Errorf("Visibility role=%q mode=%q explicit=%q", role, mode, ex)
					}
				}
			}
		}
	}
	t.Logf("%d (combination x action) decisions equal between v1 and v2", cases)
}

// fakeV2 is a V2 whose behaviour the shadow tests control.
type fakeV2 struct {
	check func(ctx context.Context) (authz.Outcome, error)
	calls atomic.Int64
}

func (f *fakeV2) Check(ctx context.Context, _, _, _ uuid.UUID, _ authz.Action) (authz.Outcome, error) {
	f.calls.Add(1)
	return f.check(ctx)
}
func (f *fakeV2) Access(ctx context.Context, _, _, _ uuid.UUID) (authz.Access, error) {
	o, err := f.check(ctx)
	return o.Access, err
}
func (f *fakeV2) FilterProjects(context.Context, uuid.UUID, uuid.UUID, []*domain.Project) ([]*domain.Project, error) {
	return nil, errors.New("x")
}
func (f *fakeV2) Visibility(context.Context, uuid.UUID, uuid.UUID) (func(uuid.UUID) bool, error) {
	return nil, errors.New("x")
}
func (f *fakeV2) Explain(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, authz.Action) string {
	return "fake"
}

func shadowSvc(f *fakeV2, obs *recObs, timeout time.Duration, inflight int) *authz.Service {
	oa := &authz.OrgAccess{OrgRole: "member", Mode: "open"}
	s := authz.New(fakeOld{oa: oa})
	s.EnableEngine(authz.EngineConfig{V2: f, Global: authz.ModeShadow, Observer: obs, Log: slog.New(slog.NewTextHandler(discard{}, nil)),
		Timeout: timeout, MaxInFlight: inflight})
	return s
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// Shadow never changes the answer nor fails the request: mismatching engine, erroring engine, panicking engine, hanging engine.
func TestShadowNeverAffectsTheResponse(t *testing.T) {
	ctx := context.Background()
	u, o, p := uuid.New(), uuid.New(), uuid.New()
	want, _ := authz.New(fakeOld{oa: &authz.OrgAccess{OrgRole: "member", Mode: "open"}}).Check(ctx, u, o, p, authz.ProjectDeploy)
	if !want.Allowed {
		t.Fatal("fixture: member must deploy")
	}

	t.Run("mismatch is counted and the old answer stands", func(t *testing.T) {
		obs := &recObs{}
		s := shadowSvc(&fakeV2{check: func(context.Context) (authz.Outcome, error) { return authz.Outcome{}, nil }}, obs, time.Second, 8)
		got, err := s.Check(ctx, u, o, p, authz.ProjectDeploy)
		if err != nil || got != want {
			t.Fatalf("response changed: %+v %v", got, err)
		}
		waitFor(t, func() bool { tot, mm, _ := obs.snap(); return tot == 1 && mm == 1 })
	})
	t.Run("engine error is ignored", func(t *testing.T) {
		obs := &recObs{}
		s := shadowSvc(&fakeV2{check: func(context.Context) (authz.Outcome, error) { return authz.Outcome{}, errors.New("db down") }}, obs, time.Second, 8)
		got, err := s.Check(ctx, u, o, p, authz.ProjectDeploy)
		if err != nil || got != want {
			t.Fatalf("response changed: %+v %v", got, err)
		}
		waitFor(t, func() bool { _, _, sk := obs.snap(); return sk == 1 })
	})
	t.Run("panic is recovered", func(t *testing.T) {
		obs := &recObs{}
		s := shadowSvc(&fakeV2{check: func(context.Context) (authz.Outcome, error) { panic("boom") }}, obs, time.Second, 8)
		got, err := s.Check(ctx, u, o, p, authz.ProjectDeploy)
		if err != nil || got != want {
			t.Fatalf("response changed: %+v %v", got, err)
		}
		waitFor(t, func() bool { _, _, sk := obs.snap(); return sk == 1 })
		if got2, _ := s.Check(ctx, u, o, p, authz.ProjectDeploy); got2 != want {
			t.Fatal("service broken after a recovered panic")
		}
	})
	t.Run("a hanging engine adds no latency and is cut by the timeout", func(t *testing.T) {
		obs := &recObs{}
		s := shadowSvc(&fakeV2{check: func(c context.Context) (authz.Outcome, error) {
			<-c.Done()
			return authz.Outcome{}, c.Err()
		}}, obs, 50*time.Millisecond, 8)
		start := time.Now()
		got, _ := s.Check(ctx, u, o, p, authz.ProjectDeploy)
		if d := time.Since(start); d > 20*time.Millisecond || got != want {
			t.Fatalf("shadow slowed or changed the request: %v %+v", d, got)
		}
		waitFor(t, func() bool { _, _, sk := obs.snap(); return sk == 1 })
	})
	t.Run("concurrency is bounded: excess comparisons are dropped, never queued", func(t *testing.T) {
		obs := &recObs{}
		release := make(chan struct{})
		f := &fakeV2{check: func(context.Context) (authz.Outcome, error) { <-release; return want, nil }}
		s := shadowSvc(f, obs, 5*time.Second, 2)
		start := time.Now()
		for i := 0; i < 50; i++ {
			s.Check(ctx, u, o, p, authz.ProjectDeploy)
		}
		if time.Since(start) > 200*time.Millisecond {
			t.Fatal("requests waited on the shadow")
		}
		waitFor(t, func() bool { _, _, sk := obs.snap(); return sk == 48 })
		waitFor(t, func() bool { return f.calls.Load() >= 2 })
		if f.calls.Load() != 2 {
			t.Fatalf("%d concurrent comparisons, want 2", f.calls.Load())
		}
		close(release)
	})
}

// Sampling: with rate 0.25 about a quarter of the decisions are compared.
func TestShadowSampling(t *testing.T) {
	obs := &recObs{}
	f := &fakeV2{check: func(context.Context) (authz.Outcome, error) {
		return authz.Outcome{Access: authz.Access{Member: true, Role: "deployer", Source: "inherited"}, Allowed: true}, nil
	}}
	s := authz.New(fakeOld{oa: &authz.OrgAccess{OrgRole: "member", Mode: "open"}})
	s.EnableEngine(authz.EngineConfig{V2: f, Global: authz.ModeShadow, Observer: obs, SampleRate: 0.25, MaxInFlight: 1000})
	for i := 0; i < 4000; i++ {
		s.Check(context.Background(), uuid.New(), uuid.New(), uuid.New(), authz.ProjectDeploy)
	}
	time.Sleep(500 * time.Millisecond) // let the bounded comparisons finish
	tot, _, _ := obs.snap()
	if tot < 800 || tot > 1200 {
		t.Fatalf("sampled %d of 4000 with rate 0.25", tot)
	}
}

// Per-organization override wins over the global mode.
func TestOrgModeOverride(t *testing.T) {
	ctx := context.Background()
	v2 := &fakeV2{check: func(context.Context) (authz.Outcome, error) { return authz.Outcome{}, nil }} // denies everything
	s := authz.New(fakeOld{oa: &authz.OrgAccess{OrgRole: "member", Mode: "open"}})
	orgV2, orgOther := uuid.New(), uuid.New()
	s.EnableEngine(authz.EngineConfig{V2: v2, Global: authz.ModeV1, OrgMode: func(_ context.Context, o uuid.UUID) authz.Mode {
		if o == orgV2 {
			return authz.ModeV2
		}
		return ""
	}})
	if ok, _ := s.Can(ctx, uuid.New(), orgOther, uuid.New(), authz.ProjectDeploy); !ok {
		t.Error("global v1 must use the legacy decision")
	}
	if ok, _ := s.Can(ctx, uuid.New(), orgV2, uuid.New(), authz.ProjectDeploy); ok {
		t.Error("org override v2 must use the new engine")
	}
	if got := s.ModeFor(ctx, orgV2); got != authz.ModeV2 {
		t.Errorf("ModeFor = %s", got)
	}
}
