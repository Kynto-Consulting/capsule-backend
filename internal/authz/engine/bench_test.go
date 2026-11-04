package engine

import (
	"testing"

	"github.com/google/uuid"
)

// benchWorld: a member with 500 own assignments (project and repo scopes), a warm cache.
type benchWorld struct {
	eng       *Engine
	st        *memStore
	org, user uuid.UUID
	own, free uuid.UUID // a project with own assignments / one that uses the fallback
	repo      uuid.UUID
}

func newBenchWorld(b *testing.B) *benchWorld {
	st := newMemStore()
	w := &benchWorld{st: st, org: st.newOrg("open"), user: st.newUser(), free: uuid.New()}
	st.setMember(w.org, w.user, sysOrgTemplate("member"), true)
	tpls := []tplRef{sysProjectTemplate("viewer"), sysProjectTemplate("deployer"), sysProjectTemplate("admin")}
	for i := 0; i < 500; i++ {
		p := uuid.New()
		if i == 250 {
			w.own = p
		}
		sc, id := ScopeProject, p
		if i%10 == 0 {
			sc, id = ScopeRepo, uuid.New()
			if i == 0 {
				w.repo = id
				w.own = p
			}
		}
		st.assign(w.org, assignOpts{kind: SubjectUser, subject: w.user, scope: sc, scopeID: id, projectID: p, tpl: tpls[i%3]})
	}
	w.eng = New(st, Options{})
	if ok, err := w.eng.Can(ctx, w.user, w.org, ProjectScope(w.free), "deployment:create"); err != nil || !ok {
		b.Fatal("warm-up decision failed")
	}
	return w
}

// BenchmarkCan is the acceptance benchmark: snapshot in cache, 99-permission catalog, user with 500
// assignments. Target <= 200 ns/op and 0 allocs/op. Baselines (P0): Service.Can 326 ns/op, Resolve+RoleAllows 76 ns/op.
func BenchmarkCan(b *testing.B) {
	w := newBenchWorld(b)
	ps := ProjectScope(w.free) // fallback path with base; own-project path is BenchmarkCanOwnProject
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, _ := w.eng.Can(ctx, w.user, w.org, ps, "deployment:create"); !ok {
			b.Fatal("must be allowed")
		}
	}
}

func BenchmarkCanOwnProject(b *testing.B) {
	w := newBenchWorld(b)
	ps := ProjectScope(w.own)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, _ := w.eng.Can(ctx, w.user, w.org, ps, "deployment:read"); !ok {
			b.Fatal("must be allowed")
		}
	}
}

func BenchmarkCanDenied(b *testing.B) {
	w := newBenchWorld(b)
	ps := ProjectScope(w.free)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, _ := w.eng.Can(ctx, w.user, w.org, ps, "project:delete"); ok {
			b.Fatal("must be denied")
		}
	}
}

func BenchmarkCanParallel(b *testing.B) {
	w := newBenchWorld(b)
	ps := ProjectScope(w.own)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if ok, _ := w.eng.Can(ctx, w.user, w.org, ps, "deployment:read"); !ok {
				b.Error("must be allowed")
				return
			}
		}
	})
}

// BenchmarkCanSensitive includes the strict path: one Epochs lookup in the (in-memory) store.
func BenchmarkCanSensitive(b *testing.B) {
	w := newBenchWorld(b)
	ps := ProjectScope(w.free)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.eng.Can(ctx, w.user, w.org, ps, "project:delete")
	}
}

func BenchmarkEffectiveRepo(b *testing.B) {
	w := newBenchWorld(b)
	sc := RepoScope(w.own, w.repo)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, set, _ := w.eng.Effective(ctx, w.user, w.org, sc); set.IsEmpty() {
			b.Fatal("empty")
		}
	}
}

func BenchmarkExplain(b *testing.B) {
	w := newBenchWorld(b)
	ps := ProjectScope(w.own)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d, _ := w.eng.Explain(ctx, w.user, w.org, ps, "deployment:read"); !d.Allowed {
			b.Fatal("must be allowed")
		}
	}
}

// BenchmarkCompile10k: SPEC 12.3, 10 000 assignments and 5 000 projects, budget 50 ms.
func BenchmarkCompile10k(b *testing.B) {
	st := newMemStore()
	org, user := st.newOrg("restricted"), st.newUser()
	st.setMember(org, user, sysOrgTemplate("member"), true)
	var projects []uuid.UUID
	for i := 0; i < 5000; i++ {
		projects = append(projects, uuid.New())
	}
	tpls := []tplRef{sysProjectTemplate("viewer"), sysProjectTemplate("deployer"), sysProjectTemplate("admin")}
	for i := 0; i < 10000; i++ {
		p := projects[i%len(projects)]
		st.assign(org, assignOpts{kind: SubjectUser, subject: user, scope: ScopeProject, scopeID: p, projectID: p, tpl: tpls[i%3]})
	}
	d, _ := st.LoadAccess(ctx, user, org)
	now := newClock().Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compile(user, org, d, now, DefaultTTL)
	}
}
