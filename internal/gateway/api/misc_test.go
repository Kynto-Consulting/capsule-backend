package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gateway/store"
)

func quotaOf(org, proj int) store.Quotas {
	return store.Quotas{MaxRandomPorts: org, MaxRandomPortsPerProject: proj}
}

// ---- cgc -----------------------------------------------------------------------------------------

func testSigner(t *testing.T, prev string) *Signer {
	t.Helper()
	s, err := NewSigner("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", prev)
	if err != nil || s == nil {
		t.Fatal(err)
	}
	return s
}

func TestCGCRoundTripAndRules(t *testing.T) {
	s := testSigner(t, "")
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	tok, jti, exp, err := s.Issue("user-1", "shop/db", now, time.Hour) // asked for 1h: capped at 5 min
	if err != nil {
		t.Fatal(err)
	}
	if exp.Sub(now) != 300*time.Second || len(jti) < 16 {
		t.Fatalf("exp %v jti %q", exp.Sub(now), jti)
	}
	c, err := s.Verify(tok, "shop/db", now.Add(time.Second))
	if err != nil || c.Sub != "user-1" || c.Jti != jti {
		t.Fatalf("verify: %v %+v", err, c)
	}
	if _, err := s.Verify(tok, "shop/db", now); !errors.Is(err, ErrCGCReplayed) {
		t.Fatalf("replay: %v", err)
	}
	other, _, _, _ := s.Issue("u", "shop/db", now, 0)
	if _, err := s.Verify(other, "shop/cache", now); !errors.Is(err, ErrCGCRoute) {
		t.Fatalf("route mismatch: %v", err)
	}
	// route mismatch must NOT burn the token: it is still usable on the right route
	if _, err := s.Verify(other, "shop/db", now); err != nil {
		t.Fatalf("token burnt by a wrong-route attempt: %v", err)
	}
	exp1, _, _, _ := s.Issue("u", "shop/db", now, 0)
	if _, err := s.Verify(exp1, "shop/db", now.Add(300*time.Second+31*time.Second)); !errors.Is(err, ErrCGCExpired) {
		t.Fatalf("expired: %v", err)
	}
	within, _, _, _ := s.Issue("u", "shop/db", now, 0)
	if _, err := s.Verify(within, "shop/db", now.Add(300*time.Second+29*time.Second)); err != nil {
		t.Fatalf("30 s tolerance: %v", err)
	}
}

func TestCGCRejectsForgeries(t *testing.T) {
	s := testSigner(t, "")
	now := time.Now()
	tok, _, _, _ := s.Issue("u", "shop/db", now, 0)
	parts := strings.Split(strings.TrimPrefix(tok, CGCPrefix), ".")
	enc := base64.RawURLEncoding.EncodeToString
	// alg none
	hdr := enc([]byte(`{"alg":"none","typ":"cgc"}`))
	if _, err := s.Verify(CGCPrefix+hdr+"."+parts[1]+".", "shop/db", now); err == nil {
		t.Error("alg none accepted")
	}
	// tampered payload keeps the old signature
	pl := enc([]byte(`{"sub":"admin","route":"shop/db","iat":1,"exp":9999999999,"jti":"x"}`))
	if _, err := s.Verify(CGCPrefix+parts[0]+"."+pl+"."+parts[2], "shop/db", now); !errors.Is(err, ErrCGCSignature) {
		t.Errorf("tampered payload: %v", err)
	}
	// a token signed with another key
	_, priv, _ := ed25519.GenerateKey(nil)
	signing := parts[0] + "." + parts[1]
	forged := CGCPrefix + signing + "." + enc(ed25519.Sign(priv, []byte(signing)))
	if _, err := s.Verify(forged, "shop/db", now); !errors.Is(err, ErrCGCSignature) {
		t.Errorf("foreign key: %v", err)
	}
	// lifetime beyond 300 s is malformed even when signed
	long := enc([]byte(`{"sub":"u","route":"shop/db","iat":1000,"exp":2000,"jti":"j"}`))
	sg := ed25519.Sign(priv, []byte(parts[0]+"."+long))
	if _, err := s.Verify(CGCPrefix+parts[0]+"."+long+"."+enc(sg), "shop/db", time.Unix(1500, 0)); err == nil {
		t.Error("lifetime > 300 s accepted")
	}
	for _, bad := range []string{"", "cgc_", "cgc_a.b", "cgc_a.b.c.d", "cap_" + parts[0] + "." + parts[1] + "." + parts[2], "cgc_!!.!!.!!"} {
		if _, err := s.Verify(bad, "shop/db", now); err == nil {
			t.Errorf("malformed %q accepted", bad)
		}
	}
}

func TestSignerRotationAcceptsPreviousKeyAndServesPublicKeys(t *testing.T) {
	old := testSigner(t, "")
	newSeed := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	prevPub := base64.StdEncoding.EncodeToString(old.keys[0].pub)
	rotated, err := NewSigner(newSeed, prevPub)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, _, _, _ := old.Issue("u", "shop/db", now, 0)
	if _, err := rotated.Verify(tok, "shop/db", now); err != nil {
		t.Fatalf("a token signed with the previous key must verify during rotation: %v", err)
	}
	if len(rotated.Keys()) != 2 || rotated.Keys()[0].Kid == rotated.Keys()[1].Kid {
		t.Fatalf("keys: %+v", rotated.Keys())
	}
	if _, err := NewSigner("short", ""); err == nil {
		t.Error("a short seed must be refused")
	}
	if s, err := NewSigner("", ""); s != nil || err != nil {
		t.Error("no seed = no signer, no error")
	}
	if _, err := NewSigner(newSeed, "###"); err == nil {
		t.Error("bad previous key must be refused")
	}
	b, _ := json.Marshal(rotated.Keys())
	if strings.Contains(string(b), newSeed) {
		t.Error("seed leaked")
	}
}

// ---- limiter -------------------------------------------------------------------------------------

func TestLimiterSlidingWindowBlockAndBucket(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(Config{}.WithDefaults(), func() time.Time { return now })
	for i := 0; i < 9; i++ {
		if l.Fail("k") {
			t.Fatalf("blocked too early at %d", i)
		}
		now = now.Add(time.Second)
	}
	if !l.Fail("k") {
		t.Fatal("the 10th failure inside a minute must block")
	}
	if ok, wait := l.Allow("k"); ok || wait <= 0 {
		t.Fatalf("blocked key: ok=%v wait=%v", ok, wait)
	}
	now = now.Add(5*time.Minute + time.Second)
	if ok, _ := l.Allow("k"); !ok {
		t.Fatal("the block must expire after 5 minutes")
	}
	// failures spread over more than a minute never block
	l2 := newLimiter(Config{}.WithDefaults(), func() time.Time { return now })
	for i := 0; i < 30; i++ {
		now = now.Add(7 * time.Second)
		if l2.Fail("slow") {
			t.Fatal("slow failures must not block")
		}
	}
}

// ---- configuration / pool ------------------------------------------------------------------------

func TestParsePool(t *testing.T) {
	if lo, hi, off, err := ParsePool("20000-29999"); err != nil || lo != 20000 || hi != 29999 || off {
		t.Fatalf("default: %v", err)
	}
	for _, off := range []string{"off", "none", "0", "Disabled"} {
		if _, _, o, err := ParsePool(off); err != nil || !o {
			t.Errorf("%q should disable the pool", off)
		}
	}
	for _, bad := range []string{"", "abc", "20000", "29999-20000", "100-2000", "20000-70000", "39000-40500", "40100-40300", "41500-42500", "1-2-3"} {
		if _, _, _, err := ParsePool(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	c := Config{}.WithDefaults()
	if c.PoolLo != 20000 || c.PoolHi != 29999 || c.Zone != "tumi-ai.com" || c.SweepInterval != time.Minute || c.AuthCacheTTL != 30*time.Second {
		t.Fatalf("defaults: %+v", c)
	}
	if big := (Config{AuthCacheTTL: time.Hour}).WithDefaults(); big.AuthCacheTTL != 30*time.Second {
		t.Fatal("the authorization cache hint is capped at 30 s")
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(EnvSecret, "  abc  ")
	t.Setenv(EnvPool, "21000-21999")
	t.Setenv(EnvZone, "example.org")
	t.Setenv(EnvSweepInterval, "5s")
	c, err := ConfigFromEnv()
	if err != nil || c.Secret != "abc" || c.PoolLo != 21000 || c.PoolHi != 21999 || c.Zone != "example.org" || c.SweepInterval != 5*time.Second {
		t.Fatalf("%+v %v", c, err)
	}
	t.Setenv(EnvPool, "40000-40100")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("a pool overlapping the direct ports must be an error")
	}
	t.Setenv(EnvPool, "")
	t.Setenv(EnvSecret, "")
	if c, _ := ConfigFromEnv(); c.Secret != "" || c.PoolLo != 20000 {
		t.Fatalf("unset: %+v", c)
	}
}

func TestSeedPoolUsesConfiguredRangeAndOffSwitch(t *testing.T) {
	st := newFakeStore()
	n, err := SeedPool(context.Background(), st, Config{PoolLo: 25000, PoolHi: 25009})
	if err != nil || n != 10 {
		t.Fatalf("seed: %d %v", n, err)
	}
	if n, _ := SeedPool(context.Background(), st, Config{PoolLo: 25000, PoolHi: 25009}); n != 0 {
		t.Fatal("seeding is idempotent")
	}
	st2 := newFakeStore()
	if n, _ := SeedPool(context.Background(), st2, Config{PoolOff: true}); n != 0 || st2.count("SeedPortPool") != 0 {
		t.Fatal("a disabled pool must not touch the store")
	}
	st3 := newFakeStore()
	_, _ = SeedPool(context.Background(), st3, Config{})
	if st3.count("seed_lo") != 20000 || st3.count("seed_hi") != 29999 {
		t.Fatalf("default range: %d-%d", st3.count("seed_lo"), st3.count("seed_hi"))
	}
}

func TestSweeperRunsPeriodicallyAndStopsOnCancel(t *testing.T) {
	st := newFakeStore()
	st.sweepErr = errors.New("boom") // a failing sweep must not stop the loop
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var woke int32
	go func() {
		RunSweeper(ctx, st, Config{SweepInterval: 10 * time.Millisecond}, nil, func() { atomic.AddInt32(&woke, 1) })
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for (st.count("SweepPool") < 3 || st.count("ReleaseIdle") < 3) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st.count("SweepPool") < 3 || st.count("ReleaseIdle") < 3 {
		t.Fatalf("sweeper did not run repeatedly: sweep=%d idle=%d", st.count("SweepPool"), st.count("ReleaseIdle"))
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the sweeper must stop when its context is cancelled")
	}
	n := st.count("SweepPool")
	time.Sleep(40 * time.Millisecond)
	if st.count("SweepPool") != n {
		t.Fatal("the sweeper kept running after cancellation")
	}
}

// ---- mirroring existing ports and databases -----------------------------------------------------

func TestSyncMirrorsPortsAndDatabasesWithoutChangingTheirBehaviour(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	pid := uuid.New()
	dbID := uuid.New()
	e.src.ports = []*domain.ProjectPort{
		{ID: pid, ProjectID: e.project.ID, Name: "Admin Panel", ContainerPort: 9000, HostPort: 41010},
		{ID: uuid.New(), ProjectID: e.project.ID, Name: "", ContainerPort: 9001, HostPort: 41011},
		{ID: uuid.New(), ProjectID: e.project.ID, Name: "metrics", ContainerPort: 9100, HostPort: 41012, Protocol: domain.ProtoUDP},
	}
	e.src.dbs = []*domain.Database{
		{ID: dbID, OrgID: e.org, Name: "orders", Engine: "mysql", Port: 40020, Status: "available"},
		{ID: uuid.New(), OrgID: e.org, Name: "pending", Engine: "postgres", Port: 0, Status: "provisioning"},
		{ID: uuid.New(), OrgID: e.org, Name: "gone", Engine: "postgres", Port: 40021, Status: "deleted"},
	}
	list, err := e.svc.ListServices(ctx, e.project)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]ServiceView{}
	for _, v := range list {
		by[v.Name] = v
	}
	if len(list) != 4 || by["admin-panel"].ID == uuid.Nil || by["port-9001"].ID == uuid.Nil || by["orders"].ID == uuid.Nil || by["metrics"].Protocol != "udp" {
		t.Fatalf("services: %v", names(list))
	}
	for _, v := range list {
		if v.DefaultAccess != "direct_port" {
			t.Errorf("%s: a mirrored service keeps the direct port as its default, got %s", v.Name, v.DefaultAccess)
		}
		var direct, gw *AccessView
		for i := range v.Accesses {
			switch v.Accesses[i].Kind {
			case "direct_port":
				direct = &v.Accesses[i]
			case "gateway":
				gw = &v.Accesses[i]
			}
		}
		if direct == nil || !direct.Enabled || direct.Port == nil || gw == nil || gw.Enabled {
			t.Errorf("%s: direct on and gateway off expected, got %+v", v.Name, v.Accesses)
		}
		if v.ManagedBy == "" {
			t.Errorf("%s: managed_by missing", v.Name)
		}
	}
	for _, a := range by["admin-panel"].Accesses {
		if a.Kind == "direct_port" && (a.Port == nil || *a.Port != 41010) {
			t.Errorf("direct port must equal the published host port: %+v", by["admin-panel"].Accesses)
		}
	}
	if by["orders"].Protocol != "mysql" {
		t.Errorf("database protocol: %s", by["orders"].Protocol)
	}
	// nothing is routable until someone enables the gateway
	snap, _, _ := e.svc.WaitRoutes(ctx, -1, 0)
	if len(snap.Routes) != 0 {
		t.Fatalf("mirrored services must not create live routes: %+v", snap.Routes)
	}
	// the host port moves (redeploy): the mirror follows, and an enabled gateway route follows too
	on := true
	if _, err := e.svc.UpdateService(ctx, e.project, Actor{UserID: e.admin}, "admin-panel", UpdateInput{GatewayEnabled: &on}); err != nil {
		t.Fatal(err)
	}
	rv, _ := e.st.ResolveService(ctx, e.project.ID, "admin-panel", "tcp")
	if rv.DestHost != "127.0.0.1" || rv.DestPort != 41010 {
		t.Fatalf("route of a mirrored port goes to its published port: %s:%d", rv.DestHost, rv.DestPort)
	}
	e.src.ports[0].HostPort = 41099
	*e.now = e.now.Add(time.Minute)
	if _, err := e.svc.ListServices(ctx, e.project); err != nil {
		t.Fatal(err)
	}
	rv, _ = e.st.ResolveService(ctx, e.project.ID, "admin-panel", "tcp")
	if rv.DestPort != 41099 {
		t.Fatalf("route destination did not follow the host port: %d", rv.DestPort)
	}
	// the port disappears from project_ports: its service goes; a soft-deleted database goes too
	e.src.ports = e.src.ports[1:]
	e.src.dbs[0].Status = "deleted"
	list, _ = e.svc.ListServices(ctx, e.project)
	by = map[string]ServiceView{}
	for _, v := range list {
		by[v.Name] = v
	}
	if _, ok := by["admin-panel"]; ok {
		t.Error("a removed port must disappear")
	}
	if _, ok := by["orders"]; ok {
		t.Error("a deleted database must disappear")
	}
}

func names(l []ServiceView) []string {
	var o []string
	for _, v := range l {
		o = append(o, v.Name)
	}
	return o
}

func TestSyncNamesDoNotCollideWithExistingServices(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.expose("web", "http", 80) // created by API first
	e.src.ports = []*domain.ProjectPort{
		{ID: uuid.New(), ProjectID: e.project.ID, Name: "web", ContainerPort: 3000, HostPort: 41001},
		{ID: uuid.New(), ProjectID: e.project.ID, Name: "web", ContainerPort: 3001, HostPort: 41002},
	}
	list, err := e.svc.ListServices(ctx, e.project)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, v := range list {
		if seen[v.Name] || !store.ValidServiceName(v.Name) {
			t.Fatalf("duplicate or invalid name %q in %v", v.Name, names(list))
		}
		seen[v.Name] = true
	}
	if len(list) != 3 {
		t.Fatalf("want 3 services, got %v", names(list))
	}
}

func TestDeleteOfMirroredServiceOnlyClosesTheGateway(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.src.ports = []*domain.ProjectPort{{ID: uuid.New(), ProjectID: e.project.ID, Name: "admin", ContainerPort: 9000, HostPort: 41010}}
	on := true
	if _, err := e.svc.ListServices(ctx, e.project); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdateService(ctx, e.project, Actor{UserID: e.admin}, "admin", UpdateInput{GatewayEnabled: &on}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteService(ctx, e.project, Actor{UserID: e.admin}, "admin"); err != nil {
		t.Fatal(err)
	}
	list, _ := e.svc.ListServices(ctx, e.project)
	if len(list) != 1 {
		t.Fatalf("the port itself must survive: %v", names(list))
	}
	for _, a := range list[0].Accesses {
		if a.Kind == "direct_port" && !a.Enabled {
			t.Fatal("the direct access must stay as it was")
		}
		if a.Kind == "gateway" && a.Enabled {
			t.Fatal("the gateway access must be closed")
		}
	}
}

func TestDirectPortToggleIsRefusedNotPretended(t *testing.T) {
	e := newEnv(t)
	e.src.ports = []*domain.ProjectPort{{ID: uuid.New(), ProjectID: e.project.ID, Name: "admin", ContainerPort: 9000, HostPort: 41010}}
	off := false
	_, err := e.svc.UpdateService(context.Background(), e.project, Actor{UserID: e.admin}, "admin", UpdateInput{DirectPortEnabled: &off})
	if ee, ok := asError(err); !ok || ee.Status != 400 {
		t.Fatalf("closing the direct port from here must be refused, got %v", err)
	}
	same := true
	if _, err := e.svc.UpdateService(context.Background(), e.project, Actor{UserID: e.admin}, "admin", UpdateInput{DirectPortEnabled: &same, GatewayEnabled: &same}); err != nil {
		t.Fatalf("restating the current value is fine: %v", err)
	}
}

func TestMultiTenantRouteIsolation(t *testing.T) {
	// A token of project A asking for project B's service gets the same "unauthorized" as for a service that does not exist.
	e := newEnv(t)
	ctx := context.Background()
	e.expose("db", "postgres", 5432)
	projB := &domain.Project{ID: uuid.New(), OrgID: uuid.New(), Slug: "other"}
	e.svc.d.Projects.(fakeProjects).m[projB.ID] = projB
	if _, err := e.svc.CreateService(ctx, projB, Actor{UserID: uuid.New()}, CreateInput{Name: "db", Protocol: "postgres", ContainerPort: 5432}); err != nil {
		t.Fatal(err)
	}
	rvB, _ := e.st.ResolveService(ctx, projB.ID, "db", "tcp")
	tokA := e.capToken(e.admin, nil) // admin of org A: not a member of org B
	res := e.authorize(rvB.ID, CredCap, tokA, "203.0.113.1")
	ghost := e.authorize(uuid.New(), CredCap, tokA, "203.0.113.2")
	a, _ := json.Marshal(res)
	b, _ := json.Marshal(ghost)
	if res.Allow || string(a) != string(b) {
		t.Fatalf("cross-project: %s vs not-exists: %s", a, b)
	}
}

func TestSweeperPurgesOrphansAndWakesLongPolls(t *testing.T) {
	st := newFakeStore()
	st.orphans = 2
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	var woke int32
	done := make(chan struct{})
	go func() {
		RunSweeper(ctx, st, Config{SweepInterval: 10 * time.Millisecond}, logger, func() { atomic.AddInt32(&woke, 1) })
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for st.count("PurgeOrphans") < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if st.count("PurgeOrphans") < 2 || atomic.LoadInt32(&woke) < 1 || !strings.Contains(logs.String(), "removed orphan services") {
		t.Fatalf("purge=%d woke=%d logs=%q", st.count("PurgeOrphans"), woke, logs.String())
	}
}
