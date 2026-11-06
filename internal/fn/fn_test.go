package fn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/vpn"
)

const k44 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

type env struct {
	svc       *Service
	org, proj uuid.UUID
	tunnel    *vpn.Tunnel
	now       time.Time
	clock     *time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{org: uuid.New(), proj: uuid.New(), now: time.Date(2026, 11, 5, 1, 0, 0, 0, time.UTC)}
	e.clock = &e.now
	v := &vpn.Service{Store: vpn.NewMemStore(), SecretKey: "unit-test-key-0123456789abcdef", Now: func() time.Time { return *e.clock }}
	e.svc = &Service{Store: NewMemStore(), VPN: v, APIBase: "https://api.example", Now: func() time.Time { return *e.clock }}
	tn, err := v.Create(context.Background(), e.org, e.proj, "u", nil, vpn.Spec{Name: "estudio", Provider: "wireguard", Host: "1.2.3.4:51820",
		CIDRs: []string{"10.48.0.0/24"}, Secret: `{"private_key":"` + k44 + `","peer_public_key":"` + k44 + `","address":"10.99.0.2/32"}`})
	if err != nil {
		t.Fatal(err)
	}
	e.tunnel = tn
	return e
}

func (e *env) deploy(t *testing.T, s Spec) *Function {
	t.Helper()
	if s.Image == "" {
		s.Image = "registry/migrar:1"
	}
	f, err := e.svc.Deploy(context.Background(), e.org, e.proj, nil, s)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSpecNormalize(t *testing.T) {
	s, err := Spec{Name: "migrar", Image: "i", Scopes: []string{"api:importacion"}}.Normalize()
	if err != nil || s.Memory != "512m" || s.Timeout != "1h" || s.MaxConcurrency != 1 || s.CPUs != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	for _, bad := range []Spec{
		{Name: "x", Image: "i", Scopes: []string{"*"}},
		{Name: "x", Image: "i", Scopes: []string{"api:*"}},
		{Name: "x", Image: "i", Scopes: []string{"admin:all"}},
		{Name: "x", Image: "i", Memory: "12"},
		{Name: "x", Image: "i", Memory: "99g"},
		{Name: "x", Image: "i", Timeout: "99h"},
		{Name: "x", Image: "i", Cron: "bad cron"},
		{Name: "x", Image: "i; rm -rf /"},
		{Name: "x", Image: "i", MaxConcurrency: 20},
	} {
		if _, err := bad.Normalize(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: expected invalid, got %v", bad, err)
		}
	}
}

func TestDeployRequiresTunnelOfSameProject(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Deploy(context.Background(), e.org, uuid.New(), nil, Spec{Name: "migrar", Image: "i", VPN: "estudio"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a function must not use another project's tunnel: %v", err)
	}
	f := e.deploy(t, Spec{Name: "migrar", VPN: "estudio", Scopes: []string{"api:importacion", "storage:biblioteca"}})
	if f.VPNID == nil || *f.VPNID != e.tunnel.ID {
		t.Fatal("tunnel not attached")
	}
}

func TestConcurrencyOneByDefault(t *testing.T) {
	e := newEnv(t)
	f := e.deploy(t, Spec{Name: "migrar", VPN: "estudio"})
	ctx := context.Background()
	r1, _ := e.svc.Enqueue(ctx, f, TriggerAPI, "user:ana", nil)
	r2, _ := e.svc.Enqueue(ctx, f, TriggerQueue, "user:ana", nil)
	*e.clock = e.clock.Add(time.Second)
	a1, err := e.svc.Claim(ctx, "nodeA")
	if err != nil || a1 == nil || a1.Run.ID != r1.ID {
		t.Fatalf("first claim: %+v %v", a1, err)
	}
	if a2, _ := e.svc.Claim(ctx, "nodeB"); a2 != nil {
		t.Fatal("second run must wait while the first is running (concurrency 1)")
	}
	if err := e.svc.Finish(ctx, r1.ID, RunSucceeded, nil, 10, 20, "ok"); err != nil {
		t.Fatal(err)
	}
	a2, _ := e.svc.Claim(ctx, "nodeB")
	if a2 == nil || a2.Run.ID != r2.ID {
		t.Fatal("second run should start after the first finished")
	}
}

func TestClaimNeverCarriesTunnelSecretInFunctionEnv(t *testing.T) {
	e := newEnv(t)
	f := e.deploy(t, Spec{Name: "migrar", VPN: "estudio", Scopes: []string{"api:importacion"}})
	ctx := context.Background()
	e.svc.Enqueue(ctx, f, TriggerAPI, "user:ana", nil)
	a, _ := e.svc.Claim(ctx, "n1")
	if a.Tunnel == nil || !strings.Contains(a.Tunnel.Secret, "private_key") {
		t.Fatal("the gateway part must receive the tunnel secret")
	}
	for k, v := range a.Env {
		if strings.Contains(v, k44) || strings.Contains(k, "SECRET") {
			t.Fatalf("function env %s leaks the tunnel secret", k)
		}
	}
	if a.Env["CAPSULE_SCOPES"] != "api:importacion" || !strings.HasPrefix(a.Env["CAPSULE_TOKEN"], TokenPrefix) {
		t.Fatalf("env: %v", a.Env)
	}
}

func TestRunTokenLifecycle(t *testing.T) {
	e := newEnv(t)
	f := e.deploy(t, Spec{Name: "migrar", VPN: "estudio", Timeout: "30m", Scopes: []string{"api:importacion"}})
	ctx := context.Background()
	r, _ := e.svc.Enqueue(ctx, f, TriggerAPI, "user:ana", nil)
	a, _ := e.svc.Claim(ctx, "n1")
	c := e.svc.Introspect(ctx, a.Token)
	if !c.Active || !c.HasScope("api:importacion") || c.HasScope("api:otro") || c.HasScope("storage:biblioteca") || c.Function != "migrar" {
		t.Fatalf("claims %+v", c)
	}
	if want := e.now.Add(35 * time.Minute); !c.ExpiresAt.Equal(want) {
		t.Fatalf("ttl = timeout + 5m, got %v", c.ExpiresAt)
	}
	if e.svc.Introspect(ctx, "capfn_deadbeef").Active || e.svc.Introspect(ctx, "cap_other").Active {
		t.Fatal("unknown tokens must be inactive")
	}
	// expiry
	*e.clock = e.clock.Add(36 * time.Minute)
	if e.svc.Introspect(ctx, a.Token).Active {
		t.Fatal("expired token still active")
	}
	*e.clock = e.clock.Add(-36 * time.Minute)
	// revoked when the run ends
	e.svc.Finish(ctx, r.ID, RunSucceeded, nil, 0, 0, "")
	if e.svc.Introspect(ctx, a.Token).Active {
		t.Fatal("token must die with the run")
	}
}

func TestKillSwitchCancelsRunsAndBlocksClaims(t *testing.T) {
	e := newEnv(t)
	f := e.deploy(t, Spec{Name: "migrar", VPN: "estudio"})
	ctx := context.Background()
	r1, _ := e.svc.Enqueue(ctx, f, TriggerAPI, "u", nil)
	a, _ := e.svc.Claim(ctx, "n1")
	r2, _ := e.svc.Enqueue(ctx, f, TriggerAPI, "u", nil)
	if err := e.svc.DisableTunnel(ctx, e.tunnel, "user:ana"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{r1.ID, r2.ID} {
		if r, _ := e.svc.Store.GetRun(ctx, id); r.Status != RunCancelled {
			t.Fatalf("run %s is %s", id, r.Status)
		}
	}
	if e.svc.Introspect(ctx, a.Token).Active {
		t.Fatal("token must be revoked by the kill switch")
	}
	if _, err := e.svc.Enqueue(ctx, f, TriggerAPI, "u", nil); !errors.Is(err, ErrDisabled) {
		t.Fatalf("enqueue on disabled tunnel: %v", err)
	}
	rep, _ := e.svc.Sync(ctx, []uuid.UUID{r1.ID}, []uuid.UUID{e.tunnel.ID})
	if len(rep.CancelRuns) != 1 || len(rep.StopTunnels) != 1 {
		t.Fatalf("sync %+v", rep)
	}
}

func TestCronFiresOnceAndDoesNotPileUp(t *testing.T) {
	e := newEnv(t) // 2026-11-05 01:00 UTC
	f := e.deploy(t, Spec{Name: "migrar", VPN: "estudio", Cron: "0 2 * * *"})
	ctx := context.Background()
	e.svc.Tick(ctx)
	if q, _ := e.svc.Store.QueuedRuns(ctx, 10); len(q) != 0 {
		t.Fatal("must not fire before 02:00")
	}
	*e.clock = time.Date(2026, 11, 5, 2, 0, 5, 0, time.UTC)
	e.svc.Tick(ctx)
	e.svc.Tick(ctx) // second instance / second minute: no double fire
	q, _ := e.svc.Store.QueuedRuns(ctx, 10)
	if len(q) != 1 || q[0].Trigger != TriggerCron || q[0].TriggeredBy != "cron" {
		t.Fatalf("queued %+v", q)
	}
	// next day while yesterday's run is still queued: no pile up
	*e.clock = time.Date(2026, 11, 6, 2, 0, 5, 0, time.UTC)
	e.svc.Tick(ctx)
	if q, _ := e.svc.Store.QueuedRuns(ctx, 10); len(q) != 1 {
		t.Fatalf("pile up: %d queued", len(q))
	}
	_ = f
}

func TestReapStuckRun(t *testing.T) {
	e := newEnv(t)
	f := e.deploy(t, Spec{Name: "migrar", VPN: "estudio", Timeout: "10m"})
	ctx := context.Background()
	r, _ := e.svc.Enqueue(ctx, f, TriggerAPI, "u", nil)
	e.svc.Claim(ctx, "n1")
	*e.clock = e.clock.Add(16 * time.Minute) // > timeout + grace
	e.svc.Tick(ctx)
	if got, _ := e.svc.Store.GetRun(ctx, r.ID); got.Status != RunTimeout {
		t.Fatalf("status %s", got.Status)
	}
}

func TestRunAudit(t *testing.T) {
	e := newEnv(t)
	f := e.deploy(t, Spec{Name: "migrar", VPN: "estudio", Scopes: []string{"api:importacion"}})
	ctx := context.Background()
	r, _ := e.svc.Enqueue(ctx, f, TriggerAPI, "user:ana", nil)
	e.svc.Claim(ctx, "n1")
	e.svc.Finish(ctx, r.ID, RunSucceeded, nil, 1000, 2000, "")
	ev, _ := e.svc.VPN.Store.Events(ctx, e.tunnel.ID, 10)
	var started, finished string
	for _, x := range ev {
		if x.Kind == vpn.EventRunStarted {
			started = x.Message
		}
		if x.Kind == vpn.EventRunFinished {
			finished = x.Message
		}
	}
	if !strings.Contains(started, "user:ana") || !strings.Contains(started, "api:importacion") || !strings.Contains(finished, "bytes in 1000 out 2000") {
		t.Fatalf("audit: %q / %q", started, finished)
	}
}

func TestDBScopeEnvOnlyWhenDeclared(t *testing.T) {
	e := newEnv(t)
	e.svc.DBs = func(_ context.Context, _ uuid.UUID, name string) (string, error) {
		return "postgres://u:pw@host.docker.internal:5433/" + name, nil
	}
	ctx := context.Background()
	f := e.deploy(t, Spec{Name: "migrar", Scopes: []string{"db:expedientes", "api:importacion"}})
	e.svc.Enqueue(ctx, f, TriggerAPI, "u", nil)
	a, _ := e.svc.Claim(ctx, "n1")
	if a.Env["CAPSULE_DB_EXPEDIENTES"] != "postgres://u:pw@host.docker.internal:5433/expedientes" {
		t.Fatalf("env: %v", a.Env)
	}
	g := e.deploy(t, Spec{Name: "otra", Scopes: []string{"api:importacion"}})
	e.svc.Finish(ctx, a.Run.ID, RunSucceeded, nil, 0, 0, "")
	e.svc.Enqueue(ctx, g, TriggerAPI, "u", nil)
	b, _ := e.svc.Claim(ctx, "n1")
	for k := range b.Env {
		if strings.HasPrefix(k, "CAPSULE_DB_") {
			t.Fatalf("function without db scope got %s", k)
		}
	}
}

func TestStorageScopeEnv(t *testing.T) {
	e := newEnv(t)
	e.svc.Storage = func(_ context.Context, _ uuid.UUID, name string) (map[string]string, error) {
		return map[string]string{"endpoint": "http://host.docker.internal:9000", "bucket": name, "access_key_id": "AK", "secret_access_key": "SK"}, nil
	}
	f := e.deploy(t, Spec{Name: "migrar", Scopes: []string{"storage:biblioteca"}})
	e.svc.Enqueue(context.Background(), f, TriggerAPI, "u", nil)
	a, _ := e.svc.Claim(context.Background(), "n1")
	if a.Env["CAPSULE_STORAGE_BIBLIOTECA_ENDPOINT"] != "http://host.docker.internal:9000" || a.Env["CAPSULE_STORAGE_BIBLIOTECA_SECRET_ACCESS_KEY"] != "SK" {
		t.Fatalf("env %v", a.Env)
	}
}
