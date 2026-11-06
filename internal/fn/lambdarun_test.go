package fn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/google/uuid"
)

type fakeRelay struct {
	mu      sync.Mutex
	idle    int
	closed  []string
	dropped []string
	in, out int64
}

func (r *fakeRelay) Idle(string) int { r.mu.Lock(); defer r.mu.Unlock(); return r.idle }
func (r *fakeRelay) Bytes(string) (int64, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.in, r.out
}
func (r *fakeRelay) CloseRun(id string)      { r.mu.Lock(); r.closed = append(r.closed, id); r.mu.Unlock() }
func (r *fakeRelay) Forget(string)           {}
func (r *fakeRelay) DropTunnel(id string)    { r.mu.Lock(); r.dropped = append(r.dropped, id); r.mu.Unlock() }
func (r *fakeRelay) wasClosed(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.closed {
		if c == id {
			return true
		}
	}
	return false
}

// blockLambda never answers: the invocation ends only when its context is cancelled (kill switch / cancel).
type blockLambda struct {
	fakeLambda
	started chan struct{}
}

func (b *blockLambda) Invoke(ctx context.Context, _ *lambda.InvokeInput, _ ...func(*lambda.Options)) (*lambda.InvokeOutput, error) {
	close(b.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func waitRun(t *testing.T, e *env, id uuid.UUID, want string) *Run {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, _ := e.svc.Store.GetRun(context.Background(), id)
		if r != nil && r.Status == want {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("run %s: status %q, want %q", id, r.Status, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLambdaRuntimeIsOptInAndNeedsRelayForTunnels(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Deploy(context.Background(), e.org, e.proj, nil, Spec{Name: "migrar", Image: "i", Runtime: "lambda"}); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("lambda must be refused while it is not enabled: %v", err)
	}
	e.svc.Lambda = e.lambda(&fakeLambda{})
	if _, err := e.svc.Deploy(context.Background(), e.org, e.proj, nil, Spec{Name: "migrar", Image: "i", Runtime: "lambda", VPN: "estudio"}); err == nil || !strings.Contains(err.Error(), "relay") {
		t.Fatalf("lambda with a tunnel needs the relay: %v", err)
	}
	if _, err := e.svc.Deploy(context.Background(), e.org, e.proj, nil, Spec{Name: "x", Image: "i", Runtime: "wasm"}); err == nil {
		t.Fatal("unknown runtime must be refused")
	}
	f, err := e.svc.Deploy(context.Background(), e.org, e.proj, nil, Spec{Name: "solo", Image: "i", Runtime: "lambda"})
	if err != nil || f.Runtime != RuntimeLambda {
		t.Fatalf("%+v %v", f, err)
	}
	g := e.deploy(t, Spec{Name: "cont", Image: "i"})
	if g.Runtime != RuntimeContainer {
		t.Fatalf("default runtime must stay container, got %q", g.Runtime)
	}
}

func TestLambdaRunBatchesWithFreshTokensAndNodesNeverClaimIt(t *testing.T) {
	e := newEnv(t)
	api := &fakeLambda{replies: []string{`{"continue":{"i":1}}`, `{"continue":{"i":2}}`, `{}`}}
	e.svc.Lambda = e.lambda(api)
	ctx := context.Background()
	f := e.deploy(t, Spec{Name: "migrar", Runtime: "lambda", Scopes: []string{"api:importacion"}, Timeout: "2h"})
	run, _ := e.svc.Enqueue(ctx, f, TriggerAPI, "user:ana", json.RawMessage(`{"lote":7}`))

	if a, _ := e.svc.Claim(ctx, "nodo-1"); a != nil {
		t.Fatal("a node must never claim a lambda run")
	}
	if err := e.svc.DispatchLambda(ctx); err != nil {
		t.Fatal(err)
	}
	got := waitRun(t, e, run.ID, RunSucceeded)
	if got.NodeID != "lambda" {
		t.Fatalf("node %q", got.NodeID)
	}
	if len(api.payloads) != 3 {
		t.Fatalf("batches: %d", len(api.payloads))
	}
	seen := map[string]bool{}
	for i, p := range api.payloads {
		tok := p.Env["CAPSULE_TOKEN"]
		if !strings.HasPrefix(tok, TokenPrefix) || seen[tok] {
			t.Fatalf("batch %d needs its own token: %q", i, tok)
		}
		seen[tok] = true
		if _, ok := p.Env["CAPSULE_PAYLOAD"]; ok || string(p.Payload) != `{"lote":7}` {
			t.Fatalf("payload must travel in the invoke payload: %+v", p)
		}
		if p.Env["CAPSULE_SCOPES"] != "api:importacion" {
			t.Fatalf("scopes %q", p.Env["CAPSULE_SCOPES"])
		}
		if _, ok := p.Env["CAPSULE_VPN_RELAY"]; ok {
			t.Fatal("no relay address for a function without a tunnel")
		}
	}
	// every token is dead once the run is over; the previous batch's token died when the next one was minted
	for tok := range seen {
		if e.svc.Introspect(ctx, tok).Active {
			t.Fatal("token still active after the run")
		}
	}
	// secrets never in the Lambda's environment variables (visible in the AWS console)
	for _, c := range api.created {
		if c.Environment != nil {
			t.Fatal("lambda environment must stay empty")
		}
	}
}

func TestLambdaPreviousBatchTokenIsRevokedWhenTheNextIsMinted(t *testing.T) {
	e := newEnv(t)
	e.svc.Lambda = e.lambda(&fakeLambda{})
	f := e.deploy(t, Spec{Name: "migrar", Runtime: "lambda"})
	ctx := context.Background()
	run, _ := e.svc.Enqueue(ctx, f, TriggerAPI, "u", nil)
	e.svc.Store.TryStart(ctx, run.ID, "lambda", e.svc.now())
	run, _ = e.svc.Store.GetRun(ctx, run.ID)
	api := &fakeLambda{replies: []string{`{"continue":1}`, `{}`}}
	var first string
	var introspectAfter bool
	e.svc.Lambda = e.lambda(&hookLambda{fakeLambda: api, before: func(n int, p InvokePayload) {
		if n == 0 {
			first = p.Env["CAPSULE_TOKEN"]
		}
		if n == 1 {
			introspectAfter = e.svc.Introspect(ctx, first).Active
		}
	}})
	e.svc.executeLambda(ctx, f, run)
	if introspectAfter {
		t.Fatal("the first batch's token must be revoked when the second is minted")
	}
}

type hookLambda struct {
	*fakeLambda
	before func(n int, p InvokePayload)
}

func (h *hookLambda) Invoke(ctx context.Context, in *lambda.InvokeInput, o ...func(*lambda.Options)) (*lambda.InvokeOutput, error) {
	var p InvokePayload
	_ = json.Unmarshal(in.Payload, &p)
	h.before(len(h.fakeLambda.payloads), p)
	return h.fakeLambda.Invoke(ctx, in, o...)
}

func lambdaTunnelEnv(t *testing.T, api LambdaAPI) (*env, *fakeRelay, *Function) {
	e := newEnv(t)
	rl := &fakeRelay{idle: 1}
	e.svc.Lambda = e.lambda(api)
	e.svc.Relay = rl
	e.svc.RelayWait = 300 * time.Millisecond
	e.svc.Store.(*MemStore).Nodes["h1"] = "nodo-1"
	e.svc.Store.(*MemStore).Nodes["h2"] = "nodo-2"
	f := e.deploy(t, Spec{Name: "migrar", Runtime: "lambda", VPN: "estudio", Scopes: []string{"api:importacion"}})
	return e, rl, f
}

func TestLambdaWithTunnelIsOwnedByTheLiveNode(t *testing.T) {
	api := &blockLambda{started: make(chan struct{})}
	e, rl, f := lambdaTunnelEnv(t, api)
	ctx := context.Background()
	run, _ := e.svc.Enqueue(ctx, f, TriggerAPI, "user:ana", nil)

	// no node reported yet: nobody could own the tunnel, the run waits
	if err := e.svc.DispatchLambda(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.svc.Store.GetRun(ctx, run.ID); r.Status != RunQueued {
		t.Fatalf("run must wait for a live node, got %s", r.Status)
	}

	mem := e.svc.Store.(*MemStore)
	mem.NodeByHash(ctx, "h2") // nodo-2 reports
	if err := e.svc.DispatchLambda(ctx); err != nil {
		t.Fatal(err)
	}
	<-api.started
	r := waitRun(t, e, run.ID, RunRunning)
	if r.NodeID != "nodo-2" {
		t.Fatalf("the run belongs to the node that was alive: %q", r.NodeID)
	}
	// only that node is told to keep the tunnel and attach it to the relay, and only it may attach
	if rep, _ := e.svc.Sync(ctx, "nodo-1", nil, nil); len(rep.Relay) != 0 {
		t.Fatalf("another node must not receive the tunnel: %+v", rep.Relay)
	}
	rep, _ := e.svc.Sync(ctx, "nodo-2", nil, nil)
	if len(rep.Relay) != 1 || rep.Relay[0].ID != e.tunnel.ID || !strings.Contains(rep.Relay[0].Secret, "private_key") {
		t.Fatalf("owner node: %+v", rep.Relay)
	}
	if e.svc.NodeServesTunnel(ctx, "nodo-1", e.tunnel.ID) || !e.svc.NodeServesTunnel(ctx, "nodo-2", e.tunnel.ID) {
		t.Fatal("NodeServesTunnel must follow the run's node")
	}
	// the function receives the token and the relay address, never the tunnel credentials
	tg, tn, ok := e.svc.RelayTarget(ctx, "capfn_nope")
	_ = tg
	if ok || tn != nil {
		t.Fatal("an unknown token must not resolve to a tunnel")
	}

	// kill switch: the run is cancelled, the relay drops its connections and idle node connections
	if err := e.svc.DisableTunnel(ctx, e.tunnel, "user:ana"); err != nil {
		t.Fatal(err)
	}
	waitRun(t, e, run.ID, RunCancelled)
	if !rl.wasClosed(run.ID.String()) || len(rl.dropped) != 1 || rl.dropped[0] != e.tunnel.ID.String() {
		t.Fatalf("relay not cut: closed=%v dropped=%v", rl.closed, rl.dropped)
	}
	if rep, _ := e.svc.Sync(ctx, "nodo-2", nil, []uuid.UUID{e.tunnel.ID}); len(rep.Relay) != 0 || len(rep.StopTunnels) != 1 {
		t.Fatalf("after the kill switch the node must stop the tunnel: %+v", rep)
	}
}

func TestLambdaTunnelEnvCarriesRelayAddressAndRunTokenAuthorizesOnlyItsTunnel(t *testing.T) {
	api := &fakeLambda{replies: []string{`{}`}}
	e, rl, f := lambdaTunnelEnv(t, api)
	rl.in, rl.out = 4096, 100 // what the relay counted: it overrides what the function reports
	ctx := context.Background()
	e.svc.Store.(*MemStore).NodeByHash(ctx, "h1")
	var claims Claims
	var target string
	e.svc.Lambda = e.lambda(&hookLambda{fakeLambda: api, before: func(_ int, p InvokePayload) {
		c, tn, ok := e.svc.RelayTarget(ctx, p.Env["CAPSULE_TOKEN"])
		if ok {
			claims, target = c, tn.Name
		}
	}})
	run, _ := e.svc.Enqueue(ctx, f, TriggerAPI, "user:ana", nil)
	if err := e.svc.DispatchLambda(ctx); err != nil {
		t.Fatal(err)
	}
	got := waitRun(t, e, run.ID, RunSucceeded)
	if target != "estudio" || claims.RunID != run.ID {
		t.Fatalf("token did not resolve to its tunnel: %q %+v", target, claims)
	}
	if got.BytesIn != 4096 || got.BytesOut != 100 {
		t.Fatalf("bytes must be the relay's: %d/%d", got.BytesIn, got.BytesOut)
	}
	if v := api.payloads[0].Env["CAPSULE_VPN_RELAY"]; v != "https://api.example/api/v1/fn/relay/connect" {
		t.Fatalf("relay address %q", v)
	}
	for k, v := range api.payloads[0].Env {
		if strings.Contains(v, k44) || strings.Contains(k, "PRIVATE") {
			t.Fatalf("env %s leaks tunnel credentials", k)
		}
	}
}

func TestLambdaRunFailsWhenTheNodeNeverAttaches(t *testing.T) {
	api := &fakeLambda{}
	e, rl, f := lambdaTunnelEnv(t, api)
	rl.idle = 0
	ctx := context.Background()
	e.svc.Store.(*MemStore).NodeByHash(ctx, "h1")
	run, _ := e.svc.Enqueue(ctx, f, TriggerAPI, "u", nil)
	e.svc.DispatchLambda(ctx)
	got := waitRun(t, e, run.ID, RunFailed)
	if !strings.Contains(got.LogTail, "did not attach") || len(api.payloads) != 0 {
		t.Fatalf("log %q, invocations %d", got.LogTail, len(api.payloads))
	}
}

func TestLambdaLogTailIsMaskedAndDeleteRemovesTheLambda(t *testing.T) {
	api := &fakeLambda{replies: []string{`{}`}}
	e := newEnv(t)
	e.svc.Lambda = e.lambda(&logLambda{fakeLambda: api})
	ctx := context.Background()
	f := e.deploy(t, Spec{Name: "migrar", Runtime: "lambda"})
	run, _ := e.svc.Enqueue(ctx, f, TriggerAPI, "u", nil)
	e.svc.DispatchLambda(ctx)
	got := waitRun(t, e, run.ID, RunSucceeded)
	if strings.Contains(got.LogTail, "capfn_") || !strings.Contains(got.LogTail, "***") {
		t.Fatalf("the run token must be masked in the log: %q", got.LogTail)
	}
	api.exists = true
	if err := e.svc.Delete(ctx, f); err != nil {
		t.Fatal(err)
	}
	if len(api.deleted) != 1 || api.deleted[0] != "capsule-fn-"+strings.ReplaceAll(f.ID.String(), "-", "")[:12] {
		t.Fatalf("deleted %v", api.deleted)
	}
	if _, err := e.svc.Store.GetFunction(ctx, e.proj, "migrar"); err == nil {
		t.Fatal("function row must be gone")
	}
}

// logLambda answers like Lambda with LogType=Tail: the function printed its own token.
type logLambda struct{ *fakeLambda }

func (l *logLambda) Invoke(ctx context.Context, in *lambda.InvokeInput, o ...func(*lambda.Options)) (*lambda.InvokeOutput, error) {
	var p InvokePayload
	_ = json.Unmarshal(in.Payload, &p)
	out, err := l.fakeLambda.Invoke(ctx, in, o...)
	if err == nil {
		line := "token " + p.Env["CAPSULE_TOKEN"] + "\n"
		enc := base64Std(line)
		out.LogResult = &enc
	}
	return out, err
}

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// lambda builds the executor on the test clock, like the service, so deadlines are consistent.
func (e *env) lambda(api LambdaAPI) *LambdaExecutor {
	return &LambdaExecutor{API: api, Account: "123", Now: func() time.Time { return *e.clock }}
}
