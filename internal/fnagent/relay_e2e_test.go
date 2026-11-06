package fnagent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/server/handlers"
	"github.com/kynto/capsule/backend/internal/vpn"
	"github.com/kynto/capsule/backend/internal/vpn/gateway"
)

// relayDial is what the SDK does inside a Lambda: an HTTP upgrade to the Capsule API with the run token and the destination.
func relayDial(relayURL, token, dest string) (net.Conn, int, error) {
	host := strings.TrimPrefix(relayURL, "http://")
	host, path, _ := strings.Cut(host, "/")
	c, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		return nil, 0, err
	}
	fmt.Fprintf(c, "POST /%s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nX-Capsule-Dest: %s\r\nConnection: Upgrade\r\nUpgrade: capsule-relay\r\nContent-Length: 0\r\n\r\n", path, host, token, dest)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		c.Close()
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		c.Close()
		return nil, resp.StatusCode, nil
	}
	return bufConn{c, br}, 101, nil
}

// fakeLambdaAPI plays AWS Lambda: Invoke runs the "function" in-process, exactly as its handler would with the event.
type fakeLambdaAPI struct {
	mu     sync.Mutex
	run    func(p fn.InvokePayload) string
	events []fn.InvokePayload
	made   []string
}

func (f *fakeLambdaAPI) CreateFunction(_ context.Context, in *lambda.CreateFunctionInput, _ ...func(*lambda.Options)) (*lambda.CreateFunctionOutput, error) {
	f.mu.Lock()
	f.made = append(f.made, *in.FunctionName)
	f.mu.Unlock()
	return &lambda.CreateFunctionOutput{}, nil
}
func (f *fakeLambdaAPI) UpdateFunctionCode(context.Context, *lambda.UpdateFunctionCodeInput, ...func(*lambda.Options)) (*lambda.UpdateFunctionCodeOutput, error) {
	return nil, fmt.Errorf("not found")
}
func (f *fakeLambdaAPI) UpdateFunctionConfiguration(context.Context, *lambda.UpdateFunctionConfigurationInput, ...func(*lambda.Options)) (*lambda.UpdateFunctionConfigurationOutput, error) {
	return &lambda.UpdateFunctionConfigurationOutput{}, nil
}
func (f *fakeLambdaAPI) DeleteFunction(context.Context, *lambda.DeleteFunctionInput, ...func(*lambda.Options)) (*lambda.DeleteFunctionOutput, error) {
	return &lambda.DeleteFunctionOutput{}, nil
}
func (f *fakeLambdaAPI) Invoke(_ context.Context, in *lambda.InvokeInput, _ ...func(*lambda.Options)) (*lambda.InvokeOutput, error) {
	var p fn.InvokePayload
	_ = json.Unmarshal(in.Payload, &p)
	f.mu.Lock()
	f.events = append(f.events, p)
	f.mu.Unlock()
	return &lambda.InvokeOutput{Payload: []byte(f.run(p))}, nil
}

func TestLambdaReachesTheTunnelThroughTheRelayEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// customer network behind WireGuard
	gwPriv, gwPub := genKey(t)
	rPriv, rPub := genKey(t)
	gwPort, rPort := freeUDP(t), freeUDP(t)
	file := bytes.Repeat([]byte("PDF-DEL-ESTUDIO-"), 40000) // ~640 KB
	customerNetwork(t, rPriv, gwPub, gwPort, rPort, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(file) }))

	// Capsule backend: real handlers (including the relay) over in-memory stores
	vs := &vpn.Service{Store: vpn.NewMemStore(), SecretKey: "unit-test-key-0123456789abcdef"}
	ms := fn.NewMemStore()
	relay := gateway.NewRelay()
	relay.Wait = 10 * time.Second
	api := &fakeLambdaAPI{}
	fs := &fn.Service{Store: ms, VPN: vs, Relay: relay, Lambda: &fn.LambdaExecutor{API: api, Account: "123"}, RelayWait: 20 * time.Second}
	h := handlers.NewVPNFnHandler(nil, nil, vs, fs)
	h.SetRelay(relay)
	r := chi.NewRouter()
	r.Post("/api/v1/fn/tokens/introspect", h.Introspect)
	r.Post("/api/v1/fn/agent/claim", h.AgentClaim)
	r.Post("/api/v1/fn/agent/sync", h.AgentSync)
	r.Post("/api/v1/fn/agent/runs/{runID}/finish", h.AgentFinish)
	r.Post("/api/v1/fn/agent/tunnels/{tunnelID}/status", h.AgentTunnelStatus)
	r.Post("/api/v1/fn/relay/node/{tunnelID}", h.RelayNode)
	r.Post("/api/v1/fn/relay/connect", h.RelayConnect)
	backend := httptest.NewServer(r)
	defer backend.Close()
	fs.APIBase = backend.URL
	nodeTok, nodeHash := fn.NewToken(fn.NodeTokPrefix)
	ms.Nodes[nodeHash] = "node-test"

	org, proj := uuid.New(), uuid.New()
	secret, _ := json.Marshal(vpn.WGSecret{PrivateKey: gwPriv, PeerPublicKey: rPub, Address: "10.99.0.2/32"})
	tn, err := vs.Create(ctx, org, proj, "user:ana", nil, vpn.Spec{Name: "estudio", Provider: "wireguard", Host: fmt.Sprintf("127.0.0.1:%d", rPort),
		CIDRs: []string{"10.99.0.0/24"}, Secret: string(secret)})
	if err != nil {
		t.Fatal(err)
	}
	f, err := fs.Deploy(ctx, org, proj, nil, fn.Spec{Name: "migrar", Image: "123.dkr.ecr/migrar:1", Runtime: "lambda", VPN: "estudio", Timeout: "2h", Scopes: []string{"api:importacion"}})
	if err != nil {
		t.Fatal(err)
	}

	// the "function": batch 0 downloads the file through the relay and asks to continue; batch 1 checks that its previous
	// token is dead, that a destination outside the declared networks is refused and finishes.
	var (
		mu                                    sync.Mutex
		downloaded                            int
		outsideStatus, badTokenStatus         int
		previousTokenStatus, secondBatchTok   int
		tokens                                []string
		sawSecret                             bool
	)
	api.run = func(p fn.InvokePayload) string {
		mu.Lock()
		defer mu.Unlock()
		tok := p.Env["CAPSULE_TOKEN"]
		tokens = append(tokens, tok)
		for k, v := range p.Env {
			if strings.Contains(v, gwPriv) || strings.Contains(k, "PRIVATE") {
				sawSecret = true
			}
		}
		relayURL := p.Env["CAPSULE_VPN_RELAY"]
		if p.Attempt == 0 {
			hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
				c, code, err := relayDial(relayURL, tok, addr)
				if err != nil || c == nil {
					return nil, fmt.Errorf("relay refused: %d %v", code, err)
				}
				return c, nil
			}}}
			resp, err := hc.Get("http://10.99.0.1:8080/biblioteca/expediente.pdf")
			if err == nil {
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				downloaded = len(b)
			}
			_, outsideStatus, _ = relayDial(relayURL, tok, "8.8.8.8:53")
			_, badTokenStatus, _ = relayDial(relayURL, "capfn_"+strings.Repeat("0", 64), "10.99.0.1:8080")
			return `{"continue":{"offset":640000}}`
		}
		_, previousTokenStatus, _ = relayDial(relayURL, tokens[0], "10.99.0.1:8080")
		c, code, _ := relayDial(relayURL, tok, "10.99.0.1:8080")
		secondBatchTok = code
		if c != nil {
			c.Close()
		}
		return `{}`
	}

	// the work node (outbound only) keeps the tunnel up and attached to the relay
	ag := &Agent{Client: &Client{Base: backend.URL, Token: nodeTok}, Runner: blockRunner{}, Mgr: NewManager(), SocksRoot: shortTemp(t), Poll: 100 * time.Millisecond}
	var denied []string
	var dmu sync.Mutex
	ag.Mgr.Audit = func(_ uuid.UUID, target, reason string) { dmu.Lock(); denied = append(denied, target+" "+reason); dmu.Unlock() }
	go ag.Loop(ctx)
	defer ag.Mgr.Stop(tn.ID)

	// dispatcher (the backend ticker)
	go func() {
		for ctx.Err() == nil {
			_ = fs.DispatchLambda(ctx)
			time.Sleep(100 * time.Millisecond)
		}
	}()

	run, err := fs.Enqueue(ctx, f, fn.TriggerAPI, "user:ana", json.RawMessage(`{"lote":1}`))
	if err != nil {
		t.Fatal(err)
	}
	var got *fn.Run
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		got, _ = ms.GetRun(ctx, run.ID)
		if got.Status != fn.RunQueued && got.Status != fn.RunRunning {
			break
		}
	}
	if got.Status != fn.RunSucceeded {
		t.Fatalf("run %s log:\n%s", got.Status, got.LogTail)
	}
	mu.Lock()
	defer mu.Unlock()
	if downloaded != len(file) {
		t.Fatalf("the Lambda downloaded %d bytes through the relay, want %d", downloaded, len(file))
	}
	if len(tokens) != 2 || tokens[0] == tokens[1] {
		t.Fatalf("two batches with different tokens expected: %v", tokens)
	}
	if outsideStatus != http.StatusForbidden {
		t.Fatalf("a destination outside the declared networks must be refused: %d", outsideStatus)
	}
	if badTokenStatus != http.StatusUnauthorized || previousTokenStatus != http.StatusUnauthorized {
		t.Fatalf("a bad or previous-batch token must be refused: %d %d", badTokenStatus, previousTokenStatus)
	}
	if secondBatchTok != 101 {
		t.Fatalf("the current batch's token must work: %d", secondBatchTok)
	}
	if sawSecret {
		t.Fatal("the function must never receive tunnel credentials")
	}
	if got.BytesIn < int64(len(file)) {
		t.Fatalf("bytes_in %d < file %d (counted by the relay)", got.BytesIn, len(file))
	}
	if got.NodeID != "node-test" {
		t.Fatalf("the run must belong to the node that owns the tunnel: %q", got.NodeID)
	}
	// the denial is audited on the tunnel with the function and run that tried it
	ev, _ := vs.Store.Events(ctx, tn.ID, 50)
	found := false
	for _, e := range ev {
		if e.Kind == vpn.EventDeniedTarget && strings.Contains(e.Message, "8.8.8.8:53") && strings.Contains(e.Message, "migrar") && strings.Contains(e.Message, run.ID.String()) {
			found = true
		}
	}
	if !found {
		t.Fatalf("denied target not audited: %+v", ev)
	}
	// all of the run's tokens are dead and nothing can be opened with them any more
	if c, code, _ := relayDial(backend.URL+"/api/v1/fn/relay/connect", tokens[1], "10.99.0.1:8080"); c != nil || code != http.StatusUnauthorized {
		t.Fatalf("token alive after the run: %d", code)
	}
	if len(api.made) != 1 || api.made[0] != fn.LambdaName(f) {
		t.Fatalf("lambda created: %v", api.made)
	}
}
