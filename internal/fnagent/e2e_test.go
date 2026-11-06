package fnagent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/server/handlers"
	"github.com/kynto/capsule/backend/internal/vpn"
	"github.com/kynto/capsule/backend/internal/vpn/gateway"
)

func genKey(t *testing.T) (priv, pub string) {
	t.Helper()
	var k [32]byte
	rand.Read(k[:])
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, _ := curve25519.X25519(k[:], curve25519.Basepoint)
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p)
}

func freeUDP(t *testing.T) int {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// customerNetwork is a WireGuard peer that serves a "file server" on 10.99.0.1:8080 inside the tunnel.
func customerNetwork(t *testing.T, priv, gwPub string, gwPort, port int, h http.Handler) {
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.99.0.1")}, nil, 1380)
	if err != nil {
		t.Fatal(err)
	}
	d := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	hx := func(k string) string { b, _ := base64.StdEncoding.DecodeString(k); return hex.EncodeToString(b) }
	if err := d.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=10.99.0.2/32\n", hx(priv), port, hx(gwPub), gwPort)); err != nil {
		t.Fatal(err)
	}
	d.Up()
	l, _ := tnet.ListenTCP(&net.TCPAddr{Port: 8080})
	srv := &http.Server{Handler: h}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close(); d.Close() })
}

// fakeContainer plays the `migrar` function: it reads a file from the customer network through ctx.vpn (the SOCKS socket)
// and uploads it to the app with ctx.api (bearer capfn_, resumable parts).
type fakeContainer struct {
	t       *testing.T
	appURL  string
	mu      sync.Mutex
	specs   []ContainerSpec
	outside error
}

func (c *fakeContainer) Run(ctx context.Context, s ContainerSpec, logs io.Writer) (int, error) {
	c.mu.Lock()
	c.specs = append(c.specs, s)
	c.mu.Unlock()
	sock := filepath.Join(s.SocksDir, "socks.sock")
	// the function never sees tunnel credentials
	for k, v := range s.Env {
		if strings.Contains(k+v, "private_key") {
			return 99, nil
		}
	}
	hc := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return gateway.SocksDial(ctx, "unix", sock, addr)
	}}}
	resp, err := hc.Get("http://10.99.0.1:8080/biblioteca/expediente.pdf")
	if err != nil {
		fmt.Fprintln(logs, "vpn get failed:", err)
		return 1, nil
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// no other way out to the customer network or anywhere else through the tunnel
	_, c.outside = gateway.SocksDial(ctx, "unix", sock, "8.8.8.8:53")
	fmt.Fprintf(logs, "token=%s downloaded %d bytes\n", s.Env["CAPSULE_TOKEN"], len(data))
	const part = 256 << 10
	for off := 0; off < len(data); off += part {
		end := min(off+part, len(data))
		req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/importacion/parts?offset=%d", c.appURL, off), bytes.NewReader(data[off:end]))
		req.Header.Set("Authorization", "Bearer "+s.Env["CAPSULE_TOKEN"])
		r, err := http.DefaultClient.Do(req)
		if err != nil || r.StatusCode != 200 {
			fmt.Fprintln(logs, "upload failed")
			return 2, nil
		}
		r.Body.Close()
	}
	// scope not granted to this function: the app must refuse
	req, _ := http.NewRequest("PUT", c.appURL+"/biblioteca/store", strings.NewReader("x"))
	req.Header.Set("Authorization", "Bearer "+s.Env["CAPSULE_TOKEN"])
	if r, _ := http.DefaultClient.Do(req); r == nil || r.StatusCode != 403 {
		return 3, nil
	}
	return 0, nil
}

func TestEndToEndWireGuardMigration(t *testing.T) {
	ctx := context.Background()
	// 1. customer network behind WireGuard
	gwPriv, gwPub := genKey(t)
	rPriv, rPub := genKey(t)
	gwPort, rPort := freeUDP(t), freeUDP(t)
	file := bytes.Repeat([]byte("PDF-DEL-ESTUDIO-"), 40000) // ~640 KB
	customerNetwork(t, rPriv, gwPub, gwPort, rPort, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(file) }))

	// 2. Capsule backend (real handlers, in-memory stores)
	vs := &vpn.Service{Store: vpn.NewMemStore(), SecretKey: "unit-test-key-0123456789abcdef"}
	ms := fn.NewMemStore()
	fs := &fn.Service{Store: ms, VPN: vs}
	h := handlers.NewVPNFnHandler(nil, nil, vs, fs)
	r := chi.NewRouter()
	r.Post("/api/v1/fn/tokens/introspect", h.Introspect)
	r.Post("/api/v1/fn/agent/claim", h.AgentClaim)
	r.Post("/api/v1/fn/agent/sync", h.AgentSync)
	r.Post("/api/v1/fn/agent/runs/{runID}/finish", h.AgentFinish)
	r.Post("/api/v1/fn/agent/tunnels/{tunnelID}/status", h.AgentTunnelStatus)
	backend := httptest.NewServer(r)
	defer backend.Close()
	nodeTok, nodeHash := fn.NewToken(fn.NodeTokPrefix)
	ms.Nodes[nodeHash] = "node-test"

	// 3. the customer's app: validates capfn_ tokens against Capsule and enforces scopes
	var recvMu sync.Mutex
	var received []byte
	introspect := func(tok string) fn.Claims {
		b, _ := json.Marshal(map[string]string{"token": tok})
		resp, err := http.Post(backend.URL+"/api/v1/fn/tokens/introspect", "application/json", bytes.NewReader(b))
		if err != nil {
			return fn.Claims{}
		}
		defer resp.Body.Close()
		var c fn.Claims
		json.NewDecoder(resp.Body).Decode(&c)
		return c
	}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c := introspect(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "))
		need := "api:importacion"
		if strings.HasPrefix(req.URL.Path, "/biblioteca") {
			need = "storage:biblioteca"
		}
		if !c.HasScope(need) {
			http.Error(w, "forbidden", 403)
			return
		}
		body, _ := io.ReadAll(req.Body)
		recvMu.Lock()
		received = append(received, body...)
		recvMu.Unlock()
	}))
	defer app.Close()

	// 4. project setup through the services (what `capsule vpn create` and `capsule fn deploy` do through the API)
	org, proj := uuid.New(), uuid.New()
	secret, _ := json.Marshal(vpn.WGSecret{PrivateKey: gwPriv, PeerPublicKey: rPub, Address: "10.99.0.2/32"})
	tn, err := vs.Create(ctx, org, proj, "user:ana", nil, vpn.Spec{Name: "estudio", Provider: "wireguard", Host: fmt.Sprintf("127.0.0.1:%d", rPort),
		CIDRs: []string{"10.99.0.0/24"}, Secret: string(secret)})
	if err != nil {
		t.Fatal(err)
	}
	f, err := fs.Deploy(ctx, org, proj, nil, fn.Spec{Name: "migrar", Image: "capsule/migrar:1", VPN: "estudio", Memory: "512m", Timeout: "10m",
		Scopes: []string{"api:importacion"}}) // storage:biblioteca is NOT granted
	if err != nil {
		t.Fatal(err)
	}
	run, err := fs.Enqueue(ctx, f, fn.TriggerAPI, "user:ana", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 5. the work node: outbound only
	fc := &fakeContainer{t: t, appURL: app.URL}
	mgr := NewManager()
	var deniedMu sync.Mutex
	var denied []string
	mgr.Audit = func(_ uuid.UUID, target, reason string) {
		deniedMu.Lock()
		denied = append(denied, target+" "+reason)
		deniedMu.Unlock()
	}
	ag := &Agent{Client: &Client{Base: backend.URL, Token: nodeTok}, Runner: fc, Mgr: mgr, SocksRoot: shortTemp(t), MaxParallel: 1}
	ag.running = map[uuid.UUID]context.CancelFunc{}
	var wg sync.WaitGroup
	ag.Tick(ctx, &wg)
	wg.Wait()
	defer mgr.Stop(tn.ID)

	got, _ := ms.GetRun(ctx, run.ID)
	if got.Status != fn.RunSucceeded {
		t.Fatalf("run %s exit=%v log:\n%s", got.Status, got.ExitCode, got.LogTail)
	}
	recvMu.Lock()
	if !bytes.Equal(received, file) {
		t.Fatalf("app received %d bytes, want %d", len(received), len(file))
	}
	recvMu.Unlock()
	if got.BytesIn < int64(len(file)) {
		t.Fatalf("bytes_in %d < file %d", got.BytesIn, len(file))
	}
	if fc.outside == nil {
		t.Fatal("traffic outside the declared networks must be refused by the gateway")
	}
	deniedMu.Lock()
	if len(denied) != 1 || !strings.HasPrefix(denied[0], "8.8.8.8:53") {
		t.Fatalf("denied audit: %v", denied)
	}
	deniedMu.Unlock()
	if strings.Contains(got.LogTail, fc.specs[0].Env["CAPSULE_TOKEN"]) || !strings.Contains(got.LogTail, "***") {
		t.Fatalf("log must hide the run token: %q", got.LogTail)
	}
	if fc.specs[0].MemoryMB != 512 {
		t.Fatalf("memory limit not passed: %d", fc.specs[0].MemoryMB)
	}
	if introspect(fc.specs[0].Env["CAPSULE_TOKEN"]).Active {
		t.Fatal("token must be dead after the run")
	}
	// health reported by the gateway and audit trail
	st, _ := vs.Store.GetByID(ctx, tn.ID)
	if st.Status != vpn.StatusUp && st.Status != vpn.StatusConnecting {
		t.Fatalf("tunnel status %q", st.Status)
	}
	ev, _ := vs.Store.Events(ctx, tn.ID, 20)
	var finished string
	for _, e := range ev {
		if e.Kind == vpn.EventRunFinished {
			finished = e.Message
		}
	}
	if !strings.Contains(finished, "succeeded") || !strings.Contains(finished, "api:importacion") || strings.Contains(finished, "bytes in 0 ") {
		t.Fatalf("audit: %q", finished)
	}

	// 6. kill switch: no new run can start and the node is told to stop the tunnel
	if err := fs.DisableTunnel(ctx, tn, "user:ana"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Enqueue(ctx, f, fn.TriggerAPI, "user:ana", nil); err == nil {
		t.Fatal("enqueue must fail while the tunnel is off")
	}
	ag.Tick(ctx, &wg)
	wg.Wait()
	if len(mgr.IDs()) != 0 {
		t.Fatal("gateway still up after kill switch")
	}
}

func TestDockerArgs(t *testing.T) {
	a := strings.Join(DockerArgs(ContainerSpec{Name: "capsule-fn-1", Image: "img:1", Entry: []string{"node", "main.js"}, MemoryMB: 512, CPUs: 1.5,
		Env: map[string]string{"CAPSULE_FN": "migrar"}, SocksDir: "/run/capsule/r1"}), " ")
	for _, want := range []string{"--memory 512m", "--memory-swap 512m", "--cpus 1.5", "--pids-limit 256", "--read-only", "--cap-drop ALL",
		"no-new-privileges", "-e CAPSULE_FN=migrar", "-v /run/capsule/r1:/capsule/vpn:ro", "CAPSULE_VPN_SOCKS=/capsule/vpn/socks.sock", "img:1 node main.js", "host.docker.internal:host-gateway"} {
		if !strings.Contains(a, want) {
			t.Errorf("missing %q in %s", want, a)
		}
	}
	if strings.Contains(a, "--privileged") || strings.Contains(a, "--network host") {
		t.Fatal("unsafe flag")
	}
}

type blockRunner struct{}

func (blockRunner) Run(ctx context.Context, s ContainerSpec, _ io.Writer) (int, error) {
	<-ctx.Done()
	return -1, ctx.Err()
}

func TestTimeoutKillsRun(t *testing.T) {
	ctx := context.Background()
	vs := &vpn.Service{Store: vpn.NewMemStore(), SecretKey: "unit-test-key-0123456789abcdef"}
	ms := fn.NewMemStore()
	fs := &fn.Service{Store: ms, VPN: vs}
	h := handlers.NewVPNFnHandler(nil, nil, vs, fs)
	r := chi.NewRouter()
	r.Post("/api/v1/fn/agent/claim", h.AgentClaim)
	r.Post("/api/v1/fn/agent/sync", h.AgentSync)
	r.Post("/api/v1/fn/agent/runs/{runID}/finish", h.AgentFinish)
	srv := httptest.NewServer(r)
	defer srv.Close()
	tok, hash := fn.NewToken(fn.NodeTokPrefix)
	ms.Nodes[hash] = "n"
	f, _ := fs.Deploy(ctx, uuid.New(), uuid.New(), nil, fn.Spec{Name: "lenta", Image: "i", Timeout: "10s"})
	f.TimeoutSeconds = 1                   // the Spec floor is 10 s; shorten the stored function for the test
	ms.CreateFunction(ctx, &fn.Function{}) // no-op row, keeps the store non-empty
	ms.DeleteFunction(ctx, f.ID)
	ms.CreateFunction(ctx, f)
	run, _ := fs.Enqueue(ctx, f, fn.TriggerQueue, "user:ana", nil)
	ag := &Agent{Client: &Client{Base: srv.URL, Token: tok}, Runner: blockRunner{}, Mgr: NewManager(), SocksRoot: shortTemp(t), MaxParallel: 1}
	ag.running = map[uuid.UUID]context.CancelFunc{}
	var wg sync.WaitGroup
	ag.Tick(ctx, &wg)
	wg.Wait()
	if got, _ := ms.GetRun(ctx, run.ID); got.Status != fn.RunTimeout {
		t.Fatalf("status %s", got.Status)
	}
}

func shortTemp(t *testing.T) string {
	d, err := os.MkdirTemp("", "c")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}
