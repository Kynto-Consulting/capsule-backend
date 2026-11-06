package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kynto/capsule/backend/internal/vpn"
)

// attachNode plays the work node: it keeps `n` idle connections offered to the relay, each served by srv.
func attachNode(r *Relay, tunnel string, srv *Server, n int) (stop func()) {
	stopped := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			for {
				select {
				case <-stopped:
					return
				default:
				}
				a, b := net.Pipe()
				r.Offer(tunnel, a)
				srv.ServeRelay(b) // returns when that connection has been used up
			}
		}()
	}
	return func() { close(stopped) }
}

// relayDialer is what the Lambda side does through the API: Open on the relay, then Splice the function's end.
func relayDialer(r *Relay, tunnel, run string, p Policy) func(ctx context.Context, _, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		node, err := r.Open(ctx, tunnel, addr, p)
		if err != nil {
			return nil, err
		}
		fnSide, apiSide := net.Pipe()
		go r.Splice(run, apiSide, node)
		return fnSide, nil
	}
}

func TestRelayDeniesOutsideCIDRsAndAudits(t *testing.T) {
	cidrs, _ := ParsePolicyCIDRs([]string{"10.99.0.0/24"})
	var denied []string
	p := Policy{AllowedCIDRs: cidrs, OnDenied: func(target, reason string) { denied = append(denied, target+" "+reason) }}
	r := NewRelay()
	r.Wait = 200 * time.Millisecond
	// the node is never asked: no node is attached at all, yet an outside destination is denied (not "no node")
	if _, err := r.Open(context.Background(), "t1", "8.8.8.8:53", p); !errors.Is(err, ErrRelayDenied) {
		t.Fatalf("outside destination: %v", err)
	}
	if _, err := r.Open(context.Background(), "t1", "example.com:80", p); !errors.Is(err, ErrRelayBadRequest) {
		t.Fatalf("names are not resolved: %v", err)
	}
	if _, err := r.Open(context.Background(), "t1", "10.99.0.1:80", p); !errors.Is(err, ErrRelayNoNode) {
		t.Fatalf("allowed destination without node: %v", err)
	}
	if len(denied) != 1 || !strings.Contains(denied[0], "8.8.8.8:53") {
		t.Fatalf("audit: %v", denied)
	}
}

func TestRelayNodeEnforcesPolicyEvenIfTheAPIAsksForMore(t *testing.T) {
	cidrs, _ := ParsePolicyCIDRs([]string{"10.99.0.0/24"})
	var nodeDenied []string
	srv := NewServer(&hang{}, Policy{AllowedCIDRs: cidrs, OnDenied: func(tg, why string) { nodeDenied = append(nodeDenied, tg) }})
	r := NewRelay()
	r.Wait = time.Second
	stop := attachNode(r, "t1", srv, 1)
	defer stop()
	// A compromised/mistaken API-side policy that allows everything: the node still refuses.
	open := Policy{AllowedCIDRs: mustCIDRs(t, "0.0.0.0/0")}
	if _, err := r.Open(context.Background(), "t1", "172.16.0.5:22", open); !errors.Is(err, ErrRelayDenied) {
		t.Fatalf("node must deny: %v", err)
	}
	if len(nodeDenied) != 1 || nodeDenied[0] != "172.16.0.5:22" {
		t.Fatalf("node audit: %v", nodeDenied)
	}
}

func mustCIDRs(t *testing.T, c ...string) []netip.Prefix {
	t.Helper()
	p, err := ParsePolicyCIDRs(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRelayCeilingBytesAndCloseRun(t *testing.T) {
	cidrs, _ := ParsePolicyCIDRs([]string{"10.0.0.0/8"})
	echo := dialerFunc(func() (net.Conn, error) {
		a, b := net.Pipe()
		go io.Copy(b, b) // echo
		return a, nil
	})
	srv := NewServer(echo, Policy{AllowedCIDRs: cidrs, MaxConns: 1})
	r := NewRelay()
	r.Wait = time.Second
	stop := attachNode(r, "t1", srv, 2)
	defer stop()
	p := Policy{AllowedCIDRs: cidrs}
	dial := relayDialer(r, "t1", "run-1", p)
	c1, err := dial(context.Background(), "tcp", "10.0.0.5:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dial(context.Background(), "tcp", "10.0.0.6:1"); !errors.Is(err, ErrRelayCeiling) {
		t.Fatalf("shared ceiling of 1 must apply to the relay: %v", err)
	}
	c1.Write([]byte("hola"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c1, buf); err != nil || string(buf) != "hola" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	if in, out := r.Bytes("run-1"); in != 4 || out != 4 {
		// counters are updated when the copy loops see the bytes; allow a beat
		time.Sleep(100 * time.Millisecond)
		if in, out = r.Bytes("run-1"); in != 4 || out != 4 {
			t.Fatalf("bytes in/out = %d/%d", in, out)
		}
	}
	r.CloseRun("run-1") // kill switch or end of run
	c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c1.Read(buf); err == nil {
		t.Fatal("the connection must be dropped when the run is closed")
	}
	// after CloseRun the same run cannot open new connections through the relay
	c2, err := dial(context.Background(), "tcp", "10.0.0.7:1")
	if err == nil {
		c2.SetReadDeadline(time.Now().Add(2 * time.Second))
		c2.Write([]byte("x"))
		if _, err := c2.Read(buf); err == nil {
			t.Fatal("a closed run must not get a working connection")
		}
	}
	r.Forget("run-1")
}

// The whole path with a real WireGuard tunnel: function side -> relay -> node gateway -> WireGuard -> customer's HTTP server.
func TestRelayWireGuardEndToEnd(t *testing.T) {
	gwPriv, gwPub := genKey(t)
	rPriv, rPub := genKey(t)
	gwPort, rPort := freeUDP(t), freeUDP(t)
	payload := strings.Repeat("archivo-del-cliente;", 3000)
	remotePeer(t, rPriv, gwPub, gwPort, rPort, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, payload)
	}))
	secret := vpn.WGSecret{PrivateKey: gwPriv, PeerPublicKey: rPub, Address: "10.99.0.2/32"}
	wg, err := StartWireGuard(WGParams{Secret: secret, Endpoint: fmt.Sprintf("127.0.0.1:%d", rPort), AllowedIPs: []string{"10.99.0.0/24"}, ListenPort: gwPort})
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()

	cidrs := mustCIDRs(t, "10.99.0.0/24")
	var denied []string
	policy := Policy{AllowedCIDRs: cidrs, MaxConns: 2, OnDenied: func(tg, why string) { denied = append(denied, tg+" "+why) }}
	srv := NewServer(wg, policy)
	r := NewRelay()
	r.Wait = 5 * time.Second
	stop := attachNode(r, "tun", srv, 2)
	defer stop()

	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: relayDialer(r, "tun", "run-wg", policy)}}
	resp, err := hc.Get("http://10.99.0.1:8080/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != payload {
		t.Fatalf("payload mismatch: got %d bytes", len(body))
	}
	var in int64
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if in, _ = r.Bytes("run-wg"); in >= int64(len(payload)) { // the counter is added just after the copy loop writes
			break
		}
	}
	if in < int64(len(payload)) {
		t.Fatalf("relay counted %d bytes in, want >= %d", in, len(payload))
	}
	// outside the declared networks: refused and audited, never dialed
	if _, err := hc.Get("http://8.8.8.8/"); err == nil {
		t.Fatal("expected denial for 8.8.8.8")
	}
	if len(denied) == 0 || !strings.Contains(denied[0], "8.8.8.8:80") {
		t.Fatalf("audit = %v", denied)
	}
}
