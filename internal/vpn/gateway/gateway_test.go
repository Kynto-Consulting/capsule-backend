package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/kynto/capsule/backend/internal/vpn"
)

func genKey(t *testing.T) (priv, pub string) {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p)
}

func freeUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// remotePeer plays the customer's network: a WireGuard peer that serves HTTP on 10.99.0.1:8080 inside the tunnel.
func remotePeer(t *testing.T, privKey, gwPub string, gwPort, myPort int, handler http.Handler) {
	t.Helper()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.99.0.1")}, nil, 1380)
	if err != nil {
		t.Fatal(err)
	}
	d := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	h := func(k string) string {
		b, _ := base64.StdEncoding.DecodeString(k)
		return hex.EncodeToString(b)
	}
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=10.99.0.2/32\n", h(privKey), myPort, h(gwPub), gwPort)
	if err := d.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := d.Up(); err != nil {
		t.Fatal(err)
	}
	l, err := tnet.ListenTCP(&net.TCPAddr{Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close(); d.Close() })
}

func TestWireGuardEndToEnd(t *testing.T) {
	gwPriv, gwPub := genKey(t)
	rPriv, rPub := genKey(t)
	gwPort, rPort := freeUDP(t), freeUDP(t)
	payload := strings.Repeat("archivo-del-cliente;", 2000)
	remotePeer(t, rPriv, gwPub, gwPort, rPort, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, payload)
	}))

	secret := vpn.WGSecret{PrivateKey: gwPriv, PeerPublicKey: rPub, Address: "10.99.0.2/32"}
	wg, err := StartWireGuard(WGParams{Secret: secret, Endpoint: fmt.Sprintf("127.0.0.1:%d", rPort), AllowedIPs: []string{"10.99.0.0/24"}, ListenPort: gwPort})
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()

	cidrs, _ := ParsePolicyCIDRs([]string{"10.99.0.0/24"})
	var denied []string
	srv := NewServer(wg, Policy{AllowedCIDRs: cidrs, MaxConns: 2, OnDenied: func(tg, r string) { denied = append(denied, tg+":"+r) }})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	defer l.Close()

	// A client of the function side: HTTP through SOCKS only.
	hc := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return SocksDial(ctx, "tcp", l.Addr().String(), addr)
		}}}
	resp, err := hc.Get("http://10.99.0.1:8080/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != payload {
		t.Fatalf("payload mismatch: got %d bytes", len(body))
	}
	if wg.LastHandshake().IsZero() {
		t.Fatal("no handshake recorded")
	}
	in, _ := srv.Bytes()
	if in < int64(len(payload)) {
		t.Fatalf("bytes in = %d, want >= %d", in, len(payload))
	}

	// Destinations outside the declared networks are refused by the gateway, never dialed.
	if _, err := SocksDial(context.Background(), "tcp", l.Addr().String(), "8.8.8.8:53"); err == nil {
		t.Fatal("expected denial for 8.8.8.8")
	}
	if _, err := SocksDial(context.Background(), "tcp", l.Addr().String(), "127.0.0.1:22"); err == nil {
		t.Fatal("expected denial for loopback")
	}
	if len(denied) != 2 {
		t.Fatalf("denied audit = %v", denied)
	}
}

type stubDialer struct{ calls int }

func (s *stubDialer) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	s.calls++
	c, _ := net.Pipe()
	return c, nil
}

func TestPolicyCeilingAndKill(t *testing.T) {
	cidrs, _ := ParsePolicyCIDRs([]string{"10.0.0.0/8"})
	srv := NewServer(&hang{}, Policy{AllowedCIDRs: cidrs, MaxConns: 1})
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(l)
	defer l.Close()
	c1, err := SocksDial(context.Background(), "tcp", l.Addr().String(), "10.1.1.1:80")
	if err != nil {
		t.Fatal(err)
	}
	// second connection exceeds the ceiling of 1
	if _, err := SocksDial(context.Background(), "tcp", l.Addr().String(), "10.1.1.2:80"); err == nil {
		t.Fatal("expected ceiling refusal")
	}
	srv.CloseAll() // kill switch
	c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c1.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection should be closed by kill switch")
	}
}

// hang returns a connection that never produces data.
type hang struct{}

func (hang) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	c, _ := net.Pipe()
	return c, nil
}

func TestBandwidthCap(t *testing.T) {
	cidrs, _ := ParsePolicyCIDRs([]string{"10.0.0.0/8"})
	src, dst := net.Pipe()
	srv := NewServer(dialerFunc(func() (net.Conn, error) { return dst, nil }), Policy{AllowedCIDRs: cidrs, BandwidthBps: 100 << 10})
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(l)
	defer l.Close()
	c, err := SocksDial(context.Background(), "tcp", l.Addr().String(), "10.0.0.5:1")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan int64, 1)
	go func() { n, _ := io.Copy(io.Discard, src); got <- n }()
	start := time.Now()
	buf := make([]byte, 300<<10) // 300 KiB at 100 KiB/s with a 64 KiB burst -> about 2.4 s
	if _, err := c.Write(buf); err != nil {
		t.Fatal(err)
	}
	c.Close()
	n := <-got
	if el := time.Since(start); el < 1500*time.Millisecond || n != int64(len(buf)) {
		t.Fatalf("bandwidth cap not applied: %v, %d bytes", el, n)
	}
}

type dialerFunc func() (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, n, a string) (net.Conn, error) { return f() }
