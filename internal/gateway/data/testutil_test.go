package data

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kynto/capsule/backend/internal/gateway/data/tunnel"
)

// ---- certificates ----

func selfSigned(t testing.TB, cn string, names ...string) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func certCN(t testing.TB, st tls.ConnectionState) string {
	t.Helper()
	if len(st.PeerCertificates) == 0 {
		t.Fatal("no peer certificate")
	}
	return st.PeerCertificates[0].Subject.CommonName
}

// ---- fake control plane (in-process ControlPlane and an HTTP front for HTTPControl) ----

type fakeControl struct {
	mu      sync.Mutex
	snap    Snapshot
	changed chan struct{}
	Decide  func(AuthorizeRequest) AuthorizeResponse
	down    atomic.Bool // simulate an outage (HTTP 503 / error)
	secret  string

	authCalls  atomic.Int64
	routeCalls atomic.Int64
	lastAuth   atomic.Value // AuthorizeRequest
}

func newFakeControl() *fakeControl {
	return &fakeControl{changed: make(chan struct{}), secret: "test-secret",
		Decide: func(AuthorizeRequest) AuthorizeResponse { return AuthorizeResponse{Allow: true, PrincipalID: "user-1"} }}
}

func (f *fakeControl) SetRoutes(rev int64, routes ...Route) {
	f.mu.Lock()
	f.snap = Snapshot{Rev: rev, Routes: routes}
	close(f.changed)
	f.changed = make(chan struct{})
	f.mu.Unlock()
}

func (f *fakeControl) Routes(ctx context.Context, since int64, wait time.Duration) (*Snapshot, error) {
	f.routeCalls.Add(1)
	if f.down.Load() {
		return nil, ErrControlUnavailable
	}
	f.mu.Lock()
	if f.snap.Rev != since {
		s := f.snap
		f.mu.Unlock()
		return &s, nil
	}
	ch := f.changed
	f.mu.Unlock()
	if wait <= 0 {
		return nil, nil
	}
	select {
	case <-ch:
		f.mu.Lock()
		s := f.snap
		f.mu.Unlock()
		return &s, nil
	case <-time.After(wait):
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeControl) Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResponse, error) {
	f.authCalls.Add(1)
	f.lastAuth.Store(req)
	if f.down.Load() {
		return nil, ErrControlUnavailable
	}
	r := f.Decide(req)
	return &r, nil
}

// ServeHTTP implements the contract of docs/gateway/API.openapi.yaml for /internal/gateway/*.
func (f *fakeControl) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Gateway-Secret") != f.secret {
		http.Error(w, `{"error":{"code":"unauthorized","message":"no"}}`, http.StatusUnauthorized)
		return
	}
	if f.down.Load() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	switch r.URL.Path {
	case "/internal/gateway/routes":
		since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
		s, err := f.Routes(r.Context(), since, time.Duration(wait)*time.Second)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if s == nil {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		json.NewEncoder(w).Encode(s)
	case "/internal/gateway/authorize":
		var req AuthorizeRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.RouteID == "" {
			http.Error(w, "bad", 400)
			return
		}
		resp, _ := f.Authorize(r.Context(), req)
		json.NewEncoder(w).Encode(resp)
	default:
		http.NotFound(w, r)
	}
}

// ---- fake destinations ----

// tlsBackend answers "backend=<name>" after the TLS handshake, then echoes until EOF.
func tlsBackend(t testing.TB, name string, alpn ...string) string {
	t.Helper()
	cert := selfSigned(t, name, name+".test")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: alpn})
				if tc.Handshake() != nil {
					c.Close()
					return
				}
				io.WriteString(tc, "backend="+name+" alpn="+tc.ConnectionState().NegotiatedProtocol+"\n")
				io.Copy(tc, tc)
				tc.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// pgBackend is a fake PostgreSQL: classic (SSLRequest then TLS) or direct TLS; it reports which mode it saw.
func pgBackend(t testing.TB, name string) (addr string, modes chan string) {
	t.Helper()
	cert := selfSigned(t, name, name+".test")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	modes = make(chan string, 64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				br := bufio.NewReader(c)
				first, err := br.Peek(1)
				if err != nil {
					c.Close()
					return
				}
				mode := "direct"
				var rc net.Conn = &bufConn{Conn: c, r: br}
				if first[0] != 0x16 {
					var req [8]byte
					if _, err := io.ReadFull(br, req[:]); err != nil || string(req[:4]) != "\x00\x00\x00\x08" || req[4] != 4 || req[5] != 0xd2 || req[6] != 0x16 || req[7] != 0x2f {
						c.Close()
						return
					}
					c.Write([]byte{'S'})
					mode = "classic"
				}
				tc := tls.Server(rc, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"postgresql"}})
				if tc.Handshake() != nil {
					c.Close()
					return
				}
				modes <- mode + " alpn=" + tc.ConnectionState().NegotiatedProtocol
				io.WriteString(tc, "backend="+name+"\n")
				io.Copy(io.Discard, tc)
				tc.Close()
			}()
		}
	}()
	return ln.Addr().String(), modes
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// echoBackend echoes bytes. When the client half-closes it answers "done:<n>" and closes, proving that the
// half-close reached the destination as FIN while the reverse direction stayed open.
func echoBackend(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				n, _ := io.Copy(c, c)
				io.WriteString(c, "done:"+strconv.FormatInt(n, 10))
			}()
		}
	}()
	return ln.Addr().String()
}

// ---- gateway under test ----

type testGW struct {
	*Server
	cp    *fakeControl
	addr  string
	certs CertProvider
	logs  *syncBuf
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

const testZone = "apps.test"

// startGW starts a gateway on 127.0.0.1:0 with the fake control plane (through the real HTTP client), the given
// routes and a certificate valid for the tunnel hosts and the terminate-mode names.
func startGW(t testing.TB, mod func(*Config), routes ...Route) *testGW {
	t.Helper()
	cp := newFakeControl()
	srv := httpTestServer(t, cp)
	hc, err := NewHTTPControl(srv, cp.secret)
	if err != nil {
		t.Fatal(err)
	}
	return startGWWith(t, cp, hc, mod, routes...)
}

func startGWWith(t testing.TB, cp *fakeControl, ctl ControlPlane, mod func(*Config), routes ...Route) *testGW {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Listeners = []ListenerSpec{{Addr: "127.0.0.1:0"}}
	cfg.Zone = testZone
	cfg.AllowLoopbackDest = true
	cfg.DenyDelay = 300 * time.Millisecond
	cfg.RoutesWait = 2 * time.Second
	cfg.ReusePort = false
	if mod != nil {
		mod(&cfg)
	}
	cp.SetRoutes(1, routes...)
	cert := selfSigned(t, "gateway", "tcp."+testZone, "udp."+testZone, "*.db.test", "*.git.test", "*.apps.test")
	logs := &syncBuf{}
	s, err := New(cfg, Deps{Control: ctl, Certs: StaticCert{cert}, Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	g := &testGW{Server: s, cp: cp, addr: s.Addrs()[0].String(), logs: logs}
	t.Cleanup(s.Close)
	waitFor(t, 5*time.Second, func() bool { return s.Routes().Ready() })
	return g
}

func httpTestServer(t testing.TB, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "http://" + ln.Addr().String()
}

func waitFor(t testing.TB, d time.Duration, cond func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met in %v", d)
}

func hostPort(a string) (string, int) {
	h, p, _ := net.SplitHostPort(a)
	n, _ := strconv.Atoi(p)
	return h, n
}

func rt(id, host, proto, mode, dest string) Route {
	h, p := hostPort(dest)
	return Route{ID: id, ServiceID: "svc-" + id, OrgID: "org", Service: "svc", Host: host, Transport: "tcp", Protocol: proto, DestHost: h, DestPort: p, Mode: mode}
}

// tunnelRoute is a route reachable through capsule/1 as project/service.
func tunnelRoute(id, project, service, dest string) Route {
	r := rt(id, "", "tcp", "terminate", dest)
	r.Project, r.Service = project, service
	return r
}

// ---- clients ----

func tlsDial(t testing.TB, addr, sni string, alpn ...string) (*tls.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: alpn})
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return tc, nil
}

func readLine(t testing.TB, r io.Reader) string {
	t.Helper()
	if c, ok := r.(net.Conn); ok {
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	var sb strings.Builder
	var b [1]byte
	for {
		if _, err := r.Read(b[:]); err != nil {
			t.Fatalf("readLine: %v (got %q)", err, sb.String())
		}
		if b[0] == '\n' {
			return sb.String()
		}
		sb.WriteByte(b[0])
	}
}

// dialTunnel opens capsule/1 and returns the connection and the decoded CAPR (nil + error if the stream ended).
func dialTunnel(t testing.TB, addr string, req *tunnel.Request, mod func(*tls.Config)) (*tls.Conn, *tunnel.Response) {
	t.Helper()
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{ServerName: "tcp." + testZone, InsecureSkipVerify: true, NextProtos: []string{"capsule/1"}, MinVersion: tls.VersionTLS13}
	if mod != nil {
		mod(cfg)
	}
	tc := tls.Client(c, cfg)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tunnel handshake: %v", err)
	}
	hdr, err := tunnel.EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tc.Write(hdr); err != nil {
		t.Fatal(err)
	}
	return tc, readCAPR(t, tc)
}

func readCAPR(t testing.TB, tc *tls.Conn) *tunnel.Response {
	t.Helper()
	var buf []byte
	tmp := make([]byte, 1)
	for {
		r, n, err := tunnel.DecodeResponse(buf, false)
		if err == nil {
			if n != len(buf) {
				t.Fatalf("CAPR followed by %d unexpected bytes", len(buf)-n)
			}
			return r
		}
		if err != tunnel.ErrIncompleteResponse {
			t.Fatalf("decode CAPR: %v (%x)", err, buf)
		}
		m, rerr := tc.Read(tmp)
		buf = append(buf, tmp[:m]...)
		if rerr != nil && m == 0 {
			t.Fatalf("stream ended before a CAPR: %v (%x)", rerr, buf)
		}
	}
}

func capReq(project, service string) *tunnel.Request {
	return &tunnel.Request{Transport: tunnel.TransportTCP, Project: project, Service: service, AuthType: tunnel.AuthCap,
		Auth: "cap_" + strings.Repeat("A", 43), ClientID: "capsule-go/test"}
}
