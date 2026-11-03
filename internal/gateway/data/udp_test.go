package data

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/kynto/capsule/backend/internal/gateway/data/tunnel"
)

// ---- fake UDP destinations ----

// udpEcho answers every datagram with the same bytes and records the distinct client addresses it saw and the count.
type udpEchoSrv struct {
	pc    net.PacketConn
	recv  atomic.Int64
	mu    sync.Mutex
	peers map[string]int
}

func (e *udpEchoSrv) Addr() string { return e.pc.LocalAddr().String() }
func (e *udpEchoSrv) Peers() int   { e.mu.Lock(); defer e.mu.Unlock(); return len(e.peers) }

func startUDPEcho(t testing.TB, network, addr string) *udpEchoSrv {
	t.Helper()
	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	e := &udpEchoSrv{pc: pc, peers: map[string]int{}}
	if uc, ok := pc.(*net.UDPConn); ok {
		uc.SetReadBuffer(4 << 20)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			e.recv.Add(1)
			e.mu.Lock()
			e.peers[a.String()]++
			e.mu.Unlock()
			pc.WriteTo(buf[:n], a)
		}
	}()
	return e
}

func udpRoute(id, project, service, dest string) Route {
	h, p := hostPort(dest)
	return Route{ID: id, ServiceID: "svc-" + id, OrgID: "org", Project: project, Service: service, Transport: "udp", Protocol: "udp", DestHost: h, DestPort: p, Mode: "passthrough"}
}

// ---- tunnel client ----

func udpReq(project, service string) *tunnel.Request {
	r := capReq(project, service)
	r.Transport = tunnel.TransportUDPFlow
	return r
}

func frame(p []byte) []byte { return tunnel.AppendFrame(nil, p) }

// udpTunnel opens a UDP session and returns the connection with a reader that skips gateway keepalives.
type udpTun struct {
	tc  *tls.Conn
	r   *bufioLike
	res *tunnel.Response
	ka  atomic.Int64 // keepalives received
}

type bufioLike struct{ c *tls.Conn }

func openUDPTunnel(t testing.TB, addr string, req *tunnel.Request) *udpTun {
	t.Helper()
	tc, res := dialTunnel(t, addr, req, nil)
	tc.SetDeadline(time.Time{})
	return &udpTun{tc: tc, res: res}
}

func (u *udpTun) send(p []byte) {
	u.tc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := u.tc.Write(frame(p)); err != nil {
		panic(fmt.Sprintf("send: %v", err))
	}
}

// recv returns the next datagram (keepalives are counted and skipped).
func (u *udpTun) recv(timeout time.Duration) ([]byte, error) {
	end := time.Now().Add(timeout)
	for {
		u.tc.SetReadDeadline(end)
		buf := make([]byte, maxUDPDatagram)
		n, err := readUDPFrame(u.tc, buf)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			u.ka.Add(1)
			continue
		}
		return buf[:n], nil
	}
}

// ---- tests ----

func TestUDPTunnelEcho1000(t *testing.T) {
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	g := startGW(t, nil, udpRoute("u1", "proj", "game", echo.Addr()))
	ut := openUDPTunnel(t, g.addr, udpReq("proj", "game"))
	defer ut.tc.Close()
	if ut.res.Status != tunnel.StatusOK {
		t.Fatalf("status %d code %#x", ut.res.Status, ut.res.Code)
	}
	if len(ut.res.SessionID) != 8 || ut.res.MaxDatagram == nil || *ut.res.MaxDatagram != 2048 || ut.res.IdleTimeout == nil || *ut.res.IdleTimeout != 60 {
		t.Fatalf("CAPR extensions: %+v", ut.res)
	}
	got := 0
	for i := 0; i < 1000; i++ {
		msg := []byte(fmt.Sprintf("dg-%04d-%s", i, bytes.Repeat([]byte{'x'}, i%700)))
		ut.send(msg)
		b, err := ut.recv(3 * time.Second)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if !bytes.Equal(b, msg) {
			t.Fatalf("datagram %d corrupted", i)
		}
		got++
	}
	if got != 1000 || echo.Peers() != 1 {
		t.Fatalf("echoed %d/1000, destination saw %d source ports (want 1: stable source port)", got, echo.Peers())
	}
	if v := mval(g.udpm.Sessions); v != 1 {
		t.Fatalf("gw_udp_sessions = %v", v)
	}
}

func TestUDPTunnelOrderlyClose(t *testing.T) {
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	g := startGW(t, nil, udpRoute("u1", "proj", "game", echo.Addr()))
	ut := openUDPTunnel(t, g.addr, udpReq("proj", "game"))
	ut.send([]byte("hello"))
	if _, err := ut.recv(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	ut.tc.CloseWrite()
	// the gateway ends the stream in an orderly way: we read EOF, not a reset
	ut.tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	if _, err := readUDPFrame(ut.tc, buf); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF after half close, got %v", err)
	}
	ut.tc.Close()
	waitFor(t, 3*time.Second, func() bool { return mval(g.udpm.Sessions) == 0 && g.Active() == 0 })
	if v := mval(g.udpm.SessionsTotal.WithLabelValues(CloseNormal)); v != 1 {
		t.Fatalf("sessions_total{normal} = %v", v)
	}
}

func TestUDPTunnelParallelSessions(t *testing.T) {
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	g := startGW(t, func(c *Config) { c.UDP.MaxSessionsRoute, c.UDP.MaxSessionsIP, c.UDP.MaxSessionsProject = 100, 100, 100 }, udpRoute("u1", "proj", "game", echo.Addr()))
	const sessions, per = 40, 150
	var wg sync.WaitGroup
	errs := make(chan error, sessions)
	for s := 0; s < sessions; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			ut := openUDPTunnel(t, g.addr, udpReq("proj", "game"))
			defer ut.tc.Close()
			if ut.res.Status != tunnel.StatusOK {
				errs <- fmt.Errorf("session %d status %d", s, ut.res.Status)
				return
			}
			for i := 0; i < per; i++ {
				msg := []byte(fmt.Sprintf("s%02d-d%04d", s, i))
				ut.send(msg)
				b, err := ut.recv(5 * time.Second)
				if err != nil || !bytes.Equal(b, msg) {
					errs <- fmt.Errorf("session %d datagram %d: %v %q", s, i, err, b)
					return
				}
			}
		}(s)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if echo.Peers() != sessions {
		t.Fatalf("destination saw %d distinct source ports for %d sessions", echo.Peers(), sessions)
	}
	if echo.recv.Load() != sessions*per {
		t.Fatalf("destination received %d datagrams, want %d", echo.recv.Load(), sessions*per)
	}
}

func TestUDPTunnelKeepaliveAndIdle(t *testing.T) {
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	g := startGW(t, func(c *Config) {
		c.UDP.IdleTimeout, c.UDP.KeepaliveInterval = 600*time.Millisecond, 150*time.Millisecond
	}, udpRoute("u1", "proj", "game", echo.Addr()))

	// (a) a client that keeps sending keepalives stays; keepalives are not forwarded to the destination
	a := openUDPTunnel(t, g.addr, udpReq("proj", "game"))
	defer a.tc.Close()
	// (b) a client that goes silent is closed after the idle time (loss of keepalive)
	b := openUDPTunnel(t, g.addr, udpReq("proj", "game"))
	defer b.tc.Close()
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(150 * time.Millisecond):
				a.tc.Write([]byte{0, 0})
			}
		}
	}()
	start := time.Now()
	b.tc.SetReadDeadline(time.Now().Add(4 * time.Second))
	buf := make([]byte, maxUDPDatagram)
	var bka int
	for {
		n, err := readUDPFrame(b.tc, buf)
		if err == nil {
			if n != 0 {
				t.Fatalf("unexpected datagram")
			}
			bka++
			continue
		}
		if !errors.Is(err, io.EOF) {
			t.Fatalf("silent session ended with %v, want orderly EOF", err)
		}
		break
	}
	el := time.Since(start)
	if el < 500*time.Millisecond || el > 2500*time.Millisecond {
		t.Fatalf("silent session closed after %v, want about 600 ms", el)
	}
	if bka == 0 {
		t.Fatalf("gateway sent no keepalive to the idle client")
	}
	// (a) is still alive after more than the idle time and works
	a.send([]byte("still-here"))
	if got, err := a.recv(2 * time.Second); err != nil || string(got) != "still-here" {
		t.Fatalf("keepalive session died: %v %q", err, got)
	}
	close(stop)
	if echo.recv.Load() != 1 {
		t.Fatalf("destination received %d datagrams; keepalives must not reach it", echo.recv.Load())
	}
	waitFor(t, 3*time.Second, func() bool { return mval(g.udpm.SessionsTotal.WithLabelValues(CloseIdle)) == 1 })
}

func TestUDPTunnelMaxDatagramAndProtocolError(t *testing.T) {
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	g := startGW(t, func(c *Config) { c.UDP.MaxDatagram = 100 }, udpRoute("u1", "proj", "game", echo.Addr()))
	ut := openUDPTunnel(t, g.addr, udpReq("proj", "game"))
	defer ut.tc.Close()
	if ut.res.MaxDatagram == nil || *ut.res.MaxDatagram != 100 {
		t.Fatalf("max_datagram %v", ut.res.MaxDatagram)
	}
	ut.send(bytes.Repeat([]byte{'a'}, 150)) // above the announced maximum: dropped, session stays
	ut.send(bytes.Repeat([]byte{'b'}, 100))
	b, err := ut.recv(2 * time.Second)
	if err != nil || len(b) != 100 || b[0] != 'b' {
		t.Fatalf("after oversize: %v len=%d", err, len(b))
	}
	if echo.recv.Load() != 1 {
		t.Fatalf("oversize datagram reached the destination")
	}
	// a frame above the protocol maximum (2048) is a protocol error: the connection closes
	bad := binary.BigEndian.AppendUint16(nil, 2049)
	ut.tc.Write(bad)
	ut.tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, maxUDPDatagram)
	var rerr error
	for rerr == nil {
		_, rerr = readUDPFrame(ut.tc, buf)
	}
	if !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
		t.Fatalf("connection should end after a frame_too_large, got %v", rerr)
	}
	waitFor(t, 3*time.Second, func() bool { return mval(g.udpm.SessionsTotal.WithLabelValues(CloseProtocol)) == 1 })
}

func TestUDPTunnelLimits(t *testing.T) {
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	routes := []Route{udpRoute("u1", "proj", "a", echo.Addr()), udpRoute("u2", "proj", "b", echo.Addr()), udpRoute("u3", "other", "c", echo.Addr())}
	pid := "project-1"
	for i := range routes[:2] {
		routes[i].ProjectID = &pid
	}
	g := startGW(t, func(c *Config) { c.UDP.MaxSessionsRoute, c.UDP.MaxSessionsIP, c.UDP.MaxSessionsProject = 3, 2, 3 }, routes...)

	open := func(project, service string) (*udpTun, *tunnel.Response) {
		tc, res := dialTunnel(t, g.addr, udpReq(project, service), nil)
		return &udpTun{tc: tc, res: res}, res
	}
	var keep []*udpTun
	defer func() {
		for _, k := range keep {
			k.tc.Close()
		}
	}()
	for i := 0; i < 2; i++ { // per IP: 2 on route a
		u, r := open("proj", "a")
		if r.Status != 0 {
			t.Fatalf("session %d refused: %d/%#x", i, r.Status, r.Code)
		}
		keep = append(keep, u)
	}
	_, r := open("proj", "a")
	if r.Status != tunnel.StatusQuota || r.Code != tunnel.CodeQuotaUDP || r.RetryAfter == nil {
		t.Fatalf("third session on one route from one IP: status %d code %#x (want 5/0x0504)", r.Status, r.Code)
	}
	// per project (3): route b has room per IP but the project is at 2 + this one = 3, then the next is refused
	u, r := open("proj", "b")
	if r.Status != 0 {
		t.Fatalf("project session 3 refused: %d/%#x", r.Status, r.Code)
	}
	keep = append(keep, u)
	_, r = open("proj", "b")
	if r.Status != tunnel.StatusQuota || r.Code != tunnel.CodeQuotaUDP {
		t.Fatalf("project limit: status %d code %#x", r.Status, r.Code)
	}
	// a session of another project is independent
	u, r = open("other", "c")
	if r.Status != 0 {
		t.Fatalf("other project refused: %d/%#x", r.Status, r.Code)
	}
	keep = append(keep, u)
	// closing one frees the slot
	keep[0].tc.Close()
	waitFor(t, 3*time.Second, func() bool {
		u, r := open("proj", "a")
		if r.Status == 0 {
			keep = append(keep, u)
			return true
		}
		return false
	})
}

func TestUDPTunnelRefusals(t *testing.T) {
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	g := startGW(t, func(c *Config) { c.DenyDelay = 20 * time.Millisecond }, udpRoute("u1", "proj", "game", echo.Addr()))
	// unknown service
	_, r := dialTunnel(t, g.addr, udpReq("proj", "nope"), nil)
	if r.Status != tunnel.StatusNotAuthorized {
		t.Fatalf("unknown service: %d/%#x", r.Status, r.Code)
	}
	// a TCP route is not reachable with transport 2 and vice versa
	g.cp.SetRoutes(2, udpRoute("u1", "proj", "game", echo.Addr()), tunnelRoute("t1", "proj", "tcp-svc", echo.Addr()))
	waitFor(t, 3*time.Second, func() bool { return g.Routes().Rev() == 2 })
	_, r = dialTunnel(t, g.addr, udpReq("proj", "tcp-svc"), nil)
	if r.Status != tunnel.StatusNotAuthorized {
		t.Fatalf("tcp service over transport 2: %d/%#x", r.Status, r.Code)
	}
	_, r = dialTunnel(t, g.addr, capReq("proj", "game"), nil)
	if r.Status != tunnel.StatusNotAuthorized {
		t.Fatalf("udp service over transport 1: %d/%#x", r.Status, r.Code)
	}
	// QUIC is future
	q := udpReq("proj", "game")
	q.Transport = tunnel.TransportUDPQUIC
	_, r = dialTunnel(t, g.addr, q, nil)
	if r.Status != tunnel.StatusBadRequest || r.Code != tunnel.CodeBadTransport {
		t.Fatalf("transport 3: %d/%#x", r.Status, r.Code)
	}
	// authorisation denied by the control plane
	g.cp.Decide = func(AuthorizeRequest) AuthorizeResponse {
		return AuthorizeResponse{Allow: false, DenyReason: ReasonIPDenied}
	}
	_, r = dialTunnel(t, g.addr, udpReq("proj", "game"), nil)
	if r.Status != tunnel.StatusIPDenied {
		t.Fatalf("denied: %d/%#x", r.Status, r.Code)
	}
}

func TestUDPTunnelDisabled(t *testing.T) {
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	g := startGW(t, func(c *Config) { c.UDP.TunnelDisabled = true }, udpRoute("u1", "proj", "game", echo.Addr()))
	_, r := dialTunnel(t, g.addr, udpReq("proj", "game"), nil)
	if r.Status != tunnel.StatusBadRequest || r.Code != tunnel.CodeBadTransport {
		t.Fatalf("disabled transport 2: %d/%#x", r.Status, r.Code)
	}
}

func TestUDPTunnelIPv6(t *testing.T) {
	echo := startUDPEcho(t, "udp6", "[::1]:0")
	g := startGW(t, func(c *Config) { c.Listeners = []ListenerSpec{{Addr: "[::1]:0"}} }, udpRoute("u6", "proj", "game6", echo.Addr()))
	ut := openUDPTunnel(t, g.addr, udpReq("proj", "game6"))
	defer ut.tc.Close()
	if ut.res.Status != 0 {
		t.Fatalf("status %d/%#x", ut.res.Status, ut.res.Code)
	}
	for i := 0; i < 100; i++ {
		msg := []byte("v6-" + strconv.Itoa(i))
		ut.send(msg)
		b, err := ut.recv(2 * time.Second)
		if err != nil || !bytes.Equal(b, msg) {
			t.Fatalf("v6 datagram %d: %v", i, err)
		}
	}
	// the destination saw a ::1 source
	echo.mu.Lock()
	defer echo.mu.Unlock()
	for p := range echo.peers {
		if ap, _ := netip.ParseAddrPort(p); !ap.Addr().Is6() {
			t.Fatalf("destination peer %s is not IPv6", p)
		}
	}
}

func TestUDPTunnelProxyInfoAndOptimisticData(t *testing.T) {
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	g := startGW(t, nil, udpRoute("u1", "proj", "game", echo.Addr()))
	req := udpReq("proj", "game")
	hdr, err := tunnel.EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	// the first datagram travels in the same TLS record as the header (optimistic data)
	tc, _ := dialTunnelRaw(t, g.addr, append(hdr, frame([]byte("early"))...))
	defer tc.Close()
	ut := &udpTun{tc: tc}
	b, err := ut.recv(3 * time.Second)
	if err != nil || string(b) != "early" {
		t.Fatalf("optimistic datagram: %v %q", err, b)
	}
}

// dialTunnelRaw sends pre-encoded bytes (header plus anything after it) and reads the CAPR.
func dialTunnelRaw(t testing.TB, addr string, raw []byte) (*tls.Conn, *tunnel.Response) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(c, &tls.Config{ServerName: "tcp." + testZone, InsecureSkipVerify: true, NextProtos: []string{"capsule/1"}, MinVersion: tls.VersionTLS13})
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := tc.Write(raw); err != nil {
		t.Fatal(err)
	}
	r := readCAPR(t, tc)
	c.SetDeadline(time.Time{})
	return tc, r
}

func TestUDPTunnelSlowClientDropsInsteadOfBlocking(t *testing.T) {
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	g := startGW(t, func(c *Config) { c.UDP.QueueBytes = 8 << 10 }, udpRoute("u1", "proj", "game", echo.Addr()))
	ut := openUDPTunnel(t, g.addr, udpReq("proj", "game"))
	defer ut.tc.Close()
	// send many datagrams without reading: replies pile up in the socket buffers and then in the bounded queue
	payload := bytes.Repeat([]byte{'z'}, 1400)
	for i := 0; i < 20000; i++ {
		ut.send(payload)
	}
	waitFor(t, 10*time.Second, func() bool {
		return mval(g.udpm.Dropped.WithLabelValues("queue_full")) > 0 || echo.recv.Load() >= 19000
	})
	// the session is still usable once the client reads again
	deadline := time.Now().Add(5 * time.Second)
	n := 0
	for time.Now().Before(deadline) && n < 100 {
		if _, err := ut.recv(500 * time.Millisecond); err != nil {
			break
		}
		n++
	}
	if n == 0 {
		t.Fatalf("no datagram readable after the burst")
	}
}

// ---- frame codec ----

func TestReadUDPFrameCases(t *testing.T) {
	buf := make([]byte, maxUDPDatagram)
	cases := []struct {
		name string
		in   []byte
		n    int
		err  error
	}{
		{"keepalive", []byte{0, 0}, 0, nil},
		{"one byte", []byte{0, 1, 'x'}, 1, nil},
		{"max", append([]byte{0x08, 0x00}, make([]byte, 2048)...), 2048, nil},
		{"too large", []byte{0x08, 0x01}, 0, tunnel.ErrFrameTooLarge},
		{"empty stream", nil, 0, io.EOF},
		{"half header", []byte{0}, 0, io.ErrUnexpectedEOF},
		{"short body", []byte{0, 5, 'a', 'b'}, 0, io.ErrUnexpectedEOF},
		{"header only", []byte{0, 5}, 0, io.ErrUnexpectedEOF},
	}
	for _, c := range cases {
		n, err := readUDPFrame(bytes.NewReader(c.in), buf)
		if n != c.n || !errors.Is(err, c.err) && err != c.err {
			t.Errorf("%s: n=%d err=%v, want n=%d err=%v", c.name, n, err, c.n, c.err)
		}
	}
}

func FuzzReadUDPFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 3, 'a', 'b', 'c', 0, 1})
	f.Add([]byte{0x08, 0x01})
	f.Add([]byte{0, 2, 'x'})
	f.Add(frame(bytes.Repeat([]byte{7}, 2048)))
	f.Fuzz(func(t *testing.T, b []byte) {
		// stream decoder versus the block decoder: same datagrams, same keepalives, same verdict
		dgs, ka, pending, serr := tunnel.SplitFrames(b)
		r := bytes.NewReader(b)
		buf := make([]byte, maxUDPDatagram)
		var got [][]byte
		kaGot := 0
		var rerr error
		for {
			n, err := readUDPFrame(r, buf)
			if err != nil {
				rerr = err
				break
			}
			if n == 0 {
				kaGot++
				continue
			}
			got = append(got, append([]byte(nil), buf[:n]...))
		}
		switch {
		case serr != nil:
			if !errors.Is(rerr, tunnel.ErrFrameTooLarge) {
				t.Fatalf("SplitFrames said %v, stream said %v", serr, rerr)
			}
		case pending > 0:
			if !errors.Is(rerr, io.ErrUnexpectedEOF) {
				t.Fatalf("incomplete trailing frame: stream said %v", rerr)
			}
		default:
			if !errors.Is(rerr, io.EOF) {
				t.Fatalf("clean input ended with %v", rerr)
			}
		}
		if len(got) != len(dgs) || kaGot != ka {
			t.Fatalf("datagrams %d/%d keepalives %d/%d", len(got), len(dgs), kaGot, ka)
		}
		for i := range got {
			if !bytes.Equal(got[i], dgs[i]) {
				t.Fatalf("datagram %d differs", i)
			}
		}
	})
}

func TestLeaseRoutesSelection(t *testing.T) {
	snap := &Snapshot{Rev: 1, Routes: []Route{
		{ID: "b-tcp", ServiceID: "s1", Transport: "tcp", DestHost: "h", DestPort: 1},
		{ID: "a-tcp", ServiceID: "s1", Transport: "tcp", DestHost: "h", DestPort: 2},
		{ID: "a-udp", ServiceID: "s1", Transport: "udp", DestHost: "h", DestPort: 3},
		{ID: "bad-udp", ServiceID: "s2", Transport: "udp", DestHost: "", DestPort: 3},
		{ID: "only-tcp", ServiceID: "s3", Transport: "tcp", DestHost: "h", DestPort: 4},
	}}
	tb := NewTable(snap)
	tcp, udp, amb := tb.leaseRoutes(Lease{ServiceID: "s1"})
	if tcp == nil || tcp.ID != "a-tcp" || udp == nil || udp.ID != "a-udp" || !amb {
		t.Fatalf("s1: %v %v amb=%v", tcp, udp, amb)
	}
	tcp, udp, _ = tb.leaseRoutes(Lease{ServiceID: "s1", Transport: "udp"})
	if tcp != nil || udp == nil {
		t.Fatalf("transport udp: %v %v", tcp, udp)
	}
	tcp, udp, _ = tb.leaseRoutes(Lease{ServiceID: "s1", RouteID: "b-tcp"})
	if tcp == nil || tcp.ID != "b-tcp" || udp != nil {
		t.Fatalf("route id: %v %v", tcp, udp)
	}
	if tcp, udp, _ = tb.leaseRoutes(Lease{ServiceID: "s2"}); tcp != nil || udp != nil {
		t.Fatalf("unusable udp route must not be exposed")
	}
	if tcp, udp, _ = tb.leaseRoutes(Lease{ServiceID: "s3"}); tcp == nil || udp != nil {
		t.Fatalf("s3: %v %v", tcp, udp)
	}
	if tb.LookupUDPService("", "") != nil || !tb.HasRoute("a-udp") || tb.HasRoute("bad-udp") {
		t.Fatalf("udp index")
	}
}

func TestUDPLimitsAccounting(t *testing.T) {
	var l udpLimits
	ip := netip.MustParseAddr("203.0.113.9")
	r1, why := l.acquire("r", ip, "p", 2, 2, 2)
	r2, _ := l.acquire("r", ip, "p", 2, 2, 2)
	if _, why = l.acquire("r", ip, "p", 2, 2, 2); why != LimitRoute && why != LimitIP {
		t.Fatalf("third: %q", why)
	}
	r1()
	r1() // idempotent
	if rel, why := l.acquire("r", ip, "p", 2, 2, 2); why != "" {
		t.Fatalf("after release: %q", why)
	} else {
		rel()
	}
	r2()
	if len(l.route)+len(l.perIP)+len(l.project) != 0 {
		t.Fatalf("counters not cleaned: %v %v %v", l.route, l.perIP, l.project)
	}
	// IPv6 clients share their /64
	a, b := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	x, _ := l.acquire("r", a, "", 5, 1, 5)
	if _, why := l.acquire("r", b, "", 5, 1, 5); why != LimitIP {
		t.Fatalf("same /64 must share the per-IP limit, got %q", why)
	}
	x()
}

func TestUDPRoutesSorted(t *testing.T) { // deterministic choice is independent of snapshot order
	mk := func(ids ...string) *Table {
		var rs []Route
		for _, id := range ids {
			rs = append(rs, Route{ID: id, ServiceID: "s", Transport: "udp", DestHost: "h", DestPort: 1})
		}
		return NewTable(&Snapshot{Routes: rs})
	}
	_, a, _ := mk("z", "m", "a").leaseRoutes(Lease{ServiceID: "s"})
	_, b, _ := mk("a", "z", "m").leaseRoutes(Lease{ServiceID: "s"})
	ids := []string{a.ID, b.ID}
	sort.Strings(ids)
	if a.ID != "a" || b.ID != "a" {
		t.Fatalf("got %v", ids)
	}
}

// mval reads the current value of a gauge or counter.
func mval(m prometheus.Metric) float64 {
	var d dto.Metric
	if err := m.Write(&d); err != nil {
		return -1
	}
	switch {
	case d.Gauge != nil:
		return d.Gauge.GetValue()
	case d.Counter != nil:
		return d.Counter.GetValue()
	}
	return -1
}
