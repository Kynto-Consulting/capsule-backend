package data

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// ---- helpers ----

// freePorts returns n ports that are free for both TCP and UDP on the given IP.
func freePorts(t testing.TB, ip string, n int) []int {
	t.Helper()
	var ports []int
	var closers []io.Closer
	defer func() {
		for _, c := range closers {
			c.Close()
		}
	}()
	for len(ports) < n {
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
		if err != nil {
			t.Skipf("cannot listen on %s: %v", ip, err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err != nil {
			ln.Close()
			continue
		}
		closers = append(closers, ln, pc)
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func setSnap(cp *fakeControl, rev int64, routes []Route, leases []Lease) {
	cp.mu.Lock()
	cp.snap = Snapshot{Rev: rev, Routes: routes, Leases: leases}
	close(cp.changed)
	cp.changed = make(chan struct{})
	cp.mu.Unlock()
}

// startPoolGW starts a gateway whose pool is the range [min,max] of the given ports on bind (default 127.0.0.1).
func startPoolGW(t testing.TB, ports []int, bind string, mod func(*Config), routes ...Route) *testGW {
	t.Helper()
	cp := newFakeControl()
	if bind == "" {
		bind = "127.0.0.1"
	}
	return startGWWith(t, cp, cp, func(c *Config) {
		c.DenyDelay = 20 * time.Millisecond
		c.Pool = PoolConfig{Min: ports[0], Max: ports[len(ports)-1], Bind: bind, FlowIdle: 400 * time.Millisecond, Revalidate: 150 * time.Millisecond, DrainTimeout: 30 * time.Second}
		if mod != nil {
			mod(c)
		}
	}, routes...)
}

func lease(port int, route Route) Lease {
	return Lease{Port: port, ServiceID: route.ServiceID, OrgID: "org"}
}

func awaitRev(t testing.TB, g *testGW, rev int64) {
	t.Helper()
	waitFor(t, 5*time.Second, func() bool { return g.Routes().Rev() == rev })
}

func awaitPorts(t testing.TB, g *testGW, tcp, udp []int) {
	t.Helper()
	waitFor(t, 5*time.Second, func() bool {
		a, b := g.PoolPorts()
		sort.Ints(a)
		sort.Ints(b)
		return fmt.Sprint(a) == fmt.Sprint(tcp) && fmt.Sprint(b) == fmt.Sprint(udp)
	})
}

func udpClient(t testing.TB, addr string) *net.UDPConn {
	t.Helper()
	ra, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// ping sends msg and waits for the echo; ok is false on timeout.
func ping(c *net.UDPConn, msg string, wait time.Duration) (string, bool) {
	c.Write([]byte(msg))
	buf := make([]byte, 4096)
	c.SetReadDeadline(time.Now().Add(wait))
	n, err := c.Read(buf)
	if err != nil {
		return "", false
	}
	return string(buf[:n]), true
}

func tcpEchoOK(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	c.Write([]byte("x"))
	c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, err = io.ReadFull(c, b[:])
	return err == nil
}

// ---- tests ----

func TestPoolTCPLeasePassthroughAndAuthorisation(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 1)
	echo := echoBackend(t)
	r := rt("t1", "", "tcp", "passthrough", echo)
	g := startPoolGW(t, ports, "", nil, r)
	setSnap(g.cp, 2, []Route{r}, []Lease{lease(ports[0], r)})
	awaitPorts(t, g, []int{ports[0]}, nil)

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0]))
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// passthrough: arbitrary bytes round trip, no TLS involved
	msg := []byte("raw bytes \x00\x01\x02 through the pool")
	c.Write(msg)
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo: %v %q", err, got)
	}
	req := g.cp.lastAuth.Load().(AuthorizeRequest)
	if req.CredentialType != CredNone || req.Access != AccessRandomPort || req.Port != ports[0] || req.SrcIP != "127.0.0.1" || req.RouteID != "t1" {
		t.Fatalf("authorize request: %+v", req)
	}
}

func TestPoolTCPDeniedByIPList(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 1)
	echo := echoBackend(t)
	r := rt("t1", "", "tcp", "passthrough", echo)
	g := startPoolGW(t, ports, "", nil, r)
	g.cp.Decide = func(AuthorizeRequest) AuthorizeResponse {
		return AuthorizeResponse{Allow: false, DenyReason: ReasonIPDenied}
	}
	setSnap(g.cp, 2, []Route{r}, []Lease{lease(ports[0], r)})
	awaitPorts(t, g, []int{ports[0]}, nil)
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0])), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hello"))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(make([]byte, 8))
	if n != 0 || err == nil {
		t.Fatalf("a denied source must be closed without data (n=%d err=%v)", n, err)
	}
	waitFor(t, 2*time.Second, func() bool { return mval(g.metrics.ConnsTotal.WithLabelValues("t1", "ip_denied")) == 1 })
}

func TestPoolUDPLeaseFlows(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 1)
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	r := udpRoute("u1", "", "", echo.Addr())
	g := startPoolGW(t, ports, "", nil, r)
	setSnap(g.cp, 2, []Route{r}, []Lease{lease(ports[0], r)})
	awaitPorts(t, g, nil, []int{ports[0]})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0]))

	a, b := udpClient(t, addr), udpClient(t, addr)
	for i := 0; i < 200; i++ {
		for _, c := range []*net.UDPConn{a, b} {
			msg := fmt.Sprintf("m%03d-%s", i, c.LocalAddr())
			if got, ok := ping(c, msg, 2*time.Second); !ok || got != msg {
				t.Fatalf("datagram %d: ok=%v got=%q", i, ok, got)
			}
		}
	}
	if echo.Peers() != 2 {
		t.Fatalf("destination saw %d sources, want one connected socket per client (2)", echo.Peers())
	}
	if v := mval(g.udpm.PoolFlows); v != 2 {
		t.Fatalf("gw_pool_udp_flows = %v", v)
	}
	// the Authorizer caches the answer: 800 datagrams cost a handful of lookups
	if n := g.cp.authCalls.Load(); n > 6 {
		t.Fatalf("%d authorise calls for 2 flows", n)
	}
	req := g.cp.lastAuth.Load().(AuthorizeRequest)
	if req.CredentialType != CredNone || req.Access != AccessRandomPort || req.Port != ports[0] {
		t.Fatalf("authorize request: %+v", req)
	}
	// idle flows disappear
	waitFor(t, 4*time.Second, func() bool { return mval(g.udpm.PoolFlows) == 0 })
}

func TestPoolUDPDeniedAndSpoofLimits(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 1)
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	r := udpRoute("u1", "", "", echo.Addr())
	g := startPoolGW(t, ports, "", func(c *Config) { c.Pool.NewFlowRate = 5 }, r)
	g.cp.Decide = func(AuthorizeRequest) AuthorizeResponse {
		return AuthorizeResponse{Allow: false, DenyReason: ReasonIPDenied}
	}
	setSnap(g.cp, 2, []Route{r}, []Lease{lease(ports[0], r)})
	awaitPorts(t, g, nil, []int{ports[0]})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0]))
	c := udpClient(t, addr)
	if _, ok := ping(c, "hi", 400*time.Millisecond); ok {
		t.Fatal("a denied source got an answer")
	}
	if echo.recv.Load() != 0 {
		t.Fatal("a denied datagram reached the destination")
	}
	// a storm of new flows (distinct source ports) is cut before it costs lookups
	for i := 0; i < 300; i++ {
		x := udpClient(t, addr)
		x.Write([]byte("storm"))
	}
	time.Sleep(300 * time.Millisecond)
	if n := g.cp.authCalls.Load(); n > 25 {
		t.Fatalf("%d lookups for a 300-flow storm with a rate of 5/s", n)
	}
	if mval(g.udpm.Dropped.WithLabelValues("flow_rate")) == 0 {
		t.Fatal("flow_rate drops not counted")
	}
	if echo.recv.Load() != 0 {
		t.Fatal("storm reached the destination")
	}
}

func TestPoolUDPFlowLimitPerIP(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 1)
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	r := udpRoute("u1", "", "", echo.Addr())
	g := startPoolGW(t, ports, "", func(c *Config) { c.Pool.FlowIdle = 5 * time.Second }, r)
	g.cp.Decide = func(AuthorizeRequest) AuthorizeResponse {
		return AuthorizeResponse{Allow: true, MaxConns: 10, MaxConnsPerIP: 2, CacheTTLSeconds: 30}
	}
	setSnap(g.cp, 2, []Route{r}, []Lease{lease(ports[0], r)})
	awaitPorts(t, g, nil, []int{ports[0]})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0]))
	var cs []*net.UDPConn
	ok := 0
	for i := 0; i < 4; i++ {
		c := udpClient(t, addr)
		cs = append(cs, c)
		if _, good := ping(c, "x", 600*time.Millisecond); good {
			ok++
		}
	}
	if ok != 2 {
		t.Fatalf("%d flows admitted from one IP, want 2 (max_conns_per_ip)", ok)
	}
	// an admitted flow keeps working
	if _, good := ping(cs[0], "again", time.Second); !good {
		t.Fatal("admitted flow stopped")
	}
}

func TestPoolDynamicLeasesDrainWithoutCuttingConnections(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 1)
	echoT := echoBackend(t)
	echoU := startUDPEcho(t, "udp4", "127.0.0.1:0")
	tr := rt("svc", "", "tcp", "passthrough", echoT)
	ur := udpRoute("svc-u", "", "", echoU.Addr())
	ur.ServiceID = tr.ServiceID // one service exposing TCP and UDP on the same leased port
	g := startPoolGW(t, ports, "", func(c *Config) { c.Pool.FlowIdle = 700 * time.Millisecond }, tr, ur)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0]))

	if tcpEchoOK(addr) {
		t.Fatal("port is open without a lease")
	}
	setSnap(g.cp, 2, []Route{tr, ur}, []Lease{{Port: ports[0], ServiceID: tr.ServiceID, OrgID: "org"}})
	awaitPorts(t, g, []int{ports[0]}, []int{ports[0]})
	if !tcpEchoOK(addr) {
		t.Fatal("tcp lease not served")
	}
	uc := udpClient(t, addr)
	if _, ok := ping(uc, "u", 2*time.Second); !ok {
		t.Fatal("udp lease not served")
	}
	open, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	open.Write([]byte("a"))
	open.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.ReadFull(open, make([]byte, 1))

	// release the lease
	setSnap(g.cp, 3, []Route{tr, ur}, nil)
	awaitPorts(t, g, nil, nil)
	waitFor(t, 3*time.Second, func() bool { return !tcpEchoOK(addr) })
	// the established TCP connection and the UDP flow carry on
	open.Write([]byte("b"))
	open.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if _, err := io.ReadFull(open, b[:]); err != nil || b[0] != 'b' {
		t.Fatalf("established tcp connection was cut: %v", err)
	}
	if _, ok := ping(uc, "u2", 1500*time.Millisecond); !ok {
		t.Fatal("established udp flow was cut")
	}
	// but a new UDP client is refused while the old flow drains
	nc := udpClient(t, addr)
	if _, ok := ping(nc, "new", 300*time.Millisecond); ok {
		t.Fatal("new flow accepted on a released lease")
	}
	// once the flow idles out the socket is released and the port can be bound by anyone
	waitFor(t, 6*time.Second, func() bool {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return false
		}
		pc.Close()
		return true
	})
	if mval(g.udpm.PoolListeners.WithLabelValues("udp")) != 0 || mval(g.udpm.PoolListeners.WithLabelValues("tcp")) != 0 {
		t.Fatal("listener gauges not back to zero")
	}
}

func TestPoolLeaseBackWhileDraining(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 1)
	echoU := startUDPEcho(t, "udp4", "127.0.0.1:0")
	ur := udpRoute("u", "", "", echoU.Addr())
	g := startPoolGW(t, ports, "", func(c *Config) { c.Pool.FlowIdle = 10 * time.Second }, ur)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0]))
	setSnap(g.cp, 2, []Route{ur}, []Lease{lease(ports[0], ur)})
	awaitPorts(t, g, nil, []int{ports[0]})
	c := udpClient(t, addr)
	if _, ok := ping(c, "1", 2*time.Second); !ok {
		t.Fatal("no echo")
	}
	setSnap(g.cp, 3, []Route{ur}, nil)
	awaitPorts(t, g, nil, nil)
	setSnap(g.cp, 4, []Route{ur}, []Lease{lease(ports[0], ur)})
	awaitPorts(t, g, nil, []int{ports[0]})
	// the same socket serves the old flow and accepts new ones
	if _, ok := ping(c, "2", 2*time.Second); !ok {
		t.Fatal("flow lost across release and re-lease")
	}
	if _, ok := ping(udpClient(t, addr), "3", 2*time.Second); !ok {
		t.Fatal("new flow refused after the lease came back")
	}
	if mval(g.udpm.PoolListeners.WithLabelValues("udp")) != 1 {
		t.Fatalf("udp listeners gauge %v", mval(g.udpm.PoolListeners.WithLabelValues("udp")))
	}
}

func TestPoolOutOfRangeAndReservedAreNeverBound(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 3)
	echo := echoBackend(t)
	r := rt("t1", "", "tcp", "passthrough", echo)
	// the range covers only ports[1]
	g := startPoolGW(t, ports, "", func(c *Config) { c.Pool.Min, c.Pool.Max = ports[1], ports[1] }, r)
	_, gwPort := hostPort(g.addr)
	setSnap(g.cp, 2, []Route{r}, []Lease{lease(ports[0], r), lease(ports[2], r), {Port: gwPort, ServiceID: r.ServiceID}, {Port: 80, ServiceID: r.ServiceID}, lease(ports[1], r)})
	awaitPorts(t, g, []int{ports[1]}, nil)
	for _, p := range []int{ports[0], ports[2]} {
		if tcpEchoOK(net.JoinHostPort("127.0.0.1", strconv.Itoa(p))) {
			t.Fatalf("port %d is outside the pool range but is served", p)
		}
	}
	if mval(g.udpm.PoolRejected.WithLabelValues("out_of_range")) != 4 {
		t.Fatalf("out_of_range rejections: %v", mval(g.udpm.PoolRejected.WithLabelValues("out_of_range")))
	}
	if !tcpEchoOK(net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[1]))) {
		t.Fatal("in-range lease not served")
	}
}

func TestPoolReservedListenerPortIsRefused(t *testing.T) {
	echo := echoBackend(t)
	r := rt("t1", "", "tcp", "passthrough", echo)
	g := startPoolGW(t, []int{1024, 65000}, "", nil, r)
	_, gwPort := hostPort(g.addr)
	setSnap(g.cp, 2, []Route{r}, []Lease{{Port: gwPort, ServiceID: r.ServiceID}})
	waitFor(t, 10*time.Second, func() bool { return mval(g.udpm.PoolRejected.WithLabelValues("reserved")) == 1 })
	if tcp, udp := g.PoolPorts(); len(tcp)+len(udp) != 0 {
		t.Fatalf("gateway's own port taken over: %v %v", tcp, udp)
	}
}

func TestPoolReassignAndRouteUpdate(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 1)
	a := startUDPEcho(t, "udp4", "127.0.0.1:0")
	b := startUDPEcho(t, "udp4", "127.0.0.1:0")
	ra := udpRoute("ra", "", "", a.Addr())
	rb := udpRoute("rb", "", "", b.Addr())
	g := startPoolGW(t, ports, "", nil, ra, rb)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0]))
	setSnap(g.cp, 2, []Route{ra, rb}, []Lease{lease(ports[0], ra)})
	awaitPorts(t, g, nil, []int{ports[0]})
	c1 := udpClient(t, addr)
	if _, ok := ping(c1, "to-a", 2*time.Second); !ok || a.recv.Load() != 1 || b.recv.Load() != 0 {
		t.Fatalf("first service: a=%d b=%d", a.recv.Load(), b.recv.Load())
	}
	// the same port is handed to another service: the old socket and flows are closed at once
	setSnap(g.cp, 3, []Route{ra, rb}, []Lease{lease(ports[0], rb)})
	waitFor(t, 5*time.Second, func() bool {
		c := udpClient(t, addr)
		_, ok := ping(c, "to-b", 400*time.Millisecond)
		return ok && b.recv.Load() >= 1
	})
	if a.recv.Load() != 1 {
		t.Fatalf("traffic still reaches the previous service (a=%d)", a.recv.Load())
	}
	// the destination of the same service changes (new container): new flows use it
	c := startUDPEcho(t, "udp4", "127.0.0.1:0")
	rb2 := udpRoute("rb", "", "", c.Addr())
	setSnap(g.cp, 4, []Route{ra, rb2}, []Lease{lease(ports[0], rb)})
	waitFor(t, 5*time.Second, func() bool {
		x := udpClient(t, addr)
		_, ok := ping(x, "to-c", 400*time.Millisecond)
		return ok && c.recv.Load() >= 1
	})
}

func TestPoolRevokedIPLosesItsFlow(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 1)
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	r := udpRoute("u1", "", "", echo.Addr())
	g := startPoolGW(t, ports, "", func(c *Config) { c.Pool.FlowIdle = 30 * time.Second }, r)
	var allow atomic.Bool
	allow.Store(true)
	g.cp.Decide = func(AuthorizeRequest) AuthorizeResponse {
		if allow.Load() {
			return AuthorizeResponse{Allow: true, CacheTTLSeconds: 1}
		}
		return AuthorizeResponse{Allow: false, DenyReason: ReasonIPDenied, CacheTTLSeconds: 1}
	}
	setSnap(g.cp, 2, []Route{r}, []Lease{lease(ports[0], r)})
	awaitPorts(t, g, nil, []int{ports[0]})
	c := udpClient(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0])))
	if _, ok := ping(c, "1", 2*time.Second); !ok {
		t.Fatal("no echo")
	}
	allow.Store(false) // the IP leaves the project list
	waitFor(t, 6*time.Second, func() bool { return mval(g.udpm.PoolFlows) == 0 })
	if _, ok := ping(c, "2", 500*time.Millisecond); ok {
		t.Fatal("revoked source still served")
	}
}

func TestPoolIPv6(t *testing.T) {
	ports := freePorts(t, "::1", 2)
	echoT := func() string {
		ln, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Skip(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); io.Copy(c, c) }()
			}
		}()
		return ln.Addr().String()
	}()
	echoU := startUDPEcho(t, "udp6", "[::1]:0")
	tr := rt("t6", "", "tcp", "passthrough", echoT)
	ur := udpRoute("u6", "", "", echoU.Addr())
	g := startPoolGW(t, ports, "::1", nil, tr, ur)
	setSnap(g.cp, 2, []Route{tr, ur}, []Lease{lease(ports[0], tr), lease(ports[1], ur)})
	awaitPorts(t, g, []int{ports[0]}, []int{ports[1]})
	if !tcpEchoOK(net.JoinHostPort("::1", strconv.Itoa(ports[0]))) {
		t.Fatal("ipv6 tcp lease not served")
	}
	c := udpClient(t, net.JoinHostPort("::1", strconv.Itoa(ports[1])))
	if got, ok := ping(c, "v6", 2*time.Second); !ok || got != "v6" {
		t.Fatalf("ipv6 udp lease: %v %q", ok, got)
	}
	if req := g.cp.lastAuth.Load().(AuthorizeRequest); req.SrcIP != "::1" {
		t.Fatalf("src_ip %q", req.SrcIP)
	}
}

func TestPoolDualStackWildcard(t *testing.T) {
	ports := freePorts(t, "::", 1)
	echoU := startUDPEcho(t, "udp4", "127.0.0.1:0")
	ur := udpRoute("u", "", "", echoU.Addr())
	g := startPoolGW(t, ports, "[::]", nil, ur)
	setSnap(g.cp, 2, []Route{ur}, []Lease{lease(ports[0], ur)})
	awaitPorts(t, g, nil, []int{ports[0]})
	// IPv4 and IPv6 clients reach the same wildcard socket
	if _, ok := ping(udpClient(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0]))), "v4", 2*time.Second); !ok {
		t.Fatal("ipv4 client refused on a dual stack listener")
	}
	if req := g.cp.lastAuth.Load().(AuthorizeRequest); req.SrcIP != "127.0.0.1" {
		t.Fatalf("an IPv4 client must be authorised as IPv4, got %q", req.SrcIP)
	}
	if _, ok := ping(udpClient(t, net.JoinHostPort("::1", strconv.Itoa(ports[0]))), "v6", 2*time.Second); !ok {
		t.Fatal("ipv6 client refused")
	}
}

func TestPoolBindFailureIsRetried(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 1)
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	r := udpRoute("u", "", "", echo.Addr())
	g := startPoolGW(t, ports, "", nil, r)
	hold, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0])))
	if err != nil {
		t.Fatal(err)
	}
	setSnap(g.cp, 2, []Route{r}, []Lease{lease(ports[0], r)})
	waitFor(t, 3*time.Second, func() bool { return mval(g.udpm.PoolBindErrors) >= 1 })
	if _, udp := g.PoolPorts(); len(udp) != 0 {
		t.Fatal("listener reported while the bind failed")
	}
	hold.Close()
	g.pool.Retry()
	awaitPorts(t, g, nil, []int{ports[0]})
	if _, ok := ping(udpClient(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0]))), "x", 2*time.Second); !ok {
		t.Fatal("not served after the retry")
	}
}

func TestPoolDisabled(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 1)
	echo := echoBackend(t)
	r := rt("t1", "", "tcp", "passthrough", echo)
	g := startPoolGW(t, ports, "", func(c *Config) { c.Pool.Disabled = true }, r)
	setSnap(g.cp, 2, []Route{r}, []Lease{lease(ports[0], r)})
	awaitRev(t, g, 2)
	time.Sleep(100 * time.Millisecond)
	if tcp, udp := g.PoolPorts(); len(tcp)+len(udp) != 0 {
		t.Fatal("pool disabled but listeners open")
	}
}

func TestPoolDrainWaitsForFlowsAndClosesSockets(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 1)
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	r := udpRoute("u", "", "", echo.Addr())
	g := startPoolGW(t, ports, "", func(c *Config) { c.Pool.FlowIdle = 600 * time.Millisecond }, r)
	setSnap(g.cp, 2, []Route{r}, []Lease{lease(ports[0], r)})
	awaitPorts(t, g, nil, []int{ports[0]})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0]))
	c := udpClient(t, addr)
	if _, ok := ping(c, "1", 2*time.Second); !ok {
		t.Fatal("no echo")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := g.Drain(ctx, 0); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if el := time.Since(start); el < 300*time.Millisecond {
		t.Fatalf("drain returned in %v without waiting for the open flow", el)
	}
	if _, ok := ping(c, "after", 300*time.Millisecond); ok {
		t.Fatal("answered after drain")
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("port still held after drain: %v", err)
	}
	pc.Close()
}

func TestPoolCloseReleasesEverythingAtOnce(t *testing.T) {
	ports := freePorts(t, "127.0.0.1", 2)
	echoT := echoBackend(t)
	echoU := startUDPEcho(t, "udp4", "127.0.0.1:0")
	tr := rt("t1", "", "tcp", "passthrough", echoT)
	ur := udpRoute("u1", "", "", echoU.Addr())
	g := startPoolGW(t, ports, "", func(c *Config) { c.Pool.FlowIdle = time.Minute }, tr, ur)
	setSnap(g.cp, 2, []Route{tr, ur}, []Lease{lease(ports[0], tr), lease(ports[1], ur)})
	awaitPorts(t, g, []int{ports[0]}, []int{ports[1]})
	c := udpClient(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[1])))
	ping(c, "x", 2*time.Second)
	open, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0])))
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	open.Write([]byte("q"))
	open.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.ReadFull(open, make([]byte, 1))
	done := make(chan struct{})
	go func() { g.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
	for _, p := range ports {
		pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			t.Fatalf("udp port %d held after Close", p)
		}
		pc.Close()
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			t.Fatalf("tcp port %d held after Close", p)
		}
		ln.Close()
	}
}
