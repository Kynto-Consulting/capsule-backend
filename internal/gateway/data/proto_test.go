package data

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ---- a minimal MySQL server and client (only the handshake shape the gateway touches) ----

// mysqlBackend greets with SSL support, expects the SSLRequest, serves TLS and answers the first packet inside TLS
// with "backend=<name> seq=<n>" (so the test sees which backend and that the sequence ids are the ones MySQL expects).
func mysqlBackend(t testing.TB, name string, withSSL bool) string {
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
				defer c.Close()
				g := buildMySQLGreeting(7, mysqlSalt(20))
				if !withSSL { // clear the CLIENT_SSL bit of the lower capability word
					i := 4 + 1 + len(mysqlServerVersion) + 1 + 4 + 8 + 1
					g[i+1] &^= 0x08
				}
				c.Write(g)
				var req [mysqlSSLReqTotal]byte
				if _, err := io.ReadFull(c, req[:]); err != nil {
					return
				}
				if _, err := parseMySQLSSLRequest(req[:]); err != nil {
					return
				}
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				if tc.Handshake() != nil {
					return
				}
				seq, p, err := readMySQLPacket(tc, 1<<16)
				if err != nil {
					return
				}
				_ = p
				tc.Write(mysqlPacket(seq+1, []byte("backend="+name+" tls="+tc.ConnectionState().ServerName)))
				io.Copy(io.Discard, tc)
			}()
		}
	}()
	return ln.Addr().String()
}

// mysqlClient plays the client side: greeting, SSLRequest, TLS with the given SNI, then one handshake-response packet.
// It returns the backend's answer (or the error) and the certificate CN it saw.
func mysqlClient(t testing.TB, addr, sni string) (answer, cn string, err error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	_, g, err := readMySQLPacket(c, 4096)
	if err != nil {
		return "", "", err
	}
	caps, err := parseMySQLGreeting(g)
	if err != nil || caps&capSSL == 0 {
		t.Fatalf("greeting without SSL: caps=%x err=%v", caps, err)
	}
	c.Write(sslRequestPacket())
	tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		return "", "", err
	}
	cn = tc.ConnectionState().PeerCertificates[0].Subject.CommonName
	tc.Write(mysqlPacket(2, bytes.Repeat([]byte{'x'}, 40)))
	_, p, err := readMySQLPacket(tc, 4096)
	if err != nil {
		return "", cn, err
	}
	return string(p), cn, nil
}

func sslRequestPacket() []byte {
	p := make([]byte, 32)
	binary.LittleEndian.PutUint32(p, capProtocol41|capSSL|capSecureConn|capPluginAuth)
	binary.LittleEndian.PutUint32(p[4:], 1<<24)
	p[8] = 0xff
	return mysqlPacket(1, p)
}

func mysqlGW(t testing.TB, mod func(*Config), routes ...Route) *testGW {
	return startGW(t, func(c *Config) {
		c.Listeners = []ListenerSpec{{Addr: "127.0.0.1:0", Allow: []Kind{KindMySQL}}, {Addr: "127.0.0.1:0", Allow: []Kind{KindTLS}}, {Addr: "[::1]:0", Allow: []Kind{KindMySQL}}}
		c.DenyDelay = 100 * time.Millisecond
		if mod != nil {
			mod(c)
		}
	}, routes...)
}

func TestMySQLRoutesBySNI(t *testing.T) {
	a, b := mysqlBackend(t, "A", true), mysqlBackend(t, "B", true)
	g := mysqlGW(t, nil,
		rt("a", "a.db.test", "mysql", "passthrough", a),
		rt("b", "b.db.test", "mysql", "passthrough", b),
		rt("ta", "ta.db.test", "mysql", "terminate", a))
	addrs := g.Addrs()
	for _, tc := range []struct{ sni, want, cn string }{
		{"a.db.test", "backend=A", "A"},
		{"b.db.test", "backend=B", "B"},
		{"ta.db.test", "backend=A", "gateway"}, // terminated: the gateway certificate faces the client, a new TLS leg reaches A
	} {
		for _, addr := range []string{addrs[0].String(), addrs[2].String()} { // IPv4 and IPv6
			ans, cn, err := mysqlClient(t, addr, tc.sni)
			if err != nil || !strings.HasPrefix(ans, tc.want) || cn != tc.cn {
				t.Errorf("%s via %s: answer=%q cn=%q err=%v", tc.sni, addr, ans, cn, err)
			}
		}
	}
	if g.cp.authCalls.Load() < 6 {
		t.Errorf("authorize calls = %d, want one per connection", g.cp.authCalls.Load())
	}
	ar := g.cp.lastAuth.Load().(AuthorizeRequest)
	if ar.CredentialType != CredNone || ar.Access != AccessSNI {
		t.Errorf("authorize request = %+v", ar)
	}
}

func TestMySQLUniformDenial(t *testing.T) {
	a := mysqlBackend(t, "A", true)
	g := mysqlGW(t, nil, rt("a", "a.db.test", "mysql", "passthrough", a), rt("r", "r.db.test", "redis", "passthrough", a))
	addr := g.Addrs()[0].String()
	timeIt := func(sni string) (time.Duration, error) {
		t0 := time.Now()
		_, _, err := mysqlClient(t, addr, sni)
		return time.Since(t0), err
	}
	var ds []time.Duration
	for _, n := range []string{"nope.db.test", "r.db.test", ""} { // unknown, a route of another protocol, no SNI
		d, err := timeIt(n)
		if err == nil {
			t.Errorf("%q: handshake completed", n)
		}
		ds = append(ds, d)
	}
	for _, d := range ds {
		if d < 40*time.Millisecond || d > 400*time.Millisecond {
			t.Errorf("denial latencies not uniform: %v", ds)
		}
	}
}

func TestMySQLNoTLSClientGetsError(t *testing.T) {
	g := mysqlGW(t, nil)
	c, err := net.Dial("tcp", g.Addrs()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	readMySQLPacket(c, 4096)
	// a full HandshakeResponse without CLIENT_SSL (what ssl-mode=DISABLED sends)
	p := make([]byte, 60)
	binary.LittleEndian.PutUint32(p, capProtocol41|capSecureConn)
	c.Write(mysqlPacket(1, p))
	seq, e, err := readMySQLPacket(c, 4096)
	if err != nil || seq != 2 || e[0] != 0xff || binary.LittleEndian.Uint16(e[1:]) != 3159 {
		t.Fatalf("want ERR 3159, got seq=%d %x err=%v", seq, e, err)
	}
}

func TestMySQLInjectedAndSlowHandshakes(t *testing.T) {
	a := mysqlBackend(t, "A", true)
	g := mysqlGW(t, func(c *Config) { c.HelloTimeout = 700 * time.Millisecond }, rt("a", "a.db.test", "mysql", "passthrough", a))
	addr := g.Addrs()[0].String()
	closedWithin := func(name string, d time.Duration, f func(c net.Conn)) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(d + 3*time.Second))
		readMySQLPacket(c, 4096)
		t0 := time.Now()
		f(c)
		var b [64]byte
		for {
			if _, err := c.Read(b[:]); err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					t.Errorf("%s: connection still open after %v", name, time.Since(t0))
				}
				return
			}
		}
	}
	// bytes injected before the SSLRequest
	closedWithin("injected", time.Second, func(c net.Conn) { c.Write(append([]byte("junk"), sslRequestPacket()...)) })
	// SSLRequest followed by something that is not a ClientHello
	closedWithin("not-hello", time.Second, func(c net.Conn) { c.Write(sslRequestPacket()); c.Write([]byte("GET / HTTP/1.1\r\n\r\n")) })
	// slowloris: one byte at a time, never completing the SSLRequest
	t0 := time.Now()
	closedWithin("slow-sslrequest", time.Second, func(c net.Conn) {
		for _, b := range sslRequestPacket()[:10] {
			c.Write([]byte{b})
			time.Sleep(150 * time.Millisecond)
		}
	})
	if time.Since(t0) > 2500*time.Millisecond {
		t.Errorf("slowloris held the connection %v", time.Since(t0))
	}
	// SSLRequest, then a ClientHello that stalls half way
	closedWithin("slow-hello", time.Second, func(c net.Conn) { c.Write(sslRequestPacket()); c.Write([]byte{0x16, 0x03, 0x01, 0x01, 0x00, 0x01}) })
	// silence after the greeting
	closedWithin("silent", time.Second, func(c net.Conn) {})
	// the gateway is still fine
	if ans, _, err := mysqlClient(t, addr, "a.db.test"); err != nil || !strings.HasPrefix(ans, "backend=A") {
		t.Fatalf("after attacks: %q %v", ans, err)
	}
}

func TestMySQLBackendWithoutTLS(t *testing.T) {
	a := mysqlBackend(t, "A", false)
	g := mysqlGW(t, nil, rt("a", "a.db.test", "mysql", "passthrough", a), rt("ta", "ta.db.test", "mysql", "terminate", a))
	for _, n := range []string{"a.db.test", "ta.db.test"} {
		if _, _, err := mysqlClient(t, g.Addrs()[0].String(), n); err == nil {
			t.Errorf("%s: want failure when the backend has no TLS", n)
		}
	}
	waitFor(t, 2*time.Second, func() bool { return strings.Contains(g.logs.String(), "dest_no_tls") })
}

func TestMySQLWrongDoorAndProtocolLimit(t *testing.T) {
	a := mysqlBackend(t, "A", true)
	g := mysqlGW(t, func(c *Config) { c.ProtoMaxConns = map[string]int{"mysql": 1} }, rt("a", "a.db.test", "mysql", "passthrough", a))
	// a mysql route reached with a direct TLS ClientHello on the "tls" listener is refused
	if tc, err := tlsDial(t, g.Addrs()[1].String(), "a.db.test"); err == nil {
		tc.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, _ := tc.Read(make([]byte, 8)); n > 0 {
			t.Error("data from a mysql route through the direct-TLS door")
		}
		tc.Close()
	}
	// the per-protocol ceiling: one open, the second refused
	open := func() net.Conn {
		c, _ := net.Dial("tcp", g.Addrs()[0].String())
		c.SetDeadline(time.Now().Add(5 * time.Second))
		readMySQLPacket(c, 4096)
		c.Write(sslRequestPacket())
		tc := tls.Client(c, &tls.Config{ServerName: "a.db.test", InsecureSkipVerify: true})
		if tc.Handshake() != nil {
			return nil
		}
		return tc
	}
	c1 := open()
	if c1 == nil {
		t.Fatal("first connection failed")
	}
	defer c1.Close()
	waitFor(t, 2*time.Second, func() bool { return g.metrics.ConnsActive.WithLabelValues("a") != nil && g.Active() >= 1 })
	if c2 := open(); c2 != nil {
		c2.SetReadDeadline(time.Now().Add(time.Second))
		c2.Write(mysqlPacket(2, []byte("x")))
		if _, err := c2.Read(make([]byte, 4)); err == nil {
			t.Error("second connection served beyond the protocol ceiling")
		}
		c2.Close()
	}
	waitFor(t, 2*time.Second, func() bool { return strings.Contains(g.logs.String(), "limit_proto") })
}

// ---- Redis and MongoDB: TLS from the first byte ----

func TestRedisMongoByNameAndWrongDoor(t *testing.T) {
	r1, r2 := tlsBackend(t, "R1"), tlsBackend(t, "R2")
	m1, m2 := tlsBackend(t, "M1"), tlsBackend(t, "M2")
	plain := echoBackend(t)
	g := startGW(t, func(c *Config) {
		c.Listeners = []ListenerSpec{{Addr: "127.0.0.1:0", Allow: []Kind{KindTLS}}, {Addr: "[::1]:0", Allow: []Kind{KindTLS, KindRedisPlain, KindMongoPlain}}}
		c.DenyDelay = 100 * time.Millisecond
	},
		rt("r1", "r1.db.test", "redis", "passthrough", r1), rt("r2", "r2.db.test", "redis", "passthrough", r2),
		rt("m1", "m1.db.test", "mongo", "passthrough", m1), rt("m2", "m2.db.test", "mongo", "passthrough", m2),
		rt("rt", "rt.db.test", "redis", "terminate", plain))
	for _, addr := range []string{g.Addrs()[0].String(), g.Addrs()[1].String()} {
		for _, n := range []string{"r1", "r2", "m1", "m2"} {
			tc, err := tlsDial(t, addr, n+".db.test")
			if err != nil {
				t.Fatalf("%s: %v", n, err)
			}
			if got := readLine(t, tc); !strings.HasPrefix(got, "backend="+strings.ToUpper(n)) {
				t.Errorf("%s via %s: %q", n, addr, got)
			}
			tc.Close()
		}
		// terminate toward a Redis without TLS: the gateway certificate faces the client, clear text goes to the server
		tc, err := tlsDial(t, addr, "rt.db.test")
		if err != nil {
			t.Fatal(err)
		}
		if cn := certCN(t, tc.ConnectionState()); cn != "gateway" {
			t.Errorf("terminate CN = %q", cn)
		}
		io.WriteString(tc, "PING\r\n")
		tc.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 6)
		if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "PING\r\n" {
			t.Errorf("terminate echo: %q %v", buf, err)
		}
		tc.Close()
	}
	// unknown name: closed without a ServerHello (no certificate leaks)
	if _, err := tlsDial(t, g.Addrs()[0].String(), "x.db.test"); err == nil {
		t.Error("unknown name completed a handshake")
	}
	// PostgreSQL SSLRequest toward a redis route must not be replayed to Redis
	c, _ := net.Dial("tcp", g.Addrs()[0].String())
	c.SetDeadline(time.Now().Add(3 * time.Second))
	req := [8]byte{0, 0, 0, 8}
	binary.BigEndian.PutUint32(req[4:], pgSSLRequest)
	c.Write(req[:])
	if _, err := c.Read(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), "EOF") { // listener kind tls: pg-ssl is not allowed
		t.Logf("pg request on a tls-only listener: %v", err)
	}
	c.Close()
	// clear-text Redis and Mongo are refused (second listener allows the plain kinds)
	c, _ = net.Dial("tcp", g.Addrs()[1].String())
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, "*1\r\n$4\r\nPING\r\n")
	b, _ := io.ReadAll(c)
	if !strings.HasPrefix(string(b), "-ERR TLS") {
		t.Errorf("plain redis answer %q", b)
	}
	c.Close()
	c, _ = net.Dial("tcp", g.Addrs()[1].String())
	c.SetDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr, 16)
	binary.LittleEndian.PutUint32(hdr[12:], mongoOpMsg)
	c.Write(hdr)
	if b, _ := io.ReadAll(c); len(b) != 0 {
		t.Errorf("plain mongo got %q", b)
	}
	c.Close()
}

func TestPGSSLRequestToRedisRouteRefused(t *testing.T) {
	backend, modes := pgBackend(t, "R") // would answer a replayed SSLRequest
	g := startGW(t, func(c *Config) { c.DenyDelay = 50 * time.Millisecond }, rt("r", "r.db.test", "redis", "passthrough", backend))
	c, err := net.Dial("tcp", g.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	req := [8]byte{0, 0, 0, 8}
	binary.BigEndian.PutUint32(req[4:], pgSSLRequest)
	c.Write(req[:])
	var s [1]byte
	io.ReadFull(c, s[:])
	tc := tls.Client(c, &tls.Config{ServerName: "r.db.test", InsecureSkipVerify: true})
	if tc.Handshake() == nil {
		t.Error("handshake completed through the wrong door")
	}
	select {
	case m := <-modes:
		t.Errorf("backend was contacted: %s", m)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestProtoConfigEnv(t *testing.T) {
	c := DefaultConfig()
	if e := applyProtoEnv(&c, func(k string) string { return map[string]string{"CAPSULE_GW_PROTO_MAX_CONNS": "mysql=10, redis=0"}[k] }); len(e) != 0 || c.ProtoMaxConns["mysql"] != 10 {
		t.Fatalf("%v %v", e, c.ProtoMaxConns)
	}
	if e := applyProtoEnv(&c, func(string) string { return "postgres=3" }); len(e) == 0 {
		t.Error("unknown protocol accepted")
	}
}

// Memory of the pre-routing state of a MySQL connection (greeting sent, waiting for the SSLRequest).
func TestMySQLIdleConnectionMemory(t *testing.T) {
	g := mysqlGW(t, func(c *Config) { c.MaxPreauthPerIP = 1000; c.NewConnsPerIP = 10000 })
	addr := g.Addrs()[0].String()
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	const n = 400
	var cs []net.Conn
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		cs = append(cs, c)
		readMySQLPacket(c, 4096)
	}
	runtime.GC()
	runtime.ReadMemStats(&m1)
	// client and server goroutines live in this process: report both, bound the total loosely
	per := (m1.HeapAlloc + m1.StackInuse - m0.HeapAlloc - m0.StackInuse) / n
	t.Logf("heap+stack per idle handshake connection (client side included): %d bytes", per)
	if per > 64<<10 {
		t.Errorf("%d bytes per connection", per)
	}
	for _, c := range cs {
		c.Close()
	}
}
