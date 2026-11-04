package data

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func freeAddr(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	ln.Close()
	return a
}

// startShared starts a gateway whose shared port is a free local port; it returns the gateway and that address.
func startShared(t testing.TB, upstream string, mod func(*Config), routes ...Route) (*testGW, string) {
	t.Helper()
	shared := freeAddr(t)
	g := startGW(t, func(c *Config) {
		c.DenyDelay = 20 * time.Millisecond
		c.Take443 = Take443Config{Enabled: true, Addr: shared, Upstream: upstream, ProxyProto: true}
		if mod != nil {
			mod(c)
		}
	}, routes...)
	return g, shared
}

func TestTake443UnknownSNIGoesToUpstreamUntouched(t *testing.T) {
	up := tlsBackend(t, "caddy")
	g, shared := startShared(t, up, func(c *Config) { c.Take443.ProxyProto = false },
		rt("r-a", "a.db.apps.test", "tls", "passthrough", tlsBackend(t, "A")))
	_ = g
	c, err := tlsDial(t, shared, "git.apps.test", "h2", "http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	if cn := certCN(t, c.ConnectionState()); cn != "caddy" {
		t.Fatalf("certificate must come from the upstream, got %s", cn)
	}
	if l := readLine(t, c); !strings.HasPrefix(l, "backend=caddy") {
		t.Fatalf("banner %q", l)
	}
	c.Close()
	// a route of the table still wins over the default upstream
	c, err = tlsDial(t, shared, "a.db.apps.test")
	if err != nil {
		t.Fatal(err)
	}
	if cn := certCN(t, c.ConnectionState()); cn != "A" {
		t.Fatalf("route must be served by its own backend, got %s", cn)
	}
	c.Close()
}

func TestTake443OwnedNamespaceAndNoSNIAreClosed(t *testing.T) {
	up := tlsBackend(t, "caddy")
	_, shared := startShared(t, up, func(c *Config) { c.Take443.ProxyProto = false })
	for _, sni := range []string{"nope.db.apps.test", ""} {
		if _, err := tlsDial(t, shared, sni); err == nil {
			t.Fatalf("sni %q must not reach the upstream", sni)
		}
	}
	// ALPN capsule/1 on a name that is not a tunnel host never goes to Caddy
	if _, err := tlsDial(t, shared, "git.apps.test", "capsule/1"); err == nil {
		t.Fatal("capsule/1 hello for another name must be closed")
	}
	// opt-in: hellos without SNI go to Caddy
	_, shared2 := startShared(t, up, func(c *Config) { c.Take443.ProxyProto = false; c.Take443.NoSNIUpstream = true })
	c, err := tlsDial(t, shared2, "")
	if err != nil {
		t.Fatalf("no-SNI with upstream mode: %v", err)
	}
	c.Close()
}

func TestTake443OnlyOnSharedPort(t *testing.T) {
	up := tlsBackend(t, "caddy")
	g, _ := startShared(t, up, func(c *Config) { c.Take443.ProxyProto = false })
	// the regular listener (index 0, "8443" role) must keep closing unknown names
	if _, err := tlsDial(t, g.Addrs()[0].String(), "git.apps.test"); err == nil {
		t.Fatal("unknown name on the non-shared listener must be closed")
	}
}

func TestTake443DisabledChangesNothing(t *testing.T) {
	up := tlsBackend(t, "caddy")
	g := startGW(t, func(c *Config) {
		c.DenyDelay = 20 * time.Millisecond
		c.Take443 = Take443Config{Enabled: false, Upstream: up}
	})
	if len(g.Addrs()) != 1 {
		t.Fatalf("flag off must not add a listener: %v", g.Addrs())
	}
	if _, err := tlsDial(t, g.addr, "git.apps.test"); err == nil {
		t.Fatal("flag off: unknown name must be closed")
	}
}

func TestTake443ProxyProtocolHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 28+5)
		io.ReadFull(c, b)
		got <- b
	}()
	_, shared := startShared(t, ln.Addr().String(), nil)
	conn, err := net.Dial("tcp", shared)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{ServerName: "git.apps.test", InsecureSkipVerify: true})
	go tc.Handshake()
	select {
	case b := <-got:
		if !bytes.HasPrefix(b, []byte("\r\n\r\n\x00\r\nQUIT\n")) || b[12] != 0x21 || b[13] != 0x11 || b[14] != 0 || b[15] != 12 {
			t.Fatalf("bad PROXY v2 header: % x", b[:16])
		}
		src := netip.AddrFrom4([4]byte(b[16:20]))
		if src != netip.MustParseAddr("127.0.0.1") {
			t.Fatalf("src %v", src)
		}
		if b[28] != 0x16 {
			t.Fatalf("ClientHello must follow the header, got % x", b[28:])
		}
		_, p, _ := net.SplitHostPort(conn.LocalAddr().String())
		if want := uint16(mustAtoi(t, p)); uint16(b[24])<<8|uint16(b[25]) != want {
			t.Fatalf("src port %d want %d", uint16(b[24])<<8|uint16(b[25]), want)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("upstream saw nothing")
	}
}

func mustAtoi(t testing.TB, s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

func TestProxyV2HeaderIPv6(t *testing.T) {
	h := proxyV2Header(netip.MustParseAddrPort("[2001:db8::1]:5555"), netip.MustParseAddrPort("[2001:db8::2]:443"))
	if len(h) != 16+36 || h[13] != 0x21 || h[14] != 0 || h[15] != 36 {
		t.Fatalf("bad v6 header len=%d % x", len(h), h[:16])
	}
	h4 := proxyV2Header(netip.MustParseAddrPort("[::ffff:1.2.3.4]:1"), netip.MustParseAddrPort("5.6.7.8:443"))
	if h4[13] != 0x11 || len(h4) != 28 {
		t.Fatalf("mapped IPv4 must use the IPv4 family: % x", h4[:16])
	}
}

func TestTake443Env(t *testing.T) {
	env := map[string]string{"CAPSULE_GW_TAKE_443": "1", "CAPSULE_GW_HTTP_UPSTREAM": "127.0.0.1:8444", "CAPSULE_GW_NO_SNI": "upstream", "CAPSULE_GW_OWNED_SUFFIXES": "svc.x.test"}
	c, err := ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	tc := c.Take443
	if !tc.Enabled || tc.Addr != "[::]:443" || !tc.ProxyProto || !tc.NoSNIUpstream || tc.OwnedSuffixes[0] != ".svc.x.test" {
		t.Fatalf("%+v", tc)
	}
	c.Zone = "z.test"
	ls := take443Listeners(c)
	if len(ls) != 2 || ls[1].Addr != "[::]:443" || len(ls[1].Allow) != 2 {
		t.Fatalf("%+v", ls)
	}
	if len(take443Listeners(Config{Listeners: ls, Take443: c.Take443})) != 2 {
		t.Fatal("must be idempotent")
	}
	off, _ := ConfigFromEnv(func(string) string { return "" })
	if off.Take443.Enabled || len(take443Listeners(off)) != 1 {
		t.Fatal("default is flag off")
	}
	if _, err := ConfigFromEnv(func(k string) string {
		if k == "CAPSULE_GW_NO_SNI" {
			return "x"
		}
		return ""
	}); err == nil {
		t.Fatal("bad NO_SNI must fail")
	}
}

// The cut-over: the gateway starts while Caddy still holds the shared port, binds it as soon as it is released
// (within one retry tick) and a client that arrives before Caddy is back waits instead of failing.
func TestTake443LateBindAndUpstreamRetry(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0") // plays the old owner of the shared port
	if err != nil {
		t.Fatal(err)
	}
	shared := held.Addr().String()
	upAddr := freeAddr(t) // Caddy is not up yet
	g := startGW(t, func(c *Config) {
		c.DenyDelay = 20 * time.Millisecond
		c.Take443 = Take443Config{Enabled: true, Addr: shared, Upstream: upAddr, BindRetry: time.Minute}
	})
	if len(g.Addrs()) != 1 {
		t.Fatalf("shared port must be pending while it is busy: %v", g.Addrs())
	}
	t0 := time.Now()
	held.Close()
	waitFor(t, 3*time.Second, func() bool { return len(g.Addrs()) == 2 })
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("late bind took %v", d)
	}
	// a client arrives while Caddy (the upstream) is still down; Caddy comes up 600 ms later
	cert := selfSigned(t, "caddy", "git.apps.test")
	go func() {
		time.Sleep(600 * time.Millisecond)
		ln, err := net.Listen("tcp", upAddr)
		if err != nil {
			return
		}
		t.Cleanup(func() { ln.Close() })
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := tls.Server(&replayless{c}, &tls.Config{Certificates: []tls.Certificate{cert}})
				if tc.Handshake() == nil {
					io.WriteString(tc, "ok\n")
				}
				c.Close()
			}()
		}
	}()
	// ProxyProto is off in this test, so the upstream sees a plain ClientHello
	g.cfg.Take443.ProxyProto = false
	t1 := time.Now()
	c, err := tlsDial(t, shared, "git.apps.test")
	if err != nil {
		t.Fatalf("client must wait for the upstream, got %v", err)
	}
	c.Close()
	if d := time.Since(t1); d < 500*time.Millisecond {
		t.Fatalf("expected a wait for the upstream, took %v", d)
	}
}

type replayless struct{ net.Conn }
