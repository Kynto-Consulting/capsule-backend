package data

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kynto/capsule/backend/internal/gateway/data/tunnel"
	"golang.org/x/crypto/ssh"
)

// ---------- SNI: TLS passthrough / termination ----------

func TestTLSPassthroughBySNI(t *testing.T) {
	a, b := tlsBackend(t, "A"), tlsBackend(t, "B")
	g := startGW(t, nil, rt("r-a", "a.apps.test", "tls", "passthrough", a), rt("r-b", "b.apps.test", "tls", "passthrough", b))
	for sni, want := range map[string]string{"a.apps.test": "A", "b.apps.test": "B"} {
		c, err := tlsDial(t, g.addr, sni)
		if err != nil {
			t.Fatal(err)
		}
		if cn := certCN(t, c.ConnectionState()); cn != want {
			t.Fatalf("%s: got cert CN %s want %s (certificate must come from the backend)", sni, cn, want)
		}
		if l := readLine(t, c); !strings.HasPrefix(l, "backend="+want) {
			t.Fatalf("banner %q", l)
		}
		io.WriteString(c, "ping\n")
		if l := readLine(t, c); l != "" { // echo of "ping\n" is the empty line before \n? no: echoes "ping"
			if l != "ping" {
				t.Fatalf("echo %q", l)
			}
		}
		c.Close()
	}
	// uppercase SNI is normalised
	c, err := tlsDial(t, g.addr, "A.Apps.Test")
	if err != nil {
		t.Fatal(err)
	}
	if certCN(t, c.ConnectionState()) != "A" {
		t.Fatal("case-insensitive SNI")
	}
	c.Close()
}

func TestUnknownSNIClosedWithoutCertificate(t *testing.T) {
	g := startGW(t, func(c *Config) { c.DenyDelay = 50 * time.Millisecond }, rt("r-a", "a.apps.test", "tls", "passthrough", tlsBackend(t, "A")))
	for _, sni := range []string{"nope.apps.test", ""} {
		_, err := tlsDial(t, g.addr, sni)
		if err == nil {
			t.Fatalf("sni %q: handshake must fail", sni)
		}
		if strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "reset") && !strings.Contains(err.Error(), "closed") {
			t.Fatalf("a certificate was presented for an unknown name: %v", err)
		}
	}
}

func TestTLSTerminate(t *testing.T) {
	echo := echoBackend(t)
	g := startGW(t, nil, rt("r-t", "x.git.test", "ssh", "terminate", echo))
	c, err := tlsDial(t, g.addr, "x.git.test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if certCN(t, c.ConnectionState()) != "gateway" {
		t.Fatal("terminate mode must present the gateway certificate")
	}
	io.WriteString(c, "hello")
	buf := make([]byte, 5)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo through terminated TLS: %q %v", buf, err)
	}
}

func TestWildcardRoute(t *testing.T) {
	g := startGW(t, nil, rt("r-w", "*.db.test", "tls", "passthrough", tlsBackend(t, "W")))
	c, err := tlsDial(t, g.addr, "anything.db.test")
	if err != nil {
		t.Fatal(err)
	}
	if certCN(t, c.ConnectionState()) != "W" {
		t.Fatal("wildcard")
	}
	c.Close()
	if _, err := tlsDial(t, g.addr, "db.test"); err == nil {
		t.Fatal("the wildcard must not match its own apex")
	}
}

// ---------- PostgreSQL ----------

func pgClassicConnect(t testing.TB, addr, sni string) (*tls.Conn, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req, 8)
	binary.BigEndian.PutUint32(req[4:], pgSSLRequest)
	c.Write(req)
	var ans [1]byte
	if _, err := io.ReadFull(c, ans[:]); err != nil {
		c.Close()
		return nil, err
	}
	if ans[0] != 'S' {
		c.Close()
		return nil, io.ErrUnexpectedEOF
	}
	tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: nil})
	if err := tc.Handshake(); err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return tc, nil
}

func TestPostgresClassicSSLRequestPassthrough(t *testing.T) {
	addrA, modesA := pgBackend(t, "PGA")
	addrB, modesB := pgBackend(t, "PGB")
	g := startGW(t, nil, rt("pg-a", "a.db.test", "postgres", "passthrough", addrA), rt("pg-b", "b.db.test", "postgres", "passthrough", addrB))
	for _, tc := range []struct {
		sni, want string
		modes     chan string
	}{{"a.db.test", "PGA", modesA}, {"b.db.test", "PGB", modesB}} {
		c, err := pgClassicConnect(t, g.addr, tc.sni)
		if err != nil {
			t.Fatal(err)
		}
		if cn := certCN(t, c.ConnectionState()); cn != tc.want {
			t.Fatalf("cert CN %s want %s", cn, tc.want)
		}
		if l := readLine(t, c); l != "backend="+tc.want {
			t.Fatalf("banner %q", l)
		}
		select {
		case m := <-tc.modes:
			if !strings.HasPrefix(m, "classic") {
				t.Fatalf("backend must see the replayed SSLRequest, saw %q", m)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("backend saw nothing")
		}
		c.Close()
	}
}

func TestPostgresDirectTLSPassthrough(t *testing.T) {
	addr, modes := pgBackend(t, "PGD")
	g := startGW(t, nil, rt("pg-d", "d.db.test", "postgres", "passthrough", addr))
	c, err := tlsDial(t, g.addr, "d.db.test", "postgresql")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if readLine(t, c) != "backend=PGD" {
		t.Fatal("banner")
	}
	if m := <-modes; m != "direct alpn=postgresql" {
		t.Fatalf("mode %q", m)
	}
}

func TestPostgresTerminateAdvertisesALPN(t *testing.T) {
	g := startGW(t, nil, rt("pg-t", "t.db.test", "postgres", "terminate", echoBackend(t)))
	c, err := tlsDial(t, g.addr, "t.db.test", "postgresql")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.ConnectionState().NegotiatedProtocol != "postgresql" {
		t.Fatal("sslnegotiation=direct needs ALPN postgresql from the server")
	}
}

func TestPostgresGSSRequestDeclinedThenSSL(t *testing.T) {
	addr, _ := pgBackend(t, "PGG")
	g := startGW(t, nil, rt("pg-g", "g.db.test", "postgres", "passthrough", addr))
	c, err := net.DialTimeout("tcp", g.addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req, 8)
	binary.BigEndian.PutUint32(req[4:], pgGSSRequest)
	c.Write(req)
	var a [1]byte
	io.ReadFull(c, a[:])
	if a[0] != 'N' {
		t.Fatalf("GSS must be declined, got %q", a[0])
	}
	binary.BigEndian.PutUint32(req[4:], pgSSLRequest)
	c.Write(req)
	io.ReadFull(c, a[:])
	if a[0] != 'S' {
		t.Fatalf("got %q", a[0])
	}
	tc := tls.Client(c, &tls.Config{ServerName: "g.db.test", InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresBytesAfterSSLRequestRejected(t *testing.T) {
	g := startGW(t, nil, rt("pg-a", "a.db.test", "postgres", "passthrough", echoBackend(t)))
	c, _ := net.DialTimeout("tcp", g.addr, 3*time.Second)
	defer c.Close()
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req, 8)
	binary.BigEndian.PutUint32(req[4:], pgSSLRequest)
	c.Write(append(req, "injected"...))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ := io.ReadAll(c)
	if len(b) != 0 {
		t.Fatalf("no 'S' may be sent when bytes were injected before the answer, got %q", b)
	}
}

// ---------- SSH over TLS ----------

func TestSSHOverTLS(t *testing.T) {
	// a real SSH server (x/crypto/ssh) behind a terminate-mode route
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, priv := mustKey(t)
	scfg := &ssh.ServerConfig{NoClientAuth: true}
	scfg.AddHostKey(priv)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, scfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, rq, _ := nc.Accept()
					go func() {
						for r := range rq {
							if r.Type == "exec" {
								r.Reply(true, nil)
								io.WriteString(ch, "ssh-ok")
								ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								ch.Close()
							} else {
								r.Reply(false, nil)
							}
						}
					}()
				}
				sc.Close()
			}()
		}
	}()
	g := startGW(t, nil, rt("ssh", "ssh-a.git.test", "ssh", "terminate", ln.Addr().String()))
	tc, err := tlsDial(t, g.addr, "ssh-a.git.test")
	if err != nil {
		t.Fatal(err)
	}
	cc, chans, reqs, err := ssh.NewClientConn(tc, "ssh-a.git.test", &ssh.ClientConfig{User: "git", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	cli := ssh.NewClient(cc, chans, reqs)
	defer cli.Close()
	sess, err := cli.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("anything")
	if err != nil || string(out) != "ssh-ok" {
		t.Fatalf("exec through SSH-over-TLS: %q %v", out, err)
	}
}

// ---------- clear HTTP ----------

func TestHTTPByHost(t *testing.T) {
	be := httpTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "host="+r.Host) }))
	h, p := hostPort(strings.TrimPrefix(be, "http://"))
	r := Route{ID: "h1", OrgID: "o", Service: "web", Host: "web.apps.test", Transport: "tcp", Protocol: "http", DestHost: h, DestPort: p, Mode: "passthrough"}
	g := startGW(t, nil, r)
	// routing is decided once per connection (the first request): one connection per request here
	cli := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	req, _ := http.NewRequest("GET", "http://"+g.addr+"/x", nil)
	req.Host = "web.apps.test"
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "host=web.apps.test" {
		t.Fatalf("body %q", b)
	}
	req2, _ := http.NewRequest("GET", "http://"+g.addr+"/x", nil)
	req2.Host = "other.apps.test"
	if resp, err := cli.Do(req2); err == nil {
		resp.Body.Close()
		t.Fatal("unknown host must be closed silently")
	}
}

func TestUnknownProtocolAndSSHBannerClosed(t *testing.T) {
	g := startGW(t, nil)
	for _, first := range []string{"SSH-2.0-OpenSSH\r\n", "\x01\x02\x03\x04garbage-bytes", "\x00\x00\x00\x08\x04\xd2\x16\x2e"} { // last: CancelRequest
		c, _ := net.DialTimeout("tcp", g.addr, 3*time.Second)
		io.WriteString(c, first)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if b, _ := io.ReadAll(c); len(b) != 0 {
			t.Fatalf("%q answered %q", first, b)
		}
		c.Close()
	}
}

func TestListenerAllowList(t *testing.T) {
	be := tlsBackend(t, "A")
	g := startGW(t, func(c *Config) { c.Listeners = []ListenerSpec{{Addr: "127.0.0.1:0", Allow: []Kind{KindHTTP}}} }, rt("r-a", "a.apps.test", "tls", "passthrough", be))
	if _, err := tlsDial(t, g.addr, "a.apps.test"); err == nil {
		t.Fatal("this listener only accepts HTTP")
	}
}

// ---------- capsule/1 tunnel ----------

func tunnelGW(t testing.TB, mod func(*Config)) (*testGW, string) {
	echo := echoBackend(t)
	g := startGW(t, mod, tunnelRoute("t-db", "mi-proyecto", "db", echo), tunnelRoute("t-other", "otro", "db", echo))
	return g, echo
}

func TestTunnelEchoAndHalfClose(t *testing.T) {
	g, _ := tunnelGW(t, nil)
	tc, resp := dialTunnel(t, g.addr, capReq("mi-proyecto", "db"), nil)
	defer tc.Close()
	if resp.Status != 0 || resp.Code != 0 {
		t.Fatalf("status %d code %#x", resp.Status, resp.Code)
	}
	io.WriteString(tc, "hello tunnel")
	buf := make([]byte, len("hello tunnel"))
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "hello tunnel" {
		t.Fatalf("echo %q %v", buf, err)
	}
	// half-close: the destination must see FIN, answer and close; we must still be able to read it.
	if err := tc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	rest, err := io.ReadAll(tc)
	if err != nil {
		t.Fatalf("reading after half-close: %v", err)
	}
	if string(rest) != "done:12" {
		t.Fatalf("destination reply after FIN: %q", rest)
	}
}

func TestTunnelWantProxyInfoAndAuthorizeContract(t *testing.T) {
	g, _ := tunnelGW(t, nil)
	r := capReq("mi-proyecto", "db")
	r.Flags = 1
	tc, resp := dialTunnel(t, g.addr, r, nil)
	defer tc.Close()
	if resp.ClientAddr == nil || resp.ClientAddr.Addr.String() != "127.0.0.1" || resp.ClientAddr.Port == 0 {
		t.Fatalf("client_addr %+v", resp.ClientAddr)
	}
	a := g.cp.lastAuth.Load().(AuthorizeRequest)
	if a.RouteID != "t-db" || a.SrcIP != "127.0.0.1" || a.CredentialType != "cap" || a.Credential != r.Auth || a.Access != "capsule_uri" {
		t.Fatalf("authorize request %+v", a)
	}
}

func TestTunnelOptimisticDataForwardedAfterAuthorization(t *testing.T) {
	g, _ := tunnelGW(t, nil)
	d := net.Dialer{Timeout: 3 * time.Second}
	c, _ := d.Dial("tcp", g.addr)
	tc := tls.Client(c, &tls.Config{ServerName: "tcp." + testZone, InsecureSkipVerify: true, NextProtos: []string{"capsule/1"}})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	hdr, _ := tunnel.EncodeRequest(capReq("mi-proyecto", "db"))
	tc.Write(append(hdr, "early-data"...)) // header and data in one write
	resp := readCAPR(t, tc)
	if resp.Status != 0 {
		t.Fatalf("status %d", resp.Status)
	}
	buf := make([]byte, 10)
	tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "early-data" {
		t.Fatalf("optimistic data lost: %q %v", buf, err)
	}
	tc.Close()

	// and it is discarded when authorisation fails
	g.cp.Decide = func(AuthorizeRequest) AuthorizeResponse {
		return AuthorizeResponse{Allow: false, DenyReason: "unauthorized"}
	}
	r2 := capReq("mi-proyecto", "db")
	r2.Auth = "cap_" + strings.Repeat("Z", 43) // a different credential: the 30 s decision cache is keyed by it
	hdr, _ = tunnel.EncodeRequest(r2)
	c2, _ := d.Dial("tcp", g.addr)
	tc2 := tls.Client(c2, &tls.Config{ServerName: "tcp." + testZone, InsecureSkipVerify: true, NextProtos: []string{"capsule/1"}})
	tc2.Handshake()
	tc2.Write(append(hdr, "must-not-arrive"...))
	if r := readCAPR(t, tc2); r.Status != 2 {
		t.Fatalf("status %d", r.Status)
	}
}

func TestTunnelUniformNotAuthorized(t *testing.T) {
	g, _ := tunnelGW(t, nil)
	g.cp.Decide = func(req AuthorizeRequest) AuthorizeResponse {
		if req.RouteID == "t-db" && req.Credential == "cap_"+strings.Repeat("A", 43) {
			return AuthorizeResponse{Allow: true, PrincipalID: "u"}
		}
		return AuthorizeResponse{Allow: false, DenyReason: "unauthorized"}
	}
	type result struct {
		raw []byte
		dur time.Duration
	}
	attempt := func(r *tunnel.Request) result {
		start := time.Now()
		tc, resp := dialTunnel(t, g.addr, r, nil)
		_ = tc
		d := time.Since(start)
		tc.Close()
		return result{tunnel.EncodeResponse(resp), d}
	}
	badToken := capReq("mi-proyecto", "db")
	badToken.Auth = "cap_" + strings.Repeat("B", 43)
	cases := map[string]*tunnel.Request{
		"bad token":          badToken,
		"project not found":  capReq("no-existe", "db"),
		"service not found":  capReq("mi-proyecto", "nada"),
		"other tenant route": capReq("otro", "db"), // valid token of project A asking B/db
	}
	var first []byte
	for name, r := range cases {
		res := attempt(r)
		if first == nil {
			first = res.raw
		}
		if !bytes.Equal(res.raw, first) {
			t.Fatalf("%s: response bytes differ: %x vs %x", name, res.raw, first)
		}
		want := tunnel.EncodeResponse(&tunnel.Response{Status: 2, Code: 0x0201, Msg: "not authorized"})
		if !bytes.Equal(res.raw, want) {
			t.Fatalf("%s: not the normative uniform answer: %x", name, res.raw)
		}
		// T_UNIF = 300 ms +- 50 ms from the end of the header (the handshake and the round trip add little on loopback)
		if res.dur < 245*time.Millisecond || res.dur > 700*time.Millisecond {
			t.Fatalf("%s: answered in %v, want about 300 ms", name, res.dur)
		}
	}
}

func TestTunnelStatusMapping(t *testing.T) {
	g, _ := tunnelGW(t, nil)
	cases := []struct {
		reason string
		status byte
		code   uint16
	}{
		{"ip_denied", 3, 0x0301},
		{"quota", 5, 0x0501},
		{"unavailable", 4, 0x0401},
	}
	for i, c := range cases {
		reason := c.reason
		g.cp.Decide = func(AuthorizeRequest) AuthorizeResponse { return AuthorizeResponse{Allow: false, DenyReason: reason} }
		r := capReq("mi-proyecto", "db")
		r.Auth = "cap_" + strings.Repeat(string(rune('a'+i)), 43) // decisions are cached per credential
		tc, resp := dialTunnel(t, g.addr, r, nil)
		tc.Close()
		if resp.Status != c.status || resp.Code != c.code {
			t.Fatalf("%s: got %d/%#x want %d/%#x", reason, resp.Status, resp.Code, c.status, c.code)
		}
	}
}

func TestTunnelFailsClosedWhenControlPlaneDown(t *testing.T) {
	g, _ := tunnelGW(t, nil)
	g.cp.down.Store(true)
	tc, resp := dialTunnel(t, g.addr, capReq("mi-proyecto", "db"), nil)
	tc.Close()
	if resp.Status != 6 || resp.Code != 0x0602 {
		t.Fatalf("got %d/%#x want 6/0x0602", resp.Status, resp.Code)
	}
}

func TestTunnelHeaderErrors(t *testing.T) {
	g, _ := tunnelGW(t, nil)
	send := func(raw []byte, closeWrite bool) (*tunnel.Response, error) {
		d := net.Dialer{Timeout: 3 * time.Second}
		c, _ := d.Dial("tcp", g.addr)
		tc := tls.Client(c, &tls.Config{ServerName: "tcp." + testZone, InsecureSkipVerify: true, NextProtos: []string{"capsule/1"}})
		if err := tc.Handshake(); err != nil {
			return nil, err
		}
		defer tc.Close()
		tc.Write(raw)
		if closeWrite {
			tc.CloseWrite()
		}
		tc.SetReadDeadline(time.Now().Add(8 * time.Second))
		b, _ := io.ReadAll(tc)
		r, _, err := tunnel.DecodeResponse(b, true)
		return r, err
	}
	good, _ := tunnel.EncodeRequest(capReq("mi-proyecto", "db"))
	mut := func(f func(b []byte)) []byte { b := append([]byte(nil), good...); f(b); return b }
	cases := []struct {
		name string
		raw  []byte
		cw   bool
		code uint16
	}{
		{"bad magic", mut(func(b []byte) { b[0] = 'X' }), false, 0x0102},
		{"http on the tunnel", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), false, 0x0102},
		{"unknown version", mut(func(b []byte) { b[4] = 9 }), false, 0x0101},
		{"hdr_len too large", mut(func(b []byte) { b[6], b[7] = 0x08, 0 }), false, 0x0103},
		{"reserved flags", mut(func(b []byte) { b[5] = 2 }), false, 0x0104},
		{"transport udp not enabled", mut(func(b []byte) { b[8] = 2 }), false, 0x0109},
		{"transport 3", mut(func(b []byte) { b[8] = 3 }), false, 0x0109},
		{"truncated at EOF", good[:30], true, 0x010A},
		{"empty at EOF", nil, true, 0x010A},
	}
	for _, c := range cases {
		r, err := send(c.raw, c.cw)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if r.Status != 1 || r.Code != c.code {
			t.Fatalf("%s: got %d/%#x want 1/%#x", c.name, r.Status, r.Code, c.code)
		}
		if c.code == 0x0101 && (r.MaxVersion == nil || *r.MaxVersion != 1) {
			t.Fatal("unsupported version must carry max_version")
		}
	}
}

func TestTunnelHeaderTimeout5s(t *testing.T) {
	g, _ := tunnelGW(t, nil)
	d := net.Dialer{Timeout: 3 * time.Second}
	c, _ := d.Dial("tcp", g.addr)
	tc := tls.Client(c, &tls.Config{ServerName: "tcp." + testZone, InsecureSkipVerify: true, NextProtos: []string{"capsule/1"}})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	start := time.Now()
	tc.Write([]byte("CAP1\x01\x00")) // slowloris: 6 bytes and silence
	tc.SetReadDeadline(time.Now().Add(9 * time.Second))
	b, _ := io.ReadAll(tc)
	r, _, err := tunnel.DecodeResponse(b, true)
	if err != nil || r.Code != 0x010A {
		t.Fatalf("got %v %v", r, err)
	}
	if el := time.Since(start); el < 4500*time.Millisecond || el > 7*time.Second {
		t.Fatalf("header timeout fired after %v, want 5 s", el)
	}
}

func TestTunnelRejectsTLS12AndWrongALPN(t *testing.T) {
	g, _ := tunnelGW(t, nil)
	d := net.Dialer{Timeout: 3 * time.Second}
	c, _ := d.Dial("tcp", g.addr)
	tc := tls.Client(c, &tls.Config{ServerName: "tcp." + testZone, InsecureSkipVerify: true, NextProtos: []string{"capsule/1"}, MaxVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err == nil {
		t.Fatal("TLS 1.2 must be rejected on capsule/1")
	}
	// ALPN other than capsule/1 on a tunnel host is not a tunnel: it follows the SNI route table (none) and closes
	c2, _ := d.Dial("tcp", g.addr)
	tc2 := tls.Client(c2, &tls.Config{ServerName: "tcp." + testZone, InsecureSkipVerify: true, NextProtos: []string{"capsule/9"}})
	if err := tc2.Handshake(); err == nil {
		t.Fatal("unknown ALPN must not complete a handshake")
	}
}

func TestTunnelDrainingReturns0601(t *testing.T) {
	g, _ := tunnelGW(t, nil)
	g.draining.Store(true)
	tc, resp := dialTunnel(t, g.addr, capReq("mi-proyecto", "db"), nil)
	tc.Close()
	if resp.Status != 6 || resp.Code != 0x0601 {
		t.Fatalf("got %d/%#x", resp.Status, resp.Code)
	}
}

func TestTunnelLimits(t *testing.T) {
	g, _ := tunnelGW(t, nil)
	g.cp.Decide = func(AuthorizeRequest) AuthorizeResponse {
		return AuthorizeResponse{Allow: true, PrincipalID: "u", MaxConns: 2, MaxConnsPerIP: 50}
	}
	var open []*tls.Conn
	for i := 0; i < 2; i++ {
		tc, resp := dialTunnel(t, g.addr, capReq("mi-proyecto", "db"), nil)
		if resp.Status != 0 {
			t.Fatalf("conn %d: %d/%#x", i, resp.Status, resp.Code)
		}
		open = append(open, tc)
	}
	tc, resp := dialTunnel(t, g.addr, capReq("mi-proyecto", "db"), nil)
	tc.Close()
	if resp.Status != 5 || resp.Code != 0x0501 {
		t.Fatalf("route limit: %d/%#x", resp.Status, resp.Code)
	}
	for _, c := range open {
		c.Close()
	}
	waitFor(t, 3*time.Second, func() bool { return g.rl.Count("t-db") == 0 })
}

func TestTunnelDestinationDown(t *testing.T) {
	r := tunnelRoute("t-x", "p", "s", "127.0.0.1:1")
	g := startGW(t, nil, r)
	tc, resp := dialTunnel(t, g.addr, capReq("p", "s"), nil)
	tc.Close()
	if resp.Status != 4 {
		t.Fatalf("got %d/%#x", resp.Status, resp.Code)
	}
}

func TestTunnelBruteForceBlock(t *testing.T) {
	g, _ := tunnelGW(t, func(c *Config) { c.DenyDelay = 10 * time.Millisecond })
	g.cp.Decide = func(AuthorizeRequest) AuthorizeResponse {
		return AuthorizeResponse{Allow: false, DenyReason: "unauthorized"}
	}
	var last *tunnel.Response
	for i := 0; i < 12; i++ {
		tc, resp := dialTunnel(t, g.addr, capReq("mi-proyecto", "db"), nil)
		tc.Close()
		last = resp
		if resp.Status == 5 {
			break
		}
	}
	if last.Status != 5 || last.Code != 0x0503 {
		t.Fatalf("after 10 failures the source must be blocked with 5/0x0503, got %d/%#x", last.Status, last.Code)
	}
}

func TestTunnelCGCLocalVerification(t *testing.T) {
	pub, priv := mustKey(t)
	_ = pub
	edpub, edpriv := newEd(t)
	g, _ := tunnelGW(t, func(c *Config) { c.CGCKeys = []CGCKey{{KID: "k1", Pub: edpub}} })
	_ = priv
	mk := func(route string, exp time.Duration, jti string) string {
		return mintCGC(t, edpriv, "k1", route, time.Now().Add(exp), jti)
	}
	cgcReq := func(tok string) *tunnel.Request {
		r := capReq("mi-proyecto", "db")
		r.AuthType, r.Auth = tunnel.AuthCgc, tok
		return r
	}
	tok := mk("mi-proyecto/db", 2*time.Minute, "jti-0123456789abcdef")
	tc, resp := dialTunnel(t, g.addr, cgcReq(tok), nil)
	tc.Close()
	if resp.Status != 0 {
		t.Fatalf("valid cgc: %d/%#x", resp.Status, resp.Code)
	}
	tc, resp = dialTunnel(t, g.addr, cgcReq(tok), nil)
	tc.Close()
	if resp.Status != 2 || resp.Code != 0x0203 {
		t.Fatalf("replayed jti: %d/%#x", resp.Status, resp.Code)
	}
	tc, resp = dialTunnel(t, g.addr, cgcReq(mk("mi-proyecto/db", -2*time.Minute, "jti-expired-0123456")), nil)
	tc.Close()
	if resp.Status != 2 || resp.Code != 0x0202 {
		t.Fatalf("expired: %d/%#x", resp.Status, resp.Code)
	}
	tc, resp = dialTunnel(t, g.addr, cgcReq(mk("otro/db", 2*time.Minute, "jti-other-0123456789")), nil)
	tc.Close()
	if resp.Status != 2 || resp.Code != 0x0201 {
		t.Fatalf("route mismatch: %d/%#x", resp.Status, resp.Code)
	}
}

// ---------- IPv6 ----------

func TestIPv6DualStack(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback on this machine")
	}
	ln.Close()
	be := tlsBackend(t, "A")
	echo := echoBackend(t)
	g := startGW(t, func(c *Config) { c.Listeners = []ListenerSpec{{Addr: "[::]:0"}} }, rt("r-a", "a.apps.test", "tls", "passthrough", be), tunnelRoute("t", "mi-proyecto", "db", echo))
	_, port := hostPort(g.addr)
	for _, host := range []string{"[::1]", "127.0.0.1"} {
		addr := host + ":" + itoa(port)
		c, err := tlsDial(t, addr, "a.apps.test")
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		c.Close()
		want := "127.0.0.1"
		if host == "[::1]" {
			want = "::1"
		}
		if a := g.cp.lastAuth.Load().(AuthorizeRequest); a.SrcIP != want { // never "::ffff:127.0.0.1"
			t.Fatalf("%s: src_ip %q want %q", host, a.SrcIP, want)
		}
	}
	tc, resp := dialTunnel(t, "[::1]:"+itoa(port), func() *tunnel.Request { r := capReq("mi-proyecto", "db"); r.Flags = 1; return r }(), nil)
	defer tc.Close()
	if resp.Status != 0 || resp.ClientAddr == nil || resp.ClientAddr.Addr.String() != "::1" {
		t.Fatalf("tunnel over IPv6: %+v", resp)
	}
	if a := g.cp.lastAuth.Load().(AuthorizeRequest); a.SrcIP != "::1" {
		t.Fatalf("src_ip %q", a.SrcIP)
	}
}

// ---------- control plane behaviour ----------

func TestHotReloadOfRoutes(t *testing.T) {
	a := tlsBackend(t, "A")
	g := startGW(t, nil, rt("r-a", "a.apps.test", "tls", "passthrough", a))
	if _, err := tlsDial(t, g.addr, "c.apps.test"); err == nil {
		t.Fatal("route c must not exist yet")
	}
	c := tlsBackend(t, "C")
	g.cp.SetRoutes(2, rt("r-a", "a.apps.test", "tls", "passthrough", a), rt("r-c", "c.apps.test", "tls", "passthrough", c))
	waitFor(t, 5*time.Second, func() bool { return g.Routes().Rev() == 2 })
	conn, err := tlsDial(t, g.addr, "c.apps.test")
	if err != nil {
		t.Fatal(err)
	}
	if certCN(t, conn.ConnectionState()) != "C" {
		t.Fatal("new route must serve C")
	}
	conn.Close()
	// removing a route takes effect without a restart
	g.cp.SetRoutes(3, rt("r-c", "c.apps.test", "tls", "passthrough", c))
	waitFor(t, 5*time.Second, func() bool { return g.Routes().Rev() == 3 })
	if _, err := tlsDial(t, g.addr, "a.apps.test"); err == nil {
		t.Fatal("removed route still served")
	}
}

func TestFailStaticAndMaxAge(t *testing.T) {
	a := tlsBackend(t, "A")
	g := startGW(t, func(c *Config) { c.RoutesMaxAge = 3 * time.Second; c.RoutesWait = time.Second }, rt("r-a", "a.apps.test", "tls", "passthrough", a))
	if c, err := tlsDial(t, g.addr, "a.apps.test"); err != nil { // one connection populates the decision cache
		t.Fatal(err)
	} else {
		c.Close()
	}
	g.cp.down.Store(true) // control plane outage
	time.Sleep(1200 * time.Millisecond)
	c, err := tlsDial(t, g.addr, "a.apps.test")
	if err != nil {
		t.Fatalf("the last known table must keep being served during an outage: %v", err)
	}
	c.Close()
	if g.Routes().ControlUp() {
		t.Fatal("control must be reported down")
	}
	// the authorisation path also needs the control plane: not cached => fail closed; the cached one (30 s) survives
	waitFor(t, 8*time.Second, func() bool { return !g.Routes().Ready() })
	if _, err := tlsDial(t, g.addr, "a.apps.test"); err == nil {
		t.Fatal("a table older than the limit must not be served")
	}
	// recovery
	g.cp.down.Store(false)
	waitFor(t, 10*time.Second, func() bool { return g.Routes().Ready() })
	c, err = tlsDial(t, g.addr, "a.apps.test")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestSNIFailsClosedWithoutCachedDecision(t *testing.T) {
	a := tlsBackend(t, "A")
	g := startGW(t, func(c *Config) { c.DenyDelay = 20 * time.Millisecond }, rt("r-a", "a.apps.test", "tls", "passthrough", a))
	c, err := tlsDial(t, g.addr, "a.apps.test") // populates the cache
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	g.cp.down.Store(true)
	if c, err := tlsDial(t, g.addr, "a.apps.test"); err != nil { // same key: served from the 30 s cache
		t.Fatalf("cached allow must survive a control plane outage: %v", err)
	} else {
		c.Close()
	}
	g.authz.mu.Lock()
	g.authz.cache = nil // forget
	g.authz.mu.Unlock()
	if _, err := tlsDial(t, g.addr, "a.apps.test"); err == nil {
		t.Fatal("not cached and control plane down must fail closed")
	}
}

func TestSNIDeniedIsSilentAndAuthorizedPerConnection(t *testing.T) {
	a := tlsBackend(t, "A")
	g := startGW(t, func(c *Config) { c.DenyDelay = 20 * time.Millisecond }, rt("r-a", "a.apps.test", "tls", "passthrough", a))
	g.cp.Decide = func(AuthorizeRequest) AuthorizeResponse {
		return AuthorizeResponse{Allow: false, DenyReason: "ip_denied"}
	}
	if _, err := tlsDial(t, g.addr, "a.apps.test"); err == nil {
		t.Fatal("denied connection must not complete a handshake")
	}
	if a := g.cp.lastAuth.Load().(AuthorizeRequest); a.CredentialType != "none" || a.Access != "sni_name" || a.RouteID != "r-a" {
		t.Fatalf("authorize request %+v", a)
	}
}

func TestSecretIsSentAndNeverLogged(t *testing.T) {
	a := tlsBackend(t, "A")
	g := startGW(t, nil, rt("r-a", "a.apps.test", "tls", "passthrough", a))
	// wrong secret: the control plane answers 401 and the gateway never becomes ready
	cp := newFakeControl()
	hc, _ := NewHTTPControl(httpTestServer(t, cp), "wrong-secret")
	if _, err := hc.Routes(context.Background(), 0, 0); err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("expected an unauthorised error, got %v", err)
	}
	tc, resp := dialTunnel(t, g.addr, func() *tunnel.Request { return capReq("zz", "zz") }(), nil)
	tc.Close()
	_ = resp
	time.Sleep(50 * time.Millisecond)
	logs := g.logs.String()
	for _, secret := range []string{"test-secret", "cap_" + strings.Repeat("A", 43)} {
		if strings.Contains(logs, secret) {
			t.Fatalf("log contains a secret/token: %s", secret)
		}
	}
	if !strings.Contains(logs, `"msg":"conn"`) || !strings.Contains(logs, "req_hash") {
		t.Fatalf("expected one JSON event per connection with a hashed request, got:\n%s", logs)
	}
}

// ---------- observability and lifecycle ----------

func TestMetricsAndHealth(t *testing.T) {
	be := tlsBackend(t, "A")
	g := startGW(t, nil, rt("r-a", "a.apps.test", "tls", "passthrough", be))
	c, err := tlsDial(t, g.addr, "a.apps.test")
	if err != nil {
		t.Fatal(err)
	}
	readLine(t, c)
	c.Close()
	waitFor(t, 3*time.Second, func() bool { return g.Active() == 0 })
	admin := httpTestServer(t, g.AdminHandler())
	get := func(p string) (int, string) {
		resp, err := http.Get(admin + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := get("/healthz"); code != 200 {
		t.Fatal("healthz")
	}
	if code, _ := get("/readyz"); code != 200 {
		t.Fatal("readyz")
	}
	_, m := get("/metrics")
	for _, want := range []string{`gw_conns_total{result="ok",route="r-a"} 1`, `gw_bytes_total{dir="out",route="r-a"}`, "gw_handshake_seconds_bucket", "gw_route_rev 1", "gw_routes 1", "gw_control_up 1", "gw_draining 0"} {
		if !strings.Contains(m, want) {
			t.Fatalf("metrics missing %q in:\n%s", want, m)
		}
	}
	g.draining.Store(true)
	if code, _ := get("/readyz"); code != 503 {
		t.Fatal("readyz must fail while draining")
	}
}

func TestDrainKeepsExistingConnectionsAndRefusesNewOnes(t *testing.T) {
	g, _ := tunnelGW(t, func(c *Config) { c.DrainGrace = 100 * time.Millisecond })
	tc, resp := dialTunnel(t, g.addr, capReq("mi-proyecto", "db"), nil)
	if resp.Status != 0 {
		t.Fatal(resp.Status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- g.Drain(ctx, 100*time.Millisecond) }()
	waitFor(t, 3*time.Second, func() bool { return g.Draining() })
	// the open connection keeps working through the drain
	time.Sleep(400 * time.Millisecond)
	io.WriteString(tc, "still alive")
	buf := make([]byte, 11)
	tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "still alive" {
		t.Fatalf("connection cut by the drain: %q %v", buf, err)
	}
	// new connections are refused (listener closed)
	if c, err := net.DialTimeout("tcp", g.addr, time.Second); err == nil {
		c.Close()
		t.Fatal("listener must be closed after the grace period")
	}
	select {
	case <-done:
		t.Fatal("drain returned while a connection is still open")
	case <-time.After(200 * time.Millisecond):
	}
	tc.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("drain: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not finish after the last connection closed")
	}
}

func TestDrainDeadlineClosesStragglers(t *testing.T) {
	g, _ := tunnelGW(t, nil)
	tc, resp := dialTunnel(t, g.addr, capReq("mi-proyecto", "db"), nil)
	if resp.Status != 0 {
		t.Fatal(resp.Status)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := g.Drain(ctx, 0)
	if err == nil {
		t.Fatal("drain with a straggler and an expired deadline must report it")
	}
	tc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, rerr := tc.Read(make([]byte, 1)); rerr == nil {
		t.Fatal("straggler must be closed")
	}
}

func TestProcessConnectionLimit(t *testing.T) {
	be := echoBackend(t)
	g := startGW(t, func(c *Config) { c.MaxConns = 3 }, rt("r-a", "a.apps.test", "tls", "terminate", be))
	var held []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", g.addr)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	waitFor(t, 2*time.Second, func() bool { return g.Active() == 3 })
	c, err := net.Dial("tcp", g.addr)
	if err == nil {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, rerr := c.Read(make([]byte, 1)); rerr == nil || n != 0 {
			t.Fatal("over the process limit the connection must be closed")
		}
		c.Close()
	}
	for _, c := range held {
		c.Close()
	}
}

func TestPerIPPreauthLimit(t *testing.T) {
	g := startGW(t, func(c *Config) { c.MaxPreauthPerIP = 5; c.NewConnsPerIP = 1000 })
	var held []net.Conn
	for i := 0; i < 5; i++ {
		c, _ := net.Dial("tcp", g.addr) // idle, unauthenticated (slowloris style)
		held = append(held, c)
	}
	waitFor(t, 2*time.Second, func() bool { return g.Active() == 5 })
	c, _ := net.Dial("tcp", g.addr)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("6th unauthenticated connection from one IP must be dropped")
	}
	for _, h := range held {
		h.Close()
	}
}

func TestDestinationGuardBlocksMetadataAddress(t *testing.T) {
	g := startGW(t, func(c *Config) { c.AllowLoopbackDest = false; c.DialTimeout = time.Second },
		Route{ID: "m", OrgID: "o", Service: "s", Host: "m.apps.test", Transport: "tcp", Protocol: "tls", DestHost: "169.254.169.254", DestPort: 80, Mode: "passthrough"},
		Route{ID: "l", OrgID: "o", Service: "s2", Host: "l.apps.test", Transport: "tcp", Protocol: "tls", DestHost: "127.0.0.1", DestPort: 80, Mode: "passthrough"})
	for _, sni := range []string{"m.apps.test", "l.apps.test"} {
		if c, err := tlsDial(t, g.addr, sni); err == nil {
			c.Close()
			t.Fatalf("%s: dial to a forbidden destination must fail", sni)
		}
	}
	if !strings.Contains(g.logs.String(), `"result":"dest_down"`) {
		t.Fatal("expected dest_down events")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
