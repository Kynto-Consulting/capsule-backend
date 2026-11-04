package data

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// MySQL / MariaDB (PLAN.md 2 and 3.1). The server speaks first, so the gateway cannot read an SNI before it has said
// something. What it does, on a listener whose only kind is "mysql" (CAPSULE_GW_LISTEN="[::]:3306=mysql"):
//
//  1. It sends its own HandshakeV10 greeting advertising CLIENT_SSL (no backend is chosen yet).
//  2. The client answers with the short SSLRequest packet (32 bytes of payload) and starts TLS: the ClientHello carries
//     the SNI. A client that does not switch to TLS gets ERROR 3159 and is closed (name-independent, leaks nothing).
//  3. SNI -> route -> /internal/gateway/authorize (credential none, access sni_name, IP list), the same as every
//     protocol. An unknown name is closed silently after the uniform delay, without an answer to the ClientHello.
//  4. passthrough: the gateway dials the backend, reads and discards the backend's greeting, replays the client's own
//     SSLRequest and ClientHello to it and then relays bytes: TLS is end to end between client and MySQL. The password
//     scramble the client computed used the gateway's salt, which the backend never issued: MySQL recovers because the
//     client's plugin either matches (caching_sha2_password: the fast path fails and the server asks for full
//     authentication, which over TLS sends the password in the clear inside the tunnel) or it does not (the server
//     sends an AuthSwitchRequest with its own salt). Both work with the stock clients.
//     terminate: the gateway terminates the client's TLS with its certificate and opens a new TLS session to the
//     backend (certificate not verified: internal network, the destination is fixed by the route), then relays.
//     The backend must offer TLS (MySQL 8 does by default).
//
// Limits (documented in docs/gateway/RUNBOOK-protocols.md): the client needs TLS and must send SNI (clients that do not
// send it cannot be routed); compression and the zstd/query-attributes capabilities are not offered; the greeting is
// the gateway's, so the server version the client displays is not the backend's.

const (
	mysqlSSLReqTotal   = 4 + 32 // header + payload of the short SSLRequest packet
	mysqlMaxGreeting   = 4096
	mysqlServerVersion = "8.0.0-capsule-gw"

	capLongPassword    = 1 << 0
	capFoundRows       = 1 << 1
	capLongFlag        = 1 << 2
	capConnectWithDB   = 1 << 3
	capLocalFiles      = 1 << 7
	capIgnoreSpace     = 1 << 8
	capProtocol41      = 1 << 9
	capInteractive     = 1 << 10
	capSSL             = 1 << 11
	capTransactions    = 1 << 13
	capSecureConn      = 1 << 15
	capMultiStatements = 1 << 16
	capMultiResults    = 1 << 17
	capPSMultiResults  = 1 << 18
	capPluginAuth      = 1 << 19
	capConnectAttrs    = 1 << 20
	capPluginAuthLenc  = 1 << 21
	capExpiredPwd      = 1 << 22
	capSessionTrack    = 1 << 23
	capDeprecateEOF    = 1 << 24

	mysqlGatewayCaps = capLongPassword | capFoundRows | capLongFlag | capConnectWithDB | capLocalFiles | capIgnoreSpace |
		capProtocol41 | capInteractive | capSSL | capTransactions | capSecureConn | capMultiStatements | capMultiResults |
		capPSMultiResults | capPluginAuth | capConnectAttrs | capPluginAuthLenc | capExpiredPwd | capSessionTrack | capDeprecateEOF
)

// mysqlSniffer never matches: a MySQL client sends nothing first, so the kind is chosen by the listener alone.
type mysqlSniffer struct{}

func (mysqlSniffer) Kind() Kind         { return KindMySQL }
func (mysqlSniffer) Match([]byte) Match { return NoMatch }

// mysqlKind is the server-first handler: serveConn calls it without reading anything (see serverFirstFor).
type mysqlKind struct {
	s *Server
	d *dbState
}

func (k *mysqlKind) serverFirst() {}
func (k *mysqlKind) Serve(ctx context.Context, c *Conn) {
	k.s.serveMySQL(ctx, k.d, c)
}

// serverFirstHandler marks a KindHandler that must run before the client sends anything.
type serverFirstHandler interface {
	KindHandler
	serverFirst()
}

// serverFirstFor returns the kind and handler for a listener dedicated to a server-first protocol.
func (s *Server) serverFirstFor(l *listener) (Kind, KindHandler, bool) {
	if len(l.allow) != 1 {
		return "", nil, false
	}
	for k := range l.allow {
		if h, ok := s.kindHandlers[k].(serverFirstHandler); ok {
			return k, h, true
		}
	}
	return "", nil, false
}

// mysqlPacket frames a payload (3-byte little-endian length, sequence id).
func mysqlPacket(seq byte, payload []byte) []byte {
	p := make([]byte, 4+len(payload))
	p[0], p[1], p[2], p[3] = byte(len(payload)), byte(len(payload)>>8), byte(len(payload)>>16), seq
	copy(p[4:], payload)
	return p
}

// mysqlSalt returns n bytes valid in a scramble (1..127, never '$' or NUL), like the server generates.
func mysqlSalt(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = b[i]%126 + 1
		if b[i] == '$' {
			b[i] = '#'
		}
	}
	return b
}

// buildMySQLGreeting builds the HandshakeV10 packet the gateway presents (sequence 0).
func buildMySQLGreeting(connID uint32, salt []byte) []byte {
	var p []byte
	p = append(p, 10)
	p = append(p, mysqlServerVersion...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint32(p, connID)
	p = append(p, salt[:8]...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint16(p, uint16(mysqlGatewayCaps&0xffff))
	p = append(p, 0xff) // utf8mb4_0900_ai_ci
	p = binary.LittleEndian.AppendUint16(p, 0x0002)
	p = binary.LittleEndian.AppendUint16(p, uint16(mysqlGatewayCaps>>16))
	p = append(p, 21)
	p = append(p, make([]byte, 10)...)
	p = append(p, salt[8:20]...)
	p = append(p, 0)
	p = append(p, "caching_sha2_password"...)
	p = append(p, 0)
	return mysqlPacket(0, p)
}

// Errors of the handshake parsers.
var (
	errMySQLSSLRequest = errors.New("data: not a MySQL SSLRequest")
	errMySQLGreeting   = errors.New("data: malformed MySQL greeting")
)

// parseMySQLSSLRequest validates the 36 bytes the client sends after the greeting and returns its capability flags. The
// client must set CLIENT_SSL and CLIENT_PROTOCOL_41; the 23 reserved bytes are not checked (MariaDB puts extended
// capabilities there).
func parseMySQLSSLRequest(b []byte) (caps uint32, err error) {
	if len(b) != mysqlSSLReqTotal {
		return 0, errMySQLSSLRequest
	}
	if b[0] != 32 || b[1] != 0 || b[2] != 0 || b[3] != 1 {
		return 0, errMySQLSSLRequest
	}
	caps = binary.LittleEndian.Uint32(b[4:8])
	if caps&capSSL == 0 || caps&capProtocol41 == 0 {
		return 0, errMySQLSSLRequest
	}
	return caps, nil
}

// parseMySQLGreeting reads the capability flags of a HandshakeV10 payload (the backend's greeting).
func parseMySQLGreeting(p []byte) (caps uint32, err error) {
	if len(p) < 1 || p[0] != 10 {
		return 0, errMySQLGreeting
	}
	i := 1
	for i < len(p) && p[i] != 0 { // server version, NUL terminated
		i++
	}
	i++ // NUL
	// connection id (4) + salt part 1 (8) + filler (1) + capabilities low (2) + charset (1) + status (2) + capabilities high (2)
	if i+4+8+1+2+1+2+2 > len(p) {
		return 0, errMySQLGreeting
	}
	i += 4 + 8 + 1
	lo := uint32(binary.LittleEndian.Uint16(p[i:]))
	i += 2 + 1 + 2
	hi := uint32(binary.LittleEndian.Uint16(p[i:]))
	return lo | hi<<16, nil
}

// readMySQLPacket reads one packet of at most max payload bytes.
func readMySQLPacket(r io.Reader, max int) (seq byte, payload []byte, err error) {
	var h [4]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	if n == 0 || n > max {
		return 0, nil, errMySQLGreeting
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return h[3], payload, nil
}

// mysqlErr is an ERR packet (sequence seq) for a client that cannot be served; it never depends on the name asked.
func mysqlErr(seq byte, code uint16, msg string) []byte {
	p := []byte{0xff}
	p = binary.LittleEndian.AppendUint16(p, code)
	p = append(p, '#')
	p = append(p, "HY000"...)
	p = append(p, msg...)
	return mysqlPacket(seq, p)
}

func (s *Server) mysqlDeny(d *dbState, c *Conn, reason, result string, reply []byte) {
	d.denied.WithLabelValues(protoMySQL, reason).Inc()
	c.Ev.Result = result
	if reply != nil {
		c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Conn.Write(reply); err == nil {
			// the client may still be sending its handshake response: read it away so the close does not turn into a
			// reset that discards the error packet
			c.Conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			io.CopyN(io.Discard, c.Conn, 4096)
		}
	}
	c.Conn.Close()
}

// serveMySQL runs the gateway's side of the handshake up to the ClientHello and then routes like any TLS connection.
func (s *Server) serveMySQL(ctx context.Context, d *dbState, c *Conn) {
	// the whole pre-routing exchange (greeting, SSLRequest, ClientHello) is bounded: slow clients are cut off here
	c.Conn.SetDeadline(c.Start.Add(s.cfg.HelloTimeout))
	if s.refusing.Load() {
		c.Ev.Result = "draining"
		c.Conn.Close()
		return
	}
	var id [4]byte
	rand.Read(id[:])
	if _, err := c.Conn.Write(buildMySQLGreeting(binary.LittleEndian.Uint32(id[:])&0x7fffffff|1, mysqlSalt(20))); err != nil {
		c.Ev.Result = "no_data"
		c.Conn.Close()
		return
	}
	var req [mysqlSSLReqTotal]byte
	if _, err := io.ReadFull(c.Conn, req[:]); err != nil {
		c.Ev.Result = "no_data"
		c.Conn.Close()
		return
	}
	if _, err := parseMySQLSSLRequest(req[:]); err != nil {
		// a client that skips TLS (or speaks something else): tell it plainly, whatever name it wanted
		s.mysqlDeny(d, c, "no_tls", "unknown_protocol", mysqlErr(2, 3159, "Connections using insecure transport are prohibited; use TLS with a server name (SNI)"))
		return
	}
	raw, hello, err := s.readHello(c)
	if err != nil {
		s.mysqlDeny(d, c, "bad_hello", "bad_hello", nil)
		return
	}
	c.Ev.SNI = hello.SNI
	t0 := time.Now()
	if hello.SNI == "" {
		d.denied.WithLabelValues(protoMySQL, "no_sni").Inc()
		s.silentDeny(ctx, c, t0, "no_sni")
		return
	}
	route := s.routes.Table().LookupHost(hello.SNI)
	if route == nil || (route.Protocol != "mysql" && route.Protocol != "mariadb") {
		s.failedAttempt(c)
		d.denied.WithLabelValues(protoMySQL, "no_route").Inc()
		s.silentDeny(ctx, c, t0, "no_route")
		return
	}
	c.Ev.RouteID = route.ID
	if route.ProjectID != nil {
		c.Ev.ProjectID = *route.ProjectID
	}
	sess := &Session{Conn: c, Route: route, Hello: hello, Raw: append(req[:], raw...)}
	if !s.admit(ctx, sess, t0, CredNone, "", AccessSNI) {
		return
	}
	s.route(ctx, sess)
}

// proxyMySQL connects to the backend and relays (sess.Raw = the client's SSLRequest followed by its ClientHello).
func (s *Server) proxyMySQL(ctx context.Context, sess *Session) {
	c, r := sess.Conn, sess.Route
	fail := func(res string, bk io.Closer) {
		c.Ev.Result = res
		if bk != nil {
			bk.Close()
		}
		c.Conn.Close()
	}
	bk, err := s.dial(ctx, r)
	if err != nil {
		fail("dest_down", nil)
		return
	}
	// the backend greets first: read it (never forwarded) and require TLS support
	bk.SetDeadline(time.Now().Add(s.cfg.DialTimeout))
	_, gp, err := readMySQLPacket(bk, mysqlMaxGreeting)
	if err != nil {
		fail("dest_down", bk)
		return
	}
	caps, err := parseMySQLGreeting(gp)
	if err != nil || caps&capSSL == 0 {
		fail("dest_no_tls", bk)
		return
	}
	sslReq, hello := sess.Raw[:mysqlSSLReqTotal], sess.Raw[mysqlSSLReqTotal:]
	if _, err := bk.Write(sslReq); err != nil {
		fail("dest_down", bk)
		return
	}
	var client = c.Conn
	var dest = bk
	if r.Mode == "terminate" {
		if s.certs == nil {
			fail("tls_fail", bk)
			return
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.certs.GetCertificate}
		tc := tls.Server(&replayConn{Conn: c.Conn, pre: hello}, cfg)
		hctx, cancel := context.WithTimeout(ctx, s.cfg.HelloTimeout)
		herr := tc.HandshakeContext(hctx)
		cancel()
		if herr != nil {
			fail("tls_fail", bk)
			return
		}
		// the gateway-to-backend leg: a new TLS session; the server certificate is the backend's own (self-signed by
		// default) on the internal network and the address was fixed by the route
		bc := tls.Client(bk, &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true})
		bctx, bcancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
		berr := bc.HandshakeContext(bctx)
		bcancel()
		if berr != nil {
			tc.Close()
			fail("dest_no_tls", bk)
			return
		}
		client, dest = tc, bc
	} else if _, err := bk.Write(hello); err != nil {
		fail("dest_down", bk)
		return
	}
	bk.SetDeadline(time.Time{})
	c.Conn.SetDeadline(time.Time{})
	s.relay(c, r.ID, client, dest, s.idleFor(sess.Decision))
}
