package data

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// replayConn delivers `pre` before reading from the embedded connection: used to hand the already-read ClientHello
// to crypto/tls (termination, tunnel) without the client noticing.
type replayConn struct {
	net.Conn
	pre []byte
}

func (r *replayConn) Read(p []byte) (int, error) {
	if len(r.pre) > 0 {
		n := copy(p, r.pre)
		r.pre = r.pre[n:]
		return n, nil
	}
	return r.Conn.Read(p)
}

// CloseWrite forwards the half-close to the TCP connection.
func (r *replayConn) CloseWrite() error {
	if cw, ok := r.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// servePG handles the classic PostgreSQL negotiation: the client sends SSLRequest, the gateway answers 'S' without
// knowing the backend yet and the TLS ClientHello (with SNI) follows. GSSENCRequest is declined with 'N'.
// The SSLRequest is replayed to the backend later (passthrough) so the backend negotiates TLS itself.
func (s *Server) servePG(ctx context.Context, c *Conn) {
	for attempt := 0; attempt < 2; attempt++ {
		if len(c.Head) < pgRequestSize {
			c.Ev.Result = "bad_request"
			c.Conn.Close()
			return
		}
		code := binary.BigEndian.Uint32(c.Head[4:8])
		switch code {
		case pgSSLRequest:
			if len(c.Head) > pgRequestSize { // bytes sent before our answer would be injected into the TLS stream
				c.Ev.Result = "bad_request"
				c.Conn.Close()
				return
			}
			c.Head = nil
			c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Conn.Write([]byte{'S'}); err != nil {
				c.Ev.Result = "no_data"
				c.Conn.Close()
				return
			}
			c.Conn.SetWriteDeadline(time.Time{})
			c.PGClassic = true
			c.Ev.Kind = KindPGSSL
			s.serveTLSAfter(ctx, c)
			return
		case pgGSSRequest:
			if len(c.Head) > pgRequestSize {
				c.Ev.Result = "bad_request"
				c.Conn.Close()
				return
			}
			c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Conn.Write([]byte{'N'}); err != nil {
				c.Conn.Close()
				return
			}
			c.Conn.SetWriteDeadline(time.Time{})
			next := make([]byte, pgRequestSize)
			if _, err := io.ReadFull(c.Conn, next); err != nil {
				c.Ev.Result = "no_data"
				c.Conn.Close()
				return
			}
			c.Head = next
			if (pgSniffer{}).Match(next) != Matched {
				c.Ev.Result = "unknown_protocol"
				c.Conn.Close()
				return
			}
		default:
			c.Ev.Result = "unknown_protocol"
			c.Conn.Close()
			return
		}
	}
	c.Conn.Close()
}

// serveTLS handles a connection that starts with a TLS record.
func (s *Server) serveTLS(ctx context.Context, c *Conn) { s.serveTLSAfter(ctx, c) }

func (s *Server) serveTLSAfter(ctx context.Context, c *Conn) {
	raw, hello, err := s.readHello(c)
	if err != nil {
		c.Ev.Result = "bad_hello"
		c.Conn.Close()
		return
	}
	c.Ev.SNI = hello.SNI
	if hello.Offers(tunnelALPN) && s.tunnelHosts[hello.SNI] {
		s.serveTunnel(ctx, c, raw, hello)
		return
	}
	t0 := time.Now()
	if s.refusing.Load() {
		c.Ev.Result = "draining"
		c.Conn.Close()
		return
	}
	if hello.SNI == "" {
		s.silentDeny(ctx, c, t0, "no_sni")
		return
	}
	route := s.routes.Table().LookupHost(hello.SNI)
	if route == nil {
		s.failedAttempt(c)
		s.silentDeny(ctx, c, t0, "no_route")
		return
	}
	c.Ev.RouteID = route.ID
	if route.ProjectID != nil {
		c.Ev.ProjectID = *route.ProjectID
	}
	sess := &Session{Conn: c, Route: route, Hello: hello, Raw: raw}
	if !s.admit(ctx, sess, t0, CredNone, "", AccessSNI) {
		return
	}
	s.route(ctx, sess)
}

// failedAttempt feeds the per-IP brute force limiter (PROTOCOL.md 15.5).
func (s *Server) failedAttempt(c *Conn) {
	if s.ip.Fail(c.Src) {
		s.log.Warn("source blocked after repeated failed attempts", "src_ip", c.Src.String())
	}
}

const tunnelALPN = "capsule/1"

// readHello reads the whole ClientHello (never more than needed) without answering it.
func (s *Server) readHello(c *Conn) (raw []byte, h *Hello, err error) {
	raw = c.Head
	c.Head = nil
	need := 0
	for {
		need, err = HelloLen(raw, s.cfg.MaxHelloBytes)
		if err != nil {
			return nil, nil, err
		}
		if need <= len(raw) {
			break
		}
		nb := make([]byte, need)
		copy(nb, raw)
		if _, err = io.ReadFull(c.Conn, nb[len(raw):]); err != nil {
			return nil, nil, err
		}
		raw = nb
	}
	h, err = ParseClientHello(raw[:need])
	if err != nil {
		return nil, nil, err
	}
	return raw, h, nil
}

// admit authorises a connection to a route with the given credential, applies the limits and, when everything is
// fine, leaves the pre-authentication state. On refusal it has already closed the connection (silently, after the
// uniform delay) and returns false.
func (s *Server) admit(ctx context.Context, sess *Session, t0 time.Time, credType, cred, access string) bool {
	c := sess.Conn
	if s.ip.Blocked(c.Src) {
		s.silentDeny(ctx, c, t0, "blocked")
		return false
	}
	d, err := s.authz.Authorize(ctx, AuthorizeRequest{
		RouteID:        sess.Route.ID,
		SrcIP:          srcString(c.Src),
		CredentialType: credType,
		Credential:     cred,
		Access:         access,
	})
	if err != nil {
		s.metrics.AuthCalls.WithLabelValues("error").Inc()
		s.silentDeny(ctx, c, t0, "control_down")
		return false
	}
	sess.Decision = d
	c.Ev.Principal = d.Principal
	if !d.Allow {
		s.metrics.AuthCalls.WithLabelValues("deny").Inc()
		if d.Reason == ReasonUnauthorized {
			s.failedAttempt(c)
		}
		res := "denied"
		switch d.Reason {
		case ReasonIPDenied:
			res = "ip_denied"
		case ReasonQuota:
			res = "quota"
		case ReasonUnavailable:
			res = "unavailable"
		}
		s.silentDeny(ctx, c, t0, res)
		return false
	}
	s.metrics.AuthCalls.WithLabelValues("allow").Inc()
	return true
}

// route applies the per-route limits and hands the session to the protocol handler.
func (s *Server) route(ctx context.Context, sess *Session) {
	c := sess.Conn
	release, why := s.rl.Acquire(sess.Route.ID, c.Src, sess.Decision.MaxConns, sess.Decision.MaxConnsPerIP)
	if why != LimitNone {
		c.Ev.Result = "limit_" + why
		c.Conn.Close()
		return
	}
	defer release()
	c.leavePreauth()
	if h := s.protoHandlers[sess.Route.Protocol]; h != nil {
		h.Proxy(ctx, sess)
		return
	}
	s.Proxy(ctx, sess)
}

// Proxy is the default behaviour for an authorised connection: connect to the route's destination and relay,
// passing the TLS bytes through (passthrough) or terminating TLS in the gateway (terminate).
func (s *Server) Proxy(ctx context.Context, sess *Session) {
	c, r := sess.Conn, sess.Route
	bk, err := s.dial(ctx, r)
	if err != nil {
		c.Ev.Result = "dest_down"
		c.Conn.Close()
		return
	}
	var client net.Conn = c.Conn
	switch {
	case sess.Hello != nil && r.Mode == "terminate":
		if s.certs == nil {
			c.Ev.Result = "tls_fail"
			bk.Close()
			c.Conn.Close()
			return
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.certs.GetCertificate, NextProtos: nextProtos(r)}
		tc := tls.Server(&replayConn{Conn: c.Conn, pre: sess.Raw}, cfg)
		hctx, cancel := context.WithTimeout(ctx, s.cfg.HelloTimeout)
		herr := tc.HandshakeContext(hctx)
		cancel()
		if herr != nil {
			c.Ev.Result = "tls_fail"
			bk.Close()
			c.Conn.Close()
			return
		}
		c.Conn.SetDeadline(time.Time{})
		client = tc
	case sess.Hello != nil: // passthrough
		if c.PGClassic { // the backend must negotiate TLS itself: repeat the SSLRequest and consume its 'S'
			bk.SetDeadline(time.Now().Add(s.cfg.DialTimeout))
			req := [8]byte{0, 0, 0, 8}
			binary.BigEndian.PutUint32(req[4:], pgSSLRequest)
			var ans [1]byte
			if _, werr := bk.Write(req[:]); werr != nil {
				c.Ev.Result = "dest_down"
				bk.Close()
				c.Conn.Close()
				return
			}
			if _, rerr := io.ReadFull(bk, ans[:]); rerr != nil || ans[0] != 'S' {
				c.Ev.Result = "dest_no_tls"
				bk.Close()
				c.Conn.Close()
				return
			}
			bk.SetDeadline(time.Time{})
		}
		if _, werr := bk.Write(sess.Raw); werr != nil {
			c.Ev.Result = "dest_down"
			bk.Close()
			c.Conn.Close()
			return
		}
		c.Conn.SetDeadline(time.Time{})
	default: // clear-text protocol: replay the bytes read so far
		if len(sess.Raw) > 0 {
			if _, werr := bk.Write(sess.Raw); werr != nil {
				c.Ev.Result = "dest_down"
				bk.Close()
				c.Conn.Close()
				return
			}
		}
		c.Conn.SetDeadline(time.Time{})
	}
	s.relay(c, sess.Route.ID, client, bk, s.idleFor(sess.Decision))
}

// relay runs the byte relay with accounting.
func (s *Server) relay(c *Conn, routeID string, client, dest net.Conn, idle time.Duration) {
	s.metrics.Handshake.WithLabelValues(string(c.Ev.Kind)).Observe(time.Since(c.Start).Seconds())
	g := s.metrics.ConnsActive.WithLabelValues(routeID)
	g.Inc()
	res := Relay(client, dest, RelayOptions{Idle: idle, HalfIdle: s.cfg.HalfCloseIdle})
	g.Dec()
	c.Ev.BytesIn, c.Ev.BytesOut, c.Ev.CloseReason = res.AToB, res.BToA, res.Reason
	if s.draining.Load() && res.Reason == CloseNormal {
		c.Ev.CloseReason = CloseDrain
	}
}

func nextProtos(r *Route) []string {
	switch r.Protocol {
	case "postgres":
		return []string{"postgresql"} // sslnegotiation=direct requires the server to select it
	case "http":
		return []string{"http/1.1"} // the destination receives clear text: no h2
	}
	return nil
}

// serveHTTP routes clear-text HTTP/1.x by Host header.
func (s *Server) serveHTTP(ctx context.Context, c *Conn) {
	t0 := time.Now()
	head := c.Head
	c.Head = nil
	var host string
	for {
		var complete bool
		host, complete = HostFromHTTPHead(head)
		if complete || host != "" {
			break
		}
		if len(head) >= s.cfg.MaxHTTPHead {
			c.Ev.Result = "bad_request"
			c.Conn.Close()
			return
		}
		buf := make([]byte, minInt(len(head)+2048, s.cfg.MaxHTTPHead))
		copy(buf, head)
		n, err := c.Conn.Read(buf[len(head):])
		head = buf[:len(head)+n]
		if err != nil && n == 0 {
			c.Ev.Result = "no_data"
			c.Conn.Close()
			return
		}
	}
	c.Ev.SNI = host
	if s.refusing.Load() {
		c.Ev.Result = "draining"
		c.Conn.Close()
		return
	}
	route := s.routes.Table().LookupHost(host)
	if route == nil || (route.Protocol != "http" && route.Protocol != "tcp") {
		s.failedAttempt(c)
		s.silentDeny(ctx, c, t0, "no_route")
		return
	}
	c.Ev.RouteID = route.ID
	sess := &Session{Conn: c, Route: route, Raw: head}
	if !s.admit(ctx, sess, t0, CredNone, "", AccessSNI) {
		return
	}
	s.route(ctx, sess)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
