package data

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/kynto/capsule/backend/internal/gateway/data/tunnel"
)

const (
	headerTimeout   = 5 * time.Second // PROTOCOL.md 9.3: FIXED
	lingerReadLimit = 64 << 10
)

func credType(authType byte) string {
	switch authType {
	case tunnel.AuthCap:
		return CredCap
	case tunnel.AuthCgt:
		return CredCgt
	case tunnel.AuthCgc:
		return CredCgc
	default:
		return CredCgs
	}
}

// reply sends a CAPR and closes the TLS connection with close_notify. Unread optimistic data from the client is
// drained for a moment first: closing a TCP socket with unread data makes the kernel send RST, which could destroy the
// reply before the client reads it.
func (s *Server) reply(tc *tls.Conn, c *Conn, status byte, code uint16, msg string, retryAfter *uint16, ver byte) {
	c.Ev.Status, c.Ev.Code = int(status), code
	resp := &tunnel.Response{Version: ver, Status: status, Code: code, Msg: msg, RetryAfter: retryAfter}
	if status == tunnel.StatusBadRequest && code == tunnel.CodeUnsupportedVersion {
		mv := byte(tunnel.Version)
		resp.Version, resp.MaxVersion = mv, &mv
	}
	tc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	tc.Write(tunnel.EncodeResponse(resp))
	tc.CloseWrite()
	tc.SetReadDeadline(time.Now().Add(time.Second))
	io.Copy(io.Discard, io.LimitReader(tc, lingerReadLimit))
	tc.Close()
}

func reqHash(project, service string) string {
	h := sha256.Sum256([]byte(project + "/" + service))
	return hex.EncodeToString(h[:6])
}

// serveTunnel implements the gateway side of capsule/1 over TCP (PROTOCOL.md sections 4-9, transport 1).
func (s *Server) serveTunnel(ctx context.Context, c *Conn, raw []byte, hello *Hello) {
	c.Ev.Kind = "tunnel"
	if s.certs == nil {
		c.Ev.Result = "tls_fail"
		c.Conn.Close()
		return
	}
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS13, // PROTOCOL.md 4: TLS 1.3 only; Go never accepts 0-RTT early data
		NextProtos:     []string{tunnelALPN},
		GetCertificate: s.certs.GetCertificate,
	}
	tc := tls.Server(&replayConn{Conn: c.Conn, pre: raw}, cfg)
	hctx, cancel := context.WithTimeout(ctx, s.cfg.HelloTimeout)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		c.Ev.Result = "tls_fail"
		c.Conn.Close()
		return
	}
	c.Ev.Transport = 1

	// --- header (5 s, <= 1024 bytes, nothing proportional to declared lengths is allocated) ---
	tc.SetReadDeadline(time.Now().Add(headerTimeout))
	var buf []byte
	tmp := make([]byte, 1024)
	eof := false
	var req *tunnel.Request
	var hdrLen int
	for {
		r, n, derr := tunnel.DecodeRequest(buf, eof)
		if derr == nil {
			req, hdrLen = r, n
			break
		}
		var te *tunnel.Error
		if errors.As(derr, &te) {
			c.Ev.Result = "bad_request"
			s.reply(tc, c, te.Status, te.Code, "bad request", nil, tunnel.Version)
			return
		}
		m, rerr := tc.Read(tmp)
		buf = append(buf, tmp[:m]...)
		if rerr != nil {
			eof = true // EOF, timeout or reset: the decoder turns it into 0x010A
		}
	}
	t0 := time.Now() // end of header: reference of the uniform delay
	extra := buf[hdrLen:]
	tc.SetReadDeadline(time.Time{})
	c.Ev.AuthType = int(req.AuthType)
	c.Ev.ClientID = req.ClientID
	c.Ev.ReqHash = reqHash(req.Project, req.Service)

	if s.refusing.Load() {
		c.Ev.Result = "draining"
		s.reply(tc, c, tunnel.StatusBusy, tunnel.CodeDraining, "gateway draining", u16(1), tunnel.Version)
		return
	}
	udp := req.Transport == tunnel.TransportUDPFlow && !s.cfg.UDP.TunnelDisabled
	if req.Transport != tunnel.TransportTCP && !udp { // 3 (QUIC) is future: see udp_quic.go
		c.Ev.Result = "bad_transport"
		s.reply(tc, c, tunnel.StatusBadRequest, tunnel.CodeBadTransport, "transport not enabled", nil, tunnel.Version)
		return
	}
	if s.ip.Blocked(c.Src) {
		c.Ev.Result = "blocked"
		s.reply(tc, c, tunnel.StatusQuota, tunnel.CodeQuotaRate, "too many failed attempts", u16(300), tunnel.Version)
		return
	}

	// --- uniform refusal: same bytes and latency for every "no" that could reveal existence (15.3) ---
	notAuthorized := func(result string) {
		c.Ev.Result = result
		s.failedAttempt(c)
		s.uniformWait(ctx, t0)
		s.reply(tc, c, tunnel.StatusNotAuthorized, tunnel.CodeNotAuthorized, tunnel.MsgNotAuthorized, nil, tunnel.Version)
	}

	var route *Route
	if udp {
		route = s.routes.Table().LookupUDPService(req.Project, req.Service)
	} else {
		route = s.routes.Table().LookupService(req.Project, req.Service)
	}
	if route != nil {
		c.Ev.RouteID = route.ID
		if route.ProjectID != nil {
			c.Ev.ProjectID = *route.ProjectID
		}
	}
	routeKey := req.Project + "/" + req.Service
	if req.AuthType == tunnel.AuthCgc && s.cgc != nil {
		sub, jti, verr := s.cgc.Verify(req.Auth, routeKey, time.Now())
		if verr == nil {
			c.Ev.Principal = sub + " jti=" + jti
		} else {
			switch {
			case errors.Is(verr, ErrCGCExpired):
				c.Ev.Result = "token_expired"
				s.reply(tc, c, tunnel.StatusNotAuthorized, tunnel.CodeTokenExpired, "token expired", nil, tunnel.Version)
			case errors.Is(verr, ErrCGCReplay):
				c.Ev.Result = "token_replay"
				s.reply(tc, c, tunnel.StatusNotAuthorized, tunnel.CodeReplay, "token already used", nil, tunnel.Version)
			default:
				notAuthorized("denied")
			}
			return
		}
	}
	if route == nil {
		notAuthorized("no_route")
		return
	}
	d, aerr := s.authz.Authorize(ctx, AuthorizeRequest{
		RouteID:        route.ID,
		SrcIP:          srcString(c.Src),
		CredentialType: credType(req.AuthType),
		Credential:     req.Auth,
		Access:         AccessCapsuleURI,
	})
	if aerr != nil {
		s.metrics.AuthCalls.WithLabelValues("error").Inc()
		c.Ev.Result = "control_down"
		s.reply(tc, c, tunnel.StatusBusy, tunnel.CodeControlDown, "control plane unavailable", u16(5), tunnel.Version)
		return
	}
	if !d.Allow {
		s.metrics.AuthCalls.WithLabelValues("deny").Inc()
		switch d.Reason {
		case ReasonIPDenied:
			c.Ev.Result = "ip_denied"
			s.reply(tc, c, tunnel.StatusIPDenied, tunnel.CodeIPDenied, "ip not allowed", nil, tunnel.Version)
		case ReasonQuota:
			c.Ev.Result = "quota"
			s.reply(tc, c, tunnel.StatusQuota, tunnel.CodeQuotaProject, "connection limit reached", u16(5), tunnel.Version)
		case ReasonUnavailable:
			c.Ev.Result = "unavailable"
			s.reply(tc, c, tunnel.StatusUnavailable, tunnel.CodeDestDown, "destination unavailable", u16(5), tunnel.Version)
		default:
			notAuthorized("denied")
		}
		return
	}
	s.metrics.AuthCalls.WithLabelValues("allow").Inc()
	if d.Principal != "" {
		c.Ev.Principal = d.Principal
	}

	// --- limits, destination, answer ---
	release, why := s.rl.Acquire(route.ID, c.Src, d.MaxConns, d.MaxConnsPerIP)
	if why != LimitNone {
		c.Ev.Result = "limit_" + why
		code := uint16(tunnel.CodeQuotaProject)
		switch why {
		case LimitIP:
			code = tunnel.CodeQuotaIP
		case LimitRate:
			code = tunnel.CodeQuotaRate
		}
		s.reply(tc, c, tunnel.StatusQuota, code, "connection limit reached", u16(5), tunnel.Version)
		return
	}
	defer release()
	c.leavePreauth()
	if udp {
		s.serveUDPTunnel(ctx, c, tc, func(status byte, code uint16, msg string, retry *uint16) {
			s.reply(tc, c, status, code, msg, retry, tunnel.Version)
		}, route, req, extra)
		return
	}
	bk, derr := s.dial(ctx, route)
	if derr != nil {
		c.Ev.Result = "dest_down"
		code := uint16(tunnel.CodeDestDown)
		var ne net.Error
		if errors.Is(derr, context.DeadlineExceeded) || (errors.As(derr, &ne) && ne.Timeout()) {
			code = tunnel.CodeDestTimeout
		}
		s.reply(tc, c, tunnel.StatusUnavailable, code, "destination unavailable", u16(2), tunnel.Version)
		return
	}
	ok := &tunnel.Response{Version: tunnel.Version, Status: tunnel.StatusOK}
	if req.WantProxyInfo() && c.Src.IsValid() {
		ok.ClientAddr = &tunnel.ClientAddr{Addr: netip.AddrFrom16(c.Src.As16()), Port: c.SrcPort}
		if c.Src.Is4() {
			ok.ClientAddr.Addr = c.Src
		}
	}
	tc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, werr := tc.Write(tunnel.EncodeResponse(ok)); werr != nil {
		c.Ev.Result = "client_gone"
		bk.Close()
		tc.Close()
		return
	}
	tc.SetWriteDeadline(time.Time{})
	if len(extra) > 0 { // optimistic data, released only now that the connection is authorised
		bk.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, werr := bk.Write(extra); werr != nil {
			c.Ev.Result = "dest_down"
			bk.Close()
			tc.Close()
			return
		}
		bk.SetWriteDeadline(time.Time{})
	}
	c.Ev.Status, c.Ev.Code = 0, 0
	s.relay(c, route.ID, tc, bk, s.idleFor(d))
}

func u16(v uint16) *uint16 { return &v }
