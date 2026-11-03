package data

import (
	"context"
	crand "crypto/rand"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/kynto/capsule/backend/internal/gateway/data/tunnel"
)

// dialUDP opens the connected UDP socket towards the route's destination (fixed by the route, SSRF guard applied by
// the dialer). The source port of this socket is stable for the whole session.
func (s *Server) dialUDP(ctx context.Context, r *Route) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
	defer cancel()
	return s.dialer.DialContext(dctx, "udp", net.JoinHostPort(r.DestHost, strconv.Itoa(r.DestPort)))
}

func (s *Server) udpParams() udpParams {
	u := s.cfg.UDP
	return udpParams{Idle: u.IdleTimeout, Keepalive: u.KeepaliveInterval, MaxDatagram: u.MaxDatagram, QueueBytes: u.QueueBytes}
}

func secondsCeil(d time.Duration) uint16 {
	n := (d + time.Second - 1) / time.Second
	if n > 65535 {
		n = 65535
	}
	if n < 0 {
		n = 0
	}
	return uint16(n)
}

// serveUDPTunnel finishes an authorised capsule/1 request with transport 2: it enforces the UDP session limits, opens
// the destination socket, answers CAPR (session_id, max_datagram, idle_timeout) and relays len16 frames until the
// session ends. The caller already holds the TCP connection slot of the route.
func (s *Server) serveUDPTunnel(ctx context.Context, c *Conn, tc net.Conn, reply func(status byte, code uint16, msg string, retry *uint16),
	route *Route, req *tunnel.Request, extra []byte) {
	project := route.Project
	if route.ProjectID != nil {
		project = *route.ProjectID
	}
	u := s.cfg.UDP
	rel, why := s.udpLim.acquire(route.ID, c.Src, project, u.MaxSessionsRoute, u.MaxSessionsIP, u.MaxSessionsProject)
	if why != "" {
		c.Ev.Result = "limit_udp_" + why
		s.metrics.Dropped.WithLabelValues("udp_" + why).Inc()
		reply(tunnel.StatusQuota, tunnel.CodeQuotaUDP, "udp session limit reached", u16(5))
		return
	}
	defer rel()
	uc, derr := s.dialUDP(ctx, route)
	if derr != nil {
		c.Ev.Result = "dest_down"
		code := uint16(tunnel.CodeDestDown)
		var ne net.Error
		if errors.Is(derr, context.DeadlineExceeded) || (errors.As(derr, &ne) && ne.Timeout()) {
			code = tunnel.CodeDestTimeout
		}
		reply(tunnel.StatusUnavailable, code, "destination unavailable", u16(2))
		return
	}
	sid := make([]byte, 8)
	if _, err := crand.Read(sid); err != nil {
		uc.Close()
		reply(tunnel.StatusBusy, tunnel.CodeInternal, "internal error", u16(1))
		return
	}
	md, idle := uint16(u.MaxDatagram), secondsCeil(u.IdleTimeout)
	ok := &tunnel.Response{Version: tunnel.Version, Status: tunnel.StatusOK, SessionID: sid, MaxDatagram: &md, IdleTimeout: &idle}
	if req.WantProxyInfo() && c.Src.IsValid() {
		ok.ClientAddr = &tunnel.ClientAddr{Addr: netip.AddrFrom16(c.Src.As16()), Port: c.SrcPort}
		if c.Src.Is4() {
			ok.ClientAddr.Addr = c.Src
		}
	}
	tc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, werr := tc.Write(tunnel.EncodeResponse(ok)); werr != nil {
		c.Ev.Result = "client_gone"
		uc.Close()
		tc.Close()
		return
	}
	tc.SetWriteDeadline(time.Time{})
	c.Ev.Status, c.Ev.Code = 0, 0
	c.Ev.Transport = tunnel.TransportUDPFlow

	s.metrics.Handshake.WithLabelValues(string(c.Ev.Kind)).Observe(time.Since(c.Start).Seconds())
	s.udpm.Sessions.Inc()
	g := s.metrics.ConnsActive.WithLabelValues(route.ID)
	g.Inc()
	res := runUDPSession(ctx, newStreamDatagrams(tc, extra), uc, s.udpParams(), s.udpm.observer(route.ID))
	g.Dec()
	s.udpm.Sessions.Dec()
	s.udpm.SessionsTotal.WithLabelValues(res.Reason).Inc()
	c.Ev.BytesIn, c.Ev.BytesOut, c.Ev.CloseReason = res.BytesIn, res.BytesOut, res.Reason
	if s.draining.Load() && res.Reason == CloseNormal {
		c.Ev.CloseReason = CloseDrain
	}
}
