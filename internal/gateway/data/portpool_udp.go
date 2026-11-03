package data

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Pending first packets of a flow being authorised: a few are kept so the first datagram is not lost.
const (
	pendingPackets = 4
	maxPending     = 256
	flowReadErrors = 50
)

// poolUDP is the UDP side of a leased port: one socket, a NAT table keyed by client address.
type poolUDP struct {
	p        *portPool
	s        *Server
	port     int
	svc      string
	pc       *net.UDPConn
	route    atomic.Pointer[Route]
	newFlows *rate.Limiter
	onClosed func() // set by the pool when the socket outlives its lease

	mu       sync.Mutex
	flows    map[netip.AddrPort]*udpFlow
	pending  map[netip.AddrPort]*pendingFlow
	closing  bool // lease released: no new flows
	closed   bool
	hard     *time.Timer
	loopDone chan struct{}
}

type pendingFlow struct {
	pkts [][]byte
}

type udpFlow struct {
	u       *poolUDP
	key     netip.AddrPort // canonical client address (map key)
	reply   netip.AddrPort // as received, used to answer
	conn    net.Conn       // connected socket to the destination
	c       *Conn
	route   *Route
	rel     func()
	last    atomic.Int64
	authAt  atomic.Int64
	reauth  atomic.Bool
	bytesIn atomic.Int64
	bytesOt atomic.Int64
	once    sync.Once
	reason  atomic.Value
}

func (p *portPool) startUDP(port int, svc string, r *Route) (*poolUDP, error) {
	if !p.inRange(port) {
		return nil, errors.New("port outside the pool range")
	}
	var lc net.ListenConfig
	pcAny, err := lc.ListenPacket(p.s.ctx, "udp", p.addr(port))
	if err != nil {
		return nil, err
	}
	pc := pcAny.(*net.UDPConn)
	rt := p.cfg.NewFlowRate
	u := &poolUDP{
		p: p, s: p.s, port: port, svc: svc, pc: pc,
		newFlows: rate.NewLimiter(rate.Limit(rt), int(2*rt)),
		flows:    map[netip.AddrPort]*udpFlow{}, pending: map[netip.AddrPort]*pendingFlow{},
		loopDone: make(chan struct{}),
	}
	u.route.Store(r)
	p.s.udpm.PoolListeners.WithLabelValues("udp").Inc()
	p.s.bg.Add(2)
	go func() { defer p.s.bg.Done(); u.readLoop() }()
	go func() { defer p.s.bg.Done(); u.janitor() }()
	return u, nil
}

// LocalAddr is the bound address.
func (u *poolUDP) LocalAddr() net.Addr { return u.pc.LocalAddr() }

func (u *poolUDP) readLoop() {
	defer close(u.loopDone)
	buf := make([]byte, maxUDPDatagram+1)
	errs := 0
	for {
		n, ap, err := u.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if errs++; errs > 1000 {
				u.s.log.Error("udp listener failing; closing", "port", u.port, "err", err.Error())
				u.closeHard("error")
				return
			}
			time.Sleep(time.Millisecond)
			continue
		}
		errs = 0
		if n == 0 || n > maxUDPDatagram {
			u.s.udpm.Dropped.WithLabelValues("oversize_in").Inc()
			continue
		}
		u.packet(buf[:n], ap)
	}
}

// packet routes one datagram from a client to its flow, or starts the admission of a new flow.
func (u *poolUDP) packet(b []byte, ap netip.AddrPort) {
	s := u.s
	key := canonicalAP(ap)
	u.mu.Lock()
	if f := u.flows[key]; f != nil {
		u.mu.Unlock()
		f.last.Store(time.Now().UnixNano())
		if _, err := f.conn.Write(b); err != nil {
			s.udpm.Dropped.WithLabelValues("dest_write").Inc()
			return
		}
		f.bytesIn.Add(int64(len(b)))
		s.udpm.Bytes.WithLabelValues("in").Add(float64(len(b)))
		return
	}
	if u.closing || u.closed {
		u.mu.Unlock()
		s.udpm.Dropped.WithLabelValues("lease_closed").Inc()
		return
	}
	if pf := u.pending[key]; pf != nil {
		if len(pf.pkts) < pendingPackets {
			pf.pkts = append(pf.pkts, append([]byte(nil), b...))
		}
		u.mu.Unlock()
		return
	}
	if len(u.pending) >= maxPending || len(u.flows)+len(u.pending) >= u.p.cfg.MaxFlows {
		u.mu.Unlock()
		s.udpm.Dropped.WithLabelValues("flow_cap").Inc()
		return
	}
	// before any per-IP state is created: a global admission rate per leased port bounds what spoofed sources cost
	if !u.newFlows.Allow() {
		u.mu.Unlock()
		s.udpm.Dropped.WithLabelValues("flow_rate").Inc()
		return
	}
	u.mu.Unlock()
	if ok, why := s.ip.Enter(key.Addr()); !ok {
		s.udpm.Dropped.WithLabelValues("ip_" + why).Inc()
		return
	}
	u.mu.Lock()
	if u.closing || u.closed || u.pending[key] != nil || u.flows[key] != nil {
		u.mu.Unlock()
		s.ip.Leave(key.Addr())
		return
	}
	pf := &pendingFlow{pkts: [][]byte{append([]byte(nil), b...)}}
	u.pending[key] = pf
	u.mu.Unlock()
	go u.admit(key, ap, pf)
}

// admit authorises the source IP (credential none, access random_port), applies the route limits, opens the
// destination socket and registers the flow. The same checks as the TCP side; the control plane answer is cached
// briefly by the Authorizer so a source that sends many datagrams costs one lookup.
func (u *poolUDP) admit(key, reply netip.AddrPort, pf *pendingFlow) {
	s := u.s
	var rel func()
	c := &Conn{Listener: u.pc.LocalAddr().String(), Start: time.Now(), srv: s, Src: key.Addr(), SrcPort: key.Port()}
	c.Ev.Kind = "pool-udp"
	registered := false
	defer func() {
		s.ip.Leave(key.Addr())
		if !registered {
			u.mu.Lock()
			delete(u.pending, key)
			u.mu.Unlock()
			if rel != nil {
				rel()
			}
			if r := c.Ev.Result; r != "" { // refusals are counted, not logged: one per datagram burst of a spoofable source
				s.metrics.ConnsTotal.WithLabelValues(route0(c), r).Inc()
				s.log.Debug("udp flow refused", "port", u.port, "src_ip", key.Addr().String(), "result", r)
			}
		}
	}()
	route := u.route.Load()
	c.Ev.RouteID = route.ID
	if route.ProjectID != nil {
		c.Ev.ProjectID = *route.ProjectID
	}
	if s.ip.Blocked(key.Addr()) {
		c.Ev.Result = "blocked"
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.AuthTimeout+s.cfg.DialTimeout)
	defer cancel()
	d, err := s.authz.Authorize(ctx, AuthorizeRequest{RouteID: route.ID, SrcIP: srcString(key.Addr()), CredentialType: CredNone, Access: AccessRandomPort, Port: u.port})
	if err != nil {
		s.metrics.AuthCalls.WithLabelValues("error").Inc()
		c.Ev.Result = "control_down"
		return
	}
	if !d.Allow {
		s.metrics.AuthCalls.WithLabelValues("deny").Inc()
		c.Ev.Result = "denied"
		switch d.Reason {
		case ReasonIPDenied:
			c.Ev.Result = "ip_denied"
		case ReasonQuota:
			c.Ev.Result = "quota"
		case ReasonUnavailable:
			c.Ev.Result = "unavailable"
		}
		return
	}
	s.metrics.AuthCalls.WithLabelValues("allow").Inc()
	c.Ev.Principal = d.Principal
	var why string
	rel, why = s.rl.Acquire(route.ID, key.Addr(), d.MaxConns, d.MaxConnsPerIP)
	if why != LimitNone {
		c.Ev.Result = "limit_" + why
		s.metrics.Dropped.WithLabelValues("udp_flow_" + why).Inc()
		return
	}
	uc, err := s.dialUDP(ctx, route)
	if err != nil {
		c.Ev.Result = "dest_down"
		return
	}
	c.Conn = uc
	f := &udpFlow{u: u, key: key, reply: reply, conn: uc, c: c, route: route, rel: rel}
	now := time.Now().UnixNano()
	f.last.Store(now)
	f.authAt.Store(now)

	u.mu.Lock()
	if u.closing || u.closed || s.draining.Load() || s.active.Load() >= int64(s.cfg.MaxConns) {
		u.mu.Unlock()
		uc.Close()
		c.Ev.Result = "lease_closed"
		return
	}
	registered = true
	delete(u.pending, key)
	u.flows[key] = f
	s.active.Add(1)
	s.metrics.ActiveTotal.Inc()
	s.wg.Add(1) // under u.mu: closing is set under the same lock, so Drain never waits on a flow added after it began
	u.mu.Unlock()
	s.conns.Store(c, struct{}{})
	s.udpm.PoolFlows.Inc()
	s.metrics.ConnsActive.WithLabelValues(route.ID).Inc()
	for _, p := range pf.pkts {
		if _, err := uc.Write(p); err == nil {
			f.bytesIn.Add(int64(len(p)))
			s.udpm.Bytes.WithLabelValues("in").Add(float64(len(p)))
		}
	}
	go f.readLoop()
}

func (f *udpFlow) readLoop() {
	u, s := f.u, f.u.s
	buf := make([]byte, maxUDPDatagram+1)
	obsOut := s.udpm.Bytes.WithLabelValues("out")
	errs := 0
	for {
		n, err := f.conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // close() already ran
			}
			if errs++; errs > flowReadErrors {
				f.close(CloseError)
				return
			}
			time.Sleep(2 * time.Millisecond)
			continue
		}
		errs = 0
		if n == 0 {
			continue
		}
		if n > maxUDPDatagram {
			s.udpm.Dropped.WithLabelValues("oversize_out").Inc()
			continue
		}
		f.last.Store(time.Now().UnixNano())
		if _, werr := u.pc.WriteToUDPAddrPort(buf[:n], f.reply); werr != nil {
			if errors.Is(werr, net.ErrClosed) {
				f.close(CloseDrain)
				return
			}
			s.udpm.Dropped.WithLabelValues("client_write").Inc()
			continue
		}
		f.bytesOt.Add(int64(n))
		obsOut.Add(float64(n))
	}
}

func (f *udpFlow) close(reason string) {
	f.once.Do(func() {
		u, s := f.u, f.u.s
		f.reason.Store(reason)
		f.conn.Close()
		u.mu.Lock()
		delete(u.flows, f.key)
		empty := len(u.flows) == 0 && len(u.pending) == 0
		last := u.closing && empty
		u.mu.Unlock()
		f.rel()
		f.c.Ev.BytesIn, f.c.Ev.BytesOut, f.c.Ev.CloseReason = f.bytesIn.Load(), f.bytesOt.Load(), reason
		s.conns.Delete(f.c)
		s.metrics.ConnsActive.WithLabelValues(f.route.ID).Dec()
		s.udpm.PoolFlows.Dec()
		s.finish(f.c)
		s.active.Add(-1)
		s.metrics.ActiveTotal.Dec()
		s.wg.Done()
		if last {
			u.closeSocket()
		}
	})
}

// janitor ends idle flows and re-authorises established ones so a revoked IP loses its flow.
func (u *poolUDP) janitor() {
	cfg := u.p.cfg
	every := cfg.FlowIdle / 4
	if every > 5*time.Second {
		every = 5 * time.Second
	}
	if r := cfg.Revalidate / 2; r < every {
		every = r
	}
	if every < 10*time.Millisecond {
		every = 10 * time.Millisecond
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-u.loopDone:
			return
		case <-t.C:
		}
		now := time.Now()
		var idle, recheck []*udpFlow
		u.mu.Lock()
		for _, f := range u.flows {
			switch {
			case now.Sub(time.Unix(0, f.last.Load())) > cfg.FlowIdle:
				idle = append(idle, f)
			case now.Sub(time.Unix(0, f.authAt.Load())) > cfg.Revalidate && f.reauth.CompareAndSwap(false, true):
				recheck = append(recheck, f)
			}
		}
		u.mu.Unlock()
		for _, f := range idle {
			f.close(CloseIdle)
		}
		for _, f := range recheck {
			go u.revalidate(f)
		}
	}
}

func (u *poolUDP) revalidate(f *udpFlow) {
	s := u.s
	defer f.reauth.Store(false)
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.AuthTimeout)
	defer cancel()
	d, err := s.authz.Authorize(ctx, AuthorizeRequest{RouteID: f.route.ID, SrcIP: srcString(f.key.Addr()), CredentialType: CredNone, Access: AccessRandomPort, Port: u.port})
	switch {
	case err != nil: // control plane down: keep the flow, it is asked again next round (no fail-open for new flows)
	case !d.Allow:
		f.c.Ev.Result = "revoked"
		f.close("revoked")
	default:
		f.authAt.Store(time.Now().UnixNano())
	}
}

// drain stops new flows. It reports whether flows remain (the socket then stays until the last one ends or
// DrainTimeout passes).
func (u *poolUDP) drain() bool {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return false
	}
	u.closing = true
	empty := len(u.flows) == 0 && len(u.pending) == 0
	if !empty && u.hard == nil {
		u.hard = time.AfterFunc(u.p.cfg.DrainTimeout, func() { u.closeHard("drain_timeout") })
	}
	u.mu.Unlock()
	if empty {
		u.closeSocket()
		return false
	}
	return true
}

// revive cancels a drain: the lease came back for the same service.
func (u *poolUDP) revive(r *Route) {
	u.mu.Lock()
	u.closing = false
	if u.hard != nil {
		u.hard.Stop()
		u.hard = nil
	}
	u.mu.Unlock()
	u.route.Store(r)
	u.setOnClosed(nil)
}

// setOnClosed installs the callback run when the socket closes; it reports false if it is closed already.
func (u *poolUDP) setOnClosed(fn func()) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return false
	}
	u.onClosed = fn
	return true
}

func (u *poolUDP) closeSocket() {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return
	}
	u.closed = true
	if u.hard != nil {
		u.hard.Stop()
	}
	cb := u.onClosed
	u.mu.Unlock()
	u.pc.Close()
	u.s.udpm.PoolListeners.WithLabelValues("udp").Dec()
	if cb != nil {
		cb()
	}
}

// closeHard closes the socket and every flow now.
func (u *poolUDP) closeHard(reason string) {
	u.mu.Lock()
	u.closing = true
	fs := make([]*udpFlow, 0, len(u.flows))
	for _, f := range u.flows {
		fs = append(fs, f)
	}
	u.mu.Unlock()
	for _, f := range fs {
		f.close(reason)
	}
	u.closeSocket()
}

func route0(c *Conn) string {
	if c.Ev.RouteID == "" {
		return "-"
	}
	return c.Ev.RouteID
}
