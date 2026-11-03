package data

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Random-port listeners (PLAN.md 3.4, PROTOCOL.md 12). The route table carries leases (port -> service). For each
// active lease the gateway listens on that port: TCP as a passthrough to the destination of the service's TCP route
// and UDP as a NAT table (one connected destination socket per client address) towards its UDP route. Both apply the
// same authorisation as every other entry: the control plane is asked per source IP with credential "none" and access
// "random_port" (the project IP list decides). Ports outside the configured range are never bound.
//
// Reconciliation is idempotent and runs on every route table change: a new lease opens listeners, a changed route
// updates the destination of new connections, a removed lease closes the TCP listener (open connections continue until
// they end or PoolConfig.DrainTimeout) and stops UDP from accepting new flows (existing flows continue likewise; the
// socket closes when the last flow ends). A port handed to another service closes the old UDP socket at once.

type portPool struct {
	s    *Server
	cfg  PoolConfig
	mu   sync.Mutex
	ent  map[int]*poolEntry
	old  map[int]*poolUDP // UDP sockets of released leases that still carry flows
	down bool             // shut down: nothing is opened any more
	need atomic.Bool      // a bind failed: retry on the next sweep
	resv atomic.Pointer[map[int]bool]
}

type poolEntry struct {
	port int
	svc  string
	tcp  *poolTCP
	udp  *poolUDP
}

func newPortPool(s *Server) *portPool {
	return &portPool{s: s, cfg: s.cfg.Pool, ent: map[int]*poolEntry{}, old: map[int]*poolUDP{}}
}

func (p *portPool) inRange(port int) bool {
	return port >= p.cfg.Min && port <= p.cfg.Max && port > 0 && port < 65536
}

func (p *portPool) addr(port int) string {
	return net.JoinHostPort(strings.Trim(p.cfg.Bind, "[]"), strconv.Itoa(port))
}

// reserved ports are the gateway's own listeners: a lease can never take them over.
func (p *portPool) reserved(port int) bool {
	m := p.resv.Load()
	return m != nil && (*m)[port]
}

func (p *portPool) setReserved(ls []*listener) {
	m := map[int]bool{}
	for _, l := range ls {
		if ta, ok := l.ln.Addr().(*net.TCPAddr); ok {
			m[ta.Port] = true
		}
	}
	p.resv.Store(&m)
}

type poolWant struct {
	l        Lease
	tcp, udp *Route
}

// Reconcile aligns the listeners with the leases of the table.
func (p *portPool) Reconcile(t *Table) {
	if p == nil || p.cfg.Disabled || t == nil {
		return
	}
	s := p.s
	want := map[int]poolWant{}
	for _, l := range t.Leases {
		switch {
		case !p.inRange(l.Port):
			s.udpm.PoolRejected.WithLabelValues("out_of_range").Inc()
			s.log.Warn("lease outside the pool range ignored", "port", l.Port)
			continue
		case p.reserved(l.Port):
			s.udpm.PoolRejected.WithLabelValues("reserved").Inc()
			continue
		}
		if _, dup := want[l.Port]; dup {
			s.udpm.PoolRejected.WithLabelValues("duplicate").Inc()
			s.log.Warn("two leases for one port; the first wins", "port", l.Port)
			continue
		}
		tcp, udp, amb := t.leaseRoutes(l)
		if tcp == nil && udp == nil {
			s.udpm.PoolRejected.WithLabelValues("no_route").Inc()
			continue
		}
		if amb {
			s.log.Warn("lease matches several routes of one transport; the lowest id is used", "port", l.Port, "service_id", l.ServiceID)
		}
		want[l.Port] = poolWant{l, tcp, udp}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.down || s.draining.Load() {
		return
	}
	retry := false
	for port, e := range p.ent {
		w, ok := want[port]
		if ok && w.l.ServiceID == e.svc {
			continue
		}
		p.retireLocked(e, ok) // reassigned (ok) or released (!ok)
		delete(p.ent, port)
	}
	for port, w := range want {
		e := p.ent[port]
		if e == nil {
			e = &poolEntry{port: port, svc: w.l.ServiceID}
		}
		// TCP
		switch {
		case w.tcp != nil && e.tcp == nil:
			if pt, err := p.startTCP(port, w.tcp); err != nil {
				retry = true
				s.udpm.PoolBindErrors.Inc()
				s.log.Warn("cannot listen on leased tcp port", "port", port, "err", err.Error())
			} else {
				e.tcp = pt
			}
		case w.tcp != nil:
			e.tcp.route.Store(w.tcp)
		case e.tcp != nil:
			e.tcp.retire()
			e.tcp = nil
		}
		// UDP
		switch {
		case w.udp != nil && e.udp == nil:
			if od := p.old[port]; od != nil {
				if od.svc == w.l.ServiceID { // the lease came back while its flows were draining
					delete(p.old, port)
					od.revive(w.udp)
					e.udp = od
					break
				}
				od.setOnClosed(nil)
				od.closeHard("reassigned")
				delete(p.old, port)
			}
			if pu, err := p.startUDP(port, w.l.ServiceID, w.udp); err != nil {
				retry = true
				s.udpm.PoolBindErrors.Inc()
				s.log.Warn("cannot listen on leased udp port", "port", port, "err", err.Error())
			} else {
				e.udp = pu
			}
		case w.udp != nil:
			e.udp.route.Store(w.udp)
		case e.udp != nil:
			p.drainUDPLocked(port, e.udp)
			e.udp = nil
		}
		if e.tcp == nil && e.udp == nil {
			delete(p.ent, port)
			continue
		}
		p.ent[port] = e
	}
	p.need.Store(retry)
}

// Retry reconciles again when a previous bind failed (e.g. the old process still held the port while draining).
func (p *portPool) Retry() {
	if p != nil && p.need.Load() {
		p.Reconcile(p.s.routes.Table())
	}
}

func (p *portPool) retireLocked(e *poolEntry, reassigned bool) {
	if e.tcp != nil {
		e.tcp.retire()
	}
	if e.udp != nil {
		if reassigned {
			e.udp.setOnClosed(nil)
			e.udp.closeHard("reassigned")
		} else {
			p.drainUDPLocked(e.port, e.udp)
		}
	}
}

func (p *portPool) drainUDPLocked(port int, u *poolUDP) {
	if prev := p.old[port]; prev != nil && prev != u {
		prev.setOnClosed(nil)
		prev.closeHard("replaced")
		delete(p.old, port)
	}
	if u.drain() { // flows remain: keep the socket until they end
		p.old[port] = u
		if !u.setOnClosed(func() {
			p.mu.Lock()
			if p.old[port] == u {
				delete(p.old, port)
			}
			p.mu.Unlock()
		}) {
			delete(p.old, port) // the last flow ended meanwhile
		}
	}
}

// Shutdown stops accepting on every port. Open TCP connections and UDP flows continue (Server.Drain waits for them
// and closes them at its deadline).
func (p *portPool) Shutdown() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.down = true
	for port, e := range p.ent {
		p.retireLocked(e, false)
		delete(p.ent, port)
	}
	p.mu.Unlock()
}

// CloseAll closes every socket at once (Server.Close / end of Drain).
func (p *portPool) CloseAll() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.down = true
	var us []*poolUDP
	for port, e := range p.ent {
		if e.tcp != nil {
			e.tcp.retire()
		}
		if e.udp != nil {
			us = append(us, e.udp)
		}
		delete(p.ent, port)
	}
	for _, u := range p.old {
		us = append(us, u)
	}
	p.old = map[int]*poolUDP{}
	p.mu.Unlock()
	for _, u := range us {
		u.closeHard("shutdown")
	}
}

// Ports lists the ports with an open listener (diagnostics and tests).
func (p *portPool) Ports() (tcp, udp []int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for port, e := range p.ent {
		if e.tcp != nil {
			tcp = append(tcp, port)
		}
		if e.udp != nil {
			udp = append(udp, port)
		}
	}
	return
}

// PoolPorts exposes the open random-port listeners (TCP and UDP) of the server.
func (s *Server) PoolPorts() (tcp, udp []int) { return s.pool.Ports() }

// ---------------- TCP ----------------

type poolTCP struct {
	p       *portPool
	port    int
	ln      net.Listener
	route   atomic.Pointer[Route]
	mu      sync.Mutex
	closing bool
	conns   sync.Map // *Conn
}

func (p *portPool) startTCP(port int, r *Route) (*poolTCP, error) {
	if !p.inRange(port) {
		return nil, errors.New("port outside the pool range")
	}
	ln, err := listenTCP(p.s.ctx, p.addr(port), p.s.cfg.ReusePort)
	if err != nil {
		return nil, err
	}
	pt := &poolTCP{p: p, port: port, ln: ln}
	pt.route.Store(r)
	p.s.udpm.PoolListeners.WithLabelValues("tcp").Inc()
	p.s.bg.Add(1)
	go func() { defer p.s.bg.Done(); pt.acceptLoop() }()
	return pt, nil
}

// retire stops accepting. Open connections continue, up to DrainTimeout.
func (pt *poolTCP) retire() {
	pt.mu.Lock()
	if pt.closing {
		pt.mu.Unlock()
		return
	}
	pt.closing = true
	pt.mu.Unlock()
	pt.ln.Close()
	pt.p.s.udpm.PoolListeners.WithLabelValues("tcp").Dec()
	time.AfterFunc(pt.p.cfg.DrainTimeout, func() {
		pt.conns.Range(func(k, _ any) bool { k.(*Conn).Conn.Close(); return true })
	})
}

func (pt *poolTCP) acceptLoop() {
	s := pt.p.s
	var delay time.Duration
	for {
		raw, err := pt.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			s.log.Warn("accept failed on leased port", "port", pt.port, "err", err.Error())
			time.Sleep(delay)
			continue
		}
		delay = 0
		if s.active.Load() >= int64(s.cfg.MaxConns) {
			s.metrics.Dropped.WithLabelValues(LimitProcess).Inc()
			raw.Close()
			continue
		}
		pt.mu.Lock()
		if pt.closing {
			pt.mu.Unlock()
			raw.Close()
			continue
		}
		s.active.Add(1)
		s.metrics.ActiveTotal.Inc()
		s.wg.Add(1)
		pt.mu.Unlock()
		go pt.serve(raw)
	}
}

func (pt *poolTCP) serve(raw net.Conn) {
	s := pt.p.s
	c := &Conn{Conn: raw, Listener: pt.ln.Addr().String(), Start: time.Now(), srv: s}
	c.Src, c.SrcPort = canonicalRemote(raw.RemoteAddr())
	c.Ev.Kind = "pool-tcp"
	s.conns.Store(c, struct{}{})
	pt.conns.Store(c, struct{}{})
	s.udpm.PoolConns.Inc()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic serving leased port", "panic", fmt.Sprint(r))
			c.Ev.Result = "internal_error"
			raw.Close()
		}
		c.leavePreauth()
		s.conns.Delete(c)
		pt.conns.Delete(c)
		s.udpm.PoolConns.Dec()
		s.finish(c)
		s.active.Add(-1)
		s.metrics.ActiveTotal.Dec()
		s.wg.Done()
	}()
	t0 := time.Now()
	if ok, why := s.ip.Enter(c.Src); !ok {
		s.metrics.Dropped.WithLabelValues(why).Inc()
		c.Ev.Result = "limit_" + why
		raw.Close()
		return
	}
	c.preauth = true
	route := pt.route.Load()
	c.Ev.RouteID = route.ID
	if route.ProjectID != nil {
		c.Ev.ProjectID = *route.ProjectID
	}
	if s.ip.Blocked(c.Src) {
		s.silentDeny(s.ctx, c, t0, "blocked")
		return
	}
	d, err := s.authz.Authorize(s.ctx, AuthorizeRequest{RouteID: route.ID, SrcIP: srcString(c.Src), CredentialType: CredNone, Access: AccessRandomPort, Port: pt.port})
	if err != nil {
		s.metrics.AuthCalls.WithLabelValues("error").Inc()
		s.silentDeny(s.ctx, c, t0, "control_down")
		return
	}
	if !d.Allow {
		s.metrics.AuthCalls.WithLabelValues("deny").Inc()
		res := "denied"
		switch d.Reason {
		case ReasonIPDenied:
			res = "ip_denied"
		case ReasonQuota:
			res = "quota"
		case ReasonUnavailable:
			res = "unavailable"
		}
		s.silentDeny(s.ctx, c, t0, res)
		return
	}
	s.metrics.AuthCalls.WithLabelValues("allow").Inc()
	c.Ev.Principal = d.Principal
	release, why := s.rl.Acquire(route.ID, c.Src, d.MaxConns, d.MaxConnsPerIP)
	if why != LimitNone {
		c.Ev.Result = "limit_" + why
		raw.Close()
		return
	}
	defer release()
	c.leavePreauth()
	bk, err := s.dial(s.ctx, route)
	if err != nil {
		c.Ev.Result = "dest_down"
		raw.Close()
		return
	}
	s.relay(c, route.ID, raw, bk, s.idleFor(d))
}

// canonicalAP normalises an address for use as a map key and as the source IP sent to the control plane.
func canonicalAP(a netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(a.Addr().Unmap().WithZone(""), a.Port())
}
