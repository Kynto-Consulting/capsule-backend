package data

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter reasons, mapped by the tunnel handler to CAPR codes.
const (
	LimitNone    = ""
	LimitRoute   = "route"   // 0x0501
	LimitIP      = "ip"      // 0x0502
	LimitRate    = "rate"    // 0x0503
	LimitBlocked = "blocked" // 0x0503
	LimitPreauth = "preauth" // closed before authentication
	LimitProcess = "process"
)

// ipKey groups IPv6 clients by /64 so that rotating the host part does not evade the limits.
func ipKey(a netip.Addr) netip.Addr {
	a = a.Unmap().WithZone("")
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}

type ipState struct {
	pre          int // unauthenticated concurrent connections
	lim          *rate.Limiter
	failStart    time.Time
	fails        int
	blockedUntil time.Time
	last         time.Time
}

// IPTracker implements the pre-authentication limits of PROTOCOL.md 15.4/15.5: concurrent unauthenticated
// connections per IP, new-connection rate per IP and a temporary block after repeated failed attempts.
type IPTracker struct {
	MaxPre     int           // concurrent unauthenticated connections per IP (default 100)
	Rate       float64       // new connections per second per IP (default 20)
	Burst      int           // default 2*Rate
	FailMax    int           // failed attempts per window before blocking (default 10)
	FailWindow time.Duration // default 1 minute
	BlockFor   time.Duration // default 5 minutes
	Now        func() time.Time

	mu sync.Mutex
	m  map[netip.Addr]*ipState
}

func (t *IPTracker) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *IPTracker) defaults() {
	if t.MaxPre <= 0 {
		t.MaxPre = 100
	}
	if t.Rate <= 0 {
		t.Rate = 20
	}
	if t.Burst <= 0 {
		t.Burst = int(2 * t.Rate)
	}
	if t.FailMax <= 0 {
		t.FailMax = 10
	}
	if t.FailWindow <= 0 {
		t.FailWindow = time.Minute
	}
	if t.BlockFor <= 0 {
		t.BlockFor = 5 * time.Minute
	}
}

func (t *IPTracker) get(k netip.Addr, now time.Time) *ipState {
	if t.m == nil {
		t.m = make(map[netip.Addr]*ipState)
		t.defaults()
	}
	s, ok := t.m[k]
	if !ok {
		s = &ipState{lim: rate.NewLimiter(rate.Limit(t.Rate), t.Burst)}
		t.m[k] = s
	}
	s.last = now
	return s
}

// Enter registers a new unauthenticated connection. On success the caller must call Leave when it is
// authenticated or closed. The reason is LimitRate or LimitPreauth (blocked IPs are checked later with Blocked, so the tunnel can still answer 5/0x0503).
func (t *IPTracker) Enter(ip netip.Addr) (ok bool, reason string) {
	now := t.now()
	k := ipKey(ip)
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.get(k, now)
	if !s.lim.AllowN(now, 1) {
		return false, LimitRate
	}
	if s.pre >= t.MaxPre {
		return false, LimitPreauth
	}
	s.pre++
	return true, LimitNone
}

// Leave undoes Enter.
func (t *IPTracker) Leave(ip netip.Addr) {
	k := ipKey(ip)
	t.mu.Lock()
	if s := t.m[k]; s != nil && s.pre > 0 {
		s.pre--
	}
	t.mu.Unlock()
}

// Fail records a failed authentication attempt; it reports whether the IP just became blocked.
func (t *IPTracker) Fail(ip netip.Addr) (blocked bool) {
	now := t.now()
	k := ipKey(ip)
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.get(k, now)
	if now.Sub(s.failStart) > t.FailWindow {
		s.failStart, s.fails = now, 0
	}
	s.fails++
	if s.fails >= t.FailMax {
		s.blockedUntil = now.Add(t.BlockFor)
		s.fails = 0
		return true
	}
	return false
}

// Blocked reports whether the IP is currently blocked.
func (t *IPTracker) Blocked(ip netip.Addr) bool {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.m[ipKey(ip)]
	return s != nil && now.Before(s.blockedUntil)
}

// Sweep removes idle entries.
func (t *IPTracker) Sweep() {
	now := t.now()
	t.mu.Lock()
	for k, s := range t.m {
		if s.pre == 0 && now.Sub(s.last) > 10*time.Minute && now.After(s.blockedUntil) {
			delete(t.m, k)
		}
	}
	t.mu.Unlock()
}

// Size is the number of tracked IPs.
func (t *IPTracker) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// RouteLimits counts authenticated connections per route and per (route, IP) and the per-route new-connection rate.
type RouteLimits struct {
	DefaultMax   int     // per route (default 200)
	DefaultMaxIP int     // per route and IP (default 50)
	RouteRate    float64 // new connections per second per route (default 100)

	mu    sync.Mutex
	route map[string]int
	perIP map[routeIP]int
	rates map[string]*rate.Limiter
}

type routeIP struct {
	route string
	ip    netip.Addr
}

// Acquire reserves a connection slot. max/maxIP of 0 use the defaults.
func (l *RouteLimits) Acquire(routeID string, ip netip.Addr, max, maxIP int) (release func(), reason string) {
	if max <= 0 {
		max = l.DefaultMax
	}
	if max <= 0 {
		max = 200
	}
	if maxIP <= 0 {
		maxIP = l.DefaultMaxIP
	}
	if maxIP <= 0 {
		maxIP = 50
	}
	k := routeIP{routeID, ipKey(ip)}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.route == nil {
		l.route = map[string]int{}
		l.perIP = map[routeIP]int{}
		l.rates = map[string]*rate.Limiter{}
	}
	rl := l.rates[routeID]
	if rl == nil {
		r := l.RouteRate
		if r <= 0 {
			r = 100
		}
		rl = rate.NewLimiter(rate.Limit(r), int(2*r))
		l.rates[routeID] = rl
	}
	if !rl.Allow() {
		return nil, LimitRate
	}
	if l.route[routeID] >= max {
		return nil, LimitRoute
	}
	if l.perIP[k] >= maxIP {
		return nil, LimitIP
	}
	l.route[routeID]++
	l.perIP[k]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			if l.route[routeID]--; l.route[routeID] <= 0 {
				delete(l.route, routeID)
			}
			if l.perIP[k]--; l.perIP[k] <= 0 {
				delete(l.perIP, k)
			}
			l.mu.Unlock()
		})
	}, LimitNone
}

// Count returns the active connections of a route.
func (l *RouteLimits) Count(routeID string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.route[routeID]
}

// Forget drops rate state of routes that no longer exist.
func (l *RouteLimits) Forget(live func(id string) bool) {
	l.mu.Lock()
	for id := range l.rates {
		if l.route[id] == 0 && !live(id) {
			delete(l.rates, id)
		}
	}
	l.mu.Unlock()
}
