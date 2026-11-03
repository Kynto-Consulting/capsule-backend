package data

import (
	"net/netip"
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// ---------------- table index for UDP and for leases ----------------

// indexExtra builds the indexes that the TCP data plane does not need: UDP routes by project/service (the tunnel's
// transport 2) and every route by service id (the random-port leases name a service, not a route).
func (t *Table) indexExtra() {
	t.udpBySvc = map[string]*Route{}
	t.udpByID = map[string]*Route{}
	t.bySvcID = map[string][]*Route{}
	for i := range t.UDP {
		r := &t.UDP[i]
		if r.Project == "" {
			r.Project = r.ProjectSlug
		}
		if r.DestHost == "" || r.DestPort <= 0 || r.DestPort > 65535 || r.ID == "" {
			continue // never route to a half-defined destination
		}
		t.udpByID[r.ID] = r
		if r.Project != "" && r.Service != "" {
			t.udpBySvc[r.Project+"/"+r.Service] = r
		}
		if r.ServiceID != "" {
			t.bySvcID[r.ServiceID] = append(t.bySvcID[r.ServiceID], r)
		}
	}
	for _, r := range t.byID {
		if r.ServiceID != "" {
			t.bySvcID[r.ServiceID] = append(t.bySvcID[r.ServiceID], r)
		}
	}
	for _, rs := range t.bySvcID {
		sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	}
}

// LookupUDPService resolves a capsule/1 project/service pair among the UDP routes.
func (t *Table) LookupUDPService(project, service string) *Route {
	if t == nil {
		return nil
	}
	return t.udpBySvc[project+"/"+service]
}

// HasRoute reports whether the route id exists (TCP or UDP).
func (t *Table) HasRoute(id string) bool {
	if t == nil {
		return false
	}
	return t.byID[id] != nil || t.udpByID[id] != nil
}

// UDPRoutes is the number of usable UDP routes.
func (t *Table) UDPRoutes() int {
	if t == nil {
		return 0
	}
	return len(t.udpByID)
}

// leaseRoutes picks the routes a lease exposes: at most one TCP and one UDP route of the leased service. When the
// control plane names the route (Lease.RouteID) or the transport (Lease.Transport: tcp | udp | both) they are honoured;
// otherwise every route of the service is a candidate and the lowest id of each transport wins (ambiguous reports
// that there was a choice to make).
func (t *Table) leaseRoutes(l Lease) (tcp, udp *Route, ambiguous bool) {
	if t == nil {
		return nil, nil, false
	}
	var nt, nu int
	for _, r := range t.bySvcID[l.ServiceID] {
		if l.RouteID != "" && r.ID != l.RouteID {
			continue
		}
		if r.Transport == "udp" {
			if l.Transport == "tcp" {
				continue
			}
			if nu++; udp == nil {
				udp = r
			}
		} else {
			if l.Transport == "udp" {
				continue
			}
			if nt++; tcp == nil {
				tcp = r
			}
		}
	}
	return tcp, udp, nt > 1 || nu > 1
}

// ---------------- limits of tunnel UDP sessions ----------------

// udpLimits counts concurrent UDP sessions of the tunnel per route, per (route, source IP) and per project.
type udpLimits struct {
	mu      sync.Mutex
	route   map[string]int
	perIP   map[routeIP]int
	project map[string]int
}

// acquire reserves a session slot; why is "route", "ip" or "project" when a limit is reached.
func (l *udpLimits) acquire(route string, ip netip.Addr, project string, maxRoute, maxIP, maxProject int) (release func(), why string) {
	k := routeIP{route, ipKey(ip)}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.route == nil {
		l.route, l.perIP, l.project = map[string]int{}, map[routeIP]int{}, map[string]int{}
	}
	if l.route[route] >= maxRoute {
		return nil, LimitRoute
	}
	if l.perIP[k] >= maxIP {
		return nil, LimitIP
	}
	if project != "" && l.project[project] >= maxProject {
		return nil, "project"
	}
	l.route[route]++
	l.perIP[k]++
	if project != "" {
		l.project[project]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			dec := func(m map[string]int, key string) {
				if m[key]--; m[key] <= 0 {
					delete(m, key)
				}
			}
			dec(l.route, route)
			if l.perIP[k]--; l.perIP[k] <= 0 {
				delete(l.perIP, k)
			}
			if project != "" {
				dec(l.project, project)
			}
			l.mu.Unlock()
		})
	}, ""
}

// ---------------- metrics ----------------

type udpMetrics struct {
	Sessions       prometheus.Gauge
	SessionsTotal  *prometheus.CounterVec
	Datagrams      *prometheus.CounterVec
	Bytes          *prometheus.CounterVec
	Dropped        *prometheus.CounterVec
	PoolListeners  *prometheus.GaugeVec
	PoolFlows      prometheus.Gauge
	PoolRejected   *prometheus.CounterVec
	PoolBindErrors prometheus.Counter
	PoolConns      prometheus.Gauge
}

func newUDPMetrics(reg *prometheus.Registry) *udpMetrics {
	m := &udpMetrics{
		Sessions:       prometheus.NewGauge(prometheus.GaugeOpts{Name: "gw_udp_sessions", Help: "Open UDP sessions of the tunnel (transport 2)."}),
		SessionsTotal:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gw_udp_sessions_total", Help: "Finished UDP tunnel sessions by close reason."}, []string{"reason"}),
		Datagrams:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gw_udp_datagrams_total", Help: "UDP datagrams forwarded by route (dir=in client to destination, out destination to client)."}, []string{"route", "dir"}),
		Bytes:          prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gw_udp_bytes_total", Help: "UDP payload bytes forwarded (tunnel and pool)."}, []string{"dir"}),
		Dropped:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gw_udp_dropped_total", Help: "UDP datagrams dropped by reason."}, []string{"reason"}),
		PoolListeners:  prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "gw_pool_listeners", Help: "Random-port listeners open for active leases (proto=tcp|udp)."}, []string{"proto"}),
		PoolFlows:      prometheus.NewGauge(prometheus.GaugeOpts{Name: "gw_pool_udp_flows", Help: "Open UDP flows on random ports."}),
		PoolConns:      prometheus.NewGauge(prometheus.GaugeOpts{Name: "gw_pool_tcp_conns", Help: "Open TCP connections on random ports."}),
		PoolRejected:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gw_pool_rejected_total", Help: "Leases or connections not served by reason."}, []string{"reason"}),
		PoolBindErrors: prometheus.NewCounter(prometheus.CounterOpts{Name: "gw_pool_bind_errors_total", Help: "Failed attempts to bind a leased port."}),
	}
	reg.MustRegister(m.Sessions, m.SessionsTotal, m.Datagrams, m.Bytes, m.Dropped, m.PoolListeners, m.PoolFlows, m.PoolConns, m.PoolRejected, m.PoolBindErrors)
	return m
}

// routeObserver feeds the metrics of one route.
type routeObserver struct {
	in, out prometheus.Counter
	m       *udpMetrics
	bin     prometheus.Counter
	bout    prometheus.Counter
}

func (m *udpMetrics) observer(route string) *routeObserver {
	return &routeObserver{
		m: m, in: m.Datagrams.WithLabelValues(route, "in"), out: m.Datagrams.WithLabelValues(route, "out"),
		bin: m.Bytes.WithLabelValues("in"), bout: m.Bytes.WithLabelValues("out"),
	}
}

func (o *routeObserver) datagram(dir string, n int) {
	if dir == "in" {
		o.in.Inc()
		o.bin.Add(float64(n))
		return
	}
	o.out.Inc()
	o.bout.Add(float64(n))
}

func (o *routeObserver) dropped(reason string) { o.m.Dropped.WithLabelValues(reason).Inc() }

// forgetUDPRoutes deletes the metric series of UDP routes that left the table.
func (s *Server) forgetUDPRoutes(old, nw *Table) {
	if old == nil {
		return
	}
	for id := range old.udpByID {
		if nw.udpByID[id] == nil {
			s.udpm.Datagrams.DeletePartialMatch(prometheus.Labels{"route": id})
			s.metrics.ConnsActive.DeletePartialMatch(prometheus.Labels{"route": id})
			s.metrics.ConnsTotal.DeletePartialMatch(prometheus.Labels{"route": id})
		}
	}
}
