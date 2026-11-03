package data

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics are the Prometheus series of the data plane (PLAN.md section 9). The `route` label is the route id
// ("-" before a route is resolved); series of routes that disappear from the table are deleted.
type Metrics struct {
	Reg          *prometheus.Registry
	ConnsActive  *prometheus.GaugeVec
	ConnsTotal   *prometheus.CounterVec
	BytesTotal   *prometheus.CounterVec
	Handshake    *prometheus.HistogramVec
	RouteRev     prometheus.Gauge
	RoutesLoaded prometheus.Gauge
	Draining     prometheus.Gauge
	AuthCalls    *prometheus.CounterVec
	Dropped      *prometheus.CounterVec
	ActiveTotal  prometheus.Gauge
}

// NewMetrics registers the series on a private registry.
func NewMetrics() *Metrics {
	m := &Metrics{Reg: prometheus.NewRegistry()}
	m.ConnsActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "gw_conns_active", Help: "Connections being proxied."}, []string{"route"})
	m.ConnsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gw_conns_total", Help: "Finished connections by route and result."}, []string{"route", "result"})
	m.BytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gw_bytes_total", Help: "Bytes relayed (dir=in client to destination, out destination to client)."}, []string{"route", "dir"})
	m.Handshake = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "gw_handshake_seconds", Help: "Time from accept to the start of relaying.", Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}}, []string{"kind"})
	m.RouteRev = prometheus.NewGauge(prometheus.GaugeOpts{Name: "gw_route_rev", Help: "Revision of the route table in force."})
	m.RoutesLoaded = prometheus.NewGauge(prometheus.GaugeOpts{Name: "gw_routes", Help: "TCP routes in the table."})
	m.Draining = prometheus.NewGauge(prometheus.GaugeOpts{Name: "gw_draining", Help: "1 while the gateway is draining for an update."})
	m.AuthCalls = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gw_authorize_total", Help: "Authorisation lookups by outcome (allow, deny, error)."}, []string{"outcome"})
	m.Dropped = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gw_dropped_total", Help: "Connections refused before any protocol work, by reason."}, []string{"reason"})
	m.ActiveTotal = prometheus.NewGauge(prometheus.GaugeOpts{Name: "gw_conns_open", Help: "All open client connections (any phase)."})
	m.Reg.MustRegister(m.ConnsActive, m.ConnsTotal, m.BytesTotal, m.Handshake, m.RouteRev, m.RoutesLoaded, m.Draining, m.AuthCalls, m.Dropped, m.ActiveTotal,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Handler serves /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Reg, promhttp.HandlerOpts{})
}
