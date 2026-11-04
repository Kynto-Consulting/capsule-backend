// Package metrics holds Prometheus collectors shared across packages.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	authzShadowTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "authz_shadow_total",
		Help: "Authorization decisions compared between the legacy and the new engine (shadow mode), by kind.",
	}, []string{"kind"})
	authzShadowMismatch = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "authz_shadow_mismatch_total",
		Help: "Shadow comparisons where the new engine disagreed with the legacy decision, by kind.",
	}, []string{"kind"})
	authzShadowSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "authz_shadow_seconds",
		Help:    "Time the new engine took to compute a shadow decision (off the request path).",
		Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.05, 0.25, 1},
	}, []string{"kind"})
	authzShadowSkipped = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "authz_shadow_skipped_total",
		Help: "Shadow comparisons not made (busy, engine error, panic), by kind and reason.",
	}, []string{"kind", "reason"})
)

// AuthzShadow implements authz.ShadowObserver with the Prometheus collectors above.
type AuthzShadow struct{}

// ObserveShadow records one comparison.
func (AuthzShadow) ObserveShadow(kind string, d time.Duration, mismatch bool) {
	authzShadowTotal.WithLabelValues(kind).Inc()
	authzShadowSeconds.WithLabelValues(kind).Observe(d.Seconds())
	if mismatch {
		authzShadowMismatch.WithLabelValues(kind).Inc()
	}
}

// ObserveShadowSkipped records a comparison that was not made.
func (AuthzShadow) ObserveShadowSkipped(kind, reason string) {
	authzShadowSkipped.WithLabelValues(kind, reason).Inc()
}
