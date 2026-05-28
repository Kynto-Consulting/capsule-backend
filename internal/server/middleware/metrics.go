package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "capsule_http_requests_total",
		Help: "Total HTTP requests by method, path pattern, and status code.",
	}, []string{"method", "path", "status"})

	httpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "capsule_http_request_duration_seconds",
		Help:    "HTTP request latency by method and path pattern.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})

	httpRequestsInFlight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "capsule_http_requests_in_flight",
		Help: "Current number of HTTP requests being processed.",
	})
)

// Metrics records Prometheus metrics for each HTTP request.
// Must be used after chi's RouteContext is populated (place after r.Use(chi.Router...))
// so chi.RouteContext gives the pattern rather than the raw URL.
func Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequestsInFlight.Inc()
		defer httpRequestsInFlight.Dec()

		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start).Seconds()
		status := strconv.Itoa(rw.status)

		// Use chi route pattern (e.g. /api/v1/orgs/{orgID}) to avoid high cardinality.
		pattern := r.URL.Path
		if rctx := chi.RouteContext(r.Context()); rctx != nil {
			if p := rctx.RoutePattern(); p != "" {
				pattern = p
			}
		}

		httpRequestsTotal.WithLabelValues(r.Method, pattern, status).Inc()
		httpRequestDuration.WithLabelValues(r.Method, pattern).Observe(duration)
	})
}

// statusRecorder wraps ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}
