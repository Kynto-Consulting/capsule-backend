package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (rr *responseRecorder) WriteHeader(status int) {
	rr.status = status
	rr.ResponseWriter.WriteHeader(status)
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	n, err := rr.ResponseWriter.Write(b)
	rr.bytes += n
	return n, err
}

// Unwrap lets http.NewResponseController (used by httputil.ReverseProxy) reach Hijack and Flush of the
// real writer. Without it no WebSocket upgrade could pass through the app proxy, and streamed
// responses were not flushed.
func (rr *responseRecorder) Unwrap() http.ResponseWriter { return rr.ResponseWriter }

func Logger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rr := &responseRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rr, r)

			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rr.status,
				"bytes", rr.bytes,
				"duration", time.Since(start).String(),
				"request_id", GetRequestID(r.Context()),
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}
