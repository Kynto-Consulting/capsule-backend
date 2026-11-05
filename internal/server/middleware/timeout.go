package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Timeout bounds a request with a deadline. Application traffic proxied by the
// platform (/_proxy/<app>/... and the legacy /apps/<org>/<project>/...) is
// exempt: those requests are the customer's own WebSocket upgrades, SSE streams
// and long downloads, and httputil.ReverseProxy tears an upgraded connection
// down as soon as the request context ends, so a 30 s deadline would cut every
// WebSocket at 30 s.
func Timeout(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p := r.URL.Path; strings.HasPrefix(p, "/_proxy/") || strings.HasPrefix(p, "/apps/") {
				next.ServeHTTP(w, r)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
