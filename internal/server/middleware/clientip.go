package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/kynto/capsule/backend/internal/netaccess"
)

type remoteKey struct{}

// CaptureRemoteAddr stores the original socket address in the request context.
// Register it BEFORE chi's RealIP middleware, which overwrites r.RemoteAddr with
// a client-supplied header value.
func CaptureRemoteAddr(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), remoteKey{}, r.RemoteAddr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ClientIP returns the trusted client IP of the request (see netaccess.ClientIP).
func ClientIP(r *http.Request) string {
	remote := r.RemoteAddr
	if v, ok := r.Context().Value(remoteKey{}).(string); ok {
		remote = v
	}
	return netaccess.ClientIP(remote, r.Header.Get("X-Forwarded-For"))
}

// RemoteAddr returns the original socket address (before chi's RealIP rewrite).
func RemoteAddr(r *http.Request) string {
	if v, ok := r.Context().Value(remoteKey{}).(string); ok {
		return v
	}
	return r.RemoteAddr
}

// InternalEdgeGuard refuses /internal/* requests that carry a public client
// address in X-Forwarded-For. Defence in depth: the real barrier is the edge
// (Caddy must not route /internal/* on its public sites) plus the per-endpoint
// shared secrets. Exempt: /internal/tls/ask (called by Caddy itself, answers only
// from the Host query and is read-only) and /internal/git-auth (Caddy forward_auth
// copies the Git client's public address into X-Forwarded-For by design).
func InternalEdgeGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/internal/") && p != "/internal/tls/ask" && p != "/internal/git-auth" &&
			netaccess.HasPublicForwarded(r.Header.Get("X-Forwarded-For")) {
			http.Error(w, `{"error":{"code":"FORBIDDEN","message":"forbidden"}}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
