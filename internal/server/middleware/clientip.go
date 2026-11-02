package middleware

import (
	"context"
	"net/http"

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
