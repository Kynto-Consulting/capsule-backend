package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/getsentry/sentry-go"
)

func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if sentry.CurrentHub().Client() != nil {
						sentry.CurrentHub().RecoverWithContext(r.Context(), rec)
						sentry.Flush(2 * time.Second)
					}
					logger.Error("panic recovered",
						"error", rec,
						"stack", string(debug.Stack()),
						"request_id", GetRequestID(r.Context()),
					)
					http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"internal server error"}}`, http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
