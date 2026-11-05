package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTimeoutExemptsProxiedApps(t *testing.T) {
	var hasDeadline = map[string]bool{}
	h := Timeout(time.Second)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := r.Context().Deadline()
		hasDeadline[r.URL.Path] = ok
	}))
	for _, p := range []string{"/api/v1/x", "/_proxy/tunnel/connect", "/apps/o/p/x"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", p, nil))
	}
	if !hasDeadline["/api/v1/x"] {
		t.Fatal("API requests must keep the deadline")
	}
	if hasDeadline["/_proxy/tunnel/connect"] || hasDeadline["/apps/o/p/x"] {
		t.Fatal("proxied app traffic must not get a deadline")
	}
}
