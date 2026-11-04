package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInternalEdgeGuard(t *testing.T) {
	h := InternalEdgeGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	cases := []struct {
		path, xff string
		want      int
	}{
		{"/internal/gateway/routes", "", 200},
		{"/internal/gateway/routes", "10.0.0.2", 200},
		{"/internal/gateway/routes", "198.51.100.7", 403},
		{"/internal/other", "1.1.1.1, 10.0.0.2", 403},
		{"/internal/tls/ask", "198.51.100.7", 200},  // answers from the query only
		{"/internal/git-auth", "198.51.100.7", 200}, // forward_auth carries the Git client's address by design
		{"/api/v1/orgs", "198.51.100.7", 200},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", c.path, nil)
		if c.xff != "" {
			req.Header.Set("X-Forwarded-For", c.xff)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s xff=%q: %d want %d", c.path, c.xff, rec.Code, c.want)
		}
	}
}
