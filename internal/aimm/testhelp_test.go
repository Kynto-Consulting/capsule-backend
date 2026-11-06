package aimm

import (
	"net/http"
	"net/http/httptest"
)

// newTranscriptServer serves a transcript over plain HTTP; the client is the server's own, so the https check of fetch is bypassed by using a TLS server.
func newTranscriptServer(body string) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}
