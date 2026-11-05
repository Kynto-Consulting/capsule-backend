package middleware

import (
	"bufio"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

type hijackable struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackable) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	c1, c2 := net.Pipe()
	c2.Close()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}

// Every wrapper in the chain must let a WebSocket upgrade (Hijack) and streaming (Flush) reach the real writer.
func TestWrappersPassHijackAndFlush(t *testing.T) {
	var hijackErr, flushErr error
	h := Logger(slog.Default())(Metrics(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		flushErr = rc.Flush()
		_, _, hijackErr = rc.Hijack()
	})))
	rec := &hijackable{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/_proxy/x/ws", nil))
	if hijackErr != nil || !rec.hijacked {
		t.Fatalf("Hijack did not reach the real writer: %v", hijackErr)
	}
	if flushErr != nil {
		t.Fatalf("Flush did not reach the real writer: %v", flushErr)
	}
}
