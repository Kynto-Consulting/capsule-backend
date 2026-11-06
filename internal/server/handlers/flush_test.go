package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type wrapW struct{ http.ResponseWriter }

func (w wrapW) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestFlusherOfReachesWrappedWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	f, ok := flusherOf(wrapW{rec})
	if !ok {
		t.Fatal("no flusher")
	}
	f.Flush()
	if !rec.Flushed {
		t.Fatal("Flush did not reach the underlying writer")
	}
}
