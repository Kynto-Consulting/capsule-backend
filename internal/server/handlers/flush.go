package handlers

import "net/http"

// rcFlusher flushes through http.ResponseController, which follows Unwrap() across the middleware
// wrappers (logger, metrics). A plain w.(http.Flusher) assertion fails behind them.
type rcFlusher struct{ rc *http.ResponseController }

func (f rcFlusher) Flush() { _ = f.rc.Flush() }

func flusherOf(w http.ResponseWriter) (http.Flusher, bool) {
	return rcFlusher{http.NewResponseController(w)}, true
}
