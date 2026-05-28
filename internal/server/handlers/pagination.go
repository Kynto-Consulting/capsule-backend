package handlers

import (
	"net/http"
	"strconv"
)

const (
	defaultPage    = 1
	defaultLimit   = 50
	maxLimit       = 200
)

// parsePagination extracts ?page= and ?limit= query params.
// Returns safe, clamped values.
func parsePagination(r *http.Request) (page, limit int) {
	page = defaultPage
	limit = defaultLimit

	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > maxLimit {
				n = maxLimit
			}
			limit = n
		}
	}
	return
}
