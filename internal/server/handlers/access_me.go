package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/kynto/capsule/backend/internal/access"
)

// etagMatches implements If-None-Match for weak comparison (a list of tags, or *).
func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(t), "W/"))
		if t == "*" || t == etag {
			return true
		}
	}
	return false
}

// GET /permissions/catalog  (cacheable by ETag)
func (h *accessAPI) catalog(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.actor(w, r); !ok {
		return
	}
	body, tag := access.CatalogJSON()
	w.Header().Set("ETag", tag)
	w.Header().Set("Cache-Control", "private, max-age=300")
	if etagMatches(r.Header.Get("If-None-Match"), tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// GET /me/permissions  (source of the sidebar; ETag and 304)
func (h *accessAPI) me(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	res, err := h.svc.MyPermissions(r.Context(), a.UserID, q.Get("org"), q.Get("project"), q.Get("expand"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("ETag", res.ETag)
	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	w.Header().Set("X-Access-Epoch", strconv.FormatInt(res.Epoch, 10))
	if etagMatches(r.Header.Get("If-None-Match"), res.ETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(res.Body)
}

// GET /me/permissions/explain?permission=&org=&scope_type=&scope_id=
func (h *accessAPI) meExplain(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	d, err := h.svc.ExplainSelf(r.Context(), a.UserID, q.Get("org"), q.Get("permission"), q.Get("scope_type"), q.Get("scope_id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	respondJSON(w, http.StatusOK, d)
}
