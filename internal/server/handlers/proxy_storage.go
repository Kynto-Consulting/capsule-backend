package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kynto/capsule/backend/internal/domain"
)

// serveStorage answers <project>-storage.<zone> through the backend's own S3 server. The preferred
// public path is Caddy → the dedicated S3 listener (no deadlines, no path rewrite); this route keeps the
// host working when only the generic app route is configured. The client signed the path it sent, so the
// /_proxy/<sub> prefix added by the rewrite is stripped before verification.
func (h *ProxyHandler) serveStorage(w http.ResponseWriter, r *http.Request, project *domain.Project, subdomain string) {
	if h.obj == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "STORAGE_DISABLED", "message": "object storage is not enabled on this platform"}})
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})

	prefix := "/_proxy/" + subdomain
	path := strings.TrimPrefix(r.URL.Path, prefix)
	if strings.Trim(path, "/") == "" && r.Header.Get("Authorization") == "" && r.URL.Query().Get("X-Amz-Signature") == "" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"service": "capsule-object-storage", "project_id": project.ID, "api": "s3", "path_style": true})
		return
	}
	// a project's host only serves that project's buckets
	if bucket, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/"); bucket != "" {
		if info, err := h.obj.Meta.Bucket(r.Context(), bucket); err != nil || info.ProjectID != project.ID.String() {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>`))
			return
		}
	}
	srv := *h.obj
	srv.StripPath = func(*http.Request) string { return path }
	srv.ServeHTTP(w, r)
}
