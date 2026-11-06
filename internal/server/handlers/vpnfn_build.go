package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// Builds of function images from source (capsule fn deploy --source, capsule fn build, capsule fn builds; docs/vpn-connector.md 7b).
// Same atoms as the rest of functions: worker:manage to upload and build, worker:read to list builds, log:read to read a build's log.

// UploadPresigner returns a presigned PUT URL for key in the artifacts bucket (the same bucket and mechanism as capsule deploy).
type UploadPresigner func(ctx context.Context, key string) (string, error)

// SetUploads enables POST /fn/uploads (nil: 503, builds from source are unavailable).
func (h *VPNFnHandler) SetUploads(p UploadPresigner) { h.presign = p }

func (h *VPNFnHandler) audit(r *http.Request, orgID, projectID uuid.UUID, action string, resource uuid.UUID, vals map[string]any) {
	if h.fn == nil || h.fn.Audit == nil {
		return
	}
	_, uid := actorOf(r)
	h.fn.Audit(r.Context(), fn.AuditEntry{OrgID: orgID, ProjectID: projectID, UserID: uid, Action: action, ResourceID: resource,
		IP: middleware.ClientIP(r), Values: vals})
}

// fnDeployed is the answer of POST /fn/functions: the function and, when deployed from source, its first build.
type fnDeployed struct {
	*fn.Function
	Build *fn.Build `json:"build,omitempty"`
}

// UploadFnSource POST /fn/uploads -> {upload_url, source_key, expires_in}: where the CLI PUTs the packed directory (.tar.gz).
func (h *VPNFnHandler) UploadFnSource(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "worker:manage")
	if !ok {
		return
	}
	if h.presign == nil || h.fn.Builds == nil {
		respondError(w, http.StatusServiceUnavailable, "BUILDS_UNAVAILABLE", "building functions from source is not available on this Capsule; publish an image and use --image")
		return
	}
	key := fn.SourceKey(projectID)
	url, err := h.presign(r.Context(), key)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "PRESIGN_ERROR", "failed to generate upload URL")
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"upload_url": url, "source_key": key, "expires_in": int((15 * time.Minute).Seconds())})
}

// BuildFn POST /fn/functions/{name}/builds {source_key}: a new image for an existing function (runs and history are kept).
func (h *VPNFnHandler) BuildFn(w http.ResponseWriter, r *http.Request) {
	orgID, projectID, ok := h.ids(w, r, "worker:manage")
	if !ok {
		return
	}
	f := h.function(w, r, projectID)
	if f == nil {
		return
	}
	var body struct {
		SourceKey string `json:"source_key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	_, uid := actorOf(r)
	b, err := h.fn.QueueBuild(r.Context(), f, body.SourceKey, uid)
	if err != nil {
		h.fail(w, err)
		return
	}
	h.audit(r, orgID, projectID, "fn.build.queued", f.ID, map[string]any{"function": f.Name, "build_id": b.ID.String(), "runtime": f.Runtime})
	respondJSON(w, http.StatusAccepted, b)
}

// ListFnBuilds GET /fn/functions/{name}/builds (newest first, without logs)
func (h *VPNFnHandler) ListFnBuilds(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "worker:read")
	if !ok {
		return
	}
	f := h.function(w, r, projectID)
	if f == nil {
		return
	}
	if h.fn.Builds == nil {
		respondJSON(w, http.StatusOK, []*fn.Build{})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	bs, err := h.fn.Builds.ListBuilds(r.Context(), f.ID, limit)
	if err != nil {
		h.fail(w, err)
		return
	}
	if bs == nil {
		bs = []*fn.Build{}
	}
	respondJSON(w, http.StatusOK, bs)
}

// GetFnBuild GET /fn/builds/{buildID} (with the log)
func (h *VPNFnHandler) GetFnBuild(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "log:read")
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "buildID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid build id")
		return
	}
	if h.fn.Builds == nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "build not found")
		return
	}
	b, err := h.fn.Builds.GetBuild(r.Context(), id)
	if err != nil || b.ProjectID != projectID {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "build not found")
		return
	}
	respondJSON(w, http.StatusOK, b)
}
