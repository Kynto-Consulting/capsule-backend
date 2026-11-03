package gitsync

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// Job is the JSON of the API's Job schema (id uuid, status queued|running|success|failed).
type Job struct {
	ID     uuid.UUID `json:"id"`
	Status string    `json:"status"`
	Detail string    `json:"detail,omitempty"`
}

// Deps is what the routes need. Rec nil answers 501 (integration off).
type Deps struct {
	Rec *Reconciler
	// Timeout bounds one whole-platform reconciliation (default 30 min).
	Timeout time.Duration

	mu   sync.Mutex
	jobs map[uuid.UUID]*Job
	busy bool
}

var (
	sharedMu sync.RWMutex
	shared   *Deps
)

// Publish makes d the instance MountGitsync serves (called from the wiring in main).
func Publish(d *Deps) { sharedMu.Lock(); shared = d; sharedMu.Unlock() }

// Shared returns the published Deps (nil until the wiring ran or when the integration is off).
func Shared() *Deps { sharedMu.RLock(); defer sharedMu.RUnlock(); return shared }

// MountGitsync registers gitReconcile inside the authenticated /api/v1 group:
//
//	POST /git/admin/reconcile   (platform.admin)  -> 202 Job
//
// d may be nil; the handler then answers 501.
func MountGitsync(r chi.Router, d *Deps) {
	r.Post("/git/admin/reconcile", func(w http.ResponseWriter, req *http.Request) {
		d.reconcile(w, req)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg}})
}

func (d *Deps) reconcile(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUser(r.Context())
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}
	if u.Role != "admin" {
		writeErr(w, http.StatusForbidden, "FORBIDDEN", "platform administrators only")
		return
	}
	if d == nil || d.Rec == nil || d.Rec.Forge == nil || !d.Rec.Forge.Enabled() {
		writeErr(w, http.StatusNotImplemented, "GIT_NOT_READY", "the Git integration is not configured")
		return
	}
	job, ok := d.start()
	if !ok {
		writeErr(w, http.StatusConflict, "CONFLICT", "a reconciliation is already running")
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

// start launches a manual reconciliation of every project in the background.
func (d *Deps) start() (Job, bool) {
	d.mu.Lock()
	if d.busy {
		d.mu.Unlock()
		return Job{}, false
	}
	d.busy = true
	if d.jobs == nil {
		d.jobs = map[uuid.UUID]*Job{}
	}
	if len(d.jobs) >= 50 {
		for id, old := range d.jobs { // drop finished jobs; only one can be running
			if old.Status == "success" || old.Status == "failed" {
				delete(d.jobs, id)
			}
		}
	}
	j := &Job{ID: uuid.New(), Status: "queued"}
	d.jobs[j.ID] = j
	snapshot := *j
	d.mu.Unlock()

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		d.setJob(j, "running", "")
		sum, err := d.Rec.ReconcileAll(ctx, TriggerManual)
		detail, _ := json.Marshal(sum)
		if err != nil {
			d.setJob(j, "failed", err.Error())
		} else if sum.Failed > 0 {
			d.setJob(j, "failed", string(detail))
		} else {
			d.setJob(j, "success", string(detail))
		}
		d.mu.Lock()
		d.busy = false
		d.mu.Unlock()
	}()
	return snapshot, true
}

func (d *Deps) setJob(j *Job, status, detail string) {
	d.mu.Lock()
	j.Status, j.Detail = status, clip(detail)
	d.mu.Unlock()
}

// JobStatus returns a snapshot of a job started by this process.
func (d *Deps) JobStatus(id uuid.UUID) (Job, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if j := d.jobs[id]; j != nil {
		return *j, true
	}
	return Job{}, false
}
