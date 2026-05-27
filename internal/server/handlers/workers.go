package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// WorkerHandler handles background worker operations.
type WorkerHandler struct {
	workers  domain.WorkerRepository
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
	logger   *slog.Logger
}

// NewWorkerHandler creates a WorkerHandler.
func NewWorkerHandler(
	workers domain.WorkerRepository,
	orgs domain.OrganizationRepository,
	projects domain.ProjectRepository,
	logger *slog.Logger,
) *WorkerHandler {
	return &WorkerHandler{
		workers:  workers,
		orgs:     orgs,
		projects: projects,
		logger:   logger,
	}
}

// Create creates a new background worker.
func (h *WorkerHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && project.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get project")
		return
	}

	var req struct {
		Name          string `json:"name"`
		Command       string `json:"command"`
		Replicas      int    `json:"replicas"`
		RestartPolicy string `json:"restart_policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name is required")
		return
	}
	if req.Command == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "command is required")
		return
	}
	if req.Replicas <= 0 {
		req.Replicas = 1
	}
	if req.RestartPolicy == "" {
		req.RestartPolicy = "unless-stopped"
	}

	worker, err := h.workers.Create(r.Context(), &domain.Worker{
		ProjectID:     projectID,
		Name:          req.Name,
		Command:       req.Command,
		Replicas:      req.Replicas,
		RestartPolicy: req.RestartPolicy,
	})
	if err != nil {
		h.logger.Error("failed to create worker", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create worker")
		return
	}

	respondJSON(w, http.StatusCreated, worker)
}

// List returns all workers for a project.
func (h *WorkerHandler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && project.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get project")
		return
	}

	workers, err := h.workers.ListByProject(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list workers")
		return
	}
	if workers == nil {
		workers = []*domain.Worker{}
	}

	respondJSON(w, http.StatusOK, map[string]any{"data": workers})
}

// Get returns a single worker.
func (h *WorkerHandler) Get(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	workerID, err := uuid.Parse(chi.URLParam(r, "workerID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid worker id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	worker, err := h.workers.GetByID(r.Context(), workerID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "worker not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get worker")
		return
	}

	respondJSON(w, http.StatusOK, worker)
}

// Delete soft-deletes a worker.
func (h *WorkerHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	workerID, err := uuid.Parse(chi.URLParam(r, "workerID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid worker id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	worker, err := h.workers.GetByID(r.Context(), workerID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "worker not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get worker")
		return
	}

	// Stop any running container in the background.
	if worker.Status == "running" {
		go h.stopContainer(worker.ID)
	}

	if err := h.workers.Delete(r.Context(), workerID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete worker")
		return
	}

	respondNoContent(w)
}

// Start launches the worker container via docker run.
func (h *WorkerHandler) Start(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	workerID, err := uuid.Parse(chi.URLParam(r, "workerID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid worker id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	worker, err := h.workers.GetByID(r.Context(), workerID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "worker not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get worker")
		return
	}

	containerName := workerContainerName(workerID)

	// Run docker in the background; update status immediately and let it settle.
	go func(wkr *domain.Worker, name string) {
		ctx := context.Background()
		out, runErr := exec.CommandContext(ctx, "docker", "run", "-d",
			"--name", name,
			"--restart", wkr.RestartPolicy,
			"alpine",
			"sh", "-c", wkr.Command,
		).Output()
		if runErr != nil {
			h.logger.Error("docker run failed", "worker_id", wkr.ID, "error", runErr)
			_ = h.workers.UpdateStatus(ctx, wkr.ID, "error", "")
			return
		}
		containerID := strings.TrimSpace(string(out))
		_ = h.workers.UpdateStatus(ctx, wkr.ID, "running", containerID)
	}(worker, containerName)

	// Optimistically update status to starting.
	_ = h.workers.UpdateStatus(r.Context(), workerID, "starting", "")

	updated, _ := h.workers.GetByID(r.Context(), workerID)
	if updated == nil {
		updated = worker
	}
	respondJSON(w, http.StatusOK, updated)
}

// Stop halts the worker container.
func (h *WorkerHandler) Stop(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	workerID, err := uuid.Parse(chi.URLParam(r, "workerID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid worker id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	worker, err := h.workers.GetByID(r.Context(), workerID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "worker not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get worker")
		return
	}

	go h.stopContainer(worker.ID)

	_ = h.workers.UpdateStatus(r.Context(), workerID, "stopped", "")

	updated, _ := h.workers.GetByID(r.Context(), workerID)
	if updated == nil {
		updated = worker
	}
	respondJSON(w, http.StatusOK, updated)
}

// --- helpers ---

// workerContainerName returns the deterministic docker container name for a worker.
func workerContainerName(id uuid.UUID) string {
	short := strings.ReplaceAll(id.String(), "-", "")[:8]
	return fmt.Sprintf("capsule-worker-%s", short)
}

func (h *WorkerHandler) stopContainer(workerID uuid.UUID) {
	name := workerContainerName(workerID)
	ctx := context.Background()
	if err := exec.CommandContext(ctx, "docker", "stop", name).Run(); err != nil {
		h.logger.Warn("docker stop failed", "container", name, "error", err)
	}
	_ = h.workers.UpdateStatus(ctx, workerID, "stopped", "")
}
