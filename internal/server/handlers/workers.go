package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	sqspkg "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

// WorkerHandler handles background worker operations.
type WorkerHandler struct {
	workers    domain.WorkerRepository
	orgs       domain.OrganizationRepository
	projects   domain.ProjectRepository
	logger     *slog.Logger
	awsClients *awsclient.Clients
}

// NewWorkerHandler creates a WorkerHandler.
// awsClients is optional; pass nil (or omit) to disable SQS queue worker support.
func NewWorkerHandler(
	workers domain.WorkerRepository,
	orgs domain.OrganizationRepository,
	projects domain.ProjectRepository,
	logger *slog.Logger,
	awsClients ...*awsclient.Clients,
) *WorkerHandler {
	var clients *awsclient.Clients
	if len(awsClients) > 0 {
		clients = awsClients[0]
	}
	return &WorkerHandler{
		workers:    workers,
		orgs:       orgs,
		projects:   projects,
		logger:     logger,
		awsClients: clients,
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
		WorkerType    string `json:"worker_type"`
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
	if req.WorkerType == "" {
		req.WorkerType = "container"
	}

	worker, err := h.workers.Create(r.Context(), &domain.Worker{
		ProjectID:     projectID,
		Name:          req.Name,
		Command:       req.Command,
		Replicas:      req.Replicas,
		RestartPolicy: req.RestartPolicy,
		WorkerType:    req.WorkerType,
	})
	if err != nil {
		h.logger.Error("failed to create worker", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create worker")
		return
	}

	// For queue workers, create SQS queue immediately and mark as running.
	if req.WorkerType == "queue" {
		go h.setupQueueWorker(context.Background(), worker)
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

	// For container workers, stop any running container in the background.
	if worker.WorkerType != "queue" && worker.Status == "running" {
		go h.stopContainer(worker.ID)
	}

	// For queue workers, delete the SQS queue.
	if worker.WorkerType == "queue" && worker.QueueURL != "" {
		go h.deleteQueue(worker.QueueURL)
	}

	if err := h.workers.Delete(r.Context(), workerID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete worker")
		return
	}

	respondNoContent(w)
}

// Start launches the worker container via docker run.
// Queue workers are always running — this is a no-op for them.
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

	// Queue workers are always running — nothing to start.
	if worker.WorkerType == "queue" {
		respondJSON(w, http.StatusOK, worker)
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
// Queue workers are always running — this is a no-op for them.
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

	// Queue workers are always running — nothing to stop.
	if worker.WorkerType == "queue" {
		respondJSON(w, http.StatusOK, worker)
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

// workerQueueName returns the SQS queue name for a queue worker.
func workerQueueName(id uuid.UUID) string {
	return fmt.Sprintf("capsule-worker-%s", id.String())
}

func (h *WorkerHandler) stopContainer(workerID uuid.UUID) {
	name := workerContainerName(workerID)
	ctx := context.Background()
	if err := exec.CommandContext(ctx, "docker", "stop", name).Run(); err != nil {
		h.logger.Warn("docker stop failed", "container", name, "error", err)
	}
	_ = h.workers.UpdateStatus(ctx, workerID, "stopped", "")
}

// setupQueueWorker creates an SQS queue for a queue-type worker and marks it running.
func (h *WorkerHandler) setupQueueWorker(ctx context.Context, worker *domain.Worker) {
	if h.awsClients == nil || h.awsClients.SQS == nil {
		h.logger.Warn("SQS client not configured — queue worker created in DB only", "worker_id", worker.ID)
		_ = h.workers.UpdateStatus(ctx, worker.ID, "running", "")
		return
	}

	queueName := workerQueueName(worker.ID)
	out, err := h.awsClients.SQS.CreateQueue(ctx, &sqspkg.CreateQueueInput{
		QueueName: aws.String(queueName),
		Attributes: map[string]string{
			"MessageRetentionPeriod": "86400", // 1 day
		},
	})
	if err != nil {
		h.logger.Error("failed to create SQS queue", "worker_id", worker.ID, "error", err)
		_ = h.workers.UpdateStatus(ctx, worker.ID, "error", "")
		return
	}

	queueURL := aws.ToString(out.QueueUrl)
	// Store queue URL and set status to running.
	// UpdateStatus only updates status+container_id; update queue_url via a separate
	// call if the repository supports it. For now, store the URL in container_id slot
	// as a best-effort and update status.
	_ = h.workers.UpdateStatus(ctx, worker.ID, "running", queueURL)
	h.logger.Info("SQS queue created for worker", "worker_id", worker.ID, "queue_url", queueURL)
}

// deleteQueue purges and deletes an SQS queue by URL.
func (h *WorkerHandler) deleteQueue(queueURL string) {
	if h.awsClients == nil || h.awsClients.SQS == nil {
		return
	}
	ctx := context.Background()
	_, err := h.awsClients.SQS.DeleteQueue(ctx, &sqspkg.DeleteQueueInput{
		QueueUrl: aws.String(queueURL),
	})
	if err != nil {
		h.logger.Warn("failed to delete SQS queue", "queue_url", queueURL, "error", err)
	}
}
