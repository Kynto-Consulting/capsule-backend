package handlers

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// LogsHandler handles runtime/lambda/worker/storage log retrieval.
type LogsHandler struct {
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
	exLogs   domain.ExecutionLogRepository
	logger   *slog.Logger
}

// NewLogsHandler creates a LogsHandler.
func NewLogsHandler(
	orgs domain.OrganizationRepository,
	projects domain.ProjectRepository,
	exLogs domain.ExecutionLogRepository,
	logger *slog.Logger,
) *LogsHandler {
	return &LogsHandler{
		orgs:     orgs,
		projects: projects,
		exLogs:   exLogs,
		logger:   logger,
	}
}

// resolveProject validates org membership and returns the project.
func (h *LogsHandler) resolveProject(r *http.Request) (*domain.Project, int, string, string) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		return nil, http.StatusBadRequest, "INVALID_ID", "invalid org id"
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		return nil, http.StatusBadRequest, "INVALID_ID", "invalid project id"
	}
	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		return nil, http.StatusForbidden, "FORBIDDEN", "not a member"
	}
	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && project.OrgID != orgID) {
		return nil, http.StatusNotFound, "NOT_FOUND", "project not found"
	}
	if err != nil {
		return nil, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get project"
	}
	return project, 0, "", ""
}

// parseTailParam reads ?tail=N, defaulting to `defaultVal`, capped at `max`.
func parseTailParam(r *http.Request, defaultVal, max int) int {
	n := defaultVal
	if s := r.URL.Query().Get("tail"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			n = v
		}
	}
	if n > max {
		n = max
	}
	return n
}

// dockerLogs runs `docker logs <name> --tail N` and returns the combined output lines.
func dockerLogs(containerName string, tail int) ([]string, error) {
	out, err := exec.CommandContext(
		context.Background(),
		"docker", "logs", containerName,
		"--tail", strconv.Itoa(tail),
	).CombinedOutput()
	if err != nil {
		// Non-zero exit (e.g. container not found) — return what we have
		return splitLines(out), err
	}
	return splitLines(out), nil
}

func splitLines(b []byte) []string {
	raw := strings.Split(strings.TrimRight(string(bytes.TrimRight(b, "\r\n")), "\r\n"), "\n")
	var lines []string
	for _, l := range raw {
		l = strings.TrimRight(l, "\r")
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// appContainerName returns the deterministic docker container name for a deployed project app.
func appContainerName(projectID uuid.UUID) string {
	short := strings.ReplaceAll(projectID.String(), "-", "")[:8]
	return "capsule-app-" + short
}

// workerContainerNameFromShort returns the worker container name from a workerID string.
func workerContainerNameFromID(workerID uuid.UUID) string {
	short := strings.ReplaceAll(workerID.String(), "-", "")[:8]
	return "capsule-worker-" + short
}

// GetRuntimeLogs — GET /orgs/{orgID}/projects/{projectID}/logs/runtime
func (h *LogsHandler) GetRuntimeLogs(w http.ResponseWriter, r *http.Request) {
	project, status, code, msg := h.resolveProject(r)
	if status != 0 {
		respondError(w, status, code, msg)
		return
	}

	tail := parseTailParam(r, 200, 1000)
	containerName := appContainerName(project.ID)

	lines, dockerErr := dockerLogs(containerName, tail)
	if dockerErr != nil {
		h.logger.Warn("docker logs failed for runtime container",
			"container", containerName, "error", dockerErr)
	}

	// Persist fetched lines to execution_logs asynchronously.
	go func(lines []string, projectID uuid.UUID, containerName string) {
		ctx := context.Background()
		for _, line := range lines {
			_ = h.exLogs.Append(ctx, &domain.ExecutionLog{
				ProjectID: projectID,
				Source:    "runtime",
				SourceID:  containerName,
				Level:     "info",
				Message:   line,
			})
		}
	}(lines, project.ID, containerName)

	if lines == nil {
		lines = []string{}
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"container": containerName,
		"lines":     lines,
	})
}

// GetLambdaLogs — GET /orgs/{orgID}/projects/{projectID}/logs/lambda
func (h *LogsHandler) GetLambdaLogs(w http.ResponseWriter, r *http.Request) {
	project, status, code, msg := h.resolveProject(r)
	if status != 0 {
		respondError(w, status, code, msg)
		return
	}

	tail := parseTailParam(r, 100, 1000)
	logs, err := h.exLogs.ListByProject(r.Context(), project.ID, "lambda", tail)
	if err != nil {
		h.logger.Error("failed to list lambda logs", "project_id", project.ID, "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to retrieve lambda logs")
		return
	}
	if logs == nil {
		logs = []*domain.ExecutionLog{}
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": logs})
}

// GetWorkerLogs — GET /orgs/{orgID}/projects/{projectID}/logs/workers/{workerID}
func (h *LogsHandler) GetWorkerLogs(w http.ResponseWriter, r *http.Request) {
	project, status, code, msg := h.resolveProject(r)
	if status != 0 {
		respondError(w, status, code, msg)
		return
	}

	workerID, err := uuid.Parse(chi.URLParam(r, "workerID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid worker id")
		return
	}

	tail := parseTailParam(r, 200, 1000)
	containerName := workerContainerNameFromID(workerID)

	lines, dockerErr := dockerLogs(containerName, tail)
	if dockerErr != nil {
		h.logger.Warn("docker logs failed for worker container",
			"container", containerName, "project_id", project.ID, "error", dockerErr)
	}
	if lines == nil {
		lines = []string{}
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"container": containerName,
		"lines":     lines,
	})
}

// GetStorageLogs — GET /orgs/{orgID}/projects/{projectID}/logs/storage
func (h *LogsHandler) GetStorageLogs(w http.ResponseWriter, r *http.Request) {
	project, status, code, msg := h.resolveProject(r)
	if status != 0 {
		respondError(w, status, code, msg)
		return
	}

	logs, err := h.exLogs.ListByProject(r.Context(), project.ID, "storage", 100)
	if err != nil {
		h.logger.Error("failed to list storage logs", "project_id", project.ID, "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to retrieve storage logs")
		return
	}
	if logs == nil {
		logs = []*domain.ExecutionLog{}
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": logs})
}
