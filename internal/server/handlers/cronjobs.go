package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// CronJobHandler handles cron job operations.
type CronJobHandler struct {
	crons    domain.CronJobRepository
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
	exLogs   domain.ExecutionLogRepository
	logger   *slog.Logger
}

// NewCronJobHandler creates a CronJobHandler.
func NewCronJobHandler(
	crons domain.CronJobRepository,
	orgs domain.OrganizationRepository,
	projects domain.ProjectRepository,
	exLogs domain.ExecutionLogRepository,
	logger *slog.Logger,
) *CronJobHandler {
	return &CronJobHandler{
		crons:    crons,
		orgs:     orgs,
		projects: projects,
		exLogs:   exLogs,
		logger:   logger,
	}
}

// Create creates a new cron job.
func (h *CronJobHandler) Create(w http.ResponseWriter, r *http.Request) {
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
		Name     string `json:"name"`
		Schedule string `json:"schedule"`
		Command  string `json:"command"`
		Timezone string `json:"timezone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name is required")
		return
	}
	if req.Schedule == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "schedule is required")
		return
	}
	if req.Command == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "command is required")
		return
	}
	if req.Timezone == "" {
		req.Timezone = "UTC"
	}

	cron, err := h.crons.Create(r.Context(), &domain.CronJob{
		ProjectID: projectID,
		Name:      req.Name,
		Schedule:  req.Schedule,
		Command:   req.Command,
		Timezone:  req.Timezone,
	})
	if err != nil {
		h.logger.Error("failed to create cronjob", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create cron job")
		return
	}

	respondJSON(w, http.StatusCreated, cron)
}

// List returns all cron jobs for a project.
func (h *CronJobHandler) List(w http.ResponseWriter, r *http.Request) {
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

	crons, err := h.crons.ListByProject(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list cron jobs")
		return
	}
	if crons == nil {
		crons = []*domain.CronJob{}
	}

	respondJSON(w, http.StatusOK, map[string]any{"data": crons})
}

// Get returns a single cron job.
func (h *CronJobHandler) Get(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	cronID, err := uuid.Parse(chi.URLParam(r, "cronID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid cron id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	cron, err := h.crons.GetByID(r.Context(), cronID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "cron job not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get cron job")
		return
	}

	respondJSON(w, http.StatusOK, cron)
}

// Delete soft-deletes a cron job.
func (h *CronJobHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	cronID, err := uuid.Parse(chi.URLParam(r, "cronID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid cron id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	_, err = h.crons.GetByID(r.Context(), cronID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "cron job not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get cron job")
		return
	}

	if err := h.crons.Delete(r.Context(), cronID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete cron job")
		return
	}

	respondNoContent(w)
}

// Trigger runs the cron job's command immediately.
func (h *CronJobHandler) Trigger(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	cronID, err := uuid.Parse(chi.URLParam(r, "cronID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid cron id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	cron, err := h.crons.GetByID(r.Context(), cronID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "cron job not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get cron job")
		return
	}

	go func(c *domain.CronJob) {
		ctx := context.Background()
		start := time.Now()
		cmd := exec.CommandContext(ctx, "sh", "-c", c.Command)
		out, runErr := cmd.CombinedOutput()
		dur := time.Since(start)
		runStatus := "success"
		level := "info"
		if runErr != nil {
			h.logger.Error("cron trigger failed", "cron_id", c.ID, "error", runErr)
			runStatus = "failed"
			level = "error"
		}
		_ = h.crons.UpdateLastRun(ctx, c.ID, runStatus, nil)

		// Persist cron execution log
		if h.exLogs != nil {
			msg := fmt.Sprintf("cron %q (%s) → %s in %s", c.Name, c.Command, runStatus, dur.Round(time.Millisecond))
			if len(out) > 0 {
				msg += "\n" + string(out)
			}
			_ = h.exLogs.Append(ctx, &domain.ExecutionLog{
				ProjectID: c.ProjectID,
				Source:    "cron",
				SourceID:  c.ID.String(),
				Level:     level,
				Message:   msg,
			})
		}
	}(cron)

	respondJSON(w, http.StatusAccepted, map[string]any{"message": "cron job triggered"})
}
