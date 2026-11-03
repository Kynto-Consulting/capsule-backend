package handlers

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// Rollback handles POST /orgs/{o}/projects/{p}/deployments/{id}/rollback.
//
// It re-deploys the source of a previous SUCCESSFUL deployment ({id}) as a new
// deployment (trigger "rollback"), which goes through the normal worker path
// (blue-green + health check), so a rollback that does not become healthy leaves
// the current version serving. The image is rebuilt from the stored source: it is
// not an instant image swap. Allowed for "deploy"-scoped tokens (authz
// project.deploy, see middleware/scope.go).
func (h *DeploymentHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	deploymentID, err := uuid.Parse(chi.URLParam(r, "deploymentID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid deployment id")
		return
	}
	projectID, ok := h.authorizeRoute(w, r, h.orgs, orgID, authz.ProjectDeploy)
	if !ok {
		return
	}
	project, ok := h.scopedProject(w, r, orgID, projectID)
	if !ok {
		return
	}
	target, ok := h.scopedDeployment(w, r, orgID, deploymentID)
	if !ok {
		return
	}
	if msg := rollbackBlocker(target); msg != "" {
		respondError(w, http.StatusConflict, "INVALID_STATE", msg)
		return
	}

	uid := user.ID
	d, err := h.deployments.Create(r.Context(), rollbackDeployment(target, &uid))
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create rollback deployment")
		return
	}
	if d.BuildStrategy == "lambda" || project.DeployType == "lambda" {
		go h.deployLambda(context.Background(), d, project)
	}
	respondJSON(w, http.StatusAccepted, d)
}

// rollbackBlocker returns why target cannot be rolled back to ("" = ok).
func rollbackBlocker(target *domain.Deployment) string {
	if target.Status != "success" {
		return "can only roll back to a deployment that finished successfully"
	}
	if target.SourceKey == nil || *target.SourceKey == "" {
		return "this deployment has no stored source to roll back to"
	}
	return ""
}

// rollbackDeployment builds the new deployment that redeploys target's source.
func rollbackDeployment(target *domain.Deployment, by *uuid.UUID) *domain.Deployment {
	return &domain.Deployment{
		ProjectID:     target.ProjectID,
		Version:       "rollback",
		GitSHA:        target.GitSHA,
		BuildStrategy: target.BuildStrategy,
		ContainerPort: target.ContainerPort,
		Trigger:       "rollback",
		TriggeredBy:   by,
		SourceKey:     target.SourceKey,
		Meta:          map[string]string{"rollback_to": target.ID.String()},
	}
}
