package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

type DeploymentHandler struct {
	deployments    domain.DeploymentRepository
	orgs           domain.OrganizationRepository
	projects       domain.ProjectRepository
	awsClients     *awsclient.Clients
	artifactsBucket string
}

func NewDeploymentHandler(deployments domain.DeploymentRepository, orgs domain.OrganizationRepository, projects domain.ProjectRepository, awsClients *awsclient.Clients, artifactsBucket string) *DeploymentHandler {
	return &DeploymentHandler{
		deployments:     deployments,
		orgs:            orgs,
		projects:        projects,
		awsClients:      awsClients,
		artifactsBucket: artifactsBucket,
	}
}

func (h *DeploymentHandler) UploadURL(w http.ResponseWriter, r *http.Request) {
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

	if h.awsClients == nil {
		respondError(w, http.StatusServiceUnavailable, "AWS_UNAVAILABLE", "AWS clients not configured")
		return
	}

	key := "deployments/" + projectID.String() + "/" + uuid.New().String() + ".tar.gz"
	presignClient := s3.NewPresignClient(h.awsClients.S3)
	presigned, err := presignClient.PresignPutObject(r.Context(), &s3.PutObjectInput{
		Bucket: &h.artifactsBucket,
		Key:    &key,
	}, s3.WithPresignExpires(15*time.Minute))
	if err != nil {
		respondError(w, http.StatusInternalServerError, "PRESIGN_ERROR", "failed to generate upload URL")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"upload_url": presigned.URL,
		"source_key": key,
	})
}

func (h *DeploymentHandler) Create(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		GitSHA        string  `json:"git_sha"`
		Version       string  `json:"version"`
		BuildStrategy string  `json:"build_strategy"`
		ContainerPort int     `json:"container_port"`
		SourceKey     *string `json:"source_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.Version == "" {
		req.Version = "manual"
	}
	if req.ContainerPort == 0 {
		req.ContainerPort = 8080
	}
	if req.BuildStrategy == "" {
		req.BuildStrategy = project.BuildStrategy
	}

	uid := user.ID
	d, err := h.deployments.Create(r.Context(), &domain.Deployment{
		ProjectID:     projectID,
		Version:       req.Version,
		GitSHA:        req.GitSHA,
		BuildStrategy: req.BuildStrategy,
		ContainerPort: req.ContainerPort,
		Trigger:       "manual",
		TriggeredBy:   &uid,
		SourceKey:     req.SourceKey,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create deployment")
		return
	}

	respondJSON(w, http.StatusCreated, d)
}

func (h *DeploymentHandler) List(w http.ResponseWriter, r *http.Request) {
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

	deployments, total, err := h.deployments.ListByProject(r.Context(), projectID, 1, 20)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list deployments")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"data": deployments,
		"meta": domain.ListMeta{Page: 1, PerPage: 20, Total: total},
	})
}

func (h *DeploymentHandler) Get(w http.ResponseWriter, r *http.Request) {
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

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	d, err := h.deployments.GetByID(r.Context(), deploymentID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "deployment not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, d)
}

func (h *DeploymentHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
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

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	logs, err := h.deployments.GetLogs(r.Context(), deploymentID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to fetch logs")
		return
	}

	respondJSON(w, http.StatusOK, logs)
}

func (h *DeploymentHandler) Cancel(w http.ResponseWriter, r *http.Request) {
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

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	d, err := h.deployments.GetByID(r.Context(), deploymentID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "deployment not found")
		return
	}

	if d.Status != "queued" && d.Status != "building" && d.Status != "deploying" {
		respondError(w, http.StatusConflict, "INVALID_STATE", "deployment cannot be cancelled in current state")
		return
	}

	if err := h.deployments.Cancel(r.Context(), deploymentID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to cancel deployment")
		return
	}
	respondNoContent(w)
}
