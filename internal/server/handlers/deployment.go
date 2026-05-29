package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	lambdapkg "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

type DeploymentHandler struct {
	deployments     domain.DeploymentRepository
	orgs            domain.OrganizationRepository
	projects        domain.ProjectRepository
	awsClients      *awsclient.Clients
	artifactsBucket string
	logger          *slog.Logger
}

// NewDeploymentHandler creates a DeploymentHandler.
// logger is optional; pass nil (or omit) to use a no-op logger.
func NewDeploymentHandler(deployments domain.DeploymentRepository, orgs domain.OrganizationRepository, projects domain.ProjectRepository, awsClients *awsclient.Clients, artifactsBucket string, logger ...*slog.Logger) *DeploymentHandler {
	var l *slog.Logger
	if len(logger) > 0 && logger[0] != nil {
		l = logger[0]
	} else {
		l = slog.Default()
	}
	return &DeploymentHandler{
		deployments:     deployments,
		orgs:            orgs,
		projects:        projects,
		awsClients:      awsClients,
		artifactsBucket: artifactsBucket,
		logger:          l,
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
		if project.DeployType != "" {
			req.BuildStrategy = project.DeployType
		} else {
			req.BuildStrategy = project.BuildStrategy
		}
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

	// If this is a Lambda deployment, kick off the background deploy process.
	if req.BuildStrategy == "lambda" || project.DeployType == "lambda" {
		go h.deployLambda(context.Background(), d, project)
	}

	respondJSON(w, http.StatusCreated, d)
}

// deployLambda handles the Lambda deployment path in the background.
// It updates deployment status/logs as it progresses.
func (h *DeploymentHandler) deployLambda(ctx context.Context, d *domain.Deployment, project *domain.Project) {
	appendLog := func(level, msg string) {
		_ = h.deployments.AppendLog(ctx, &domain.BuildLog{
			DeploymentID: d.ID,
			Level:        level,
			Message:      msg,
		})
	}

	if h.awsClients == nil || h.awsClients.Lambda == nil {
		appendLog("warn", "Lambda deployment queued. Image will be built and pushed to ECR.")
		_ = h.deployments.UpdateStatus(ctx, d.ID, "queued")
		return
	}

	_ = h.deployments.UpdateStatus(ctx, d.ID, "deploying")
	appendLog("info", "Lambda deployment queued. Image will be built and pushed to ECR.")

	functionName := fmt.Sprintf("capsule-%s", project.Slug)
	region := h.awsClients.Region
	account := h.awsClients.Account

	// Build ECR image URI from the deployment image tag (if set) or derive a default.
	imageTag := d.ImageTag
	if imageTag == "" {
		imageTag = "latest"
	}
	imageURI := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s:%s", account, region, functionName, imageTag)
	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/capsule-lambda-role", account)

	// Check if the Lambda function already exists.
	_, getErr := h.awsClients.Lambda.GetFunction(ctx, &lambdapkg.GetFunctionInput{
		FunctionName: aws.String(functionName),
	})

	if getErr == nil {
		// Function exists — update the image.
		appendLog("info", fmt.Sprintf("Updating Lambda function %s with image %s", functionName, imageURI))
		_, err := h.awsClients.Lambda.UpdateFunctionCode(ctx, &lambdapkg.UpdateFunctionCodeInput{
			FunctionName: aws.String(functionName),
			ImageUri:     aws.String(imageURI),
		})
		if err != nil {
			appendLog("error", fmt.Sprintf("Failed to update Lambda function code: %v", err))
			_ = h.deployments.UpdateStatus(ctx, d.ID, "failed")
			h.logger.Error("lambda update function code failed", "deployment_id", d.ID, "error", err)
			return
		}
		appendLog("info", "Lambda function code updated successfully.")
	} else {
		// Function does not exist — create it.
		appendLog("info", fmt.Sprintf("Creating Lambda function %s with image %s", functionName, imageURI))
		_, err := h.awsClients.Lambda.CreateFunction(ctx, &lambdapkg.CreateFunctionInput{
			FunctionName: aws.String(functionName),
			Role:         aws.String(roleArn),
			PackageType:  lambdatypes.PackageTypeImage,
			Code: &lambdatypes.FunctionCode{
				ImageUri: aws.String(imageURI),
			},
			Architectures: []lambdatypes.Architecture{lambdatypes.ArchitectureX8664},
		})
		if err != nil {
			appendLog("error", fmt.Sprintf("Failed to create Lambda function: %v", err))
			_ = h.deployments.UpdateStatus(ctx, d.ID, "failed")
			h.logger.Error("lambda create function failed", "deployment_id", d.ID, "error", err)
			return
		}
		appendLog("info", "Lambda function created successfully.")
	}

	// Retrieve the function URL (if a URL config exists) and store it.
	urlOut, err := h.awsClients.Lambda.GetFunctionUrlConfig(ctx, &lambdapkg.GetFunctionUrlConfigInput{
		FunctionName: aws.String(functionName),
	})
	if err == nil && urlOut.FunctionUrl != nil {
		functionURL := aws.ToString(urlOut.FunctionUrl)
		_ = h.deployments.UpdateFunctionURL(ctx, d.ID, functionURL)
		appendLog("info", fmt.Sprintf("Function URL: %s", functionURL))
	}

	_ = h.deployments.UpdateStatus(ctx, d.ID, "success")
	appendLog("info", "Lambda deployment complete.")
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

	page, limit := parsePagination(r)
	deployments, total, err := h.deployments.ListByProject(r.Context(), projectID, page, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list deployments")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"data": deployments,
		"meta": domain.ListMeta{Page: page, PerPage: limit, Total: total},
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

	if logs == nil {
		logs = []*domain.BuildLog{}
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
