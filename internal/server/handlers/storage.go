package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/pkg/awsclient"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

type StorageHandler struct {
	dbs       domain.DatabaseRepository
	orgs      domain.OrganizationRepository
	projects  domain.ProjectRepository
	aws       *awsclient.Clients
	secretKey string
	logger    *slog.Logger
}

func NewStorageHandler(
	dbs domain.DatabaseRepository,
	orgs domain.OrganizationRepository,
	projects domain.ProjectRepository,
	awsClients *awsclient.Clients,
	secretKey string,
	logger *slog.Logger,
) *StorageHandler {
	return &StorageHandler{
		dbs:       dbs,
		orgs:      orgs,
		projects:  projects,
		aws:       awsClients,
		secretKey: secretKey,
		logger:    logger,
	}
}

func (h *StorageHandler) Create(w http.ResponseWriter, r *http.Request) {
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
		Name   string `json:"name"`
		Public bool   `json:"public"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name is required")
		return
	}

	org, err := h.orgs.GetByID(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get organization")
		return
	}

	// Format S3 bucket name
	bucketName := fmt.Sprintf("capsule-%s-%s", org.Slug, req.Name)

	db, err := h.dbs.Create(r.Context(), &domain.Database{
		OrgID:          orgID,
		ProjectID:      &projectID,
		Name:           req.Name,
		Engine:         "s3",
		Version:        "latest",
		Host:           "s3.amazonaws.com",
		Port:           443,
		DBName:         bucketName,
		Status:         "provisioning",
		CredentialsEnc: []byte{},
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create storage database record")
		return
	}

	go h.provisionS3(db, bucketName, req.Public)

	respondJSON(w, http.StatusCreated, db)
}

func (h *StorageHandler) List(w http.ResponseWriter, r *http.Request) {
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

	allDBs, err := h.dbs.ListByProject(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list databases")
		return
	}

	var results []*domain.Database
	for _, db := range allDBs {
		if db.Engine == "s3" {
			results = append(results, db)
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{"data": results})
}

func (h *StorageHandler) Get(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	dbID, err := uuid.Parse(chi.URLParam(r, "dbID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid database id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	db, err := h.dbs.GetByID(r.Context(), dbID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "storage bucket not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	type storageResponse struct {
		domain.Database
		AWSAccessKey string `json:"aws_access_key"`
		AWSSecretKey string `json:"aws_secret_key"`
	}

	var accessKey, secretKey string
	if len(db.CredentialsEnc) > 0 {
		plain, err := crypto.Decrypt(db.CredentialsEnc, h.secretKey)
		if err == nil {
			var creds struct {
				AccessKey string `json:"aws_access_key"`
				SecretKey string `json:"aws_secret_key"`
			}
			if json.Unmarshal(plain, &creds) == nil {
				accessKey = creds.AccessKey
				secretKey = creds.SecretKey
			}
		}
	}

	respondJSON(w, http.StatusOK, storageResponse{
		Database:     *db,
		AWSAccessKey: accessKey,
		AWSSecretKey: secretKey,
	})
}

func (h *StorageHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	dbID, err := uuid.Parse(chi.URLParam(r, "dbID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid database id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	db, err := h.dbs.GetByID(r.Context(), dbID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "storage bucket not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	if err := h.dbs.Delete(r.Context(), dbID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete database record")
		return
	}

	if h.aws != nil {
		go h.deleteS3Bucket(db.DBName)
	}

	respondNoContent(w)
}

func (h *StorageHandler) Presign(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	dbID, err := uuid.Parse(chi.URLParam(r, "dbID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid database id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	db, err := h.dbs.GetByID(r.Context(), dbID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "storage bucket not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	var req struct {
		Key     string `json:"key"`
		Expires int    `json:"expires"` // in seconds
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.Key == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "key is required")
		return
	}
	if req.Expires <= 0 {
		req.Expires = 3600
	}

	if h.aws == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "AWS S3 client not available")
		return
	}

	presignClient := s3.NewPresignClient(h.aws.S3)
	presignedReq, err := presignClient.PresignGetObject(r.Context(), &s3.GetObjectInput{
		Bucket: aws.String(db.DBName),
		Key:    aws.String(req.Key),
	}, s3.WithPresignExpires(time.Duration(req.Expires)*time.Second))
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to presign request")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"url": presignedReq.URL,
	})
}

// Helpers
func (h *StorageHandler) provisionS3(db *domain.Database, bucketName string, public bool) {
	ctx := context.Background()
	logger := h.logger.With("db_id", db.ID, "bucket_name", bucketName)

	if h.aws == nil {
		logger.Warn("AWS S3 client not initialized; skipping S3 bucket creation")
		_ = h.dbs.UpdateStatus(ctx, db.ID, "failed", "s3.amazonaws.com", 443)
		return
	}

	_, err := h.aws.S3.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		logger.Error("failed to create S3 bucket", "error", err)
		_ = h.dbs.UpdateStatus(ctx, db.ID, "failed", "s3.amazonaws.com", 443)
		return
	}

	if public {
		// Disable public access block
		_, _ = h.aws.S3.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
			Bucket: aws.String(bucketName),
			PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
				BlockPublicAcls:       aws.Bool(false),
				IgnorePublicAcls:      aws.Bool(false),
				BlockPublicPolicy:     aws.Bool(false),
				RestrictPublicBuckets: aws.Bool(false),
			},
		})
		// Apply public read bucket policy
		policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":"PublicRead","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}]}`, bucketName)
		_, _ = h.aws.S3.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: aws.String(bucketName),
			Policy: aws.String(policy),
		})
		logger.Info("S3 bucket configured as public", "bucket", bucketName)
	}

	// Encrypt credentials (reusing active environment credentials)
	credsJSON, _ := json.Marshal(map[string]string{
		"aws_access_key": os.Getenv("AWS_ACCESS_KEY_ID"),
		"aws_secret_key": os.Getenv("AWS_SECRET_ACCESS_KEY"),
	})
	enc, err := crypto.Encrypt(credsJSON, h.secretKey)
	if err != nil {
		logger.Error("failed to encrypt credentials", "error", err)
		_ = h.dbs.UpdateStatus(ctx, db.ID, "failed", "s3.amazonaws.com", 443)
		return
	}

	// Update record
	_ = h.dbs.UpdateStatus(ctx, db.ID, "available", "s3.amazonaws.com", 443)
	_ = h.dbs.UpdateCredentials(ctx, db.ID, enc)
}

func (h *StorageHandler) deleteS3Bucket(bucketName string) {
	ctx := context.Background()
	_, err := h.aws.S3.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		h.logger.Error("failed to delete S3 bucket", "bucket", bucketName, "error", err)
	}
}
