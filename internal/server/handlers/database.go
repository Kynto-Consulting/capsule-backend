package handlers

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/pkg/awsclient"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

// DatabaseHandler handles managed database operations.
type DatabaseHandler struct {
	dbs                domain.DatabaseRepository
	orgs               domain.OrganizationRepository
	projects           domain.ProjectRepository
	aws                *awsclient.Clients
	secretKey          string
	dbSubnetGroup      string
	rdsSecurityGroupID string
	publicHost         string
	logger             *slog.Logger
}

// NewDatabaseHandler creates a DatabaseHandler.
func NewDatabaseHandler(
	dbs domain.DatabaseRepository,
	orgs domain.OrganizationRepository,
	projects domain.ProjectRepository,
	awsClients *awsclient.Clients,
	secretKey string,
	dbSubnetGroup string,
	rdsSecurityGroupID string,
	publicHost string,
	logger *slog.Logger,
) *DatabaseHandler {
	if publicHost == "" {
		publicHost = "13.218.92.228"
	}
	return &DatabaseHandler{
		dbs:                dbs,
		orgs:               orgs,
		projects:           projects,
		aws:                awsClients,
		secretKey:          secretKey,
		dbSubnetGroup:      dbSubnetGroup,
		rdsSecurityGroupID: rdsSecurityGroupID,
		publicHost:         publicHost,
		logger:             logger,
	}
}

// List returns all databases for a project.
func (h *DatabaseHandler) List(w http.ResponseWriter, r *http.Request) {
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

	dbs, err := h.dbs.ListByProject(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list databases")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"data": h.toResponseList(dbs)})
}

// Create provisions a new managed database.
func (h *DatabaseHandler) Create(w http.ResponseWriter, r *http.Request) {
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

	_ = user

	db, err := h.parseAndCreate(r, orgID, &projectID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	respondJSON(w, http.StatusCreated, h.toResponse(db))
}

// Get returns a single database with connection URL.
func (h *DatabaseHandler) Get(w http.ResponseWriter, r *http.Request) {
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
		respondError(w, http.StatusNotFound, "NOT_FOUND", "database not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, h.toResponse(db))
}

// Delete removes a database and its Docker container.
func (h *DatabaseHandler) Delete(w http.ResponseWriter, r *http.Request) {
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
		respondError(w, http.StatusNotFound, "NOT_FOUND", "database not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	_ = user

	if err := h.dbs.Delete(r.Context(), dbID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete database")
		return
	}

	go h.removeDockerContainer(db)

	respondNoContent(w)
}

// ListByOrg returns all databases for an org (including those not tied to a project).
func (h *DatabaseHandler) ListByOrg(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	dbs, err := h.dbs.ListByOrg(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list databases")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"data": h.toResponseList(dbs)})
}

// CreateOrgLevel provisions a database not tied to any project.
func (h *DatabaseHandler) CreateOrgLevel(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	_ = user

	db, err := h.parseAndCreate(r, orgID, nil)
	if err != nil {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	respondJSON(w, http.StatusCreated, h.toResponse(db))
}

// --- shared create logic ---

func (h *DatabaseHandler) parseAndCreate(r *http.Request, orgID uuid.UUID, projectID *uuid.UUID) (*domain.Database, error) {
	var req struct {
		Name    string `json:"name"`
		Engine  string `json:"engine"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, fmt.Errorf("invalid request body")
	}
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if !validEngine(req.Engine) {
		return nil, fmt.Errorf("unsupported engine")
	}

	port, dbVersion := engineDefaults(req.Engine)
	if req.Version != "" {
		dbVersion = req.Version
	}

	db, err := h.dbs.Create(r.Context(), &domain.Database{
		OrgID:          orgID,
		ProjectID:      projectID,
		Name:           req.Name,
		Engine:         req.Engine,
		Version:        dbVersion,
		Port:           port,
		DBName:         req.Name,
		Status:         "provisioning",
		CredentialsEnc: []byte{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create database record")
	}

	go h.provisionDocker(db)

	return db, nil
}

// --- Docker provisioning ---

func (h *DatabaseHandler) provisionDocker(db *domain.Database) {
	ctx := context.Background()
	logger := h.logger.With("db_id", db.ID, "name", db.Name, "engine", db.Engine)

	password, err := generatePassword(24)
	if err != nil {
		logger.Error("failed to generate password", "error", err)
		_ = h.dbs.UpdateStatus(ctx, db.ID, "failed", "", 0)
		return
	}

	image, envVars := dockerImageAndEnv(db.Engine, db.Version, db.DBName, password)
	containerName := fmt.Sprintf("capsule-db-%s", db.ID.String())
	containerPort := fmt.Sprintf("%d/tcp", db.Port)

	// Build docker run args
	args := []string{"run", "-d", "--name", containerName,
		"-p", fmt.Sprintf("0:%d", db.Port),
		"--restart", "unless-stopped",
	}
	for _, e := range envVars {
		args = append(args, "-e", e)
	}
	if db.Engine == "cockroachdb" {
		args = append(args, image, "start-single-node", "--insecure", "--advertise-addr=localhost")
	} else {
		args = append(args, image)
	}

	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		logger.Error("docker run failed", "error", err, "output", string(out))
		_ = h.dbs.UpdateStatus(ctx, db.ID, "failed", "", 0)
		return
	}
	containerID := strings.TrimSpace(string(out))

	// Wait a moment for container to start and port to bind
	time.Sleep(3 * time.Second)

	// Get the mapped host port
	portOut, err := exec.CommandContext(ctx, "docker", "port", containerID, containerPort).Output()
	if err != nil {
		logger.Error("docker port failed", "error", err)
		_ = h.dbs.UpdateStatus(ctx, db.ID, "failed", "", 0)
		return
	}

	// portOut format: "0.0.0.0:54321\n" or ":::54321\n"
	portStr := strings.TrimSpace(string(portOut))
	if idx := strings.LastIndex(portStr, ":"); idx >= 0 {
		portStr = portStr[idx+1:]
	}

	var hostPort int
	if _, err := fmt.Sscanf(portStr, "%d", &hostPort); err != nil || hostPort == 0 {
		logger.Error("could not parse host port", "raw", string(portOut))
		_ = h.dbs.UpdateStatus(ctx, db.ID, "failed", "", 0)
		return
	}

	// Store encrypted credentials
	credsJSON, _ := json.Marshal(map[string]string{
		"username": "capsuleadmin",
		"password": password,
	})
	enc, err := crypto.Encrypt(credsJSON, h.secretKey)
	if err != nil {
		logger.Error("failed to encrypt credentials", "error", err)
		_ = h.dbs.UpdateStatus(ctx, db.ID, "failed", "", 0)
		return
	}

	if err := h.dbs.UpdateStatus(ctx, db.ID, "available", h.publicHost, hostPort); err != nil {
		logger.Error("failed to update database status", "error", err)
		return
	}
	if err := h.dbs.UpdateCredentials(ctx, db.ID, enc); err != nil {
		logger.Error("failed to store credentials", "error", err)
	}

	logger.Info("database provisioned", "host", h.publicHost, "port", hostPort, "container", containerName)
}

func (h *DatabaseHandler) removeDockerContainer(db *domain.Database) {
	name := fmt.Sprintf("capsule-db-%s", db.ID.String())
	_ = exec.Command("docker", "stop", name).Run()
	_ = exec.Command("docker", "rm", name).Run()
}

// --- response helpers ---

type dbResponse struct {
	domain.Database
	ConnectionURL string `json:"connection_url"`
}

func (h *DatabaseHandler) toResponse(db *domain.Database) dbResponse {
	return dbResponse{Database: *db, ConnectionURL: h.buildConnectionURL(db)}
}

func (h *DatabaseHandler) toResponseList(dbs []*domain.Database) []dbResponse {
	out := make([]dbResponse, 0, len(dbs))
	for _, db := range dbs {
		out = append(out, h.toResponse(db))
	}
	return out
}

func (h *DatabaseHandler) buildConnectionURL(db *domain.Database) string {
	if len(db.CredentialsEnc) == 0 || db.Host == "" || db.Port == 0 {
		return ""
	}

	plain, err := crypto.Decrypt(db.CredentialsEnc, h.secretKey)
	if err != nil {
		return ""
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(plain, &creds); err != nil {
		return ""
	}

	h2, p2 := db.Host, db.Port
	switch db.Engine {
	case "postgres":
		return fmt.Sprintf("postgres://%s:%s@%s:%d/%s", creds.Username, creds.Password, h2, p2, db.DBName)
	case "mysql", "mariadb":
		return fmt.Sprintf("mysql://%s:%s@%s:%d/%s", creds.Username, creds.Password, h2, p2, db.DBName)
	case "redis":
		if creds.Password != "" {
			return fmt.Sprintf("redis://:%s@%s:%d", creds.Password, h2, p2)
		}
		return fmt.Sprintf("redis://%s:%d", h2, p2)
	case "mongodb":
		return fmt.Sprintf("mongodb://%s:%s@%s:%d/%s", creds.Username, creds.Password, h2, p2, db.DBName)
	case "cassandra":
		return fmt.Sprintf("cassandra://%s:%s@%s:%d", creds.Username, creds.Password, h2, p2)
	case "clickhouse":
		return fmt.Sprintf("clickhouse://%s:%s@%s:%d/%s", creds.Username, creds.Password, h2, p2, db.DBName)
	case "elasticsearch":
		return fmt.Sprintf("http://%s:%s@%s:%d", creds.Username, creds.Password, h2, p2)
	case "cockroachdb":
		return fmt.Sprintf("postgresql://%s:%s@%s:%d/%s?sslmode=disable", creds.Username, creds.Password, h2, p2, db.DBName)
	default:
		return fmt.Sprintf("%s://%s:%s@%s:%d/%s", db.Engine, creds.Username, creds.Password, h2, p2, db.DBName)
	}
}

// --- engine metadata ---

func dockerImageAndEnv(engine, version, dbName, password string) (image string, envVars []string) {
	switch engine {
	case "postgres":
		return fmt.Sprintf("postgres:%s", version), []string{
			"POSTGRES_USER=capsuleadmin",
			"POSTGRES_PASSWORD=" + password,
			"POSTGRES_DB=" + dbName,
		}
	case "mysql":
		return fmt.Sprintf("mysql:%s", version), []string{
			"MYSQL_ROOT_PASSWORD=" + password,
			"MYSQL_USER=capsuleadmin",
			"MYSQL_PASSWORD=" + password,
			"MYSQL_DATABASE=" + dbName,
		}
	case "mariadb":
		return fmt.Sprintf("mariadb:%s", version), []string{
			"MARIADB_ROOT_PASSWORD=" + password,
			"MARIADB_USER=capsuleadmin",
			"MARIADB_PASSWORD=" + password,
			"MARIADB_DATABASE=" + dbName,
		}
	case "redis":
		return fmt.Sprintf("redis:%s-alpine", version), []string{
			"REDIS_PASSWORD=" + password,
		}
	case "mongodb":
		return fmt.Sprintf("mongo:%s", version), []string{
			"MONGO_INITDB_ROOT_USERNAME=capsuleadmin",
			"MONGO_INITDB_ROOT_PASSWORD=" + password,
			"MONGO_INITDB_DATABASE=" + dbName,
		}
	case "cassandra":
		return fmt.Sprintf("cassandra:%s", version), []string{
			"CASSANDRA_USER=capsuleadmin",
			"CASSANDRA_PASSWORD=" + password,
		}
	case "clickhouse":
		return fmt.Sprintf("clickhouse/clickhouse-server:%s", version), []string{
			"CLICKHOUSE_USER=capsuleadmin",
			"CLICKHOUSE_PASSWORD=" + password,
			"CLICKHOUSE_DB=" + dbName,
		}
	case "elasticsearch":
		return fmt.Sprintf("elasticsearch:%s", version), []string{
			"discovery.type=single-node",
			"ELASTIC_PASSWORD=" + password,
			"xpack.security.enabled=true",
		}
	case "cockroachdb":
		return "cockroachdb/cockroach:latest", nil
	default:
		return fmt.Sprintf("postgres:%s", version), []string{
			"POSTGRES_USER=capsuleadmin",
			"POSTGRES_PASSWORD=" + password,
			"POSTGRES_DB=" + dbName,
		}
	}
}

func validEngine(e string) bool {
	switch e {
	case "postgres", "mysql", "mariadb", "redis", "mongodb", "cassandra", "clickhouse", "elasticsearch", "cockroachdb":
		return true
	}
	return false
}

func engineDefaults(e string) (port int, version string) {
	switch e {
	case "mysql", "mariadb":
		return 3306, "8.0"
	case "redis":
		return 6379, "7"
	case "mongodb":
		return 27017, "6.0"
	case "cassandra":
		return 9042, "4.1"
	case "clickhouse":
		return 8123, "24.3"
	case "elasticsearch":
		return 9200, "8.13.0"
	case "cockroachdb":
		return 26257, "latest"
	default: // postgres
		return 5432, "15"
	}
}

const passwordChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generatePassword(length int) (string, error) {
	buf := make([]byte, length)
	max := big.NewInt(int64(len(passwordChars)))
	for i := range buf {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("generating random byte: %w", err)
		}
		buf[i] = passwordChars[n.Int64()]
	}
	return string(buf), nil
}
