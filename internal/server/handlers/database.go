package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
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
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

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

// Query executes a read-only SQL query against a postgres or mysql database.
// Route: POST /orgs/{orgID}/databases/{dbID}/query (or with projectID)
func (h *DatabaseHandler) Query(w http.ResponseWriter, r *http.Request) {
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

	if db.Engine != "postgres" && db.Engine != "mysql" {
		respondError(w, http.StatusBadRequest, "UNSUPPORTED_ENGINE", "SQL Explorer not supported for this engine")
		return
	}

	var body struct {
		SQL string `json:"sql"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.SQL) == "" {
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "sql field is required")
		return
	}

	// Reject mutating statements
	upperSQL := strings.ToUpper(body.SQL)
	forbidden := []string{"DROP", "TRUNCATE", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE", "GRANT", "REVOKE"}
	for _, kw := range forbidden {
		if strings.Contains(upperSQL, kw) {
			respondError(w, http.StatusBadRequest, "FORBIDDEN_STATEMENT", fmt.Sprintf("keyword %s is not allowed in SQL Explorer (read-only)", kw))
			return
		}
	}

	if db.Host == "" || db.Port == 0 || len(db.CredentialsEnc) == 0 {
		respondError(w, http.StatusBadRequest, "DB_NOT_READY", "database is not yet available")
		return
	}

	plain, err := crypto.Decrypt(db.CredentialsEnc, h.secretKey)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to decrypt credentials")
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(plain, &creds); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to parse credentials")
		return
	}

	var (
		driverName string
		dsn        string
	)
	switch db.Engine {
	case "postgres":
		driverName = "pgx"
		dsn = fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", creds.Username, creds.Password, db.Host, db.Port, db.DBName)
	case "mysql":
		driverName = "mysql"
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", creds.Username, creds.Password, db.Host, db.Port, db.DBName)
	}

	sqlDB, err := sql.Open(driverName, dsn)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "CONNECTION_ERROR", "failed to open database connection")
		return
	}
	defer sqlDB.Close()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	rows, err := sqlDB.QueryContext(ctx, body.SQL)
	if err != nil {
		respondError(w, http.StatusBadRequest, "QUERY_ERROR", err.Error())
		return
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to read columns")
		return
	}

	var resultRows [][]any
	for rows.Next() {
		if len(resultRows) >= 200 {
			break
		}
		vals := make([]any, len(columns))
		valPtrs := make([]any, len(columns))
		for i := range vals {
			valPtrs[i] = &vals[i]
		}
		if err := rows.Scan(valPtrs...); err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to scan row")
			return
		}
		// Convert []byte values to string for JSON serialisation
		row := make([]any, len(vals))
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				row[i] = string(b)
			} else {
				row[i] = v
			}
		}
		resultRows = append(resultRows, row)
	}
	if err := rows.Err(); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"columns":   columns,
		"rows":      resultRows,
		"row_count": len(resultRows),
	})
}

// --- shared create logic ---

func (h *DatabaseHandler) parseAndCreate(r *http.Request, orgID uuid.UUID, projectID *uuid.UUID) (*domain.Database, error) {
	var req struct {
		Name    string `json:"name"`
		Engine  string `json:"engine"`
		Version string `json:"version"`
		Tier    string `json:"tier"`
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

	tier := req.Tier
	if tier == "" {
		tier = "dev"
	}
	if tier != "dev" && tier != "prod" {
		return nil, fmt.Errorf("tier must be 'dev' or 'prod'")
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
		Tier:           tier,
		CredentialsEnc: []byte{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create database record")
	}

	if tier == "prod" {
		go h.provisionRDS(db)
	} else {
		go h.provisionDocker(db)
	}

	return db, nil
}

// --- RDS Aurora Serverless v2 provisioning ---

func (h *DatabaseHandler) provisionRDS(db *domain.Database) {
	ctx := context.Background()
	logger := h.logger.With("db_id", db.ID, "name", db.Name, "engine", db.Engine, "tier", "prod")

	if h.aws == nil || h.aws.RDS == nil || h.dbSubnetGroup == "" {
		logger.Warn("RDS client or subnet group not configured, falling back to Docker provisioning")
		h.provisionDocker(db)
		return
	}

	password, err := generatePassword(24)
	if err != nil {
		logger.Error("failed to generate password", "error", err)
		_ = h.dbs.UpdateStatus(ctx, db.ID, "failed", "", 0)
		return
	}

	clusterID := fmt.Sprintf("capsule-%s", db.ID.String())

	input := &rds.CreateDBClusterInput{
		DBClusterIdentifier: aws.String(clusterID),
		Engine:              aws.String("aurora-postgresql"),
		EngineMode:          aws.String("provisioned"),
		MasterUsername:      aws.String("capsuleadmin"),
		MasterUserPassword:  aws.String(password),
		DatabaseName:        aws.String(db.DBName),
		DBSubnetGroupName:   aws.String(h.dbSubnetGroup),
		ServerlessV2ScalingConfiguration: &rdstypes.ServerlessV2ScalingConfiguration{
			MinCapacity: aws.Float64(0.5),
			MaxCapacity: aws.Float64(8),
		},
	}
	if h.rdsSecurityGroupID != "" {
		input.VpcSecurityGroupIds = []string{h.rdsSecurityGroupID}
	}

	result, err := h.aws.RDS.CreateDBCluster(ctx, input)
	if err != nil {
		logger.Error("failed to create RDS cluster", "error", err)
		_ = h.dbs.UpdateStatus(ctx, db.ID, "failed", "", 0)
		return
	}

	clusterEndpoint := ""
	if result.DBCluster != nil && result.DBCluster.Endpoint != nil {
		clusterEndpoint = *result.DBCluster.Endpoint
	}

	// Poll until the cluster endpoint is available (up to 20 minutes)
	if clusterEndpoint == "" {
		for i := 0; i < 40; i++ {
			time.Sleep(30 * time.Second)
			desc, err := h.aws.RDS.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{
				DBClusterIdentifier: aws.String(clusterID),
			})
			if err != nil {
				logger.Warn("polling RDS cluster status failed", "error", err)
				continue
			}
			if len(desc.DBClusters) > 0 {
				c := desc.DBClusters[0]
				if c.Endpoint != nil && *c.Endpoint != "" {
					clusterEndpoint = *c.Endpoint
					break
				}
			}
		}
	}

	if clusterEndpoint == "" {
		logger.Error("RDS cluster endpoint still empty after polling")
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

	if err := h.dbs.UpdateStatus(ctx, db.ID, "available", clusterEndpoint, db.Port); err != nil {
		logger.Error("failed to update database status", "error", err)
		return
	}
	if err := h.dbs.UpdateCredentials(ctx, db.ID, enc); err != nil {
		logger.Error("failed to store credentials", "error", err)
	}

	logger.Info("RDS Aurora cluster provisioned", "cluster_id", clusterID, "endpoint", clusterEndpoint)
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
	case "graphql":
		return fmt.Sprintf("http://%s:%d/v1/graphql", h2, p2)
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
	case "graphql":
		return "hasura/graphql-engine:v2.40.0", []string{
			"HASURA_GRAPHQL_METADATA_DATABASE_URL=postgres://capsuleadmin:" + password + "@localhost:5432/hasura_metadata",
			"HASURA_GRAPHQL_ENABLE_CONSOLE=true",
			"HASURA_GRAPHQL_DEV_MODE=true",
			"HASURA_GRAPHQL_ENABLED_LOG_TYPES=startup,http-log,webhook-log,websocket-log,query-log",
		}
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
	case "postgres", "mysql", "mariadb", "redis", "mongodb", "cassandra", "clickhouse", "elasticsearch", "cockroachdb", "graphql":
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
	case "graphql":
		return 8080, "v2.40.0"
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
