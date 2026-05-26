//go:build integration
// +build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"log/slog"

	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/service"
	"github.com/kynto/capsule/backend/pkg/awsclient"
	"github.com/kynto/capsule/backend/pkg/totp"
)

// loadEnv manually parses the .env file located at backend/.env or ../../.env
func loadEnv() error {
	paths := []string{
		".env",
		"../.env",
		"../../.env",
		"d:\\Github\\Kynto\\capsule\\backend\\.env",
	}

	var content []byte
	var err error
	for _, p := range paths {
		content, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("failed to read .env file from any search path: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			// Strip quotes if any
			if strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"") {
				v = strings.Trim(v, "\"")
			}
			if strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'") {
				v = strings.Trim(v, "'")
			}
			os.Setenv(k, v)
		}
	}
	return nil
}

func TestE2ECapsuleIntegration(t *testing.T) {
	// 1. Load environment variables
	if err := loadEnv(); err != nil {
		t.Logf("Warning loading .env: %v. Using system environment.", err)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("failed to load configuration: %v", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 2. Connect to the Neon DB
	pool, err := repository.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		t.Fatalf("failed to connect to Neon PostgreSQL database: %v", err)
	}
	defer pool.Close()

	// 3. Initialize Repositories and Services
	userRepo := repository.NewUserRepository(pool)
	orgRepo := repository.NewOrgRepository(pool)
	projRepo := repository.NewProjectRepository(pool)
	envVarRepo := repository.NewEnvVarRepository(pool, cfg.SecretKey)
	deploymentRepo := repository.NewDeploymentRepository(pool)
	dbRepo := repository.NewDatabaseRepository(pool)
	domainRepo := repository.NewDomainRepository(pool)
	apiTokenRepo := repository.NewAPITokenRepository(pool)
	settingsRepo := repository.NewSettingsRepository(pool)
	authSvc := service.NewAuthService(userRepo, settingsRepo, cfg.SecretKey, cfg.JWTAccessTTL, cfg.JWTRefreshTTL, logger)

	var cacheStore domain.CacheStore
	redisCache, err := repository.NewRedisCache(cfg.RedisURL)
	if err != nil {
		t.Logf("Redis unavailable; cache store integration test will use memory fallback or be disabled. Error: %v", err)
	} else {
		cacheStore = redisCache
	}

	awsCtx, awsCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer awsCancel()
	awsClients, err := awsclient.New(awsCtx, cfg.AWSRegion,
		os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), cfg.AWSAccountID)
	if err != nil {
		t.Logf("AWS clients unavailable for integration: %v", err)
		awsClients = nil
	}

	// 4. Instantiate router and boot test server
	router := newRouter(cfg, logger, "integration-test", Deps{
		AuthSvc:            authSvc,
		OrgRepo:            orgRepo,
		ProjRepo:           projRepo,
		EnvVarRepo:         envVarRepo,
		DeploymentRepo:     deploymentRepo,
		CacheStore:         cacheStore,
		DatabaseRepo:       dbRepo,
		DomainRepo:         domainRepo,
		APITokenRepo:       apiTokenRepo,
		AWSClients:         awsClients,
		ALBDNSName:         cfg.ALBDNSName,
		DBSubnetGroup:      cfg.DBSubnetGroup,
		RDSSecurityGroupID: cfg.RDSSecurityGroupID,
		SecretKey:          cfg.SecretKey,
	})

	ts := httptest.NewServer(router)
	defer ts.Close()

	client := ts.Client()

	// 5. Test Helper Request Methods
	var jwtToken string

	doReq := func(method, path string, body interface{}, expectStatus int) []byte {
		var bodyReader io.Reader
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("failed to marshal request body: %v", err)
			}
			bodyReader = bytes.NewReader(b)
		}

		req, err := http.NewRequest(method, ts.URL+path, bodyReader)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		req.Header.Set("Content-Type", "application/json")
		if jwtToken != "" {
			req.Header.Set("Authorization", "Bearer "+jwtToken)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to execute request: %v", err)
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		if resp.StatusCode != expectStatus {
			t.Fatalf("expected status %d for %s %s, got %d. Body: %s", expectStatus, method, path, resp.StatusCode, string(respBody))
		}

		return respBody
	}

	// Test Suite Executions

	// A. USER AUTHENTICATION
	email := fmt.Sprintf("integration-%d@capsule.dev", time.Now().UnixNano())
	password := "integration-secure-pass-123!"

	t.Run("Auth - Register and Login", func(t *testing.T) {
		// Trigger onboarding status check to ensure settings are initialized
		statRespBytes := doReq("GET", "/api/v1/auth/onboarding/status", nil, http.StatusOK)
		var status struct {
			Saved  bool   `json:"saved"`
			Secret string `json:"secret"`
		}
		if err := json.Unmarshal(statRespBytes, &status); err != nil {
			t.Fatalf("failed to decode onboarding status: %v", err)
		}

		// Always fetch the actual global 2FA secret directly from the settings repo
		// to remain robust if onboarding was already completed by a concurrent or previous test.
		secret, err := settingsRepo.Get(ctx, "global_2fa_secret")
		if err != nil {
			t.Fatalf("failed to get global 2fa secret from settings repo: %v", err)
		}
		if secret == "" {
			t.Fatalf("global 2fa secret is empty in database")
		}

		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("failed to generate onboarding code: %v", err)
		}

		// Register
		regBody := map[string]string{
			"email":           email,
			"password":        password,
			"name":            "Integration Tester",
			"onboarding_code": code,
		}
		doReq("POST", "/api/v1/auth/register", regBody, http.StatusCreated)

		// Login
		loginBody := map[string]string{
			"email":    email,
			"password": password,
		}
		loginRespBytes := doReq("POST", "/api/v1/auth/login", loginBody, http.StatusOK)

		var loginData struct {
			Tokens struct {
				AccessToken string `json:"access_token"`
			} `json:"tokens"`
		}
		if err := json.Unmarshal(loginRespBytes, &loginData); err != nil {
			t.Fatalf("failed to parse login response: %v", err)
		}

		if loginData.Tokens.AccessToken == "" {
			t.Fatal("login response AccessToken is empty")
		}
		jwtToken = loginData.Tokens.AccessToken

		// Validate Auth Me
		meBytes := doReq("GET", "/api/v1/auth/me", nil, http.StatusOK)
		var meData struct {
			Email string `json:"email"`
		}
		json.Unmarshal(meBytes, &meData)
		if meData.Email != email {
			t.Fatalf("auth/me returned wrong email: expected %s, got %s", email, meData.Email)
		}
	})

	// B. ORGANIZATION & PROJECT CREATION
	var orgID string
	var projectID string
	projectSlug := "test-integration-project"

	t.Run("Create Organization and Project", func(t *testing.T) {
		orgBody := map[string]string{
			"name": "Integration testing organization",
			"slug": fmt.Sprintf("integration-org-%d", time.Now().UnixNano()),
		}
		orgRespBytes := doReq("POST", "/api/v1/orgs", orgBody, http.StatusCreated)

		var orgData struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(orgRespBytes, &orgData); err != nil {
			t.Fatalf("failed to parse organization response: %v", err)
		}
		orgID = orgData.ID

		projBody := map[string]interface{}{
			"name":           "Integration Test Project",
			"slug":           projectSlug,
			"runtime":        "node",
			"build_strategy": "dockerfile",
			"serverless":     false,
		}
		projRespBytes := doReq("POST", "/api/v1/orgs/"+orgID+"/projects", projBody, http.StatusCreated)

		var projData struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(projRespBytes, &projData); err != nil {
			t.Fatalf("failed to parse project response: %v", err)
		}
		projectID = projData.ID
	})

	// C. ENVIRONMENT VARIABLES INJECTION AND SCOPES
	t.Run("Environment Variables Scopes", func(t *testing.T) {
		// Set runtime secret env var
		setBody := map[string]interface{}{
			"key":       "DATABASE_URL",
			"value":     "postgresql://neondb_owner:pass@ep-sweet-bird.internal/neondb",
			"is_secret": true,
			"scope":     "runtime",
		}
		doReq("PUT", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/env", setBody, http.StatusOK)

		// Set build-time env var
		setBuildBody := map[string]interface{}{
			"key":       "NEXT_PUBLIC_API_URL",
			"value":     "https://api.capsule.dev",
			"is_secret": false,
			"scope":     "build",
		}
		doReq("PUT", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/env", setBuildBody, http.StatusOK)

		// List env vars
		listBytes := doReq("GET", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/env", nil, http.StatusOK)
		var envList []struct {
			Key      string `json:"key"`
			Value    string `json:"value"`
			IsSecret bool   `json:"is_secret"`
			Scope    string `json:"scope"`
		}
		if err := json.Unmarshal(listBytes, &envList); err != nil {
			t.Fatalf("failed to parse env list: %v", err)
		}

		if len(envList) < 2 {
			t.Fatalf("expected at least 2 environment variables, got %d", len(envList))
		}

		foundRuntime := false
		foundBuild := false
		for _, ev := range envList {
			if ev.Key == "DATABASE_URL" {
				foundRuntime = true
				if ev.Scope != "runtime" {
					t.Fatalf("expected scope runtime, got %s", ev.Scope)
				}
				if !ev.IsSecret {
					t.Fatal("expected database url to be flagged as secret")
				}
			}
			if ev.Key == "NEXT_PUBLIC_API_URL" {
				foundBuild = true
				if ev.Scope != "build" {
					t.Fatalf("expected scope build, got %s", ev.Scope)
				}
			}
		}

		if !foundRuntime || !foundBuild {
			t.Fatal("failed to find both set environment variables in scopes list")
		}
	})

	// D. CLOUD PROVISIONERS (POSTGRES, REDIS, MONGODB, S3)
	t.Run("Multi-Engine Database and Storage Provisioning", func(t *testing.T) {
		// Postgres RDS
		pgBody := map[string]interface{}{
			"name":       "integration-rds-pg",
			"engine":     "postgres",
			"version":    "15",
			"serverless": true,
		}
		doReq("POST", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/databases", pgBody, http.StatusCreated)

		// Redis Cache
		redisBody := map[string]interface{}{
			"name":    "integration-cache-redis",
			"engine":  "redis",
			"version": "7.0",
		}
		doReq("POST", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/databases", redisBody, http.StatusCreated)

		// MongoDB (DocumentDB)
		mongoBody := map[string]interface{}{
			"name":    "integration-docdb-mongo",
			"engine":  "mongodb",
			"version": "5.0",
		}
		doReq("POST", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/databases", mongoBody, http.StatusCreated)

		// S3 Bucket Storage
		s3Body := map[string]interface{}{
			"name": "integration-s3-bucket",
		}
		s3Resp := doReq("POST", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/storage", s3Body, http.StatusCreated)
		var s3Bucket struct {
			ID     string `json:"id"`
			Engine string `json:"engine"`
			Status string `json:"status"`
		}
		json.Unmarshal(s3Resp, &s3Bucket)
		if s3Bucket.Engine != "s3" {
			t.Fatalf("expected storage engine to be s3, got %s", s3Bucket.Engine)
		}

		// List storage
		storageListBytes := doReq("GET", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/storage", nil, http.StatusOK)
		var storageList struct {
			Data []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"data"`
		}
		json.Unmarshal(storageListBytes, &storageList)
		if len(storageList.Data) == 0 {
			t.Fatal("expected at least 1 provisioned storage bucket")
		}
	})

	// E. MAILING SYSTEM SETUP & TEST
	t.Run("SES Email Mailing Setup", func(t *testing.T) {
		setupBody := map[string]string{
			"domain": "capsule.dev",
		}
		setupResp := doReq("POST", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/email/setup", setupBody, http.StatusCreated)
		var emailStatus struct {
			Engine string `json:"engine"`
			Status string `json:"status"`
		}
		json.Unmarshal(setupResp, &emailStatus)
		if emailStatus.Engine != "ses" {
			t.Fatalf("expected engine to be ses, got %s", emailStatus.Engine)
		}

		// Status check
		doReq("GET", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/email/status", nil, http.StatusOK)

		// Stats
		doReq("GET", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/email/stats", nil, http.StatusOK)
	})

	// F. AI BEDROCK API TOKEN GENERATION AND ASSISTANT PROXIES
	t.Run("Bedrock AI Integration", func(t *testing.T) {
		// Generate API Key
		keyBody := map[string]interface{}{
			"name": "Integration Test Key",
		}
		keyRespBytes := doReq("POST", "/api/v1/ai/keys", keyBody, http.StatusCreated)
		var apiKey struct {
			ID       string `json:"id"`
			RawToken string `json:"key"`
		}
		if err := json.Unmarshal(keyRespBytes, &apiKey); err != nil {
			t.Fatalf("failed to parse API Key response: %v", err)
		}

		if !strings.HasPrefix(apiKey.RawToken, "csk_live_") {
			t.Fatalf("expected API Key prefix csk_live_, got %s", apiKey.RawToken)
		}

		// AI cost optimizer
		costOptBody := map[string]interface{}{
			"project_id": projectID,
		}
		doReq("POST", "/api/v1/ai/optimize-costs", costOptBody, http.StatusOK)

		// Dockerfile builder
		dfBody := map[string]interface{}{
			"runtime": "go",
		}
		doReq("POST", "/api/v1/ai/dockerfile", dfBody, http.StatusOK)

		// Explain Failure
		failBody := map[string]interface{}{
			"deployment_id": projectID,
		}
		doReq("POST", "/api/v1/ai/explain-failure", failBody, http.StatusOK)

		// Chat Proxy
		chatBody := map[string]interface{}{
			"messages": []map[string]string{
				{"role": "user", "content": "How do I optimize auto-scaling on ECS?"},
			},
		}
		chatBytes, _ := json.Marshal(chatBody)

		// Test using the newly generated Bedrock API Key
		req, err := http.NewRequest("POST", ts.URL+"/api/v1/ai/chat", bytes.NewReader(chatBytes))
		if err != nil {
			t.Fatalf("failed to create proxy chat request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+apiKey.RawToken)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to run proxy chat request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("expected 200 OK, 503 service unavailable or 500 internal server error (bedrock invocation error), got %d", resp.StatusCode)
		}

		// Delete / Revoke API Key
		doReq("DELETE", "/api/v1/ai/keys/"+apiKey.ID, nil, http.StatusNoContent)
	})

	// G. PRICING PREVIEWS
	t.Run("Infrastructure Pricing Previews", func(t *testing.T) {
		pricingBody := map[string]interface{}{
			"resource_type": "rds",
			"config": map[string]interface{}{
				"instance_class": "db.t3.medium",
				"storage_gb":     50,
			},
		}
		doReq("POST", "/api/v1/pricing/estimate", pricingBody, http.StatusOK)
	})

	// H. SCALING & GLOBAL AUTO-SCALING CONFIGURATION
	t.Run("Horizontal and Auto-scaling Bounds", func(t *testing.T) {
		scaleBody := map[string]interface{}{
			"replicas": 3,
			"labels": map[string]interface{}{
				"min_replicas":  2,
				"max_replicas":  10,
				"cpu_threshold": 80,
			},
		}
		// Patch project config
		patchBytes := doReq("PATCH", "/api/v1/orgs/"+orgID+"/projects/"+projectID, scaleBody, http.StatusOK)
		var projResp struct {
			Replicas int      `json:"replicas"`
			Labels   []string `json:"labels"`
		}
		json.Unmarshal(patchBytes, &projResp)
		if projResp.Replicas != 3 {
			t.Fatalf("expected replicas count to scale to 3, got %d", projResp.Replicas)
		}
	})

	// I. DEPLOYMENTS (EC2 AND SERVERLESS / LAMBDA)
	t.Run("Trigger EC2 Normal and Serverless Deployments", func(t *testing.T) {
		// Normal deploy
		normalBody := map[string]interface{}{
			"git_sha":        "a1b2c3d4",
			"version":        "v1.0.0-prod",
			"build_strategy": "dockerfile",
			"container_port": 8080,
		}
		normalResp := doReq("POST", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/deployments", normalBody, http.StatusCreated)
		var normalDep struct {
			ID string `json:"id"`
		}
		json.Unmarshal(normalResp, &normalDep)

		// List deployments
		listBytes := doReq("GET", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/deployments", nil, http.StatusOK)
		var listResp struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		json.Unmarshal(listBytes, &listResp)
		if len(listResp.Data) == 0 {
			t.Fatal("expected at least 1 registered deployment record")
		}

		// Fetch deploy logs
		doReq("GET", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/deployments/"+normalDep.ID+"/logs", nil, http.StatusOK)

		// Cancel deploy
		doReq("POST", "/api/v1/orgs/"+orgID+"/projects/"+projectID+"/deployments/"+normalDep.ID+"/cancel", nil, http.StatusNoContent)
	})
}
