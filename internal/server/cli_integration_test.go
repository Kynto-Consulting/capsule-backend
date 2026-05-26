//go:build integration
// +build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func TestE2ECLIIntegration(t *testing.T) {
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

	// 4. Instantiate server and boot test server
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

	// 5. Compile Capsule CLI locally in an isolated temporary directory
	tempHome := t.TempDir()
	binaryName := "capsule_test"
	if runtime.GOOS == "windows" {
		binaryName = "capsule_test.exe"
	}
	binaryPath := filepath.Join(tempHome, binaryName)

	t.Log("Building local Capsule CLI binary...")
	cliDir, err := filepath.Abs("../../../cli")
	if err != nil {
		t.Fatalf("failed to find cli directory: %v", err)
	}

	buildCmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/capsule")
	buildCmd.Dir = cliDir
	var buildErr bytes.Buffer
	buildCmd.Stderr = &buildErr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("failed to compile CLI binary: %v. Stderr: %s", err, buildErr.String())
	}
	t.Logf("CLI compiled successfully at: %s", binaryPath)

	// 6. Setup isolated configuration directory
	capsuleConfigDir := filepath.Join(tempHome, ".capsule")
	if err := os.MkdirAll(capsuleConfigDir, 0700); err != nil {
		t.Fatalf("failed to create isolated config dir: %v", err)
	}

	// Write isolated config pointing to the httptest server initially
	configContent := fmt.Sprintf("api_url: %s\n", ts.URL)
	configPath := filepath.Join(capsuleConfigDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("failed to write isolated config file: %v", err)
	}

	// Helper to execute compiled CLI with duplicate-filtered environment variables and explicit api-url flags
	runCLI := func(stdinInput string, args ...string) (string, string, error) {
		defaultFlags := []string{"--api-url", ts.URL}
		fullArgs := append(args, defaultFlags...)

		cmd := exec.Command(binaryPath, fullArgs...)
		cmd.Dir = cliDir

		// Filter out duplicate home/profile keys to ensure absolute windows isolation
		var cleanEnv []string
		for _, env := range os.Environ() {
			k := strings.SplitN(env, "=", 2)[0]
			ku := strings.ToUpper(k)
			if ku == "USERPROFILE" || ku == "HOME" || ku == "HOMEDRIVE" || ku == "HOMEPATH" {
				continue
			}
			cleanEnv = append(cleanEnv, env)
		}
		cmd.Env = cleanEnv

		if runtime.GOOS == "windows" {
			cmd.Env = append(cmd.Env, "USERPROFILE="+tempHome)
			cmd.Env = append(cmd.Env, "HOME="+tempHome)
			cmd.Env = append(cmd.Env, "HOMEDRIVE=C:")
			cmd.Env = append(cmd.Env, "HOMEPATH="+strings.TrimPrefix(tempHome, "C:"))
		} else {
			cmd.Env = append(cmd.Env, "HOME="+tempHome)
		}

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if stdinInput != "" {
			cmd.Stdin = strings.NewReader(stdinInput)
		}

		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}

	// 7. PREPARATION: Register test user via API so we can login via CLI
	email := fmt.Sprintf("cli-integration-%d@capsule.dev", time.Now().UnixNano())
	password := "cli-secure-pass-123!"

	// Trigger onboarding status check to ensure settings are initialized
	statResp, err := ts.Client().Get(ts.URL + "/api/v1/auth/onboarding/status")
	if err != nil {
		t.Fatalf("failed to get onboarding status: %v", err)
	}
	var status struct {
		Saved  bool   `json:"saved"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(statResp.Body).Decode(&status); err != nil {
		statResp.Body.Close()
		t.Fatalf("failed to decode onboarding status: %v", err)
	}
	statResp.Body.Close()

	// Always fetch the actual global 2FA secret directly from the settings repo
	// to remain robust if onboarding was already completed by a concurrent or previous test.
	secret, err := settingsRepo.Get(ctx, "global_2fa_secret")
	if err != nil {
		t.Fatalf("failed to get global 2fa secret from settings repo: %v", err)
	}
	if secret == "" {
		t.Fatalf("global 2fa secret is empty in database")
	}

	// Generate the correct current 6-digit TOTP code
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate totp code: %v", err)
	}

	regBody, _ := json.Marshal(map[string]string{
		"email":           email,
		"password":        password,
		"name":            "CLI Tester",
		"onboarding_code": code,
	})
	regResp, err := ts.Client().Post(ts.URL+"/api/v1/auth/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatalf("failed to pre-register user: %v", err)
	}
	regResp.Body.Close()
	if regResp.StatusCode != http.StatusCreated {
		t.Fatalf("failed to register user: expected 201 Created, got %d", regResp.StatusCode)
	}

	// =========================================================================
	// CLI TEST SUITE RUNS
	// =========================================================================

	// A. AUTHENTICATION & LOGIN
	t.Run("CLI Login & Auth", func(t *testing.T) {
		stdout, stderr, err := runCLI("", "login", "--email", email, "--password", password)
		if err != nil {
			t.Fatalf("cli login failed: %v. Stderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, fmt.Sprintf("Logged in as %s", email)) {
			t.Fatalf("unexpected login success output: %s", stdout)
		}

		// Verify that whoami command works
		stdout, stderr, err = runCLI("", "whoami")
		if err != nil {
			t.Fatalf("cli whoami failed: %v. Stderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, email) {
			t.Fatalf("unexpected whoami output: %s", stdout)
		}
	})

	var orgID string
	var projectID string
	projectSlug := "cli-test-project"

	// B. ORGANIZATION CREATION & LISTING
	t.Run("CLI Orgs Management", func(t *testing.T) {
		orgSlug := fmt.Sprintf("cli-org-%d", time.Now().UnixNano())
		stdout, stderr, err := runCLI("", "orgs", "create", "--name", "CLI Organization", "--slug", orgSlug)
		if err != nil {
			t.Fatalf("cli orgs create failed: %v. Stderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "Created org") {
			t.Fatalf("unexpected orgs create output: %s", stdout)
		}

		// List organizations in JSON to retrieve ID
		stdout, stderr, err = runCLI("", "orgs", "list", "--output", "json")
		if err != nil {
			t.Fatalf("cli orgs list failed: %v. Stderr: %s", err, stderr)
		}

		type org struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		}
		var orgList []org
		if err := json.Unmarshal([]byte(stdout), &orgList); err != nil {
			t.Fatalf("failed to decode orgs JSON output: %v. Output: %s", err, stdout)
		}

		for _, o := range orgList {
			if o.Slug == orgSlug {
				orgID = o.ID
				break
			}
		}

		if orgID == "" {
			t.Fatalf("could not find created org with slug %s in org list: %s", orgSlug, stdout)
		}
	})

	// C. PROJECT CREATION & LISTING
	t.Run("CLI Projects Management", func(t *testing.T) {
		stdout, stderr, err := runCLI("", "projects", "create", "--org", orgID, "--name", "CLI Project", "--slug", projectSlug, "--runtime", "go")
		if err != nil {
			t.Fatalf("cli projects create failed: %v. Stderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "Created project") {
			t.Fatalf("unexpected projects create output: %s", stdout)
		}

		// List projects to retrieve Project ID
		stdout, stderr, err = runCLI("", "projects", "list", "--org", orgID, "--output", "json")
		if err != nil {
			t.Fatalf("cli projects list failed: %v. Stderr: %s", err, stderr)
		}

		type project struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		}
		var projList []project
		if err := json.Unmarshal([]byte(stdout), &projList); err != nil {
			t.Fatalf("failed to decode projects JSON output: %v. Output: %s", err, stdout)
		}

		for _, p := range projList {
			if p.Slug == projectSlug {
				projectID = p.ID
				break
			}
		}

		if projectID == "" {
			t.Fatalf("could not find created project with slug %s in project list: %s", projectSlug, stdout)
		}
	})

	// D. STORAGE PROVISIONING & CONFIRMATION BYPASS
	t.Run("CLI Storage Provisioning (S3)", func(t *testing.T) {
		// First verify cancellation works when writing "no"
		stdout, stderr, err := runCLI("n\n", "storage", "create", "--org", orgID, "--project", projectID, "--name", "cli-s3-cancel")
		if err != nil {
			t.Fatalf("cli storage create command error: %v. Stderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "Provisioning cancelled") {
			t.Fatalf("expected cancelled output, got: %s", stdout)
		}

		// Trigger actual creation by piping "y"
		stdout, stderr, err = runCLI("y\n", "storage", "create", "--org", orgID, "--project", projectID, "--name", "cli-s3-bucket")
		if err != nil {
			t.Fatalf("cli storage create failed: %v. Stderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "Created S3 Bucket") {
			t.Fatalf("unexpected storage create output: %s", stdout)
		}

		// Verify cost estimates are explicitly printed
		if !strings.Contains(stdout, "Cost Estimate") || !strings.Contains(stdout, "Annual:") {
			t.Fatalf("expected cost estimate card in output, got: %s", stdout)
		}

		// List storage
		stdout, stderr, err = runCLI("", "storage", "list", "--org", orgID, "--project", projectID, "--output", "json")
		if err != nil {
			t.Fatalf("cli storage list failed: %v. Stderr: %s", err, stderr)
		}

		type storage struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		var storageList []storage
		if err := json.Unmarshal([]byte(stdout), &storageList); err != nil {
			t.Fatalf("failed to decode storage list JSON: %v. Output: %s", err, stdout)
		}
		if len(storageList) == 0 {
			t.Fatal("expected at least 1 provisioned storage bucket in list")
		}
	})

	// E. EMAIL INTEGRATION (SES)
	t.Run("CLI SES Email Configuration", func(t *testing.T) {
		stdout, stderr, err := runCLI("", "email", "setup", "--org", orgID, "--project", projectID, "--domain", "cli-domain.dev")
		if err != nil {
			t.Fatalf("cli email setup failed: %v. Stderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "Email Setup Initiated") {
			t.Fatalf("unexpected email setup output: %s", stdout)
		}

		// Verify SES cost breakdown is shown
		if !strings.Contains(stdout, "Cost Estimate") || !strings.Contains(stdout, "Amazon SES Outbound") {
			t.Fatalf("expected SES cost preview in output, got: %s", stdout)
		}

		// Check Stats
		stdout, stderr, err = runCLI("", "email", "stats", "--org", orgID, "--project", projectID, "--output", "json")
		if err != nil {
			t.Fatalf("cli email stats failed: %v. Stderr: %s", err, stderr)
		}
		var stats struct {
			Sent      int `json:"sent"`
			Delivered int `json:"delivered"`
		}
		if err := json.Unmarshal([]byte(stdout), &stats); err != nil {
			t.Fatalf("failed to parse email stats JSON: %v. Output: %s", err, stdout)
		}
	})

	// F. BEDROCK AI KEY MANAGEMENT & UTILITIES
	t.Run("CLI Bedrock AI & Key Management", func(t *testing.T) {
		// Generate Bedrock API Key
		stdout, stderr, err := runCLI("", "ai", "keys", "create", "--name", "CLI Integration Key")
		if err != nil {
			t.Fatalf("cli ai keys create failed: %v. Stderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "API Key generated successfully") || !strings.Contains(stdout, "csk_live_") {
			t.Fatalf("unexpected API key generation output: %s", stdout)
		}

		// Retrieve key ID
		var keyID string
		lines := strings.Split(stdout, "\n")
		for _, line := range lines {
			if strings.Contains(line, "KeyID:") {
				parts := strings.Split(line, "KeyID:")
				if len(parts) == 2 {
					keyID = strings.TrimSpace(parts[1])
				}
			}
		}

		if keyID == "" {
			t.Fatalf("failed to parse API Key ID from output: %s", stdout)
		}

		// List Keys
		stdout, stderr, err = runCLI("", "ai", "keys", "list", "--output", "json")
		if err != nil {
			t.Fatalf("cli ai keys list failed: %v. Stderr: %s", err, stderr)
		}

		type apiKey struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		var keysList []apiKey
		if err := json.Unmarshal([]byte(stdout), &keysList); err != nil {
			t.Fatalf("failed to decode API keys JSON: %v. Output: %s", err, stdout)
		}

		found := false
		for _, k := range keysList {
			if k.ID == keyID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("created API key %s not found in listed keys: %s", keyID, stdout)
		}

		// Dockerfile Builder (Case-insensitive robust matching)
		stdout, stderr, err = runCLI("", "ai", "dockerfile", "--runtime", "go")
		if err != nil {
			t.Fatalf("cli ai dockerfile failed: %v. Stderr: %s", err, stderr)
		}
		lowerDF := strings.ToLower(stdout)
		if !strings.Contains(lowerDF, "from golang") && !strings.Contains(lowerDF, "cmd") {
			t.Fatalf("unexpected dockerfile content: %s", stdout)
		}

		// Cost Optimizer (Case-insensitive robust matching)
		stdout, stderr, err = runCLI("", "ai", "optimize-costs", "--project", projectID)
		if err != nil {
			t.Fatalf("cli ai optimize-costs failed: %v. Stderr: %s", err, stderr)
		}
		lowerOpt := strings.ToLower(stdout)
		if !strings.Contains(lowerOpt, "optimization") && !strings.Contains(lowerOpt, "recommendation") {
			t.Fatalf("unexpected cost recommendations: %s", stdout)
		}

		// Revoke Key
		stdout, stderr, err = runCLI("", "ai", "keys", "revoke", keyID)
		if err != nil {
			t.Fatalf("cli ai keys revoke failed: %v. Stderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, fmt.Sprintf("Successfully revoked API key %s", keyID)) {
			t.Fatalf("unexpected revoke output: %s", stdout)
		}
	})

	// G. INFRASTRUCTURE PRICING PREVIEWS
	t.Run("CLI Cost Previews Calculator", func(t *testing.T) {
		stdout, stderr, err := runCLI("", "pricing", "estimate", "--resource", "rds", "--engine", "postgres", "--class", "db.t3.medium", "--storage", "100")
		if err != nil {
			t.Fatalf("cli pricing estimate failed: %v. Stderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "Cost Estimate") || !strings.Contains(stdout, "RDS") {
			t.Fatalf("unexpected pricing estimate output: %s", stdout)
		}

		// Run EC2 estimation
		stdout, stderr, err = runCLI("", "pricing", "estimate", "--resource", "ec2", "--type", "t3.medium", "--count", "3")
		if err != nil {
			t.Fatalf("cli pricing estimate ec2 failed: %v. Stderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "EC2") || !strings.Contains(stdout, "Total:") {
			t.Fatalf("unexpected pricing estimate output: %s", stdout)
		}
	})

	// H. AUTO-SCALING CONFIGURATION
	t.Run("CLI Global Auto-Scaling Settings", func(t *testing.T) {
		stdout, stderr, err := runCLI("", "scale", projectSlug, "--org", orgID, "--replicas", "4", "--min", "2", "--max", "8", "--cpu-threshold", "70")
		if err != nil {
			t.Fatalf("cli scale failed: %v. Stderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, fmt.Sprintf("Successfully updated scaling configurations for %s", projectSlug)) {
			t.Fatalf("unexpected scale output: %s", stdout)
		}
		if !strings.Contains(stdout, "Replicas: 4") || !strings.Contains(stdout, "bounds [2 - 8]") {
			t.Fatalf("expected updated bounds in scale output, got: %s", stdout)
		}
	})

	// I. DEPLOYMENTS
	t.Run("CLI Deployments normal/serverless", func(t *testing.T) {
		stdout, stderr, err := runCLI("", "deploy", "--org", orgID, "--project", projectID, "--sha", "b2c3d4e5")
		if err != nil {
			t.Fatalf("cli deploy failed: %v. Stderr: %s", err, stderr)
		}
		if !strings.Contains(stdout, "Deployment triggered") {
			t.Fatalf("unexpected deploy output: %s", stdout)
		}
	})
}
