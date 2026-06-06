package service

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

// maxRetries is the number of times a deployment will be retried before marking it permanently failed.
const maxRetries = 3

// FargateConfig holds the AWS infrastructure parameters needed to launch
// ECS Fargate tasks and wire them to an ALB.
type FargateConfig struct {
	Cluster         string // ECS cluster ARN or name
	Subnets         []string
	SecurityGroup   string
	ExecutionRoleARN string
	ALBListenerARN  string
	VpcID           string
	AppsDomain      string // e.g. "apps.example.com"
	ECRRegistry     string // e.g. "123456789012.dkr.ecr.us-east-1.amazonaws.com"
}

// IsConfigured returns true when all required Fargate fields are non-empty.
func (f *FargateConfig) IsConfigured() bool {
	return f.Cluster != "" && len(f.Subnets) > 0 && f.SecurityGroup != "" &&
		f.ALBListenerARN != "" && f.VpcID != ""
}

// DeployWorker polls for queued deployments and executes them.
type DeployWorker struct {
	deployments domain.DeploymentRepository
	pool        *pgxpool.Pool
	aws         *awsclient.Clients
	bucket      string
	fargate     FargateConfig
	logger      *slog.Logger
	wg          sync.WaitGroup
}

// NewDeployWorker creates a new deployment worker.
func NewDeployWorker(
	deployments domain.DeploymentRepository,
	pool *pgxpool.Pool,
	aws *awsclient.Clients,
	bucket string,
	fargate FargateConfig,
	logger *slog.Logger,
) *DeployWorker {
	return &DeployWorker{
		deployments: deployments,
		pool:        pool,
		aws:         aws,
		bucket:      bucket,
		fargate:     fargate,
		logger:      logger,
	}
}

// Run starts the polling loop. It blocks until ctx is cancelled, then waits for
// any in-flight deployment to finish before returning.
func (w *DeployWorker) Run(ctx context.Context) {
	w.logger.Info("deploy worker started")

	const (
		minPoll = 1 * time.Second
		maxPoll = 30 * time.Second
	)
	backoff := minPoll

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("deploy worker: context cancelled, waiting for in-flight deployments")
			w.wg.Wait()
			w.logger.Info("deploy worker stopped")
			return
		default:
		}

		found := w.processNext(ctx)
		if found {
			backoff = minPoll // reset on work found
		} else {
			// Exponential backoff when idle: 1s → 2s → 4s → 8s → 16s → 30s
			backoff *= 2
			if backoff > maxPoll {
				backoff = maxPoll
			}
		}

		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
	}
}

// processNext picks the oldest queued deployment using SKIP LOCKED and processes it.
// Returns true if a deployment was found and dispatched.
func (w *DeployWorker) processNext(ctx context.Context) bool {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		w.logger.Error("deploy worker: begin tx", "error", err)
		return false
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var (
		id            uuid.UUID
		projectID     uuid.UUID
		sourceKey     *string
		buildStrategy string
		retryCount    int
	)
	err = tx.QueryRow(ctx, `
		SELECT id, project_id, source_key, build_strategy, COALESCE(retry_count, 0)
		FROM deployments
		WHERE status = 'queued'
		ORDER BY created_at
		LIMIT 1
		FOR UPDATE SKIP LOCKED
	`).Scan(&id, &projectID, &sourceKey, &buildStrategy, &retryCount)
	if err != nil {
		// No rows available — nothing to do.
		return false
	}

	// Too many retries → mark permanently failed without processing.
	if retryCount >= maxRetries {
		_, _ = tx.Exec(ctx, `UPDATE deployments SET status = 'failed' WHERE id = $1`, id)
		_ = tx.Commit(ctx)
		w.logger.Warn("deploy worker: deployment exceeded max retries, marking failed",
			"id", id, "retries", retryCount)
		_ = w.deployments.AppendLog(ctx, &domain.BuildLog{
			DeploymentID: id,
			Level:        "error",
			Message:      fmt.Sprintf("Deployment failed after %d retries", retryCount),
		})
		return true
	}

	if err := tx.Commit(ctx); err != nil {
		w.logger.Error("deploy worker: commit tx", "error", err)
		return false
	}

	w.logger.Info("deploy worker: picked deployment", "id", id, "project_id", projectID, "retry", retryCount)

	// Track in-flight so graceful shutdown waits.
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.runDeployment(ctx, id, projectID, sourceKey, buildStrategy)
	}()
	return true
}

func (w *DeployWorker) appendLog(ctx context.Context, id uuid.UUID, msg string) {
	_ = w.deployments.AppendLog(ctx, &domain.BuildLog{
		DeploymentID: id,
		Level:        "info",
		Message:      msg,
	})
}

func (w *DeployWorker) failDeployment(ctx context.Context, id uuid.UUID, msg string, err error) {
	full := msg
	if err != nil {
		full = fmt.Sprintf("%s: %v", msg, err)
	}
	w.logger.Error("deploy worker: deployment failed", "id", id, "error", full)
	_ = w.deployments.AppendLog(ctx, &domain.BuildLog{
		DeploymentID: id,
		Level:        "error",
		Message:      full,
	})
	_ = w.deployments.UpdateStatus(ctx, id, "failed")
}

// runDeployment executes a single deployment end-to-end, dispatching by build strategy.
func (w *DeployWorker) runDeployment(ctx context.Context, id, projectID uuid.UUID, sourceKey *string, buildStrategy string) {
	// --- transition to building ---
	if err := w.deployments.UpdateStatus(ctx, id, "building"); err != nil {
		w.failDeployment(ctx, id, "failed to update status to building", err)
		return
	}
	w.appendLog(ctx, id, "Starting build...")

	// short tag for container/image name — first 12 chars of project UUID (no dashes)
	shortID := strings.ReplaceAll(projectID.String(), "-", "")[:12]
	imageName := "capsule-app-" + shortID

	// --- prepare build directory ---
	buildDir, err := os.MkdirTemp("", "capsule-build-*")
	if err != nil {
		w.failDeployment(ctx, id, "failed to create temp build dir", err)
		return
	}
	defer os.RemoveAll(buildDir)

	if sourceKey != nil && *sourceKey != "" {
		w.appendLog(ctx, id, fmt.Sprintf("Downloading source from S3: %s", *sourceKey))
		if err := w.downloadAndExtract(ctx, *sourceKey, buildDir); err != nil {
			w.failDeployment(ctx, id, "failed to download/extract source", err)
			return
		}
		w.appendLog(ctx, id, "Source extracted successfully")
	} else {
		w.appendLog(ctx, id, "No source key provided, using generated Dockerfile")
	}

	// --- find an available host port in range 20000-29999 (deterministic from project ID) ---
	shortBytes := []byte(projectID.String())
	portOffset := 0
	for _, b := range shortBytes {
		portOffset = (portOffset*31 + int(b)) % 10000
	}
	hostPort := 20000 + portOffset

	// --- dispatch by build strategy ---
	switch buildStrategy {
	case "lambda":
		w.runLambdaDeploy(ctx, id, projectID, buildDir)
	case "static":
		w.runStaticDeploy(ctx, id, projectID, buildDir)
	case "docker":
		// Explicit docker-on-EC2 (local dev / fallback).
		w.runDockerDeploy(ctx, id, projectID, buildDir, imageName, hostPort)
	default:
		// "fargate" or empty — use ECS Fargate when configured, else fall back to local Docker.
		if w.aws != nil && w.fargate.IsConfigured() {
			w.runFargateDeploy(ctx, id, projectID, buildDir, imageName)
		} else {
			w.runDockerDeploy(ctx, id, projectID, buildDir, imageName, hostPort)
		}
	}
}

// detectExposePort reads a Dockerfile and returns the first EXPOSE port.
// Falls back to 3000 if none found.
func detectExposePort(dockerfilePath string) int {
	f, err := os.Open(dockerfilePath)
	if err != nil {
		return 3000
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "EXPOSE ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				// Strip /tcp or /udp suffix
				portStr := strings.Split(parts[1], "/")[0]
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
					return p
				}
			}
		}
	}
	return 3000
}

// runDockerDeploy handles the docker build + run flow.
func (w *DeployWorker) runDockerDeploy(ctx context.Context, id, projectID uuid.UUID, buildDir, imageName string, hostPort int) {
	// --- ensure Dockerfile exists ---
	dockerfilePath := filepath.Join(buildDir, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		w.appendLog(ctx, id, "No Dockerfile found, generating default")
		if err := w.writeDefaultDockerfile(buildDir); err != nil {
			w.failDeployment(ctx, id, "failed to write default Dockerfile", err)
			return
		}
	}

	// --- docker build ---
	w.appendLog(ctx, id, fmt.Sprintf("Building image: %s", imageName))
	buildCmd := exec.CommandContext(ctx, "docker", "build", "-t", imageName, ".")
	buildCmd.Dir = buildDir
	buildOut, err := buildCmd.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(buildOut)), "\n") {
		if line != "" {
			w.appendLog(ctx, id, line)
		}
	}
	if err != nil {
		w.failDeployment(ctx, id, "docker build failed", err)
		return
	}

	// --- transition to deploying ---
	if err := w.deployments.UpdateStatus(ctx, id, "deploying"); err != nil {
		w.failDeployment(ctx, id, "failed to update status to deploying", err)
		return
	}
	w.appendLog(ctx, id, "Deploying container...")

	// --- detect container port from Dockerfile ---
	containerPort := detectExposePort(dockerfilePath)
	w.appendLog(ctx, id, fmt.Sprintf("Detected container port: %d", containerPort))

	// --- stop and remove old container (keep volume) ---
	rmCmd := exec.CommandContext(ctx, "docker", "rm", "-f", imageName)
	_ = rmCmd.Run()

	// --- ensure named volume exists for persistent data ---
	// Volume survives redeploys; mounted at /data inside the container.
	// Users store databases, uploads, or any state there.
	volumeName := "capsule-data-" + projectID.String()
	volCmd := exec.CommandContext(ctx, "docker", "volume", "create", volumeName)
	if volOut, volErr := volCmd.CombinedOutput(); volErr != nil {
		w.appendLog(ctx, id, fmt.Sprintf("Warning: could not create volume %s: %s", volumeName, string(volOut)))
	} else {
		w.appendLog(ctx, id, fmt.Sprintf("Persistent volume: %s → /data", volumeName))
	}

	// --- fetch project env vars from DB ---
	envPairsDocker, envErr := w.fetchEnvVarsForDocker(ctx, projectID)
	if envErr != nil {
		w.appendLog(ctx, id, fmt.Sprintf("Warning: could not load env vars: %v", envErr))
	} else {
		w.appendLog(ctx, id, fmt.Sprintf("Injecting %d env vars", len(envPairsDocker)))
	}

	// --- start new container ---
	// Build args: docker run -d --name X --restart ... -e K=V ... -p ... -v ... image
	runArgs := []string{"run", "-d",
		"--name", imageName,
		"--restart", "unless-stopped",
		"-e", fmt.Sprintf("PORT=%d", containerPort),
	}
	for _, kv := range envPairsDocker {
		runArgs = append(runArgs, "-e", kv)
	}
	runArgs = append(runArgs,
		"-p", fmt.Sprintf("%d:%d", hostPort, containerPort),
		"-v", fmt.Sprintf("%s:/data", volumeName),
		imageName,
	)
	runCmd := exec.CommandContext(ctx, "docker", runArgs...)
	runOut, err := runCmd.CombinedOutput()
	if err != nil {
		w.failDeployment(ctx, id, fmt.Sprintf("docker run failed: %s", string(runOut)), err)
		return
	}

	containerID := strings.TrimSpace(string(runOut))
	w.appendLog(ctx, id, fmt.Sprintf("Container started: %s (port %d)", containerID, hostPort))

	// Connect deployed container to backend network so proxy can reach it
	networkName := "capsule-prod_capsule-net"
	netCmd := exec.CommandContext(ctx, "docker", "network", "connect", networkName, imageName)
	if netOut, netErr := netCmd.CombinedOutput(); netErr != nil {
		w.logger.Warn("deploy worker: could not connect to backend network (proxy disabled)",
			"id", id, "error", string(netOut))
	} else {
		w.appendLog(ctx, id, "Connected to backend network")
	}

	// --- store host port ---
	if err := w.deployments.UpdateHostPort(ctx, id, hostPort); err != nil {
		w.logger.Warn("deploy worker: failed to store host port", "id", id, "error", err)
	}

	// --- success ---
	if err := w.deployments.UpdateStatus(ctx, id, "success"); err != nil {
		w.logger.Error("deploy worker: failed to set success status", "id", id, "error", err)
	}
	w.appendLog(ctx, id, "Deployment completed successfully")
	w.logger.Info("deploy worker: deployment succeeded", "id", id, "image", imageName)
}

// runFargateDeploy builds the image, pushes to ECR, registers an ECS task definition,
// creates or updates an ECS Fargate service, and wires it to the ALB.
func (w *DeployWorker) runFargateDeploy(ctx context.Context, id, projectID uuid.UUID, buildDir, imageName string) {
	fc := w.fargate
	shortID := strings.ReplaceAll(projectID.String(), "-", "")[:12]
	ecrRepo := "capsule-apps/" + shortID

	// ── 1. Ensure Dockerfile ────────────────────────────────────────────────
	dockerfilePath := filepath.Join(buildDir, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		w.appendLog(ctx, id, "No Dockerfile found, generating default")
		if err := w.writeDefaultDockerfile(buildDir); err != nil {
			w.failDeployment(ctx, id, "failed to write default Dockerfile", err)
			return
		}
	}
	containerPort := detectExposePort(dockerfilePath)
	w.appendLog(ctx, id, fmt.Sprintf("Detected container port: %d", containerPort))

	// ── 2. Ensure ECR repository ────────────────────────────────────────────
	w.appendLog(ctx, id, fmt.Sprintf("Ensuring ECR repository: %s", ecrRepo))
	repoURI, err := w.ensureECRRepo(ctx, ecrRepo)
	if err != nil {
		w.failDeployment(ctx, id, "failed to ensure ECR repo", err)
		return
	}

	// ── 3. docker build ─────────────────────────────────────────────────────
	imageTag := id.String()[:8]
	imageURI := fmt.Sprintf("%s:%s", repoURI, imageTag)
	w.appendLog(ctx, id, fmt.Sprintf("Building image: %s", imageURI))
	buildCmd := exec.CommandContext(ctx, "docker", "build",
		"--platform", "linux/amd64",
		"-t", imageURI, ".")
	buildCmd.Dir = buildDir
	buildOut, err := buildCmd.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(buildOut)), "\n") {
		if line != "" {
			w.appendLog(ctx, id, line)
		}
	}
	if err != nil {
		w.failDeployment(ctx, id, "docker build failed", err)
		return
	}

	// ── 4. ECR auth + docker push ────────────────────────────────────────────
	w.appendLog(ctx, id, "Authenticating to ECR...")
	authOut, err := w.aws.ECR.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		w.failDeployment(ctx, id, "failed to get ECR auth token", err)
		return
	}
	if len(authOut.AuthorizationData) == 0 {
		w.failDeployment(ctx, id, "ECR returned empty auth data", nil)
		return
	}
	tokenDecoded, err := base64.StdEncoding.DecodeString(*authOut.AuthorizationData[0].AuthorizationToken)
	if err != nil {
		w.failDeployment(ctx, id, "failed to decode ECR token", err)
		return
	}
	parts := strings.SplitN(string(tokenDecoded), ":", 2)
	if len(parts) != 2 {
		w.failDeployment(ctx, id, "malformed ECR token", nil)
		return
	}
	loginCmd := exec.CommandContext(ctx, "docker", "login",
		"--username", parts[0], "--password-stdin",
		fmt.Sprintf("https://%s", fc.ECRRegistry))
	loginCmd.Stdin = strings.NewReader(parts[1])
	if loginOut, err := loginCmd.CombinedOutput(); err != nil {
		w.failDeployment(ctx, id, fmt.Sprintf("docker login failed: %s", string(loginOut)), err)
		return
	}

	w.appendLog(ctx, id, "Pushing image to ECR...")
	pushCmd := exec.CommandContext(ctx, "docker", "push", imageURI)
	pushOut, err := pushCmd.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(pushOut)), "\n") {
		if line != "" {
			w.appendLog(ctx, id, line)
		}
	}
	if err != nil {
		w.failDeployment(ctx, id, "docker push failed", err)
		return
	}

	// ── 5. Transition to deploying ───────────────────────────────────────────
	if err := w.deployments.UpdateStatus(ctx, id, "deploying"); err != nil {
		w.failDeployment(ctx, id, "failed to update status to deploying", err)
		return
	}
	w.appendLog(ctx, id, "Deploying to ECS Fargate...")

	// ── 6. Fetch project env vars for task definition ─────────────────────────
	envPairs, err := w.fetchEnvVarsForTask(ctx, projectID)
	if err != nil {
		w.logger.Warn("deploy worker fargate: could not fetch env vars", "id", id, "error", err)
		envPairs = nil // non-fatal
	}

	// ── 7. Register ECS task definition ─────────────────────────────────────
	taskDefARN, err := w.registerECSTaskDef(ctx, imageName, imageURI, containerPort, envPairs)
	if err != nil {
		w.failDeployment(ctx, id, "failed to register ECS task definition", err)
		return
	}
	w.appendLog(ctx, id, fmt.Sprintf("Task definition registered: %s", taskDefARN))

	// ── 8. Create ALB target group ───────────────────────────────────────────
	tgARN, err := w.ensureTargetGroup(ctx, imageName, containerPort)
	if err != nil {
		w.failDeployment(ctx, id, "failed to create ALB target group", err)
		return
	}
	w.appendLog(ctx, id, fmt.Sprintf("Target group ready: %s", tgARN))

	// ── 9. Create or update ECS service ──────────────────────────────────────
	serviceARN, err := w.upsertECSService(ctx, imageName, taskDefARN, tgARN, containerPort)
	if err != nil {
		w.failDeployment(ctx, id, "failed to upsert ECS service", err)
		return
	}
	w.appendLog(ctx, id, fmt.Sprintf("ECS service ready: %s", serviceARN))

	// ── 10. ALB listener rule ─────────────────────────────────────────────────
	slug := imageName // "capsule-app-<shortID>" — reuse as subdomain base
	appURL := fmt.Sprintf("https://%s.%s", strings.TrimPrefix(slug, "capsule-app-"), fc.AppsDomain)
	if fc.AppsDomain == "" {
		// Fallback: expose via ALB DNS directly (no subdomain routing)
		appURL = fmt.Sprintf("http://%s", fc.Cluster) // cluster name as placeholder
	}
	if err := w.upsertALBListenerRule(ctx, tgARN, shortID+"."+fc.AppsDomain, shortID); err != nil {
		// Non-fatal — app still runs, just no ALB rule yet
		w.logger.Warn("deploy worker fargate: failed to set ALB listener rule", "id", id, "error", err)
	} else {
		w.appendLog(ctx, id, fmt.Sprintf("ALB listener rule set for %s", appURL))
	}

	// ── 11. Store results ────────────────────────────────────────────────────
	if err := w.deployments.UpdateECSInfo(ctx, id, serviceARN, taskDefARN, appURL); err != nil {
		w.logger.Warn("deploy worker fargate: failed to store ECS info", "id", id, "error", err)
	}
	if err := w.deployments.UpdateStatus(ctx, id, "success"); err != nil {
		w.logger.Error("deploy worker fargate: failed to set success status", "id", id, "error", err)
	}
	w.appendLog(ctx, id, fmt.Sprintf("Deployment completed: %s", appURL))
	w.logger.Info("deploy worker fargate: deployment succeeded", "id", id, "url", appURL)
}

// ── ECS / ALB helpers ────────────────────────────────────────────────────────

// ensureECRRepo creates the ECR repo if it doesn't exist and returns the repository URI.
func (w *DeployWorker) ensureECRRepo(ctx context.Context, name string) (string, error) {
	out, err := w.aws.ECR.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
		RepositoryNames: []string{name},
	})
	if err == nil && len(out.Repositories) > 0 {
		return *out.Repositories[0].RepositoryUri, nil
	}
	created, err := w.aws.ECR.CreateRepository(ctx, &ecr.CreateRepositoryInput{
		RepositoryName: aws.String(name),
	})
	if err != nil {
		return "", fmt.Errorf("create ECR repo: %w", err)
	}
	return *created.Repository.RepositoryUri, nil
}

// fetchEnvVarsForDocker loads env vars from the DB as "KEY=VALUE" strings for docker run -e.
func (w *DeployWorker) fetchEnvVarsForDocker(ctx context.Context, projectID uuid.UUID) ([]string, error) {
	rows, err := w.pool.Query(ctx,
		`SELECT key, value FROM env_vars WHERE project_id = $1 AND (scope = 'runtime' OR scope = 'both') ORDER BY key`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pairs []string
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		pairs = append(pairs, k+"="+v)
	}
	return pairs, nil
}

// fetchEnvVarsForTask loads env vars from the DB for use in the ECS task definition.
func (w *DeployWorker) fetchEnvVarsForTask(ctx context.Context, projectID uuid.UUID) ([]ecstypes.KeyValuePair, error) {
	rows, err := w.pool.Query(ctx,
		`SELECT key, value FROM env_vars WHERE project_id = $1 AND (scope = 'runtime' OR scope = 'both')`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pairs []ecstypes.KeyValuePair
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		pairs = append(pairs, ecstypes.KeyValuePair{
			Name:  aws.String(k),
			Value: aws.String(v),
		})
	}
	return pairs, nil
}

// registerECSTaskDef registers a new ECS task definition revision and returns its ARN.
func (w *DeployWorker) registerECSTaskDef(ctx context.Context, family, imageURI string, containerPort int, envVars []ecstypes.KeyValuePair) (string, error) {
	fc := w.fargate
	logGroup := "/capsule/apps/" + family

	input := &ecs.RegisterTaskDefinitionInput{
		Family:                  aws.String(family),
		NetworkMode:             ecstypes.NetworkModeAwsvpc,
		RequiresCompatibilities: []ecstypes.Compatibility{ecstypes.CompatibilityFargate},
		Cpu:                     aws.String("256"),
		Memory:                  aws.String("512"),
		ExecutionRoleArn:        aws.String(fc.ExecutionRoleARN),
		ContainerDefinitions: []ecstypes.ContainerDefinition{
			{
				Name:      aws.String("app"),
				Image:     aws.String(imageURI),
				Essential: aws.Bool(true),
				PortMappings: []ecstypes.PortMapping{
					{
						ContainerPort: aws.Int32(int32(containerPort)),
						Protocol:      ecstypes.TransportProtocolTcp,
					},
				},
				Environment: envVars,
				LogConfiguration: &ecstypes.LogConfiguration{
					LogDriver: ecstypes.LogDriverAwslogs,
					Options: map[string]string{
						"awslogs-group":         logGroup,
						"awslogs-region":        w.aws.Region,
						"awslogs-stream-prefix": "app",
						"awslogs-create-group":  "true",
					},
				},
			},
		},
	}

	out, err := w.aws.ECS.RegisterTaskDefinition(ctx, input)
	if err != nil {
		return "", fmt.Errorf("register task definition: %w", err)
	}
	return *out.TaskDefinition.TaskDefinitionArn, nil
}

// ensureTargetGroup creates (or reuses) an ALB IP-type target group for the Fargate task.
func (w *DeployWorker) ensureTargetGroup(ctx context.Context, name string, port int) (string, error) {
	fc := w.fargate

	// Check if TG already exists by name
	existing, err := w.aws.ELBV2.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{
		Names: []string{name},
	})
	if err == nil && len(existing.TargetGroups) > 0 {
		return *existing.TargetGroups[0].TargetGroupArn, nil
	}

	out, err := w.aws.ELBV2.CreateTargetGroup(ctx, &elbv2.CreateTargetGroupInput{
		Name:       aws.String(name),
		Protocol:   elbv2types.ProtocolEnumHttp,
		Port:       aws.Int32(int32(port)),
		VpcId:      aws.String(fc.VpcID),
		TargetType: elbv2types.TargetTypeEnumIp,
		HealthCheckPath:     aws.String("/health"),
		HealthCheckProtocol: elbv2types.ProtocolEnumHttp,
	})
	if err != nil {
		return "", fmt.Errorf("create target group: %w", err)
	}
	return *out.TargetGroups[0].TargetGroupArn, nil
}

// upsertECSService creates the ECS service if it doesn't exist, or updates it to the new task def.
func (w *DeployWorker) upsertECSService(ctx context.Context, serviceName, taskDefARN, tgARN string, containerPort int) (string, error) {
	fc := w.fargate
	netCfg := &ecstypes.NetworkConfiguration{
		AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{
			Subnets:        fc.Subnets,
			SecurityGroups: []string{fc.SecurityGroup},
			AssignPublicIp: ecstypes.AssignPublicIpEnabled,
		},
	}

	// Try to update an existing service first
	updateOut, err := w.aws.ECS.UpdateService(ctx, &ecs.UpdateServiceInput{
		Cluster:              aws.String(fc.Cluster),
		Service:              aws.String(serviceName),
		TaskDefinition:       aws.String(taskDefARN),
		DesiredCount:         aws.Int32(1),
		NetworkConfiguration: netCfg,
		ForceNewDeployment:   true,
	})
	if err == nil {
		return *updateOut.Service.ServiceArn, nil
	}

	// Service doesn't exist — create it
	createOut, err := w.aws.ECS.CreateService(ctx, &ecs.CreateServiceInput{
		Cluster:        aws.String(fc.Cluster),
		ServiceName:    aws.String(serviceName),
		TaskDefinition: aws.String(taskDefARN),
		DesiredCount:   aws.Int32(1),
		LaunchType:     ecstypes.LaunchTypeFargate,
		NetworkConfiguration: netCfg,
		LoadBalancers: []ecstypes.LoadBalancer{
			{
				TargetGroupArn: aws.String(tgARN),
				ContainerName:  aws.String("app"),
				ContainerPort:  aws.Int32(int32(containerPort)),
			},
		},
		DeploymentConfiguration: &ecstypes.DeploymentConfiguration{
			MinimumHealthyPercent: aws.Int32(0),
			MaximumPercent:        aws.Int32(200),
		},
	})
	if err != nil {
		return "", fmt.Errorf("create ECS service: %w", err)
	}
	return *createOut.Service.ServiceArn, nil
}

// upsertALBListenerRule creates or updates an ALB listener host-header rule
// that forwards <subdomain>.<domain> traffic to the given target group.
func (w *DeployWorker) upsertALBListenerRule(ctx context.Context, tgARN, hostHeader, priority string) error {
	// Convert shortID (hex) to a numeric priority in 1-50000.
	// Use sum of bytes mod 49000 + 1000 to avoid collisions with the default rule (priority 50000).
	var prioVal int32 = 1000
	for _, b := range []byte(priority) {
		prioVal = (prioVal*31 + int32(b)) % 49000
	}
	prioVal += 1000

	// Check if a rule for this host header already exists
	rulesOut, err := w.aws.ELBV2.DescribeRules(ctx, &elbv2.DescribeRulesInput{
		ListenerArn: aws.String(w.fargate.ALBListenerARN),
	})
	if err != nil {
		return fmt.Errorf("describe ALB rules: %w", err)
	}
	for _, rule := range rulesOut.Rules {
		for _, cond := range rule.Conditions {
			if aws.ToString(cond.Field) == "host-header" {
				for _, v := range cond.Values {
					if v == hostHeader {
						// Rule exists — update target group
						_, err := w.aws.ELBV2.ModifyRule(ctx, &elbv2.ModifyRuleInput{
							RuleArn: rule.RuleArn,
							Actions: []elbv2types.Action{
								{Type: elbv2types.ActionTypeEnumForward, TargetGroupArn: aws.String(tgARN)},
							},
						})
						return err
					}
				}
			}
		}
	}

	// Create new rule
	_, err = w.aws.ELBV2.CreateRule(ctx, &elbv2.CreateRuleInput{
		ListenerArn: aws.String(w.fargate.ALBListenerARN),
		Priority:    aws.Int32(prioVal),
		Conditions: []elbv2types.RuleCondition{
			{
				Field:  aws.String("host-header"),
				Values: []string{hostHeader},
			},
		},
		Actions: []elbv2types.Action{
			{Type: elbv2types.ActionTypeEnumForward, TargetGroupArn: aws.String(tgARN)},
		},
	})
	if err != nil {
		return fmt.Errorf("create ALB rule: %w", err)
	}
	return nil
}

// runLambdaDeploy routes to container image deploy (if Dockerfile present) or zip deploy.
func (w *DeployWorker) runLambdaDeploy(ctx context.Context, id, projectID uuid.UUID, buildDir string) {
	if _, err := os.Stat(filepath.Join(buildDir, "Dockerfile")); err == nil {
		w.runLambdaContainerDeploy(ctx, id, projectID, buildDir)
		return
	}
	w.runLambdaZipDeploy(ctx, id, projectID, buildDir)
}

// runLambdaContainerDeploy builds a Docker image, pushes to ECR, and deploys as a Lambda container image.
// The image should include the AWS Lambda Web Adapter extension for HTTP bridging.
func (w *DeployWorker) runLambdaContainerDeploy(ctx context.Context, id, projectID uuid.UUID, buildDir string) {
	shortID := strings.ReplaceAll(projectID.String(), "-", "")[:12]
	functionName := "capsule-" + shortID
	repoName := "capsule-apps/" + shortID
	registry := w.aws.Account + ".dkr.ecr." + w.aws.Region + ".amazonaws.com"
	imageURI := registry + "/" + repoName + ":latest"

	w.appendLog(ctx, id, "Building Lambda container image (ECR)...")

	// Ensure ECR repository exists
	_, err := w.aws.ECR.CreateRepository(ctx, &ecr.CreateRepositoryInput{
		RepositoryName: aws.String(repoName),
	})
	// Ignore AlreadyExistsException
	if err != nil && !strings.Contains(err.Error(), "RepositoryAlreadyExistsException") {
		w.failDeployment(ctx, id, "creating ECR repository", err)
		return
	}

	// ECR login via SDK (no aws-cli needed — works inside Docker container with instance role)
	authOut, err := w.aws.ECR.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		w.failDeployment(ctx, id, "ECR GetAuthorizationToken failed", err)
		return
	}
	if len(authOut.AuthorizationData) == 0 {
		w.failDeployment(ctx, id, "ECR GetAuthorizationToken returned no data", nil)
		return
	}
	// Token is base64-encoded "AWS:{password}"
	rawToken := aws.ToString(authOut.AuthorizationData[0].AuthorizationToken)
	decoded, err := base64.StdEncoding.DecodeString(rawToken)
	if err != nil {
		w.failDeployment(ctx, id, "decoding ECR auth token", err)
		return
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		w.failDeployment(ctx, id, "unexpected ECR auth token format", nil)
		return
	}
	ecrUser, ecrPass := parts[0], parts[1]
	loginCmd := exec.CommandContext(ctx, "docker", "login",
		"--username", ecrUser,
		"--password-stdin",
		registry,
	)
	loginCmd.Stdin = strings.NewReader(ecrPass)
	if out, err := loginCmd.CombinedOutput(); err != nil {
		w.failDeployment(ctx, id, "docker login ECR failed: "+string(out), err)
		return
	}
	w.appendLog(ctx, id, "ECR login successful")

	// docker build (linux/amd64 — Lambda runs on x86)
	w.appendLog(ctx, id, fmt.Sprintf("Building image: %s", imageURI))
	buildCmd := exec.CommandContext(ctx, "docker", "build",
		"--platform", "linux/amd64",
		"-t", imageURI, ".")
	buildCmd.Dir = buildDir
	buildOut, err := buildCmd.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(buildOut)), "\n") {
		if line != "" {
			w.appendLog(ctx, id, line)
		}
	}
	if err != nil {
		w.failDeployment(ctx, id, "docker build failed", err)
		return
	}

	// docker push
	w.appendLog(ctx, id, "Pushing image to ECR...")
	pushCmd := exec.CommandContext(ctx, "docker", "push", imageURI)
	pushOut, err := pushCmd.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(pushOut)), "\n") {
		if line != "" {
			w.appendLog(ctx, id, line)
		}
	}
	if err != nil {
		w.failDeployment(ctx, id, "docker push failed", err)
		return
	}

	if err := w.deployments.UpdateStatus(ctx, id, "deploying"); err != nil {
		w.failDeployment(ctx, id, "updating status", err)
		return
	}

	role := "arn:aws:iam::" + w.aws.Account + ":role/capsule-lambda-role"
	lambdaClient := w.aws.Lambda

	// Try update first (function already exists)
	_, err = lambdaClient.UpdateFunctionCode(ctx, &lambda.UpdateFunctionCodeInput{
		FunctionName: aws.String(functionName),
		ImageUri:     aws.String(imageURI),
	})
	if err != nil {
		// Create new image-based function
		_, err = lambdaClient.CreateFunction(ctx, &lambda.CreateFunctionInput{
			FunctionName: aws.String(functionName),
			Role:         aws.String(role),
			PackageType:  lambdatypes.PackageTypeImage,
			Code:         &lambdatypes.FunctionCode{ImageUri: aws.String(imageURI)},
			Timeout:      aws.Int32(30),
			MemorySize:   aws.Int32(512),
		})
		if err != nil {
			w.failDeployment(ctx, id, "creating lambda function", err)
			return
		}
	}

	w.appendLog(ctx, id, fmt.Sprintf("Lambda container function deployed: %s", functionName))
	if err := w.deployments.UpdateStatus(ctx, id, "success"); err != nil {
		w.logger.Error("deploy worker: failed to set success status", "id", id, "error", err)
	}
	w.appendLog(ctx, id, "Lambda container deployment completed successfully")
	w.logger.Info("deploy worker: lambda container deployment succeeded", "id", id, "function", functionName)
}

// runLambdaZipDeploy builds and deploys a Lambda function as a zip package (no Dockerfile).
func (w *DeployWorker) runLambdaZipDeploy(ctx context.Context, id, projectID uuid.UUID, buildDir string) {
	functionName := "capsule-" + strings.ReplaceAll(projectID.String(), "-", "")[:12]

	w.appendLog(ctx, id, "Building Lambda function (zip)...")

	// Detect runtime
	runtime := lambdatypes.RuntimeProvidedal2023
	var buildCmd *exec.Cmd

	if _, err := os.Stat(filepath.Join(buildDir, "go.mod")); err == nil {
		w.appendLog(ctx, id, "Detected Go runtime")
		buildCmd = exec.CommandContext(ctx, "sh", "-c",
			"cd "+buildDir+" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bootstrap .")
		runtime = lambdatypes.RuntimeProvidedal2023
	} else if _, err := os.Stat(filepath.Join(buildDir, "package.json")); err == nil {
		w.appendLog(ctx, id, "Detected Node.js runtime")
		runtime = lambdatypes.RuntimeNodejs20x
		buildCmd = exec.CommandContext(ctx, "sh", "-c",
			"cd "+buildDir+" && npm install --omit=dev")
	} else {
		w.appendLog(ctx, id, "Detected generic runtime")
	}

	if buildCmd != nil {
		if out, err := buildCmd.CombinedOutput(); err != nil {
			w.failDeployment(ctx, id, "lambda build failed: "+string(out), err)
			return
		}
	}

	// Create ZIP
	zipPath := filepath.Join(buildDir, "function.zip")
	zipCmd := exec.CommandContext(ctx, "sh", "-c",
		"cd "+buildDir+" && zip -r function.zip . -x '*.zip'")
	if out, err := zipCmd.CombinedOutput(); err != nil {
		w.failDeployment(ctx, id, "zip failed: "+string(out), err)
		return
	}

	zipData, err := os.ReadFile(zipPath)
	if err != nil {
		w.failDeployment(ctx, id, "reading zip", err)
		return
	}

	w.appendLog(ctx, id, fmt.Sprintf("Deploying to Lambda: %s", functionName))

	if err := w.deployments.UpdateStatus(ctx, id, "deploying"); err != nil {
		w.failDeployment(ctx, id, "updating status", err)
		return
	}

	lambdaClient := w.aws.Lambda

	// Try update first, then create
	_, err = lambdaClient.UpdateFunctionCode(ctx, &lambda.UpdateFunctionCodeInput{
		FunctionName: &functionName,
		ZipFile:      zipData,
	})
	if err != nil {
		// Function doesn't exist, create it
		role := "arn:aws:iam::" + w.aws.Account + ":role/capsule-lambda-role"
		handler := "bootstrap"
		if runtime == lambdatypes.RuntimeNodejs20x {
			handler = "index.handler"
		}
		_, err = lambdaClient.CreateFunction(ctx, &lambda.CreateFunctionInput{
			FunctionName: &functionName,
			Runtime:      runtime,
			Role:         &role,
			Handler:      &handler,
			Code:         &lambdatypes.FunctionCode{ZipFile: zipData},
			Timeout:      aws.Int32(30),
			MemorySize:   aws.Int32(256),
		})
		if err != nil {
			w.failDeployment(ctx, id, "creating lambda function", err)
			return
		}
	}

	// Create/get Function URL
	urlConfig, err := lambdaClient.GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{
		FunctionName: &functionName,
	})

	var functionURL string
	if err != nil {
		// Create URL
		authType := lambdatypes.FunctionUrlAuthTypeNone
		result, err2 := lambdaClient.CreateFunctionUrlConfig(ctx, &lambda.CreateFunctionUrlConfigInput{
			FunctionName: &functionName,
			AuthType:     authType,
		})
		if err2 != nil {
			w.failDeployment(ctx, id, "creating function URL", err2)
			return
		}
		functionURL = *result.FunctionUrl
		// Allow public unauthenticated invocation via Function URL
		_, _ = lambdaClient.AddPermission(ctx, &lambda.AddPermissionInput{
			FunctionName:        &functionName,
			StatementId:         aws.String("AllowPublicFunctionURL"),
			Action:              aws.String("lambda:InvokeFunctionUrl"),
			Principal:           aws.String("*"),
			FunctionUrlAuthType: lambdatypes.FunctionUrlAuthTypeNone,
		})
	} else {
		functionURL = *urlConfig.FunctionUrl
	}

	w.appendLog(ctx, id, fmt.Sprintf("Lambda deployed. Function URL: %s", functionURL))

	if err := w.deployments.UpdateFunctionURL(ctx, id, functionURL); err != nil {
		w.logger.Warn("deploy worker: failed to store function url", "id", id, "error", err)
	}

	if err := w.deployments.UpdateStatus(ctx, id, "success"); err != nil {
		w.logger.Error("deploy worker: failed to set success status", "id", id, "error", err)
	}
	w.appendLog(ctx, id, "Lambda deployment completed successfully")
	w.logger.Info("deploy worker: lambda deployment succeeded", "id", id, "function", functionName)
}

// runStaticDeploy builds a static site and uploads it to S3.
func (w *DeployWorker) runStaticDeploy(ctx context.Context, id, projectID uuid.UUID, buildDir string) {
	w.appendLog(ctx, id, "Building static site...")

	// Detect build command
	outputDir := buildDir
	if _, err := os.Stat(filepath.Join(buildDir, "package.json")); err == nil {
		w.appendLog(ctx, id, "Running npm build...")
		buildCmd := exec.CommandContext(ctx, "sh", "-c", "npm install && npm run build")
		buildCmd.Dir = buildDir
		if out, err := buildCmd.CombinedOutput(); err != nil {
			w.failDeployment(ctx, id, "npm build failed: "+string(out), err)
			return
		}
		// Check common output dirs
		for _, d := range []string{"dist", "build", "out", ".next"} {
			if _, err := os.Stat(filepath.Join(buildDir, d)); err == nil {
				outputDir = filepath.Join(buildDir, d)
				break
			}
		}
	}

	if err := w.deployments.UpdateStatus(ctx, id, "deploying"); err != nil {
		w.failDeployment(ctx, id, "updating status", err)
		return
	}

	// Upload to the public static bucket under {projectID}/
	staticBucket := strings.ReplaceAll(w.bucket, "artifacts", "static")
	prefix := projectID.String() + "/"
	w.appendLog(ctx, id, fmt.Sprintf("Uploading to S3: s3://%s/%s", staticBucket, prefix))

	err := filepath.WalkDir(outputDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(outputDir, path)
		key := prefix + filepath.ToSlash(rel)

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		contentType := "application/octet-stream"
		switch {
		case strings.HasSuffix(path, ".html"):
			contentType = "text/html"
		case strings.HasSuffix(path, ".css"):
			contentType = "text/css"
		case strings.HasSuffix(path, ".js"):
			contentType = "application/javascript"
		case strings.HasSuffix(path, ".json"):
			contentType = "application/json"
		case strings.HasSuffix(path, ".png"):
			contentType = "image/png"
		case strings.HasSuffix(path, ".jpg"), strings.HasSuffix(path, ".jpeg"):
			contentType = "image/jpeg"
		case strings.HasSuffix(path, ".svg"):
			contentType = "image/svg+xml"
		case strings.HasSuffix(path, ".woff2"):
			contentType = "font/woff2"
		}

		_, err = w.aws.S3.PutObject(ctx, &s3.PutObjectInput{
			Bucket:      &staticBucket,
			Key:         &key,
			Body:        bytes.NewReader(data),
			ContentType: &contentType,
		})
		if err != nil {
			return fmt.Errorf("uploading %s: %w", key, err)
		}
		w.appendLog(ctx, id, fmt.Sprintf("Uploaded: %s", rel))
		return nil
	})

	if err != nil {
		w.failDeployment(ctx, id, "uploading static files", err)
		return
	}

	if err := w.deployments.UpdateStatus(ctx, id, "success"); err != nil {
		w.logger.Error("deploy worker: failed to set success status", "id", id, "error", err)
	}
	websiteURL := fmt.Sprintf("http://%s.s3-website-us-east-1.amazonaws.com/%s", staticBucket, projectID.String()+"/")
	w.appendLog(ctx, id, "Static site live at: "+websiteURL)
	w.logger.Info("deploy worker: static deployment succeeded", "id", id)
}

// downloadAndExtract downloads a tar.gz from S3 and extracts it into destDir.
func (w *DeployWorker) downloadAndExtract(ctx context.Context, key, destDir string) error {
	if w.aws == nil {
		return fmt.Errorf("AWS clients not configured")
	}

	result, err := w.aws.S3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &w.bucket,
		Key:    &key,
	})
	if err != nil {
		return fmt.Errorf("S3 GetObject: %w", err)
	}
	defer result.Body.Close()

	// Write to a temp file first so we can seek if needed; streaming is fine here.
	tmpFile, err := os.CreateTemp(destDir, "source-*.tar.gz")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, result.Body); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seeking temp file: %w", err)
	}

	return extractTarGz(tmpFile, destDir)
}

// extractTarGz extracts a gzip-compressed tar archive into destDir.
func extractTarGz(r io.Reader, destDir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}

		// Sanitize path — prevent directory traversal.
		cleanName := filepath.Clean(hdr.Name)
		if strings.HasPrefix(cleanName, "..") {
			continue
		}
		target := filepath.Join(destDir, cleanName)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir parent %s: %w", target, err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			f.Close()
		}
	}
	return nil
}

// writeDefaultDockerfile writes a minimal Dockerfile if none is present.
func (w *DeployWorker) writeDefaultDockerfile(dir string) error {
	// Check for common runtime indicators.
	dockerfile := defaultDockerfileContent(dir)
	return os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644)
}

func defaultDockerfileContent(dir string) string {
	// Node.js
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		return `FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 3000
CMD ["node", "index.js"]
`
	}
	// Python
	if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err == nil {
		return `FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 3000
CMD ["python", "app.py"]
`
	}
	// Go
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		return `FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /server .

FROM alpine:3.20
COPY --from=builder /server /server
EXPOSE 3000
ENTRYPOINT ["/server"]
`
	}
	// Generic fallback
	return `FROM alpine:3.20
WORKDIR /app
COPY . .
EXPOSE 3000
CMD ["sh", "-c", "echo 'No start command configured'; sleep infinity"]
`
}
