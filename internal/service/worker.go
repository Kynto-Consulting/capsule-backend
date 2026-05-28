package service

import (
	"archive/tar"
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
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
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

// DeployWorker polls for queued deployments and executes them.
type DeployWorker struct {
	deployments domain.DeploymentRepository
	pool        *pgxpool.Pool
	aws         *awsclient.Clients
	bucket      string
	logger      *slog.Logger
	wg          sync.WaitGroup
}

// NewDeployWorker creates a new deployment worker.
func NewDeployWorker(
	deployments domain.DeploymentRepository,
	pool *pgxpool.Pool,
	aws *awsclient.Clients,
	bucket string,
	logger *slog.Logger,
) *DeployWorker {
	return &DeployWorker{
		deployments: deployments,
		pool:        pool,
		aws:         aws,
		bucket:      bucket,
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
	default:
		w.runDockerDeploy(ctx, id, projectID, buildDir, imageName, hostPort)
	}
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

	// --- stop and remove old container ---
	rmCmd := exec.CommandContext(ctx, "docker", "rm", "-f", imageName)
	_ = rmCmd.Run()

	// --- start new container ---
	runCmd := exec.CommandContext(ctx, "docker", "run", "-d",
		"--name", imageName,
		"--restart", "unless-stopped",
		"-e", "PORT=3000",
		"-p", fmt.Sprintf("%d:3000", hostPort),
		imageName,
	)
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
