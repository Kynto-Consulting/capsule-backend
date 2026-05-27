package service

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

// DeployWorker polls for queued deployments and executes them.
type DeployWorker struct {
	deployments domain.DeploymentRepository
	pool        *pgxpool.Pool
	aws         *awsclient.Clients
	bucket      string
	logger      *slog.Logger
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

// Run starts the polling loop. It blocks until ctx is cancelled.
func (w *DeployWorker) Run(ctx context.Context) {
	w.logger.Info("deploy worker started")
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("deploy worker stopping")
			return
		default:
			w.processNext(ctx)
			time.Sleep(5 * time.Second)
		}
	}
}

// processNext picks the oldest queued deployment using SKIP LOCKED and processes it.
func (w *DeployWorker) processNext(ctx context.Context) {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		w.logger.Error("deploy worker: begin tx", "error", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var (
		id        uuid.UUID
		projectID uuid.UUID
		sourceKey *string
	)
	err = tx.QueryRow(ctx, `
		SELECT id, project_id, source_key
		FROM deployments
		WHERE status = 'queued'
		ORDER BY created_at
		LIMIT 1
		FOR UPDATE SKIP LOCKED
	`).Scan(&id, &projectID, &sourceKey)
	if err != nil {
		// No rows available — nothing to do.
		return
	}

	if err := tx.Commit(ctx); err != nil {
		w.logger.Error("deploy worker: commit tx", "error", err)
		return
	}

	w.logger.Info("deploy worker: picked deployment", "id", id, "project_id", projectID)
	w.runDeployment(ctx, id, projectID, sourceKey)
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

// runDeployment executes a single deployment end-to-end.
func (w *DeployWorker) runDeployment(ctx context.Context, id, projectID uuid.UUID, sourceKey *string) {
	// --- transition to building ---
	if err := w.deployments.UpdateStatus(ctx, id, "building"); err != nil {
		w.failDeployment(ctx, id, "failed to update status to building", err)
		return
	}
	w.appendLog(ctx, id, "Starting build...")

	// short tag for container/image name — first 8 chars of project UUID
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

	// --- find an available host port in range 20000-29999 (deterministic from project ID) ---
	shortBytes := []byte(projectID.String())
	portOffset := 0
	for _, b := range shortBytes {
		portOffset = (portOffset*31 + int(b)) % 10000
	}
	hostPort := 20000 + portOffset

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
