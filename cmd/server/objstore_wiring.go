package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/backup"
	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/objstore"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server"
)

// wireObjstore opens Capsule's own object store (CAPSULE_OBJSTORE_DIR; empty = disabled), connects it to the
// backup service and returns what the router and the dedicated S3 listener need.
func wireObjstore(cfg *config.Config, logger *slog.Logger, pool *pgxpool.Pool, backups *backup.Service) *server.ObjstoreDeps {
	dir := strings.TrimSpace(os.Getenv("CAPSULE_OBJSTORE_DIR"))
	if dir == "" {
		logger.Info("object storage disabled (CAPSULE_OBJSTORE_DIR)")
		return nil
	}
	store, err := objstore.Open(dir)
	if err != nil {
		logger.Error("object storage disabled: cannot open data directory", "dir", dir, "error", err)
		return nil
	}
	repo := repository.NewObjstoreRepository(pool, cfg.SecretKey)
	repo.DefaultProjectMax = envBytes("CAPSULE_OBJSTORE_DEFAULT_PROJECT_BYTES")
	repo.DefaultOrgMax = envBytes("CAPSULE_OBJSTORE_DEFAULT_ORG_BYTES")
	zone := cfg.AppsDomain
	if zone == "" {
		zone = "apps.tumi-ai.com"
	}
	internal := os.Getenv("CAPSULE_OBJSTORE_INTERNAL_ENDPOINT")
	if internal == "" {
		internal = "http://host.docker.internal:9000"
	}
	if backups != nil {
		backups.SetObjects(backupObjects{store: store, repo: repo})
	}
	addr := os.Getenv("CAPSULE_OBJSTORE_ADDR")
	if addr == "" {
		addr = ":9000"
	}
	logger.Info("object storage enabled", "dir", dir, "addr", addr)
	return &server.ObjstoreDeps{
		Store: store, Repo: repo, Addr: addr, InternalEndpoint: internal, Region: "us-east-1",
		PublicEndpoint: func(slug string) string { return fmt.Sprintf("https://%s-storage.%s", slug, zone) },
		S3:             &objstore.Server{Store: store, Meta: repo, Region: "us-east-1", Log: logger},
	}
}

func envBytes(k string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(os.Getenv(k)), 10, 64)
	return n
}

// backupObjects adapts the store to backup.ObjectSource.
type backupObjects struct {
	store *objstore.Store
	repo  *repository.ObjstoreRepository
}

func (b backupObjects) Buckets(ctx context.Context, p uuid.UUID) ([]string, error) {
	return b.repo.ProjectBucketNames(ctx, p)
}

func (b backupObjects) Archive(buckets []string, w io.Writer) error { return b.store.Archive(buckets, w) }

func (b backupObjects) Restore(ctx context.Context, p uuid.UUID, r io.Reader) error {
	names, err := b.repo.ProjectBucketNames(ctx, p)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, n := range names {
		allowed[n] = true
	}
	_, err = b.store.Restore(r, func(bucket string) bool { return allowed[bucket] })
	return err
}

var _ http.Handler = (*objstore.Server)(nil)
