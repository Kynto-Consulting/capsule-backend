package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/kynto/capsule/backend/internal/objstore"
	"github.com/kynto/capsule/backend/internal/repository"
)

// ObjstoreDeps wires Capsule's own object store (internal/objstore) into the router and the
// dedicated S3 listener.
type ObjstoreDeps struct {
	Store            *objstore.Store
	Repo             *repository.ObjstoreRepository
	S3               *objstore.Server
	Addr             string                          // dedicated S3 listener (CAPSULE_OBJSTORE_ADDR), e.g. ":9000"
	InternalEndpoint string                          // what apps on this server use: http://host.docker.internal:9000
	Region           string
	PublicEndpoint   func(projectSlug string) string // https://<slug>-storage.<zone>
}

// s3Listener serves the S3 API on its own port without the read/write deadlines of the main
// server (large uploads and downloads); only slow-header clients are cut.
func s3Listener(d *ObjstoreDeps, logger *slog.Logger) *http.Server {
	return &http.Server{Addr: d.Addr, Handler: d.S3, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute}
}

func runS3(srv *http.Server, logger *slog.Logger, errCh chan<- error) {
	logger.Info("object storage S3 listener started", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errCh <- err
	}
}

func shutdownS3(srv *http.Server, ctx context.Context) {
	if srv != nil {
		_ = srv.Shutdown(ctx)
	}
}
