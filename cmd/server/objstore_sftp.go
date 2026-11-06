package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/kynto/capsule/backend/internal/objstore/sftpd"
	"github.com/kynto/capsule/backend/internal/repository"
	"github.com/kynto/capsule/backend/internal/server"
	"github.com/kynto/capsule/backend/internal/server/handlers"
)

// wireSFTP adds the SFTP front end to the object store deps. It listens on CAPSULE_OBJSTORE_SFTP_ADDR (default
// ":2222"; "off" disables it) and is never published to the internet: the gateway (service "sftp" of the project)
// and apps of the same server (host.docker.internal:<port>) are the only ways in.
func wireSFTP(d *server.ObjstoreDeps, dir string, logger *slog.Logger) {
	addr := strings.TrimSpace(os.Getenv("CAPSULE_OBJSTORE_SFTP_ADDR"))
	if addr == "" {
		addr = ":2222"
	}
	if strings.EqualFold(addr, "off") {
		logger.Info("object storage SFTP disabled (CAPSULE_OBJSTORE_SFTP_ADDR=off)")
		return
	}
	keyPath := strings.TrimSpace(os.Getenv("CAPSULE_OBJSTORE_SFTP_HOSTKEY"))
	if keyPath == "" {
		keyPath = filepath.Join(dir, ".sftp", "host_ed25519") // inside the volume: survives restarts and redeploys
	}
	hk, err := sftpd.LoadOrCreateHostKey(keyPath)
	if err != nil {
		logger.Error("object storage SFTP disabled: host key", "path", keyPath, "error", err)
		return
	}
	cfg := sftpd.Config{
		Objects: d.S3, Auth: sftpAuth{d.Repo}, HostKey: hk, Log: logger,
		MaxConns:          int(envBytes("CAPSULE_SFTP_MAX_CONNS")),
		MaxConnsPerBucket: int(envBytes("CAPSULE_SFTP_MAX_CONNS_PER_BUCKET")),
		ConnBytesPerSec:   envSigned("CAPSULE_SFTP_CONN_BPS"),
		TotalBytesPerSec:  envSigned("CAPSULE_SFTP_TOTAL_BPS"),
		MaxObjectBytes:    envBytes("CAPSULE_SFTP_MAX_OBJECT_BYTES"),
	}
	if v, err := time.ParseDuration(strings.TrimSpace(os.Getenv("CAPSULE_SFTP_IDLE"))); err == nil && v > 0 {
		cfg.IdleTimeout = v
	}
	d.SFTP = sftpd.New(cfg)
	d.SFTPAddr = addr
	port := "2222"
	if _, p, err := net.SplitHostPort(addr); err == nil && p != "" {
		port = p
	}
	internal := strings.TrimSpace(os.Getenv("CAPSULE_OBJSTORE_SFTP_INTERNAL"))
	if internal == "" {
		internal = "host.docker.internal:" + port
	}
	d.SFTPInfo = &handlers.SFTPInfo{InternalAddr: internal, Fingerprint: sftpd.Fingerprint(hk)}
	logger.Info("object storage SFTP enabled", "addr", addr, "host_key", d.SFTPInfo.Fingerprint)
}

func envSigned(k string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(os.Getenv(k)), 10, 64)
	return n
}

// sftpAuth adapts the object store repository to sftpd.Auth.
type sftpAuth struct{ repo *repository.ObjstoreRepository }

func (a sftpAuth) Resolve(ctx context.Context, user string) (string, error) {
	b, err := a.repo.ResolveSFTPUser(ctx, user)
	if err != nil {
		return "", sftpd.ErrNoUser
	}
	return b, nil
}

func (a sftpAuth) Secret(ctx context.Context, bucket string) (string, error) {
	return a.repo.BucketSecret(ctx, bucket)
}

func (a sftpAuth) AuthorizedKeys(ctx context.Context, bucket string) ([]sftpd.AuthorizedKey, error) {
	recs, err := a.repo.SSHKeysCached(ctx, bucket)
	if err != nil {
		return nil, err
	}
	var out []sftpd.AuthorizedKey
	for _, r := range recs {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.PublicKey))
		if err != nil {
			continue
		}
		out = append(out, sftpd.AuthorizedKey{ID: r.ID.String(), Key: pk})
	}
	return out, nil
}

func (a sftpAuth) KeyUsed(ctx context.Context, id string) {
	if u, err := uuid.Parse(id); err == nil {
		a.repo.TouchSSHKey(ctx, u)
	}
}

var _ sftpd.Auth = sftpAuth{}
