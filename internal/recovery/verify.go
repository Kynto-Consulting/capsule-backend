package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kynto/capsule/backend/internal/backup"
)

const (
	metaDEK         = "capsule-dek" // S3 object metadata key written by internal/backup
	maxManifestSize = 8 << 20
)

// Verifier opens and checks backup objects. Integrity has three independent layers
// (DR-BACKUP.md section 7): the AES-256-GCM tags of the envelope (any flipped, dropped or
// reordered chunk fails; forging one needs the data key, which is wrapped with the platform
// secret, so it plays the role of the manifest HMAC), the sha256 recorded at backup time, and
// structural checks (schema, project id and run id must match the object key).
type Verifier struct {
	Store  backup.Store
	Secret string // CAPSULE_SECRET_KEY
}

func (v *Verifier) open(ctx context.Context, key string) (io.ReadCloser, io.Reader, error) {
	body, meta, err := v.Store.Download(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	wrapped := ""
	for k, val := range meta {
		if strings.EqualFold(k, metaDEK) {
			wrapped = val
		}
	}
	if wrapped == "" {
		body.Close()
		return nil, nil, errors.New("backup object has no encryption metadata")
	}
	dek, err := backup.UnwrapDEK(wrapped, v.Secret)
	if err != nil {
		body.Close()
		return nil, nil, err
	}
	return body, backup.NewDecryptReader(body, dek), nil
}

// Stream decrypts sn, hashes the plaintext, optionally copies it to sink and compares the sha256
// with the recorded checksum (when there is one). Nothing is trusted until the whole stream passed.
func (v *Verifier) Stream(ctx context.Context, sn SnapshotRef, sink io.Writer) (int64, string, error) {
	body, plain, err := v.open(ctx, sn.ObjectKey)
	if err != nil {
		return 0, "", err
	}
	defer body.Close()
	h := sha256.New()
	w := io.Writer(h)
	if sink != nil {
		w = io.MultiWriter(h, sink)
	}
	n, err := io.Copy(w, plain)
	if err != nil {
		return n, "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if sn.Checksum != "" && sum != sn.Checksum {
		return n, sum, ErrChecksum
	}
	return n, sum, nil
}

// Manifest downloads, decrypts and validates a project manifest. Any failure wraps ErrManifest.
func (v *Verifier) Manifest(ctx context.Context, sn SnapshotRef) (*backup.Manifest, error) {
	var buf limitedBuf
	buf.max = maxManifestSize
	if _, _, err := v.Stream(ctx, sn, &buf); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrManifest, err)
	}
	var m backup.Manifest
	if err := json.Unmarshal(buf.b, &m); err != nil {
		return nil, fmt.Errorf("%w: unreadable: %v", ErrManifest, err)
	}
	if m.Schema != backup.ManifestSchema {
		return nil, fmt.Errorf("%w: schema %d is unknown (this build reads %d)", ErrManifest, m.Schema, backup.ManifestSchema)
	}
	if sn.ProjectID == nil || m.Project.ID != *sn.ProjectID {
		return nil, fmt.Errorf("%w: manifest belongs to project %s, not to the snapshot's project", ErrManifest, m.Project.ID)
	}
	if !strings.Contains(sn.ObjectKey, m.RunID.String()) || !strings.Contains(sn.ObjectKey, sn.ProjectID.String()) {
		return nil, fmt.Errorf("%w: run id or project id does not match the object key (replaced object?)", ErrManifest)
	}
	return &m, nil
}

// Summarize reduces a verified manifest to what the planner needs.
func Summarize(sn SnapshotRef, m *backup.Manifest) *ManifestSummary {
	s := &ManifestSummary{SnapshotID: sn.ID, Databases: []string{}, Volumes: []string{}}
	for _, d := range m.Databases {
		s.Databases = append(s.Databases, d.ID.String())
	}
	for _, vol := range m.Volumes {
		s.Volumes = append(s.Volumes, vol.Name)
	}
	if d := m.Deployment; d != nil {
		s.HasSource = d.SourceKey != "" || len(d.ImageDigests) > 0
		s.Deployment = d.Version
	}
	return s
}

type limitedBuf struct {
	b   []byte
	max int
}

func (l *limitedBuf) Write(p []byte) (int, error) {
	if len(l.b)+len(p) > l.max {
		return 0, errors.New("object larger than the allowed manifest size")
	}
	l.b = append(l.b, p...)
	return len(p), nil
}
