package backup

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
)

// ObjectSource is Capsule's own object store as the backup service sees it: the project's buckets
// are archived in-process (no helper container) and restored from a verified archive.
type ObjectSource interface {
	Buckets(ctx context.Context, projectID uuid.UUID) ([]string, error)
	Archive(buckets []string, w io.Writer) error
	// Restore replaces the content of the project's buckets found in the archive.
	Restore(ctx context.Context, projectID uuid.UUID, r io.Reader) error
}

// SetObjects enables backups of the project's object-store buckets (snapshot kind "objects").
func (s *Service) SetObjects(o ObjectSource) { s.objects = o }

const objectsSource = "objstore"

type pipeSource struct{ *io.PipeReader }

func (s *Service) backupObjects(ctx context.Context, rs *runState, run Run) error {
	buckets, err := s.objects.Buckets(ctx, *run.ProjectID)
	if err != nil {
		return err
	}
	if len(buckets) == 0 {
		rs.done["objects"] = true
		return nil
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(s.objects.Archive(buckets, pw)) }()
	key := ObjectKey(*run.ProjectID, "objects", run.StartedAt, run.ID, "tar.gz")
	stored, sum, err := s.putStream(ctx, key, pipeSource{pr})
	if err != nil {
		return err
	}
	if err := s.record(ctx, rs, run, "objects", objectsSource, "", "", key, stored, sum, true); err != nil {
		return err
	}
	rs.done["objects"] = true
	return nil
}

func (s *Service) restoreObjects(ctx context.Context, sn *Snapshot) error {
	if s.objects == nil || sn.ProjectID == nil || sn.Source != objectsSource {
		return errors.New("object storage restore is not available for this snapshot")
	}
	body, plain, err := openObject(ctx, s.store, s.secret, sn.ObjectKey)
	if err != nil {
		return err
	}
	defer body.Close()
	if err := s.objects.Restore(ctx, *sn.ProjectID, plain); err != nil {
		return fmt.Errorf("restoring objects (live data untouched on failure): %w", err)
	}
	return nil
}
