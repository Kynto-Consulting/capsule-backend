package backup

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type fakeObjects struct {
	buckets  []string
	archived []string
	restored []byte
}

func (f *fakeObjects) Buckets(context.Context, uuid.UUID) ([]string, error) { return f.buckets, nil }
func (f *fakeObjects) Archive(b []string, w io.Writer) error {
	f.archived = b
	_, err := io.WriteString(w, "OBJECT-ARCHIVE")
	return err
}
func (f *fakeObjects) Restore(_ context.Context, _ uuid.UUID, r io.Reader) error {
	var err error
	f.restored, err = io.ReadAll(r)
	return err
}

func TestObjectsBackupAndRestore(t *testing.T) {
	e := newEnv(t, true)
	fo := &fakeObjects{buckets: []string{"capsule-acme-files"}}
	e.svc.SetObjects(fo)
	run := e.runNow(t, "backup", Settings{Enabled: true, IncludeVolumes: true, RetentionDays: 14})
	if run.Status != "success" {
		t.Fatalf("%s %s", run.Status, run.Error)
	}
	var sn *Snapshot
	for _, s := range e.repo.snaps {
		if s.Kind == "objects" {
			sn = s
		}
	}
	if sn == nil || sn.Source != objectsSource || !strings.HasSuffix(sn.ObjectKey, ".tar.gz.enc") {
		t.Fatalf("objects snapshot: %+v", sn)
	}
	if string(e.plain(t, sn.ObjectKey)) != "OBJECT-ARCHIVE" || len(fo.archived) != 1 {
		t.Fatal("archive stream not stored encrypted")
	}
	if err := e.svc.restoreObjects(context.Background(), sn); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fo.restored, []byte("OBJECT-ARCHIVE")) {
		t.Fatalf("restore got %q", fo.restored)
	}
	// without databases/volumes included nothing is archived
	fo.archived = nil
	e.runNow(t, "backup", Settings{Enabled: true, IncludeDatabases: true, RetentionDays: 14})
	if fo.archived != nil {
		t.Fatal("objects archived although volumes are excluded")
	}
}
