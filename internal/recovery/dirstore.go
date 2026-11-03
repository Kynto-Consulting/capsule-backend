package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kynto/capsule/backend/internal/backup"
)

// DirStore is a backup.Store on a local directory (objects as files, metadata as `<file>.meta.json`).
// It backs the local drill and the tests; production uses backup.S3Store.
type DirStore struct{ Root string }

var _ backup.Store = (*DirStore)(nil)

func (d *DirStore) path(key string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(strings.ReplaceAll(key, ":", "%3A"))) // ":" is not valid in Windows file names
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return "", errors.New("dirstore: bad key")
	}
	return filepath.Join(d.Root, clean), nil
}

func (d *DirStore) Upload(_ context.Context, key string, meta map[string]string, r io.Reader) (int64, error) {
	p, err := d.path(key)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return 0, err
	}
	f, err := os.Create(p)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(p)
		return 0, err
	}
	mb, _ := json.Marshal(meta)
	return n, os.WriteFile(p+".meta.json", mb, 0o644)
}

func (d *DirStore) Download(_ context.Context, key string) (io.ReadCloser, map[string]string, error) {
	p, err := d.path(key)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, nil, err
	}
	meta := map[string]string{}
	if mb, err := os.ReadFile(p + ".meta.json"); err == nil {
		_ = json.Unmarshal(mb, &meta)
	}
	return f, meta, nil
}

func (d *DirStore) Delete(_ context.Context, key string) error {
	p, err := d.path(key)
	if err != nil {
		return err
	}
	_ = os.Remove(p + ".meta.json")
	return os.Remove(p)
}

func (d *DirStore) List(_ context.Context, prefix string) ([]backup.ObjectInfo, error) {
	var out []backup.ObjectInfo
	err := filepath.WalkDir(d.Root, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || strings.HasSuffix(p, ".meta.json") {
			return err
		}
		rel, _ := filepath.Rel(d.Root, p)
		key := strings.ReplaceAll(filepath.ToSlash(rel), "%3A", ":")
		if !strings.HasPrefix(key, prefix) {
			return nil
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		out = append(out, backup.ObjectInfo{Key: key, Size: info.Size(), LastModified: info.ModTime()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, err
}

// file returns the on-disk path of key (tests use it to tamper with stored objects).
func (d *DirStore) file(key string) string { p, _ := d.path(key); return p }
