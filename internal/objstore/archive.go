package objstore

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Archive writes a tar.gz of the given buckets (object bytes + metadata, no in-flight multipart
// uploads). Objects are write-once files, so the archive is consistent per object while the store
// keeps serving; an object deleted during the run is skipped.
func (s *Store) Archive(buckets []string, w io.Writer) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	for _, b := range buckets {
		s.mu.RLock()
		bi := s.b[b]
		var objs []Object
		if bi != nil {
			for _, o := range bi.objects {
				objs = append(objs, o)
			}
		}
		s.mu.RUnlock()
		if bi == nil {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: b + "/", Mode: 0o750}); err != nil {
			return err
		}
		for _, o := range objs {
			data, meta := s.paths(b, o.Key)
			for _, p := range []string{data, meta} {
				rel, _ := filepath.Rel(s.root, p)
				if err := addFile(tw, p, filepath.ToSlash(rel)); err != nil {
					if errors.Is(err, os.ErrNotExist) {
						break
					}
					return err
				}
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func addFile(tw *tar.Writer, p, name string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Size: st.Size(), Mode: 0o640, ModTime: st.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// Restore replaces the content of the buckets contained in a tar.gz produced by Archive. Only
// buckets accepted by allow are touched. The archive is extracted into a staging directory first
// and each bucket is swapped in atomically; a failure leaves the live data as it was.
func (s *Store) Restore(r io.Reader, allow func(bucket string) bool) ([]string, error) {
	stage, err := os.MkdirTemp(s.root, ".restore-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	got := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := path.Clean(h.Name)
		bucket, rest, _ := strings.Cut(name, "/")
		if !ValidBucketName(bucket) || !allow(bucket) || strings.Contains(name, "..") || strings.HasPrefix(rest, ".uploads") {
			return nil, fmt.Errorf("archive entry %q is not allowed", h.Name)
		}
		dst := filepath.Join(stage, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(dst, 0o750)
		case tar.TypeReg:
			if err = os.MkdirAll(filepath.Dir(dst), 0o750); err == nil {
				err = writeFrom(dst, tr)
			}
		default:
			err = fmt.Errorf("archive entry %q has an unsupported type", h.Name)
		}
		if err != nil {
			return nil, err
		}
		got[bucket] = true
	}
	var done []string
	s.mu.Lock()
	defer s.mu.Unlock()
	for b := range got {
		live := filepath.Join(s.root, b)
		old := filepath.Join(stage, ".old-"+b)
		hadLive := false
		if _, err := os.Stat(live); err == nil {
			hadLive = true
			if err := os.Rename(live, old); err != nil {
				return done, err
			}
		}
		if err := os.Rename(filepath.Join(stage, b), live); err != nil {
			if hadLive {
				_ = os.Rename(old, live)
			}
			return done, err
		}
		if err := os.MkdirAll(filepath.Join(live, "data"), 0o750); err != nil {
			return done, err
		}
		if err := s.load(b); err != nil {
			return done, err
		}
		done = append(done, b)
	}
	return done, nil
}

func writeFrom(p string, r io.Reader) error {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
