package objstore

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Hooks the SFTP front end (internal/objstore/sftpd) uses on top of the same engine and the same atomic
// quota reservations as the S3 API.

// StagingDir is where an SFTP upload is assembled before it becomes an object (inside the bucket directory,
// so the final rename stays on one filesystem). It is never listed and not part of an archive.
func (s *Store) StagingDir(bucket string) (string, error) {
	if !s.HasBucket(bucket) {
		return "", ErrNotFound
	}
	d := filepath.Join(s.root, bucket, ".sftp")
	return d, os.MkdirAll(d, 0o750)
}

// SweepStaging removes staging files older than maxAge left by a crash (live uploads touch theirs).
func (s *Store) SweepStaging(maxAge time.Duration) {
	s.mu.RLock()
	names := make([]string, 0, len(s.b))
	for n := range s.b {
		names = append(names, n)
	}
	s.mu.RUnlock()
	for _, n := range names {
		d := filepath.Join(s.root, n, ".sftp")
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > maxAge {
				_ = os.Remove(filepath.Join(d, e.Name()))
			}
		}
	}
}

// PutFile turns a finished staging file (same filesystem) into bucket/key atomically. The file is consumed.
func (s *Store) PutFile(bucket, key, path, contentType string) (Object, error) {
	if err := validKey(key); err != nil {
		return Object{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return Object{}, err
	}
	md := md5.New()
	n, err := io.Copy(md, f)
	f.Close()
	if err != nil {
		return Object{}, err
	}
	data, meta := s.paths(bucket, key)
	if err := os.MkdirAll(filepath.Dir(data), 0o750); err != nil {
		return Object{}, err
	}
	obj := Object{Key: key, Size: n, ETag: hex.EncodeToString(md.Sum(nil)), ContentType: contentType, Modified: time.Now().UTC().Truncate(time.Second)}
	return s.commit(bucket, path, data, meta, obj)
}

// Rename moves bucket/from to bucket/to inside the bucket: the bytes are not copied, the destination is
// replaced atomically and the stored size does not change (quota neutral apart from a replaced object).
func (s *Store) Rename(bucket, from, to string) error {
	if err := validKey(from); err != nil {
		return err
	}
	if err := validKey(to); err != nil {
		return err
	}
	if from == to {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bi := s.b[bucket]
	if bi == nil {
		return ErrNotFound
	}
	o, ok := bi.objects[from]
	if !ok {
		return ErrNotFound
	}
	srcData, srcMeta := s.paths(bucket, from)
	dstData, dstMeta := s.paths(bucket, to)
	if err := os.MkdirAll(filepath.Dir(dstData), 0o750); err != nil {
		return err
	}
	if err := os.Rename(srcData, dstData); err != nil {
		return err
	}
	n := o
	n.Key = to
	raw, _ := json.Marshal(n)
	mt := dstMeta + ".tmp"
	if err := os.WriteFile(mt, raw, 0o640); err != nil {
		_ = os.Rename(dstData, srcData)
		return err
	}
	if err := os.Rename(mt, dstMeta); err != nil {
		_ = os.Rename(dstData, srcData)
		return err
	}
	_ = os.Remove(srcMeta)
	if old, exists := bi.objects[to]; exists {
		bi.size -= old.Size
	}
	delete(bi.objects, from)
	bi.objects[to] = n
	bi.dirty = true
	return nil
}

// Reservation holds quota bytes for an upload whose final size is not known up front (SFTP writes at
// offsets). Grow reserves atomically with the same check the S3 API uses, so concurrent uploads cannot
// each pass on the same free space; Release returns everything when the upload ends.
type Reservation struct {
	s         *Server
	ctx       context.Context
	bucket    string
	replacing int64
	mu        sync.Mutex
	held      int64
}

// NewReservation starts a reservation in bucket; replacing is the size of the object being overwritten.
func (s *Server) NewReservation(ctx context.Context, bucket string, replacing int64) *Reservation {
	return &Reservation{s: s, ctx: ctx, bucket: bucket, replacing: replacing}
}

// Grow makes sure the upload may reach total bytes; ErrQuota when the bucket, project or organization is full.
func (r *Reservation) Grow(total int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	need := total - r.replacing
	if need < 0 {
		need = 0
	}
	delta := need - r.held
	if delta <= 0 {
		return nil
	}
	r.s.Store.qmu.Lock()
	defer r.s.Store.qmu.Unlock()
	room, err := r.s.room(r.ctx, r.bucket)
	if err != nil {
		return err
	}
	if room >= 0 && delta > room {
		return ErrQuota
	}
	r.s.Store.addInflight(r.bucket, delta)
	r.held = need
	return nil
}

// Release returns the held bytes (call after the object is committed or the upload is abandoned).
func (r *Reservation) Release() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.held != 0 {
		r.s.Store.addInflight(r.bucket, -r.held)
		r.held = 0
	}
}

// IsPrefix reports whether any object lives under prefix (which must end in "/").
func (s *Store) IsPrefix(bucket, prefix string) bool {
	res, err := s.List(bucket, prefix, "", "", 1)
	return err == nil && len(res.Objects) > 0 && strings.HasPrefix(res.Objects[0].Key, prefix)
}

// PutEmpty stores a zero-byte object (folder markers: keys ending in "/").
func (s *Store) PutEmpty(bucket, key, contentType string) (Object, error) {
	return s.Put(bucket, key, strings.NewReader(""), writeOpts{ContentType: contentType, MaxBytes: 0})
}

// Root is the directory holding the buckets (for tests and diagnostics).
func (s *Store) Root() string { return s.root }
