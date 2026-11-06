// Package objstore is Capsule's own S3-compatible object store: objects live on a host volume,
// buckets belong to a project, access is by per-bucket SigV4 credentials and sizes are capped by
// bucket, project and organization quotas. No AWS dependency.
//
// Layout under the root directory (everything needed to restore is inside it):
//
//	<root>/<bucket>/data/<aa>/<sha256(key)>        object bytes
//	<root>/<bucket>/data/<aa>/<sha256(key)>.json   {key,size,etag,content_type,modified}
//	<root>/<bucket>/.uploads/<id>/{meta.json,part-N}   multipart uploads in flight
//
// The listing index is rebuilt from the .json files at start, so copying the directory is a valid
// backup and restore.
package objstore

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrQuota      = errors.New("quota exceeded")
	ErrNotEmpty   = errors.New("bucket not empty")
	ErrBadPart    = errors.New("invalid part")
	ErrNoUpload   = errors.New("no such upload")
	ErrBadDigest  = errors.New("content hash mismatch")
	ErrBadChunk   = errors.New("invalid chunked payload")
	ErrBadKey     = errors.New("invalid key")
	MaxKeyLen     = 1024
	multipartKeep = 7 * 24 * time.Hour
)

// Object describes a stored object.
type Object struct {
	Key         string    `json:"key"`
	Size        int64     `json:"size"`
	ETag        string    `json:"etag"`
	ContentType string    `json:"content_type"`
	Modified    time.Time `json:"modified"`
}

type bucketIdx struct {
	objects map[string]Object
	sorted  []string // lazily rebuilt
	dirty   bool
	size    int64
}

// Store is the filesystem engine. Safe for concurrent use.
type Store struct {
	root string
	mu   sync.RWMutex
	b    map[string]*bucketIdx
}

// Open loads (or creates) a store rooted at dir, rebuilding the index from disk.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	s := &Store{root: dir, b: map[string]*bucketIdx{}}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if e.IsDir() && ValidBucketName(e.Name()) {
			if err := s.load(e.Name()); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}

func (s *Store) load(bucket string) error {
	bi := &bucketIdx{objects: map[string]Object{}, dirty: true}
	data := filepath.Join(s.root, bucket, "data")
	err := filepath.WalkDir(data, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var o Object
		if json.Unmarshal(raw, &o) != nil || o.Key == "" {
			return nil // torn metadata of an interrupted write: the object was never acknowledged
		}
		if _, err := os.Stat(strings.TrimSuffix(p, ".json")); err != nil {
			return nil
		}
		bi.objects[o.Key] = o
		bi.size += o.Size
		return nil
	})
	if err != nil {
		return err
	}
	s.b[bucket] = bi
	s.sweepUploads(bucket)
	return nil
}

func (s *Store) sweepUploads(bucket string) {
	dir := filepath.Join(s.root, bucket, ".uploads")
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > multipartKeep {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}

// ValidBucketName: 3-63 chars of lowercase letters, digits, '-' and '.', starting and ending alphanumeric.
func ValidBucketName(n string) bool {
	if len(n) < 3 || len(n) > 63 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alnum && c != '-' && c != '.' || (i == 0 || i == len(n)-1) && !alnum {
			return false
		}
	}
	return !strings.Contains(n, "..")
}

func validKey(k string) error {
	if k == "" || len(k) > MaxKeyLen || strings.ContainsRune(k, 0) {
		return ErrBadKey
	}
	return nil
}

// CreateBucket makes the bucket directory (idempotent).
func (s *Store) CreateBucket(name string) error {
	if !ValidBucketName(name) {
		return fmt.Errorf("invalid bucket name %q", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.b[name]; ok {
		return nil
	}
	if err := os.MkdirAll(filepath.Join(s.root, name, "data"), 0o750); err != nil {
		return err
	}
	s.b[name] = &bucketIdx{objects: map[string]Object{}, dirty: true}
	return nil
}

// DeleteBucket removes the bucket and all its data. With force=false it refuses a non-empty bucket.
func (s *Store) DeleteBucket(name string, force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	bi, ok := s.b[name]
	if !ok {
		return ErrNotFound
	}
	if len(bi.objects) > 0 && !force {
		return ErrNotEmpty
	}
	delete(s.b, name)
	return os.RemoveAll(filepath.Join(s.root, name))
}

// HasBucket reports whether the bucket exists.
func (s *Store) HasBucket(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.b[name]
	return ok
}

// Usage returns the bytes stored in bucket (0 for an unknown one).
func (s *Store) Usage(bucket string) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if bi := s.b[bucket]; bi != nil {
		return bi.size
	}
	return 0
}

// Count returns the number of objects in bucket.
func (s *Store) Count(bucket string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if bi := s.b[bucket]; bi != nil {
		return len(bi.objects)
	}
	return 0
}

func (s *Store) paths(bucket, key string) (data, meta string) {
	h := sha256.Sum256([]byte(key))
	x := hex.EncodeToString(h[:])
	data = filepath.Join(s.root, bucket, "data", x[:2], x)
	return data, data + ".json"
}

// room returns how many more bytes may be written to bucket given extra limits already resolved by
// the caller (negative = unlimited). Used by the server to cap streaming bodies.
type writeOpts struct {
	ContentType string
	MaxBytes    int64  // cap on this body (<0 unlimited); exceeding it fails with ErrQuota
	WantSHA256  string // hex; verified at EOF when set
	Reader      func(io.Reader) io.Reader
}

// Put stores r as bucket/key atomically and returns the object.
func (s *Store) Put(bucket, key string, r io.Reader, o writeOpts) (Object, error) {
	if err := validKey(key); err != nil {
		return Object{}, err
	}
	if !s.HasBucket(bucket) {
		return Object{}, ErrNotFound
	}
	data, meta := s.paths(bucket, key)
	if err := os.MkdirAll(filepath.Dir(data), 0o750); err != nil {
		return Object{}, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(data), ".put-*")
	if err != nil {
		return Object{}, err
	}
	defer os.Remove(tmp.Name())
	n, etag, err := copyHashed(tmp, r, o.MaxBytes, o.WantSHA256)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Object{}, err
	}
	obj := Object{Key: key, Size: n, ETag: etag, ContentType: o.ContentType, Modified: time.Now().UTC().Truncate(time.Second)}
	return s.commit(bucket, tmp.Name(), data, meta, obj)
}

func (s *Store) commit(bucket, tmp, data, meta string, obj Object) (Object, error) {
	raw, _ := json.Marshal(obj)
	s.mu.Lock()
	defer s.mu.Unlock()
	bi := s.b[bucket]
	if bi == nil {
		return Object{}, ErrNotFound
	}
	if err := os.Rename(tmp, data); err != nil {
		return Object{}, err
	}
	mt := meta + ".tmp"
	if err := os.WriteFile(mt, raw, 0o640); err != nil {
		return Object{}, err
	}
	if err := os.Rename(mt, meta); err != nil {
		return Object{}, err
	}
	if old, ok := bi.objects[obj.Key]; ok {
		bi.size -= old.Size
	} else {
		bi.dirty = true
	}
	bi.objects[obj.Key] = obj
	bi.size += obj.Size
	return obj, nil
}

// copyHashed copies r to w computing the MD5 ETag, enforcing max (<0: none) and an optional SHA-256.
func copyHashed(w io.Writer, r io.Reader, max int64, wantSHA string) (int64, string, error) {
	md := md5.New()
	var sh = sha256.New()
	src := r
	if max >= 0 {
		src = io.LimitReader(r, max+1)
	}
	n, err := io.Copy(io.MultiWriter(w, md, sh), src)
	if err != nil {
		return n, "", err
	}
	if max >= 0 && n > max {
		return n, "", ErrQuota
	}
	if wantSHA != "" && !strings.EqualFold(wantSHA, hex.EncodeToString(sh.Sum(nil))) {
		return n, "", ErrBadDigest
	}
	return n, hex.EncodeToString(md.Sum(nil)), nil
}

// Stat returns the object's metadata.
func (s *Store) Stat(bucket, key string) (Object, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if bi := s.b[bucket]; bi != nil {
		if o, ok := bi.objects[key]; ok {
			return o, nil
		}
	}
	return Object{}, ErrNotFound
}

// Open opens the object for reading.
func (s *Store) OpenObject(bucket, key string) (*os.File, Object, error) {
	o, err := s.Stat(bucket, key)
	if err != nil {
		return nil, Object{}, err
	}
	data, _ := s.paths(bucket, key)
	f, err := os.Open(data)
	if err != nil {
		return nil, Object{}, ErrNotFound
	}
	return f, o, nil
}

// Delete removes the object (deleting a missing key succeeds, like S3).
func (s *Store) Delete(bucket, key string) error {
	data, meta := s.paths(bucket, key)
	s.mu.Lock()
	defer s.mu.Unlock()
	bi := s.b[bucket]
	if bi == nil {
		return ErrNotFound
	}
	o, ok := bi.objects[key]
	if !ok {
		return nil
	}
	_ = os.Remove(meta)
	_ = os.Remove(data)
	delete(bi.objects, key)
	bi.size -= o.Size
	bi.dirty = true
	return nil
}

// ListResult is one page of a listing.
type ListResult struct {
	Objects        []Object
	CommonPrefixes []string
	Truncated      bool
	Next           string // last key/prefix returned, to pass as `after`
}

// List returns keys with prefix after `after`, up to max (>0), grouping by delimiter when set.
func (s *Store) List(bucket, prefix, delimiter, after string, max int) (ListResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bi := s.b[bucket]
	if bi == nil {
		return ListResult{}, ErrNotFound
	}
	if bi.dirty {
		bi.sorted = bi.sorted[:0]
		for k := range bi.objects {
			bi.sorted = append(bi.sorted, k)
		}
		sort.Strings(bi.sorted)
		bi.dirty = false
	}
	keys := bi.sorted
	if max <= 0 || max > 1000 {
		max = 1000
	}
	var res ListResult
	i := sort.SearchStrings(keys, prefix)
	if after > prefix {
		i = sort.SearchStrings(keys, after)
	}
	seen := map[string]bool{}
	count := 0
	for ; i < len(keys); i++ {
		k := keys[i]
		if !strings.HasPrefix(k, prefix) {
			break
		}
		if k <= after {
			continue
		}
		if delimiter != "" {
			if j := strings.Index(k[len(prefix):], delimiter); j >= 0 {
				cp := k[:len(prefix)+j+len(delimiter)]
				if cp <= after || seen[cp] {
					continue
				}
				if count == max {
					res.Truncated = true
					break
				}
				seen[cp] = true
				res.CommonPrefixes = append(res.CommonPrefixes, cp)
				res.Next = cp
				count++
				continue
			}
		}
		if count == max {
			res.Truncated = true
			break
		}
		res.Objects = append(res.Objects, bi.objects[k])
		res.Next = k
		count++
	}
	return res, nil
}

// ---- multipart -------------------------------------------------------------------------------

type uploadMeta struct {
	Key         string `json:"key"`
	ContentType string `json:"content_type"`
}

// Part is one uploaded part of a multipart upload.
type Part struct {
	Number int
	Size   int64
	ETag   string
}

func (s *Store) uploadDir(bucket, id string) (string, error) {
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" || !s.HasBucket(bucket) {
		return "", ErrNoUpload
	}
	d := filepath.Join(s.root, bucket, ".uploads", id)
	if _, err := os.Stat(d); err != nil {
		return "", ErrNoUpload
	}
	return d, nil
}

// InitUpload starts a multipart upload and returns its id.
func (s *Store) InitUpload(bucket, key, contentType string) (string, error) {
	if err := validKey(key); err != nil {
		return "", err
	}
	if !s.HasBucket(bucket) {
		return "", ErrNotFound
	}
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(rnd[:])
	d := filepath.Join(s.root, bucket, ".uploads", id)
	if err := os.MkdirAll(d, 0o750); err != nil {
		return "", err
	}
	raw, _ := json.Marshal(uploadMeta{key, contentType})
	return id, os.WriteFile(filepath.Join(d, "meta.json"), raw, 0o640)
}

func (s *Store) uploadInfo(d string) (uploadMeta, error) {
	var m uploadMeta
	raw, err := os.ReadFile(filepath.Join(d, "meta.json"))
	if err != nil || json.Unmarshal(raw, &m) != nil {
		return m, ErrNoUpload
	}
	return m, nil
}

// PutPart stores one part (1..10000). max caps the part size (<0 unlimited).
func (s *Store) PutPart(bucket, id string, n int, r io.Reader, max int64, wantSHA string) (string, int64, error) {
	if n < 1 || n > 10000 {
		return "", 0, ErrBadPart
	}
	d, err := s.uploadDir(bucket, id)
	if err != nil {
		return "", 0, err
	}
	tmp, err := os.CreateTemp(d, ".part-*")
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(tmp.Name())
	size, etag, err := copyHashed(tmp, r, max, wantSHA)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", 0, err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(d, "part-"+strconv.Itoa(n))); err != nil {
		return "", 0, err
	}
	_ = os.WriteFile(filepath.Join(d, "part-"+strconv.Itoa(n)+".etag"), []byte(etag), 0o640)
	return etag, size, nil
}

// Parts lists the parts uploaded so far, ordered by number.
func (s *Store) Parts(bucket, id string) ([]Part, error) {
	d, err := s.uploadDir(bucket, id)
	if err != nil {
		return nil, err
	}
	ents, _ := os.ReadDir(d)
	var out []Part
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, "part-") || strings.HasSuffix(name, ".etag") {
			continue
		}
		num, err := strconv.Atoi(strings.TrimPrefix(name, "part-"))
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		et, _ := os.ReadFile(filepath.Join(d, name+".etag"))
		out = append(out, Part{num, info.Size(), string(et)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out, nil
}

// UploadKey returns the destination key of an upload.
func (s *Store) UploadKey(bucket, id string) (string, error) {
	d, err := s.uploadDir(bucket, id)
	if err != nil {
		return "", err
	}
	m, err := s.uploadInfo(d)
	return m.Key, err
}

// UploadSize is the bytes already stored in the parts of an upload.
func (s *Store) UploadSize(bucket, id string) int64 {
	ps, _ := s.Parts(bucket, id)
	var t int64
	for _, p := range ps {
		t += p.Size
	}
	return t
}

// CompleteUpload assembles the listed parts (number+etag, ascending) into the object. max caps the
// assembled size (<0 unlimited).
func (s *Store) CompleteUpload(bucket, id string, want []Part, max int64) (Object, error) {
	d, err := s.uploadDir(bucket, id)
	if err != nil {
		return Object{}, err
	}
	m, err := s.uploadInfo(d)
	if err != nil {
		return Object{}, err
	}
	have, _ := s.Parts(bucket, id)
	idx := map[int]Part{}
	for _, p := range have {
		idx[p.Number] = p
	}
	if len(want) == 0 {
		return Object{}, ErrBadPart
	}
	data, meta := s.paths(bucket, m.Key)
	if err := os.MkdirAll(filepath.Dir(data), 0o750); err != nil {
		return Object{}, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(data), ".mp-*")
	if err != nil {
		return Object{}, err
	}
	defer os.Remove(tmp.Name())
	var total int64
	sum := md5.New()
	prev := 0
	for _, w := range want {
		p, ok := idx[w.Number]
		if !ok || w.Number <= prev || (w.ETag != "" && strings.Trim(w.ETag, `"`) != p.ETag) {
			tmp.Close()
			return Object{}, ErrBadPart
		}
		prev = w.Number
		total += p.Size
		if max >= 0 && total > max {
			tmp.Close()
			return Object{}, ErrQuota
		}
		raw, _ := hex.DecodeString(p.ETag)
		sum.Write(raw)
		f, err := os.Open(filepath.Join(d, "part-"+strconv.Itoa(w.Number)))
		if err != nil {
			tmp.Close()
			return Object{}, ErrBadPart
		}
		_, err = io.Copy(tmp, f)
		f.Close()
		if err != nil {
			tmp.Close()
			return Object{}, err
		}
	}
	if err := tmp.Close(); err != nil {
		return Object{}, err
	}
	obj := Object{Key: m.Key, Size: total, ETag: hex.EncodeToString(sum.Sum(nil)) + "-" + strconv.Itoa(len(want)),
		ContentType: m.ContentType, Modified: time.Now().UTC().Truncate(time.Second)}
	out, err := s.commit(bucket, tmp.Name(), data, meta, obj)
	if err == nil {
		_ = os.RemoveAll(d)
	}
	return out, err
}

// AbortUpload discards an upload and its parts.
func (s *Store) AbortUpload(bucket, id string) error {
	d, err := s.uploadDir(bucket, id)
	if err != nil {
		return err
	}
	return os.RemoveAll(d)
}

// Pending is the bytes held by multipart parts still in flight in bucket.
func (s *Store) Pending(bucket string) int64 {
	var t int64
	root := filepath.Join(s.root, bucket, ".uploads")
	ents, err := os.ReadDir(root)
	if err != nil {
		return 0
	}
	for _, e := range ents {
		parts, _ := os.ReadDir(filepath.Join(root, e.Name()))
		for _, p := range parts {
			if strings.HasPrefix(p.Name(), "part-") && !strings.HasSuffix(p.Name(), ".etag") {
				if i, err := p.Info(); err == nil {
					t += i.Size()
				}
			}
		}
	}
	return t
}
