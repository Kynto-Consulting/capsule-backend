package sftpd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"

	"github.com/kynto/capsule/backend/internal/objstore"
)

var (
	errBadPath    = errors.New("invalid path")
	errIsDir      = errors.New("is a directory")
	errNotDir     = errors.New("not a directory")
	errNotEmpty   = errors.New("directory not empty")
	errTooMany    = errors.New("too many open files in this connection")
	errTooLarge   = errors.New("file too large")
	errQuotaFull  = errors.New("quota exceeded: the storage quota of this bucket, project or organization is exhausted")
	errUnsupposed = sftp.ErrSSHFxOpUnsupported
)

// fsys is one authenticated connection's view of one bucket: a tree of folders over object keys. Paths are
// strings that are cleaned lexically against "/", so ".." and absolute paths can never leave the bucket, and
// no path ever reaches the host file system.
type fsys struct {
	srv    *Server
	bucket string
	log    *slog.Logger
	open   atomic.Int32
}

func newFS(s *Server, bucket string, log *slog.Logger) *fsys {
	return &fsys{srv: s, bucket: bucket, log: log}
}

func (f *fsys) store() *objstore.Store { return f.srv.cfg.Objects.Store }

// key turns an SFTP path into an object key ("" is the bucket root).
func (f *fsys) key(p string) (string, error) {
	c := path.Clean("/" + p)
	if c == "/" {
		return "", nil
	}
	k := c[1:]
	if len(k) >= objstore.MaxKeyLen-1 || strings.ContainsRune(k, 0) {
		return "", errBadPath
	}
	return k, nil
}

func pathErr(op, p string, err error) error { return &os.PathError{Op: op, Path: p, Err: err} }

func (f *fsys) mapErr(op, p string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, objstore.ErrNotFound):
		return pathErr(op, p, os.ErrNotExist)
	case errors.Is(err, objstore.ErrQuota):
		return errQuotaFull
	case errors.Is(err, objstore.ErrBadKey):
		return pathErr(op, p, errBadPath)
	}
	f.log.Error("sftp storage error", "op", op, "path", p, "error", err)
	return pathErr(op, p, errors.New("internal error"))
}

func (f *fsys) isDir(key string) bool {
	if key == "" {
		return true
	}
	if _, err := f.store().Stat(f.bucket, key+"/"); err == nil {
		return true
	}
	return f.store().IsPrefix(f.bucket, key+"/")
}

// parentIsFile reports whether an ancestor of key is a regular object (a file cannot hold children).
func (f *fsys) parentIsFile(key string) bool {
	for d := path.Dir(key); d != "." && d != "/" && d != ""; d = path.Dir(d) {
		if _, err := f.store().Stat(f.bucket, d); err == nil {
			return true
		}
	}
	return false
}

type finfo struct {
	name string
	size int64
	mod  time.Time
	dir  bool
}

func (i finfo) Name() string { return i.name }
func (i finfo) Size() int64  { return i.size }
func (i finfo) ModTime() time.Time {
	if i.mod.IsZero() {
		return time.Unix(0, 0)
	}
	return i.mod
}
func (i finfo) IsDir() bool { return i.dir }
func (i finfo) Sys() any    { return nil }
func (i finfo) Mode() os.FileMode {
	if i.dir {
		return os.ModeDir | 0o755
	}
	return 0o644
}

type sliceLister []os.FileInfo

func (l sliceLister) ListAt(ls []os.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(ls, l[off:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

// dirLister streams a folder page by page from the engine's sorted index, so huge folders do not load at once.
type dirLister struct {
	f       *fsys
	prefix  string
	pos     int64
	after   string
	done    bool
	pending []os.FileInfo
}

func (d *dirLister) fill() {
	res, err := d.f.store().List(d.f.bucket, d.prefix, "/", d.after, 1000)
	if err != nil {
		d.done = true
		return
	}
	for _, o := range res.Objects {
		name := o.Key[len(d.prefix):]
		if name == "" || strings.Contains(name, "/") {
			continue // the folder's own marker
		}
		d.pending = append(d.pending, finfo{name: name, size: o.Size, mod: o.Modified})
	}
	for _, p := range res.CommonPrefixes {
		name := strings.TrimSuffix(p[len(d.prefix):], "/")
		if name == "" {
			continue
		}
		d.pending = append(d.pending, finfo{name: name, dir: true})
	}
	d.after = res.Next
	d.done = !res.Truncated
}

func (d *dirLister) next() (os.FileInfo, bool) {
	for len(d.pending) == 0 {
		if d.done {
			return nil, false
		}
		d.fill()
	}
	e := d.pending[0]
	d.pending = d.pending[1:]
	d.pos++
	return e, true
}

func (d *dirLister) ListAt(ls []os.FileInfo, off int64) (int, error) {
	if off != d.pos { // the client rewound or skipped: replay from the start
		d.pos, d.after, d.done, d.pending = 0, "", false, nil
		for d.pos < off {
			if _, ok := d.next(); !ok {
				return 0, io.EOF
			}
		}
	}
	n := 0
	for n < len(ls) {
		e, ok := d.next()
		if !ok {
			return n, io.EOF
		}
		ls[n] = e
		n++
	}
	return n, nil
}

// ── reads and listings ──────────────────────────────────────────────────────

type reader struct {
	*os.File
	f    *fsys
	once sync.Once
}

func (r *reader) Close() error {
	r.once.Do(func() { r.f.open.Add(-1) })
	return r.File.Close()
}

func (f *fsys) takeSlot() error {
	if int(f.open.Add(1)) > f.srv.cfg.MaxOpenFiles {
		f.open.Add(-1)
		return errTooMany
	}
	return nil
}

// Fileread opens an object for reading; ReadAt serves any byte range.
func (f *fsys) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	key, err := f.key(r.Filepath)
	if err != nil || key == "" {
		return nil, pathErr("open", r.Filepath, errIsDirOr(err))
	}
	if err := f.takeSlot(); err != nil {
		return nil, err
	}
	file, _, err := f.store().OpenObject(f.bucket, key)
	if err != nil {
		f.open.Add(-1)
		if f.isDir(key) {
			return nil, pathErr("open", r.Filepath, errIsDir)
		}
		return nil, f.mapErr("open", r.Filepath, err)
	}
	f.log.Info("sftp read", "key", key)
	return &reader{File: file, f: f}, nil
}

func errIsDirOr(err error) error {
	if err != nil {
		return err
	}
	return errIsDir
}

func (f *fsys) stat(op, p string) (os.FileInfo, error) {
	key, err := f.key(p)
	if err != nil {
		return nil, pathErr(op, p, err)
	}
	if key == "" {
		return finfo{name: "/", dir: true}, nil
	}
	if o, err := f.store().Stat(f.bucket, key); err == nil {
		return finfo{name: path.Base(key), size: o.Size, mod: o.Modified}, nil
	}
	if f.isDir(key) {
		return finfo{name: path.Base(key), dir: true}, nil
	}
	return nil, pathErr(op, p, os.ErrNotExist)
}

func (f *fsys) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	switch r.Method {
	case "List":
		key, err := f.key(r.Filepath)
		if err != nil {
			return nil, pathErr("readdir", r.Filepath, err)
		}
		if key != "" && !f.isDir(key) {
			if _, e := f.store().Stat(f.bucket, key); e == nil {
				return nil, pathErr("readdir", r.Filepath, errNotDir)
			}
			return nil, pathErr("readdir", r.Filepath, os.ErrNotExist)
		}
		prefix := ""
		if key != "" {
			prefix = key + "/"
		}
		return &dirLister{f: f, prefix: prefix}, nil
	case "Stat", "Lstat":
		fi, err := f.stat("stat", r.Filepath)
		if err != nil {
			return nil, err
		}
		return sliceLister{fi}, nil
	}
	return nil, errUnsupposed // Readlink: there are no links
}

func (f *fsys) Lstat(r *sftp.Request) (sftp.ListerAt, error) { return f.Filelist(r) }

// ── writes ──────────────────────────────────────────────────────────────────

// upload assembles an SFTP write (offset-addressed, possibly out of order and concurrent) in a staging file inside
// the bucket directory and publishes it as one object on Close. Quota is reserved as the high-water mark grows.
type upload struct {
	f       *fsys
	key     string
	file    *os.File
	res     *objstore.Reservation
	hadPrev bool

	mu      sync.Mutex
	size    int64
	aborted bool
	failed  error
	closed  bool
}

func (u *upload) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errBadPath
	}
	end := off + int64(len(p))
	if m := u.f.srv.cfg.MaxObjectBytes; m > 0 && end > m {
		return 0, errTooLarge
	}
	u.mu.Lock()
	if u.failed != nil {
		u.mu.Unlock()
		return 0, u.failed
	}
	if u.closed {
		u.mu.Unlock()
		return 0, os.ErrClosed
	}
	if end > u.size {
		if err := u.res.Grow(end); err != nil {
			if errors.Is(err, objstore.ErrQuota) {
				err = errQuotaFull
				u.f.log.Warn("sftp quota exceeded", "key", u.key, "wanted_bytes", end)
			} else {
				err = u.f.mapErr("write", u.key, err)
			}
			u.failed = err // a refused write voids the upload: nothing half-written is published
			defer u.res.Release() // and its reserved bytes go back at once
			u.mu.Unlock()
			return 0, err
		}
		u.size = end
	}
	u.mu.Unlock()
	return u.file.WriteAt(p, off)
}

func (u *upload) TransferError(error) {
	u.mu.Lock()
	u.aborted = true
	u.mu.Unlock()
}

// Close publishes the object. An upload cut off by a lost connection is published as the partial object when the
// key did not exist before (so `reput`/resume continues from its size); when it was overwriting an existing
// object, the old object is kept.
func (u *upload) Close() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil
	}
	u.closed = true
	aborted, failed := u.aborted, u.failed
	u.mu.Unlock()
	defer u.f.open.Add(-1)
	defer u.res.Release()
	name := u.file.Name()
	cerr := u.file.Close()
	if failed != nil {
		_ = os.Remove(name)
		return failed
	}
	if aborted && u.hadPrev {
		_ = os.Remove(name)
		return nil
	}
	if cerr != nil {
		_ = os.Remove(name)
		return cerr
	}
	ct := mime.TypeByExtension(path.Ext(u.key))
	if ct == "" {
		ct = "application/octet-stream"
	}
	o, err := u.f.store().PutFile(u.f.bucket, u.key, name, ct)
	if err != nil {
		_ = os.Remove(name)
		return u.f.mapErr("close", u.key, err)
	}
	u.f.log.Info("sftp write", "key", o.Key, "size", o.Size, "etag", o.ETag, "partial", aborted)
	return nil
}

func (f *fsys) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	key, err := f.key(r.Filepath)
	if err != nil || key == "" {
		return nil, pathErr("open", r.Filepath, errIsDirOr(err))
	}
	fl := r.Pflags()
	if f.isDir(key) {
		return nil, pathErr("open", r.Filepath, errIsDir)
	}
	if f.parentIsFile(key) {
		return nil, pathErr("open", r.Filepath, errNotDir)
	}
	prev, perr := f.store().Stat(f.bucket, key)
	exists := perr == nil
	if fl.Excl && exists {
		return nil, pathErr("open", r.Filepath, os.ErrExist)
	}
	if !fl.Creat && !exists {
		return nil, pathErr("open", r.Filepath, os.ErrNotExist)
	}
	if err := f.takeSlot(); err != nil {
		return nil, err
	}
	fail := func(e error) (io.WriterAt, error) {
		f.open.Add(-1)
		return nil, e
	}
	dir, err := f.store().StagingDir(f.bucket)
	if err != nil {
		return fail(f.mapErr("open", r.Filepath, err))
	}
	tmp, err := os.CreateTemp(dir, "up-*")
	if err != nil {
		return fail(f.mapErr("open", r.Filepath, err))
	}
	u := &upload{f: f, key: key, file: tmp, hadPrev: exists, res: f.srv.cfg.Objects.NewReservation(f.srv.ctx, f.bucket, prev.Size)}
	if exists && !fl.Trunc { // resume or in-place update: start from the stored bytes
		src, _, err := f.store().OpenObject(f.bucket, key)
		if err == nil {
			_, err = io.Copy(tmp, src)
			src.Close()
		}
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return fail(f.mapErr("open", r.Filepath, err))
		}
		u.size = prev.Size
	}
	return u, nil
}

// ── commands ────────────────────────────────────────────────────────────────

func (f *fsys) Filecmd(r *sftp.Request) error {
	switch r.Method {
	case "Setstat":
		return nil // permissions, owners and times do not exist here; clients set them after an upload
	case "Rename", "PosixRename":
		return f.rename(r.Filepath, r.Target)
	case "Remove":
		return f.remove(r.Filepath)
	case "Mkdir":
		return f.mkdir(r.Filepath)
	case "Rmdir":
		return f.rmdir(r.Filepath)
	}
	return errUnsupposed // Symlink, Link
}

func (f *fsys) PosixRename(r *sftp.Request) error { return f.rename(r.Filepath, r.Target) }

func (f *fsys) remove(p string) error {
	key, err := f.key(p)
	if err != nil || key == "" {
		return pathErr("remove", p, errIsDirOr(err))
	}
	if _, err := f.store().Stat(f.bucket, key); err != nil {
		if f.isDir(key) {
			return pathErr("remove", p, errIsDir)
		}
		return pathErr("remove", p, os.ErrNotExist)
	}
	if err := f.store().Delete(f.bucket, key); err != nil {
		return f.mapErr("remove", p, err)
	}
	f.log.Info("sftp delete", "key", key)
	return nil
}

func (f *fsys) mkdir(p string) error {
	key, err := f.key(p)
	if err != nil {
		return pathErr("mkdir", p, err)
	}
	if key == "" || f.isDir(key) {
		return pathErr("mkdir", p, os.ErrExist)
	}
	if _, err := f.store().Stat(f.bucket, key); err == nil || f.parentIsFile(key) {
		return pathErr("mkdir", p, os.ErrExist)
	}
	if _, err := f.store().PutEmpty(f.bucket, key+"/", "application/x-directory"); err != nil {
		return f.mapErr("mkdir", p, err)
	}
	f.log.Info("sftp mkdir", "key", key+"/")
	return nil
}

func (f *fsys) rmdir(p string) error {
	key, err := f.key(p)
	if err != nil || key == "" {
		return pathErr("rmdir", p, errIsDirOr(err))
	}
	if !f.isDir(key) {
		if _, e := f.store().Stat(f.bucket, key); e == nil {
			return pathErr("rmdir", p, errNotDir)
		}
		return pathErr("rmdir", p, os.ErrNotExist)
	}
	prefix := key + "/"
	res, err := f.store().List(f.bucket, prefix, "", "", 2)
	if err != nil {
		return f.mapErr("rmdir", p, err)
	}
	for _, o := range res.Objects {
		if o.Key != prefix {
			return pathErr("rmdir", p, errNotEmpty)
		}
	}
	_ = f.store().Delete(f.bucket, prefix)
	f.log.Info("sftp rmdir", "key", prefix)
	return nil
}

// rename moves a file or a whole folder inside the bucket. Files are moved without copying their bytes.
func (f *fsys) rename(from, to string) error {
	fk, err := f.key(from)
	if err != nil || fk == "" {
		return pathErr("rename", from, errIsDirOr(err))
	}
	tk, err := f.key(to)
	if err != nil || tk == "" {
		return pathErr("rename", to, errIsDirOr(err))
	}
	if fk == tk {
		return nil
	}
	if f.parentIsFile(tk) {
		return pathErr("rename", to, errNotDir)
	}
	if _, err := f.store().Stat(f.bucket, fk); err == nil { // file
		if f.isDir(tk) {
			return pathErr("rename", to, errIsDir)
		}
		if err := f.store().Rename(f.bucket, fk, tk); err != nil {
			return f.mapErr("rename", from, err)
		}
		f.log.Info("sftp rename", "from", fk, "to", tk)
		return nil
	}
	if !f.isDir(fk) {
		return pathErr("rename", from, os.ErrNotExist)
	}
	if strings.HasPrefix(tk+"/", fk+"/") {
		return pathErr("rename", to, errors.New("cannot move a directory into itself"))
	}
	if _, err := f.store().Stat(f.bucket, tk); err == nil {
		return pathErr("rename", to, os.ErrExist)
	}
	if res, _ := f.store().List(f.bucket, tk+"/", "", "", 2); len(res.Objects) > 1 || (len(res.Objects) == 1 && res.Objects[0].Key != tk+"/") {
		return pathErr("rename", to, errNotEmpty)
	}
	var keys []string
	after := ""
	for {
		res, err := f.store().List(f.bucket, fk+"/", "", after, 1000)
		if err != nil {
			return f.mapErr("rename", from, err)
		}
		for _, o := range res.Objects {
			keys = append(keys, o.Key)
		}
		if !res.Truncated {
			break
		}
		after = res.Next
	}
	for _, k := range keys {
		if err := f.store().Rename(f.bucket, k, tk+"/"+strings.TrimPrefix(k, fk+"/")); err != nil {
			return f.mapErr("rename", from, fmt.Errorf("moving %q: %w", k, err))
		}
	}
	f.log.Info("sftp rename", "from", fk+"/", "to", tk+"/", "objects", len(keys))
	return nil
}

