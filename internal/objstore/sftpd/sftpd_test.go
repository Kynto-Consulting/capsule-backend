package sftpd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/kynto/capsule/backend/internal/objstore"
)

type memAuth struct {
	mu     sync.Mutex
	meta   map[string]*objstore.BucketInfo
	limits map[string]objstore.Limits
	keys   map[string][]AuthorizedKey
}

func (m *memAuth) Bucket(_ context.Context, n string) (*objstore.BucketInfo, error) {
	if b, ok := m.meta[n]; ok {
		return b, nil
	}
	return nil, objstore.ErrNotFound
}
func (m *memAuth) Credential(context.Context, string) (*objstore.Credential, error) {
	return nil, objstore.ErrNotFound
}
func (m *memAuth) Limits(_ context.Context, b string) (objstore.Limits, error) { return m.limits[b], nil }

func (m *memAuth) Resolve(_ context.Context, user string) (string, error) {
	if _, ok := m.meta[user]; ok {
		return user, nil
	}
	return "", ErrNoUser
}
func (m *memAuth) Secret(_ context.Context, b string) (string, error) { return "secret-" + b, nil }
func (m *memAuth) AuthorizedKeys(_ context.Context, b string) ([]AuthorizedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys[b], nil
}
func (m *memAuth) KeyUsed(context.Context, string) {}

type rig struct {
	t    *testing.T
	st   *objstore.Store
	auth *memAuth
	srv  *Server
	addr string
	host ssh.PublicKey
}

func newRig(t *testing.T, mod func(*Config)) *rig {
	t.Helper()
	st, err := objstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := &memAuth{meta: map[string]*objstore.BucketInfo{}, limits: map[string]objstore.Limits{}, keys: map[string][]AuthorizedKey{}}
	for _, b := range []string{"alpha-files", "beta-files"} {
		if err := st.CreateBucket(b); err != nil {
			t.Fatal(err)
		}
		a.meta[b] = &objstore.BucketInfo{Name: b, OrgID: "o", ProjectID: "p"}
		a.limits[b] = objstore.Limits{ProjectBuckets: []string{"alpha-files", "beta-files"}, OrgBuckets: []string{"alpha-files", "beta-files"}}
	}
	hk, err := LoadOrCreateHostKey(filepath.Join(t.TempDir(), "host"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Objects: &objstore.Server{Store: st, Meta: a}, Auth: a, HostKey: hk, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		FailDelay: time.Millisecond, ConnBytesPerSec: -1, TotalBytesPerSec: -1}
	if mod != nil {
		mod(&cfg)
	}
	srv := New(cfg)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return &rig{t, st, a, srv, l.Addr().String(), hk.PublicKey()}
}

func (r *rig) ssh(user string, auth ...ssh.AuthMethod) (*ssh.Client, error) {
	return ssh.Dial("tcp", r.addr, &ssh.ClientConfig{User: user, Auth: auth, HostKeyCallback: ssh.FixedHostKey(r.host), Timeout: 5 * time.Second})
}

func (r *rig) sftp(bucket string) *sftp.Client {
	r.t.Helper()
	c, err := r.ssh(bucket, ssh.Password("secret-"+bucket))
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { c.Close() })
	cl, err := sftp.NewClient(c)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { cl.Close() })
	return cl
}

func put(t *testing.T, c *sftp.Client, p string, data []byte) {
	t.Helper()
	f, err := c.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, c *sftp.Client, p string) []byte {
	t.Helper()
	f, err := c.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBasicOperations(t *testing.T) {
	r := newRig(t, nil)
	c := r.sftp("alpha-files")
	if err := c.MkdirAll("/docs/2026"); err != nil {
		t.Fatal(err)
	}
	put(t, c, "/docs/2026/a.txt", []byte("hello world"))
	put(t, c, "/docs/b.bin", bytes.Repeat([]byte{7}, 1000))
	put(t, c, "root.txt", []byte("x"))

	root, err := c.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range root {
		names[e.Name()] = e.IsDir()
	}
	if len(names) != 2 || !names["docs"] || names["root.txt"] {
		t.Fatalf("root listing: %v", names)
	}
	docs, _ := c.ReadDir("/docs")
	if len(docs) != 2 {
		t.Fatalf("docs listing: %d", len(docs))
	}
	st, err := c.Stat("/docs/2026/a.txt")
	if err != nil || st.Size() != 11 || st.IsDir() {
		t.Fatalf("stat: %v %v", st, err)
	}
	if d, err := c.Stat("/docs/2026"); err != nil || !d.IsDir() {
		t.Fatalf("dir stat: %v %v", d, err)
	}
	if string(get(t, c, "/docs/2026/a.txt")) != "hello world" {
		t.Fatal("download differs")
	}
	// range read
	f, _ := c.Open("/docs/2026/a.txt")
	buf := make([]byte, 5)
	if _, err := f.ReadAt(buf, 6); err != nil || string(buf) != "world" {
		t.Fatalf("range: %q %v", buf, err)
	}
	f.Close()
	// object as the S3 API sees it
	if o, err := r.st.Stat("alpha-files", "docs/2026/a.txt"); err != nil || o.Size != 11 {
		t.Fatalf("engine object: %v %v", o, err)
	}
	// rename a file and a folder
	if err := c.Rename("/docs/b.bin", "/docs/c.bin"); err != nil {
		t.Fatal(err)
	}
	if err := c.PosixRename("/docs", "/papers"); err != nil {
		t.Fatal(err)
	}
	if string(get(t, c, "/papers/2026/a.txt")) != "hello world" {
		t.Fatal("moved folder content")
	}
	if _, err := c.Stat("/docs/2026/a.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old path still there: %v", err)
	}
	// rmdir of a non-empty folder fails, remove then rmdir works
	if err := c.RemoveDirectory("/papers/2026"); err == nil {
		t.Fatal("rmdir of non-empty folder succeeded")
	}
	if err := c.Remove("/papers/2026/a.txt"); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveDirectory("/papers/2026"); err != nil {
		t.Fatal(err)
	}
	if err := c.Remove("/papers"); err == nil {
		t.Fatal("remove of a folder succeeded")
	}
	if _, err := c.Open("/papers"); err == nil {
		t.Fatal("open of a folder for reading succeeded")
	}
	if err := c.Mkdir("/papers"); err == nil {
		t.Fatal("mkdir of an existing folder succeeded")
	}
	if err := c.Remove("/missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove missing: %v", err)
	}
	if err := c.Symlink("/root.txt", "/link"); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := c.ReadLink("/root.txt"); err == nil {
		t.Fatal("readlink accepted")
	}
}

func TestLargeListingPaginates(t *testing.T) {
	r := newRig(t, nil)
	for i := 0; i < 2300; i++ {
		if _, err := r.st.PutEmpty("alpha-files", "many/f"+strings.Repeat("0", 5-len(itoa(i)))+itoa(i), ""); err != nil {
			t.Fatal(err)
		}
	}
	c := r.sftp("alpha-files")
	ents, err := c.ReadDir("/many")
	if err != nil || len(ents) != 2300 {
		t.Fatalf("listed %d, %v", len(ents), err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// A big upload that the connection loses half way is resumed from the stored size and ends byte-identical.
func TestBigUploadResume(t *testing.T) {
	r := newRig(t, nil)
	const total = 66 << 20
	data := make([]byte, total)
	rand.Read(data)
	sum := md5.Sum(data)

	user := "alpha-files"
	conn, err := r.ssh(user, ssh.Password("secret-"+user))
	if err != nil {
		t.Fatal(err)
	}
	cl, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	f, err := cl.OpenFile("/backups/big.bin", os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		t.Fatal(err)
	}
	const cut = 30 << 20
	for off := 0; off < cut; off += 1 << 20 {
		if _, err := f.Write(data[off : off+1<<20]); err != nil {
			t.Fatal(err)
		}
	}
	conn.Close() // the connection dies without closing the file
	cl.Close()

	var stored int64
	for i := 0; i < 100; i++ {
		if o, err := r.st.Stat("alpha-files", "backups/big.bin"); err == nil {
			stored = o.Size
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if stored != cut {
		t.Fatalf("partial object size %d, want %d", stored, cut)
	}

	c2 := r.sftp("alpha-files")
	st, err := c2.Stat("/backups/big.bin")
	if err != nil || st.Size() != cut {
		t.Fatalf("remote size %v %v", st, err)
	}
	f2, err := c2.OpenFile("/backups/big.bin", os.O_WRONLY|os.O_CREATE) // no truncate: resume
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f2.Seek(st.Size(), io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(f2, bytes.NewReader(data[cut:])); err != nil {
		t.Fatal(err)
	}
	if err := f2.Close(); err != nil {
		t.Fatal(err)
	}
	o, err := r.st.Stat("alpha-files", "backups/big.bin")
	if err != nil || o.Size != total || o.ETag != hex.EncodeToString(sum[:]) {
		t.Fatalf("final object %+v %v", o, err)
	}
	back := get(t, c2, "/backups/big.bin")
	if sha256.Sum256(back) != sha256.Sum256(data) {
		t.Fatal("downloaded content differs")
	}
	if r.st.Inflight("alpha-files") != 0 {
		t.Fatalf("reservation leaked: %d", r.st.Inflight("alpha-files"))
	}
}

func TestAbortedOverwriteKeepsOldObject(t *testing.T) {
	r := newRig(t, nil)
	c := r.sftp("alpha-files")
	put(t, c, "/keep.txt", []byte("original"))
	conn, _ := r.ssh("alpha-files", ssh.Password("secret-alpha-files"))
	cl, _ := sftp.NewClient(conn)
	f, err := cl.OpenFile("/keep.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("partial"))
	conn.Close()
	time.Sleep(300 * time.Millisecond)
	if string(get(t, c, "/keep.txt")) != "original" {
		t.Fatal("an aborted overwrite replaced the object")
	}
}

func TestQuota(t *testing.T) {
	r := newRig(t, nil)
	r.auth.meta["alpha-files"].MaxBytes = 1 << 20
	c := r.sftp("alpha-files")
	f, err := c.Create("/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(bytes.Repeat([]byte{1}, 2<<20))
	if err == nil {
		err = f.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "quota") && !strings.Contains(err.Error(), "ailure") {
		t.Fatalf("want a quota error, got %v", err)
	}
	f.Close()
	if r.st.Usage("alpha-files") > 1<<20 {
		t.Fatalf("usage %d is over the cap", r.st.Usage("alpha-files"))
	}
	if r.st.Inflight("alpha-files") != 0 {
		t.Fatalf("reservation leaked: %d", r.st.Inflight("alpha-files"))
	}
	// within the cap still works, and overwriting an object only needs the difference
	put(t, c, "/ok.bin", bytes.Repeat([]byte{2}, 900<<10))
	put(t, c, "/ok.bin", bytes.Repeat([]byte{3}, 950<<10))
}

func TestQuotaConcurrentReservations(t *testing.T) {
	r := newRig(t, nil)
	r.auth.meta["alpha-files"].MaxBytes = 1 << 20
	var wg sync.WaitGroup
	var okc int
	var mu sync.Mutex
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := r.sftp("alpha-files")
			f, err := c.Create("/c" + itoa(i))
			if err != nil {
				return
			}
			_, err = f.Write(bytes.Repeat([]byte{9}, 700<<10))
			if err == nil {
				err = f.Close()
			}
			if err == nil {
				mu.Lock()
				okc++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if okc > 1 || r.st.Usage("alpha-files") > 1<<20 || r.st.Inflight("alpha-files") != 0 {
		t.Fatalf("%d uploads fit a 1 MiB bucket, usage %d, inflight %d", okc, r.st.Usage("alpha-files"), r.st.Inflight("alpha-files"))
	}
}

func TestBucketIsolationAndPathEscape(t *testing.T) {
	r := newRig(t, nil)
	if _, err := r.st.PutEmpty("beta-files", "secret.txt", ""); err != nil {
		t.Fatal(err)
	}
	beta := r.sftp("beta-files")
	put(t, beta, "/private.txt", []byte("beta only"))
	c := r.sftp("alpha-files")

	// alpha's password does not open beta, and the reverse
	if _, err := r.ssh("beta-files", ssh.Password("secret-alpha-files")); err == nil {
		t.Fatal("alpha secret opened beta")
	}
	// an unknown bucket fails like a wrong secret
	if _, err := r.ssh("nope-nope", ssh.Password("x")); err == nil {
		t.Fatal("unknown user accepted")
	}
	for _, p := range []string{"/../secret.txt", "//secret.txt", "/a/../../secret.txt", "../../beta-files/secret.txt", "/beta-files/secret.txt",
		"/../private.txt", `\..\secret.txt`, "/%2e%2e/secret.txt"} {
		if _, err := c.Stat(p); err == nil {
			t.Errorf("alpha stat %q succeeded", p)
		}
		if f, err := c.Open(p); err == nil {
			f.Close()
			t.Errorf("alpha open %q succeeded", p)
		}
	}
	ents, _ := c.ReadDir("/..")
	if len(ents) != 0 {
		t.Fatalf("alpha root is not empty: %v", ents)
	}
	// a write that tries to climb out lands inside alpha, never in beta
	put(t, c, "/../../evil.txt", []byte("e"))
	if _, err := r.st.Stat("alpha-files", "evil.txt"); err != nil {
		t.Fatal("clamped write missing in alpha")
	}
	if _, err := r.st.Stat("beta-files", "evil.txt"); err == nil {
		t.Fatal("write escaped into beta")
	}
	if err := c.Rename("/evil.txt", "/../../../beta-files/evil.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.st.Stat("beta-files", "beta-files/evil.txt"); err == nil {
		t.Fatal("rename escaped into beta")
	}
	// nothing outside the bucket directories is created by any of this
	if entries, _ := os.ReadDir(filepath.Dir(r.st.Root())); len(entries) > 3 {
		t.Fatalf("unexpected host entries: %v", entries)
	}
	if _, err := c.RealPath("/../../.."); err != nil {
		t.Fatal(err)
	}
	if p, _ := c.RealPath("/a/../../.."); p != "/" {
		t.Fatalf("realpath %q", p)
	}
	// beta still sees only its own
	if _, err := beta.Stat("/private.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Stat("/private.txt"); err == nil {
		t.Fatal("alpha sees beta's file")
	}
}

func TestPublicKeyAuth(t *testing.T) {
	r := newRig(t, nil)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	signer, _ := ssh.NewSignerFromKey(priv)
	r.auth.keys["alpha-files"] = []AuthorizedKey{{ID: "k1", Key: sp}}

	c, err := r.ssh("alpha-files", ssh.PublicKeys(signer))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cl, err := sftp.NewClient(c)
	if err != nil {
		t.Fatal(err)
	}
	put(t, cl, "/k.txt", []byte("by key"))
	// the same key is not valid for another bucket
	if _, err := r.ssh("beta-files", ssh.PublicKeys(signer)); err == nil {
		t.Fatal("key of alpha opened beta")
	}
	// an unregistered key is refused
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	os2, _ := ssh.NewSignerFromKey(other)
	if _, err := r.ssh("alpha-files", ssh.PublicKeys(os2)); err == nil {
		t.Fatal("unregistered key accepted")
	}
}

func TestLoginBlockAfterFailures(t *testing.T) {
	r := newRig(t, func(c *Config) { c.MaxFailures = 3 })
	for i := 0; i < 6; i++ {
		_, _ = r.ssh("alpha-files", ssh.Password("wrong"))
	}
	if _, err := r.ssh("alpha-files", ssh.Password("secret-alpha-files")); err == nil {
		t.Fatal("login allowed while blocked")
	}
	// another user is unaffected
	if _, err := r.ssh("beta-files", ssh.Password("secret-beta-files")); err != nil {
		t.Fatal(err)
	}
}

func TestNoShellExecOrForwarding(t *testing.T) {
	r := newRig(t, nil)
	c, err := r.ssh("alpha-files", ssh.Password("secret-alpha-files"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, _ := c.NewSession()
	if err := s.Shell(); err == nil {
		t.Fatal("shell accepted")
	}
	s2, _ := c.NewSession()
	if out, err := s2.CombinedOutput("ls /"); err == nil {
		t.Fatalf("exec accepted: %s", out)
	}
	s3, _ := c.NewSession()
	if err := s3.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
		t.Fatal("pty accepted")
	}
	s4, _ := c.NewSession()
	if err := s4.Setenv("A", "b"); err == nil {
		t.Fatal("env accepted")
	}
	if conn, err := c.Dial("tcp", "127.0.0.1:22"); err == nil {
		conn.Close()
		t.Fatal("direct-tcpip accepted")
	}
	if l, err := c.Listen("tcp", "127.0.0.1:0"); err == nil {
		l.Close()
		t.Fatal("remote forwarding accepted")
	}
	if ok, _, _ := c.SendRequest("auth-agent-req@openssh.com", true, nil); ok {
		t.Fatal("agent forwarding accepted")
	}
	s5, _ := c.NewSession()
	if err := s5.RequestSubsystem("netconf"); err == nil {
		t.Fatal("other subsystem accepted")
	}
}

func TestOversizedPacketDropsConnection(t *testing.T) {
	r := newRig(t, nil)
	c, err := r.ssh("alpha-files", ssh.Password("secret-alpha-files"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, _ := c.NewSession()
	w, _ := s.StdinPipe()
	rd, _ := s.StdoutPipe()
	if err := s.RequestSubsystem("sftp"); err != nil {
		t.Fatal(err)
	}
	// SSH_FXP_INIT with a 1 GiB declared length
	hdr := make([]byte, 5)
	binary.BigEndian.PutUint32(hdr, 1<<30)
	hdr[4] = 1
	w.Write(hdr)
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, rd); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server kept reading an oversized packet")
	}
}

func TestConnectionLimitsAndIdle(t *testing.T) {
	r := newRig(t, func(c *Config) { c.MaxConnsPerBucket = 1; c.IdleTimeout = 400 * time.Millisecond })
	c := r.sftp("alpha-files")
	if conn, err := r.ssh("alpha-files", ssh.Password("secret-alpha-files")); err == nil {
		if _, err := sftp.NewClient(conn); err == nil {
			t.Fatal("second connection to the same bucket allowed")
		}
		conn.Close()
	}
	// a client that says nothing is dropped
	time.Sleep(900 * time.Millisecond)
	if _, err := c.Stat("/"); err == nil {
		t.Fatal("idle connection survived")
	}
}

func TestBandwidthLimit(t *testing.T) {
	r := newRig(t, func(c *Config) { c.ConnBytesPerSec = 1 << 20 })
	c := r.sftp("alpha-files")
	start := time.Now()
	put(t, c, "/slow.bin", bytes.Repeat([]byte{1}, 3<<20))
	if d := time.Since(start); d < 1500*time.Millisecond {
		t.Fatalf("3 MiB at 1 MiB/s took only %v", d)
	}
}

func TestHostKeyPersists(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "host_key")
	a, err := LoadOrCreateHostKey(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateHostKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(a) != Fingerprint(b) || !strings.HasPrefix(Fingerprint(a), "SHA256:") {
		t.Fatal("host key changed between loads")
	}
}

func TestKeyParsing(t *testing.T) {
	r := newRig(t, nil)
	c := r.sftp("alpha-files")
	for _, k := range []string{"", ".", "a\x00b", strings.Repeat("a/", 600)} {
		if f, err := c.Create("/" + k); err == nil {
			f.Close()
			t.Errorf("created invalid path %q", k)
		}
	}
	if f, err := c.Create("/"); err == nil {
		f.Close()
		t.Error("created the root as a file")
	}
}

func TestDotDotResolvesToRoot(t *testing.T) {
	r := newRig(t, nil)
	c := r.sftp("alpha-files")
	for _, p := range []string{"..", "/./../..", "/a/../.."} {
		st, err := c.Stat(p)
		if err != nil || !st.IsDir() {
			t.Errorf("%q: %v %v", p, st, err)
		}
	}
}
