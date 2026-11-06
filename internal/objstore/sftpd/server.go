package sftpd

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"

	"github.com/kynto/capsule/backend/internal/objstore"
)

// ErrNoUser is returned by Auth.Resolve for a user name that maps to no bucket.
var ErrNoUser = errors.New("unknown user")

// AuthorizedKey is an SSH public key registered for a bucket.
type AuthorizedKey struct {
	ID  string
	Key ssh.PublicKey
}

// Auth is the control-plane side: who may enter which bucket.
type Auth interface {
	// Resolve maps the SSH user name (bucket name, "<project>-<name>" or the access key) to a bucket name.
	Resolve(ctx context.Context, user string) (string, error)
	// Secret is the plaintext secret key of the bucket (the SFTP password).
	Secret(ctx context.Context, bucket string) (string, error)
	AuthorizedKeys(ctx context.Context, bucket string) ([]AuthorizedKey, error)
	KeyUsed(ctx context.Context, id string)
}

// Config tunes the server. Zero values mean the documented defaults; a negative bandwidth means unlimited.
type Config struct {
	Objects *objstore.Server
	Auth    Auth
	HostKey ssh.Signer
	Log     *slog.Logger

	MaxConns          int           // total simultaneous connections (default 128)
	MaxConnsPerIP     int           // per remote address, counted before login (default 64: behind the gateway they share one)
	MaxConnsPerBucket int           // per bucket after login (default 8)
	HandshakeTimeout  time.Duration // from accept to a finished login (default 20s)
	IdleTimeout       time.Duration // no traffic from the client (default 10m)
	ConnBytesPerSec   int64         // per connection, each direction (default 40 MiB/s)
	TotalBytesPerSec  int64         // all connections, each direction (default 120 MiB/s)
	MaxObjectBytes    int64         // one uploaded object (default 0: only the quotas apply)
	MaxOpenFiles      int           // open handles per connection (default 64)
	MaxFailures       int           // failed logins per (address, user) per FailWindow before a block (default 10)
	FailWindow        time.Duration // default 5m
	FailDelay         time.Duration // pause before answering a failed login (default 400ms)
}

func (c *Config) defaults() {
	def := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	def(&c.MaxConns, 128)
	def(&c.MaxConnsPerIP, 64)
	def(&c.MaxConnsPerBucket, 8)
	def(&c.MaxOpenFiles, 64)
	def(&c.MaxFailures, 10)
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 20 * time.Second
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 10 * time.Minute
	}
	if c.ConnBytesPerSec == 0 {
		c.ConnBytesPerSec = 40 << 20
	}
	if c.TotalBytesPerSec == 0 {
		c.TotalBytesPerSec = 120 << 20
	}
	if c.FailWindow == 0 {
		c.FailWindow = 5 * time.Minute
	}
	if c.FailDelay == 0 {
		c.FailDelay = 400 * time.Millisecond
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
}

// Server is the SFTP listener.
type Server struct {
	cfg    Config
	ssh    *ssh.ServerConfig
	global *rate.Limiter

	mu       sync.Mutex
	total    int
	perIP    map[string]int
	perBkt   map[string]int
	fails    map[string]*failState
	listener net.Listener
	closing  bool
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

type failState struct {
	n     int
	reset time.Time
}

// New builds a server; call Serve with a listener.
func New(cfg Config) *Server {
	cfg.defaults()
	s := &Server{cfg: cfg, global: newLimiter(cfg.TotalBytesPerSec), perIP: map[string]int{}, perBkt: map[string]int{}, fails: map[string]*failState{}}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	sc := &ssh.ServerConfig{
		MaxAuthTries:  4,
		ServerVersion: "SSH-2.0-CapsuleSFTP",
		PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			return s.authPassword(m, pw)
		},
		PublicKeyCallback: func(m ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			return s.authKey(m, k)
		},
	}
	sc.AddHostKey(cfg.HostKey)
	s.ssh = sc
	return s
}

var errAuth = errors.New("permission denied")

func (s *Server) failKey(m ssh.ConnMetadata) string {
	return hostOf(m.RemoteAddr().String()) + "|" + strings.ToLower(m.User())
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func (s *Server) blocked(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.fails[key]
	return f != nil && time.Now().Before(f.reset) && f.n >= s.cfg.MaxFailures
}

func (s *Server) fail(m ssh.ConnMetadata, method string) error {
	key := s.failKey(m)
	s.mu.Lock()
	f := s.fails[key]
	if f == nil || time.Now().After(f.reset) {
		f = &failState{reset: time.Now().Add(s.cfg.FailWindow)}
		s.fails[key] = f
	}
	f.n++
	if len(s.fails) > 10000 { // bounded memory under a spray of user names
		for k, v := range s.fails {
			if time.Now().After(v.reset) {
				delete(s.fails, k)
			}
		}
	}
	s.mu.Unlock()
	s.cfg.Log.Warn("sftp login failed", "user", m.User(), "remote", m.RemoteAddr().String(), "method", method)
	time.Sleep(s.cfg.FailDelay) // the same pause for an unknown user and a wrong secret
	return errAuth
}

func (s *Server) authPassword(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
	if s.blocked(s.failKey(m)) {
		return nil, s.fail(m, "password")
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	bucket, err := s.cfg.Auth.Resolve(ctx, m.User())
	if err != nil {
		return nil, s.fail(m, "password")
	}
	secret, err := s.cfg.Auth.Secret(ctx, bucket)
	if err != nil || secret == "" || subtle.ConstantTimeCompare([]byte(secret), pw) != 1 {
		return nil, s.fail(m, "password")
	}
	return &ssh.Permissions{Extensions: map[string]string{"bucket": bucket, "method": "password"}}, nil
}

func (s *Server) authKey(m ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
	if s.blocked(s.failKey(m)) {
		return nil, s.fail(m, "publickey")
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	bucket, err := s.cfg.Auth.Resolve(ctx, m.User())
	if err != nil {
		return nil, s.fail(m, "publickey")
	}
	keys, err := s.cfg.Auth.AuthorizedKeys(ctx, bucket)
	if err != nil {
		return nil, s.fail(m, "publickey")
	}
	for _, ak := range keys {
		if bytes.Equal(ak.Key.Marshal(), k.Marshal()) {
			go s.cfg.Auth.KeyUsed(context.Background(), ak.ID)
			return &ssh.Permissions{Extensions: map[string]string{"bucket": bucket, "method": "publickey", "key": ak.ID}}, nil
		}
	}
	return nil, s.fail(m, "publickey")
}

// Serve accepts connections until the listener closes or Close is called.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()
	s.cfg.Objects.Store.SweepStaging(24 * time.Hour)
	for {
		nc, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if !s.admit(nc) {
			_ = nc.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(nc)
		}()
	}
}

func (s *Server) admit(nc net.Conn) bool {
	ip := hostOf(nc.RemoteAddr().String())
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total >= s.cfg.MaxConns || s.perIP[ip] >= s.cfg.MaxConnsPerIP {
		s.cfg.Log.Warn("sftp connection refused: limit", "remote", nc.RemoteAddr().String())
		return false
	}
	s.total++
	s.perIP[ip]++
	return true
}

func (s *Server) release(nc net.Conn) {
	ip := hostOf(nc.RemoteAddr().String())
	s.mu.Lock()
	s.total--
	if s.perIP[ip]--; s.perIP[ip] <= 0 {
		delete(s.perIP, ip)
	}
	s.mu.Unlock()
}

// Close stops accepting, drops every connection and waits for them.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closing = true
	l := s.listener
	s.mu.Unlock()
	s.cancel()
	var err error
	if l != nil {
		err = l.Close()
	}
	s.wg.Wait()
	return err
}

func (s *Server) handle(nc net.Conn) {
	defer s.release(nc)
	defer nc.Close()
	lc := &limitedConn{Conn: nc, idle: s.cfg.IdleTimeout, conn: newLimiter(s.cfg.ConnBytesPerSec), global: s.global, ctx: s.ctx}
	_ = nc.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	sc, chans, reqs, err := ssh.NewServerConn(lc, s.ssh)
	if err != nil {
		return
	}
	_ = nc.SetDeadline(time.Time{})
	lc.active.Store(true)
	defer sc.Close()
	go func() { // server shutdown drops live sessions
		<-s.ctx.Done()
		sc.Close()
	}()
	bucket := sc.Permissions.Extensions["bucket"]
	if !s.enterBucket(bucket) {
		s.cfg.Log.Warn("sftp connection refused: bucket limit", "bucket", bucket, "remote", nc.RemoteAddr().String())
		return
	}
	defer s.leaveBucket(bucket)
	start := time.Now()
	log := s.cfg.Log.With("bucket", bucket, "user", sc.User(), "remote", nc.RemoteAddr().String(), "method", sc.Permissions.Extensions["method"])
	log.Info("sftp login")
	defer func() {
		log.Info("sftp disconnect", "seconds", int(time.Since(start).Seconds()), "bytes_in", lc.rx.Load(), "bytes_out", lc.tx.Load())
	}()
	go ssh.DiscardRequests(reqs) // global requests (tcpip-forward, ...) are all refused
	fs := newFS(s, bucket, log)
	var sessions int
	for ch := range chans {
		if ch.ChannelType() != "session" || sessions >= 8 { // no direct-tcpip, x11 or agent channels
			_ = ch.Reject(ssh.UnknownChannelType, "only sftp sessions are allowed")
			continue
		}
		sessions++
		c, creqs, err := ch.Accept()
		if err != nil {
			continue
		}
		go s.session(c, creqs, fs)
	}
}

func (s *Server) enterBucket(b string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perBkt[b] >= s.cfg.MaxConnsPerBucket {
		return false
	}
	s.perBkt[b]++
	return true
}

func (s *Server) leaveBucket(b string) {
	s.mu.Lock()
	if s.perBkt[b]--; s.perBkt[b] <= 0 {
		delete(s.perBkt, b)
	}
	s.mu.Unlock()
}

func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request, fs *fsys) {
	defer ch.Close()
	started := false
	for r := range reqs {
		// subsystem payload: uint32 length + name
		if r.Type == "subsystem" && !started && len(r.Payload) == 8 && string(r.Payload[4:]) == "sftp" {
			started = true
			_ = r.Reply(true, nil)
			rs := sftp.NewRequestServer(ch, sftp.Handlers{FileGet: fs, FilePut: fs, FileCmd: fs, FileList: fs}, sftp.WithRSMaxTxPacket(256<<10))
			go func() {
				_ = rs.Serve()
				_ = rs.Close()
				_ = ch.Close()
			}()
			continue
		}
		// shell, exec, pty-req, env, x11-req, auth-agent-req, a second subsystem...: all refused
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
	}
}
