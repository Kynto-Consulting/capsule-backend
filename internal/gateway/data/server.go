// Package data is the data plane of the Capsule gateway (docs/gateway/PLAN.md): it accepts connections, identifies the
// protocol from the first bytes (TLS with SNI/ALPN, PostgreSQL SSLRequest, clear HTTP, the capsule/1 tunnel), asks the
// control plane whether the connection is allowed and proxies bytes to the destination fixed by the route.
//
// Extension points for later packages: RegisterKind (new first-packet protocols), RegisterProtocol (how a route of a
// given protocol is proxied), the CertProvider (ACME/wildcard certificates) and the ControlPlane interface.
package data

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Dialer opens connections to destinations (net.Dialer satisfies it).
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Deps are the pluggable collaborators of a Server.
type Deps struct {
	Control ControlPlane // required
	Certs   CertProvider // nil disables TLS termination and the tunnel
	Dialer  Dialer       // nil = a net.Dialer that refuses link-local/metadata (and loopback unless allowed) destinations
	Logger  *slog.Logger
	Metrics *Metrics
}

// KindHandler serves a connection whose first bytes were classified as its kind. c.Head holds the bytes read so far.
type KindHandler interface {
	Serve(ctx context.Context, c *Conn)
}

// ProtocolHandler proxies an authorised connection to a route of a given protocol (route.Protocol).
// Implementations may call Server.Proxy for the default behaviour.
type ProtocolHandler interface {
	Proxy(ctx context.Context, s *Session)
}

// Event is the audit/log record of one connection (PROTOCOL.md section 13): no payload, no tokens.
type Event struct {
	Kind        Kind
	SNI         string
	RouteID     string
	ProjectID   string
	Principal   string
	AuthType    int
	Transport   int
	Status      int
	Code        uint16
	Result      string
	ClientID    string
	BytesIn     int64 // client to destination
	BytesOut    int64 // destination to client
	CloseReason string
	ReqHash     string // truncated hash of the project/service asked by an unauthenticated client
}

// Conn is an accepted client connection plus what the demux already knows about it.
type Conn struct {
	net.Conn
	Head      []byte     // bytes already read from the client and not yet consumed
	Src       netip.Addr // canonical remote address (IPv4-mapped IPv6 normalised)
	SrcPort   uint16
	Listener  string
	Start     time.Time
	PGClassic bool // TLS follows a PostgreSQL SSLRequest that the gateway already answered with 'S'
	Ev        Event

	srv     *Server
	preauth bool
}

// Session is an authorised connection ready to be proxied.
type Session struct {
	Conn     *Conn
	Route    *Route
	Hello    *Hello // nil for clear-text protocols
	Raw      []byte // the bytes read from the client to be replayed (ClientHello records or HTTP head)
	Decision Decision
}

type listener struct {
	spec  ListenerSpec
	ln    net.Listener
	allow map[Kind]bool
}

func (l *listener) allows(k Kind) bool { return len(l.allow) == 0 || l.allow[k] }

// Server is the gateway data plane.
type Server struct {
	cfg     Config
	log     *slog.Logger
	routes  *RouteManager
	authz   *Authorizer
	certs   CertProvider
	dialer  Dialer
	metrics *Metrics
	cgc     *CGCVerifier
	ip      *IPTracker
	rl      *RouteLimits
	udpLim  udpLimits
	udpm    *udpMetrics
	pool    *portPool

	sniffers      []Sniffer
	kindHandlers  map[Kind]KindHandler
	protoHandlers map[string]ProtocolHandler
	tunnelHosts   map[string]bool

	mu        sync.Mutex
	listeners []*listener
	started   bool

	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup // open client connections
	bg       sync.WaitGroup // background goroutines
	active   atomic.Int64
	draining atomic.Bool
	conns    sync.Map // *Conn -> struct{}
}

// New builds a Server. Start binds the listeners.
func New(cfg Config, d Deps) (*Server, error) {
	if d.Control == nil {
		return nil, errors.New("a ControlPlane is required")
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if d.Metrics == nil {
		d.Metrics = NewMetrics()
	}
	def := DefaultConfig()
	fill := func(dst *time.Duration, v time.Duration) {
		if *dst == 0 {
			*dst = v
		}
	}
	fill(&cfg.HelloTimeout, def.HelloTimeout)
	fill(&cfg.DialTimeout, def.DialTimeout)
	fill(&cfg.HalfCloseIdle, def.HalfCloseIdle)
	fill(&cfg.AuthTimeout, def.AuthTimeout)
	fill(&cfg.DrainGrace, def.DrainGrace)
	cfg.UDP.fill()
	cfg.Pool.fill()
	if cfg.MaxHelloBytes <= 0 {
		cfg.MaxHelloBytes = def.MaxHelloBytes
	}
	if cfg.MaxHTTPHead <= 0 {
		cfg.MaxHTTPHead = def.MaxHTTPHead
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = def.MaxConns
	}
	s := &Server{
		cfg:           cfg,
		log:           d.Logger,
		certs:         d.Certs,
		dialer:        d.Dialer,
		metrics:       d.Metrics,
		sniffers:      BuiltinSniffers(),
		kindHandlers:  map[Kind]KindHandler{},
		protoHandlers: map[string]ProtocolHandler{},
		tunnelHosts:   cfg.TunnelHostSet(),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.routes = &RouteManager{CP: d.Control, Log: d.Logger, Wait: cfg.RoutesWait, MaxAge: cfg.RoutesMaxAge, CacheFile: cfg.RoutesCache, OnChange: s.onRoutes}
	s.authz = &Authorizer{CP: d.Control, Timeout: cfg.AuthTimeout, StaleGrace: cfg.AuthStale}
	s.ip = &IPTracker{MaxPre: cfg.MaxPreauthPerIP, Rate: cfg.NewConnsPerIP}
	s.rl = &RouteLimits{DefaultMax: cfg.RouteMaxConns, DefaultMaxIP: cfg.RouteMaxConnsIP, RouteRate: cfg.RouteConnRate}
	s.udpm = newUDPMetrics(d.Metrics.Reg)
	s.pool = newPortPool(s)
	if len(cfg.CGCKeys) > 0 {
		s.cgc = &CGCVerifier{Keys: cfg.CGCKeys}
	}
	if s.dialer == nil {
		s.dialer = &net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 30 * time.Second, Control: s.destControl}
	}
	s.kindHandlers[KindTLS] = KindHandlerFunc(s.serveTLS)
	s.kindHandlers[KindPGSSL] = KindHandlerFunc(s.servePG)
	s.kindHandlers[KindHTTP] = KindHandlerFunc(s.serveHTTP)
	s.kindHandlers[KindSSH] = KindHandlerFunc(func(ctx context.Context, c *Conn) {
		c.Ev.Result = "unsupported"
		c.Conn.Close() // SSH goes through TLS (ProxyCommand) or the tunnel; port 22 stays with Forgejo
	})
	reg := s.metrics.Reg
	reg.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "gw_routes_age_seconds", Help: "Seconds since the control plane was last reached."}, func() float64 { return s.routes.Age().Seconds() }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "gw_control_up", Help: "1 if the last control plane request succeeded."}, func() float64 {
			if s.routes.ControlUp() {
				return 1
			}
			return 0
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "gw_auth_cache_entries", Help: "Cached authorisation decisions."}, func() float64 { return float64(s.authz.CacheLen()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "gw_tracked_ips", Help: "Source IPs with limiter state."}, func() float64 { return float64(s.ip.Size()) }),
	)
	return s, nil
}

// KindHandlerFunc adapts a function to KindHandler.
type KindHandlerFunc func(ctx context.Context, c *Conn)

// Serve implements KindHandler.
func (f KindHandlerFunc) Serve(ctx context.Context, c *Conn) { f(ctx, c) }

// RegisterKind adds (or replaces) a first-packet protocol: its sniffer is consulted after the built-in ones.
// Must be called before Start.
func (s *Server) RegisterKind(sn Sniffer, h KindHandler) {
	for i, e := range s.sniffers {
		if e.Kind() == sn.Kind() {
			s.sniffers[i] = sn
			s.kindHandlers[sn.Kind()] = h
			return
		}
	}
	s.sniffers = append(s.sniffers, sn)
	s.kindHandlers[sn.Kind()] = h
}

// RegisterProtocol sets how routes with the given Route.Protocol are proxied (default: Server.Proxy).
func (s *Server) RegisterProtocol(protocol string, h ProtocolHandler) { s.protoHandlers[protocol] = h }

// SetCertProvider replaces the certificate source (used by the ACME package before Start).
func (s *Server) SetCertProvider(c CertProvider) { s.certs = c }

// Routes exposes the route manager (readiness, tests, bootstrap).
func (s *Server) Routes() *RouteManager { return s.routes }

// Draining reports whether Drain started.
func (s *Server) Draining() bool { return s.draining.Load() }

// Active is the number of open client connections.
func (s *Server) Active() int64 { return s.active.Load() }

// Addrs lists the bound listener addresses.
func (s *Server) Addrs() []net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []net.Addr
	for _, l := range s.listeners {
		out = append(out, l.ln.Addr())
	}
	return out
}

func (s *Server) onRoutes(old, nw *Table) {
	s.metrics.RouteRev.Set(float64(nw.Rev))
	s.metrics.RoutesLoaded.Set(float64(nw.Len()))
	s.forgetUDPRoutes(old, nw)
	s.pool.Reconcile(nw)
	if old != nil {
		for _, r := range old.Routes() {
			if nw.byID[r.ID] == nil {
				lbl := prometheus.Labels{"route": r.ID}
				s.metrics.ConnsActive.DeletePartialMatch(lbl)
				s.metrics.ConnsTotal.DeletePartialMatch(lbl)
				s.metrics.BytesTotal.DeletePartialMatch(lbl)
			}
		}
	}
}

// destControl is the SSRF guard applied to the address actually dialled (after name resolution).
func (s *Server) destControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("bad destination")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return errors.New("bad destination")
	}
	ip = ip.Unmap()
	switch {
	case ip.IsUnspecified(), ip.IsMulticast(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return errors.New("destination address not allowed")
	case ip.IsLoopback() && !s.cfg.AllowLoopbackDest:
		return errors.New("destination address not allowed")
	}
	return nil
}

// Start binds the listeners and starts the background work. It returns once every listener is bound.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("already started")
	}
	var ls []*listener
	for _, sp := range s.cfg.Listeners {
		ln, err := listenTCP(ctx, sp.Addr, s.cfg.ReusePort)
		if err != nil {
			for _, l := range ls {
				l.ln.Close()
			}
			return fmt.Errorf("listen %s: %w", sp.Addr, err)
		}
		l := &listener{spec: sp, ln: ln}
		if len(sp.Allow) > 0 {
			l.allow = map[Kind]bool{}
			for _, k := range sp.Allow {
				l.allow[k] = true
			}
		}
		ls = append(ls, l)
	}
	s.listeners = ls
	s.started = true
	s.pool.setReserved(ls)
	if s.cfg.RoutesCache != "" {
		s.routes.LoadCache()
	}
	s.bg.Add(2)
	go func() { defer s.bg.Done(); s.routes.Run(s.ctx) }()
	go func() { defer s.bg.Done(); s.sweeper() }()
	for _, l := range ls {
		s.bg.Add(1)
		go func(l *listener) { defer s.bg.Done(); s.acceptLoop(l) }(l)
		s.log.Info("listening", "addr", l.ln.Addr().String(), "kinds", kindNames(l.spec.Allow))
	}
	return nil
}

func kindNames(k []Kind) []string {
	if len(k) == 0 {
		return []string{"all"}
	}
	out := make([]string, len(k))
	for i := range k {
		out[i] = string(k[i])
	}
	return out
}

func (s *Server) sweeper() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.authz.Sweep()
			s.ip.Sweep()
			if s.cgc != nil {
				s.cgc.Sweep(time.Now())
			}
			if tb := s.routes.Table(); tb != nil {
				s.rl.Forget(tb.HasRoute)
				s.pool.Retry()
			}
		}
	}
}

func (s *Server) acceptLoop(l *listener) {
	var delay time.Duration
	for {
		raw, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// e.g. EMFILE: back off instead of spinning
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			s.log.Warn("accept failed", "err", err.Error())
			time.Sleep(delay)
			continue
		}
		delay = 0
		if s.active.Load() >= int64(s.cfg.MaxConns) {
			s.metrics.Dropped.WithLabelValues(LimitProcess).Inc()
			raw.Close()
			continue
		}
		s.active.Add(1)
		s.metrics.ActiveTotal.Inc()
		s.wg.Add(1)
		go s.serveConn(raw, l)
	}
}

func canonicalRemote(a net.Addr) (netip.Addr, uint16) {
	if ta, ok := a.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(ta.IP); ok {
			return ip.Unmap().WithZone(""), uint16(ta.Port)
		}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}, 0
	}
	return ap.Addr().Unmap().WithZone(""), ap.Port()
}

func (s *Server) serveConn(raw net.Conn, l *listener) {
	c := &Conn{Conn: raw, Listener: l.ln.Addr().String(), Start: time.Now(), srv: s}
	c.Src, c.SrcPort = canonicalRemote(raw.RemoteAddr())
	s.conns.Store(c, struct{}{})
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic serving connection", "panic", fmt.Sprint(r))
			c.Ev.Result = "internal_error"
			raw.Close()
		}
		c.leavePreauth()
		s.conns.Delete(c)
		s.finish(c)
		s.active.Add(-1)
		s.metrics.ActiveTotal.Dec()
		s.wg.Done()
	}()
	if ok, why := s.ip.Enter(c.Src); !ok {
		s.metrics.Dropped.WithLabelValues(why).Inc()
		c.Ev.Result = "limit_" + why
		raw.Close()
		return
	}
	c.preauth = true
	raw.SetReadDeadline(time.Now().Add(s.cfg.HelloTimeout))
	kind, head, err := s.readFirst(c)
	if err != nil {
		c.Ev.Result = "no_data"
		raw.Close()
		return
	}
	c.Head = head
	c.Ev.Kind = kind
	h := s.kindHandlers[kind]
	if kind == KindUnknown || h == nil || !l.allows(kind) {
		c.Ev.Result = "unknown_protocol"
		raw.Close()
		return
	}
	h.Serve(s.ctx, c)
}

func (c *Conn) leavePreauth() {
	if c.preauth {
		c.preauth = false
		c.srv.ip.Leave(c.Src)
	}
}

// readFirst reads just enough bytes to classify the connection (at most 16).
func (s *Server) readFirst(c *Conn) (Kind, []byte, error) {
	var buf [16]byte
	n := 0
	for {
		m, err := c.Conn.Read(buf[n:])
		n += m
		if n > 0 {
			kind, need := Classify(s.sniffers, buf[:n])
			if kind != KindUnknown {
				return kind, append([]byte(nil), buf[:n]...), nil
			}
			if !need || n == len(buf) {
				return KindUnknown, nil, nil
			}
		}
		if err != nil {
			return KindUnknown, nil, err
		}
	}
}

// finish records metrics and the audit log line of a connection.
func (s *Server) finish(c *Conn) {
	ev := &c.Ev
	if ev.Result == "" {
		ev.Result = "ok"
	}
	route := ev.RouteID
	if route == "" {
		route = "-"
	}
	s.metrics.ConnsTotal.WithLabelValues(route, ev.Result).Inc()
	if ev.BytesIn > 0 {
		s.metrics.BytesTotal.WithLabelValues(route, "in").Add(float64(ev.BytesIn))
	}
	if ev.BytesOut > 0 {
		s.metrics.BytesTotal.WithLabelValues(route, "out").Add(float64(ev.BytesOut))
	}
	lvl := slog.LevelInfo
	switch ev.Result {
	case "no_data", "unknown_protocol", "bad_hello", "limit_rate", "limit_preauth", "no_route", "no_sni":
		lvl = slog.LevelDebug
	}
	if !s.log.Enabled(context.Background(), lvl) {
		return
	}
	attrs := []slog.Attr{
		slog.String("kind", string(ev.Kind)),
		slog.String("result", ev.Result),
		slog.String("src_ip", c.Src.String()),
		slog.String("sni", ev.SNI),
		slog.String("route_id", ev.RouteID),
		slog.Int64("bytes_in", ev.BytesIn),
		slog.Int64("bytes_out", ev.BytesOut),
		slog.Int64("duration_ms", time.Since(c.Start).Milliseconds()),
	}
	if ev.ProjectID != "" {
		attrs = append(attrs, slog.String("project_id", ev.ProjectID))
	}
	if ev.Principal != "" {
		attrs = append(attrs, slog.String("principal", ev.Principal))
	}
	if ev.AuthType != 0 {
		attrs = append(attrs, slog.Int("auth_type", ev.AuthType))
	}
	if ev.Transport != 0 {
		attrs = append(attrs, slog.Int("transport", ev.Transport), slog.Int("status", ev.Status), slog.String("code", fmt.Sprintf("0x%04x", ev.Code)))
	}
	if ev.ClientID != "" {
		attrs = append(attrs, slog.String("client_id", ev.ClientID))
	}
	if ev.ReqHash != "" {
		attrs = append(attrs, slog.String("req_hash", ev.ReqHash))
	}
	if ev.CloseReason != "" {
		attrs = append(attrs, slog.String("close_reason", ev.CloseReason))
	}
	s.log.LogAttrs(context.Background(), lvl, "conn", attrs...)
}

// uniformWait sleeps until start+DenyDelay(+-50 ms jitter): the same latency for every refusal that must not leak
// whether a project, service or credential exists (PROTOCOL.md 15.3).
func (s *Server) uniformWait(ctx context.Context, start time.Time) {
	d := s.cfg.DenyDelay
	if d <= 0 {
		return
	}
	jit := time.Duration(rand.Int64N(int64(100*time.Millisecond))) - 50*time.Millisecond
	if d < 100*time.Millisecond {
		jit = 0
	}
	wait := time.Until(start.Add(d + jit))
	if wait <= 0 {
		return
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// silentDeny closes without any answer after the uniform delay.
func (s *Server) silentDeny(ctx context.Context, c *Conn, start time.Time, result string) {
	c.Ev.Result = result
	s.uniformWait(ctx, start)
	c.Conn.Close()
}

// dial opens the connection to the route's destination (fixed by the route, never by the client).
func (s *Server) dial(ctx context.Context, r *Route) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
	defer cancel()
	return s.dialer.DialContext(dctx, "tcp", net.JoinHostPort(r.DestHost, strconv.Itoa(r.DestPort)))
}

func (s *Server) idleFor(d Decision) time.Duration {
	if d.IdleTimeout > 0 {
		return d.IdleTimeout
	}
	return s.cfg.IdleTimeout
}

// Drain stops accepting new connections after a grace period (during which new tunnel clients get 6/0x0601 and
// other connections are closed, so clients retry on the new process that already listens thanks to SO_REUSEPORT)
// and waits for open connections to end, at most until ctx is done; then it closes what is left.
func (s *Server) Drain(ctx context.Context, grace time.Duration) error {
	s.draining.Store(true)
	s.metrics.Draining.Set(1)
	s.log.Info("draining", "grace", grace.String(), "open", s.active.Load())
	if grace > 0 {
		select {
		case <-time.After(grace):
		case <-ctx.Done():
		}
	}
	s.closeListeners()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		s.stop()
		return nil
	case <-ctx.Done():
		s.log.Warn("drain deadline reached; closing remaining connections", "open", s.active.Load())
		s.conns.Range(func(k, _ any) bool { k.(*Conn).Conn.Close(); return true })
		s.stop()
		<-done
		return ctx.Err()
	}
}

// Close stops everything immediately.
func (s *Server) Close() {
	s.draining.Store(true)
	s.closeListeners()
	s.pool.CloseAll()
	s.conns.Range(func(k, _ any) bool { k.(*Conn).Conn.Close(); return true })
	s.stop()
	s.wg.Wait()
}

func (s *Server) closeListeners() {
	s.mu.Lock()
	for _, l := range s.listeners {
		l.ln.Close()
	}
	s.mu.Unlock()
	s.pool.Shutdown() // random-port listeners: no new connections or flows; open ones continue
}

func (s *Server) stop() {
	s.pool.CloseAll()
	s.cancel()
	s.bg.Wait()
}

// AdminHandler serves /metrics, /healthz (process alive), /readyz (a usable route table is loaded and the gateway is
// not draining) and /status (JSON for operators).
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", s.metrics.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.draining.Load() || !s.routes.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ready":%t,"draining":%t,"control_up":%t,"routes_rev":%d,"routes":%d,"routes_age_seconds":%d,"open_conns":%d}`+"\n",
			s.routes.Ready(), s.draining.Load(), s.routes.ControlUp(), s.routes.Rev(), s.routes.Table().Len(), int64(s.routes.Age().Seconds()), s.active.Load())
	})
	return mux
}
