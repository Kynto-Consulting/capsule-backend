package data

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Port 443 shared with Caddy (docs/gateway/RUNBOOK-443.md). With CAPSULE_GW_TAKE_443=1 the gateway listens on 443 and
// decides from the ClientHello: capsule/1 tunnel (ALPN capsule/1 on a tunnel host), a route of the table (SNI), and any
// OTHER name is relayed untouched (no TLS termination) to Caddy, which keeps terminating TLS for git.<zone> and
// renewing certificates over HTTP-01 on port 80. The real client address travels to Caddy in a PROXY protocol v2 header.

// Take443Config is the configuration of the shared 443 (all fields come from CAPSULE_GW_* variables, see applyTake443Env).
type Take443Config struct {
	Enabled       bool     // CAPSULE_GW_TAKE_443: 0 = nothing changes, the gateway does not listen on 443
	Addr          string   // CAPSULE_GW_443_ADDR: where to listen ("[::]:443"); tests use another port
	Upstream      string   // CAPSULE_GW_HTTP_UPSTREAM: Caddy ("127.0.0.1:8444")
	ProxyProto    bool     // CAPSULE_GW_HTTP_UPSTREAM_PROXY: send a PROXY protocol v2 header first (default true)
	NoSNIUpstream bool     // CAPSULE_GW_NO_SNI=upstream sends hellos without SNI to Caddy; default "close"
	OwnedSuffixes []string // names under these suffixes are never relayed to Caddy (unknown route = close); default ".db.<zone>"
	// BindRetry (CAPSULE_GW_BIND_RETRY): while a listener port is still held by its previous owner (Caddy on 443, or the
	// previous gateway process when it runs under another uid and SO_REUSEPORT cannot be shared) keep trying to bind it
	// every 100 ms for this long instead of failing at start. 0 = fail at start. The cut-over uses it so no port is
	// ownerless for more than one retry tick (docs/gateway/RUNBOOK-443.md).
	BindRetry time.Duration
}

const defaultTake443Addr = "[::]:443"

func applyTake443Env(c *Config, getenv func(string) string) []string {
	var errs []string
	t := &c.Take443
	t.Addr, t.ProxyProto = defaultTake443Addr, true
	if v := getenv("CAPSULE_GW_TAKE_443"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, "CAPSULE_GW_TAKE_443: "+err.Error())
		}
		t.Enabled = b
	}
	if v := getenv("CAPSULE_GW_443_ADDR"); v != "" {
		t.Addr = v
	}
	t.Upstream = getenv("CAPSULE_GW_HTTP_UPSTREAM")
	if v := getenv("CAPSULE_GW_HTTP_UPSTREAM_PROXY"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, "CAPSULE_GW_HTTP_UPSTREAM_PROXY: "+err.Error())
		} else {
			t.ProxyProto = b
		}
	}
	switch v := strings.ToLower(getenv("CAPSULE_GW_NO_SNI")); v {
	case "", "close":
	case "upstream":
		t.NoSNIUpstream = true
	default:
		errs = append(errs, "CAPSULE_GW_NO_SNI: must be close or upstream")
	}
	if v := getenv("CAPSULE_GW_BIND_RETRY"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, "CAPSULE_GW_BIND_RETRY: "+err.Error())
		}
		t.BindRetry = d
	}
	for _, p := range strings.Split(getenv("CAPSULE_GW_OWNED_SUFFIXES"), ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			t.OwnedSuffixes = append(t.OwnedSuffixes, "."+strings.Trim(p, "."))
		}
	}
	return errs
}

// normalised returns the configuration with defaults filled in (used by the server, so tests may set only Enabled).
func (t Take443Config) normalised(zone string) Take443Config {
	if t.Addr == "" {
		t.Addr = defaultTake443Addr
	}
	if t.Upstream == "" {
		t.Upstream = "127.0.0.1:8444"
	}
	if z := strings.ToLower(strings.Trim(zone, ".")); z != "" && len(t.OwnedSuffixes) == 0 {
		t.OwnedSuffixes = []string{".db." + z}
		// the tunnel zone is "apps.<domain>" (tcp.apps.<domain>) while database names are <project>.db.<domain>
		if _, parent, ok := strings.Cut(z, "."); ok && strings.Contains(parent, ".") {
			t.OwnedSuffixes = append(t.OwnedSuffixes, ".db."+parent)
		}
	}
	return t
}

func addrPort(a string) string {
	_, p, err := net.SplitHostPort(a)
	if err != nil {
		return ""
	}
	return p
}

// take443Listeners adds the 443 listener (TLS and PostgreSQL SSLRequest only: clear text on 443 is closed) when enabled
// and not already configured. Idempotent.
func take443Listeners(cfg Config) []ListenerSpec {
	if !cfg.Take443.Enabled {
		return cfg.Listeners
	}
	t := cfg.Take443.normalised(cfg.Zone)
	for _, l := range cfg.Listeners {
		if addrPort(l.Addr) == addrPort(t.Addr) {
			return cfg.Listeners
		}
	}
	return append(append([]ListenerSpec(nil), cfg.Listeners...), ListenerSpec{Addr: t.Addr, Allow: []Kind{KindTLS, KindPGSSL}})
}

// proxyV2Header builds a PROXY protocol v2 PROXY/STREAM header for src -> dst.
func proxyV2Header(src, dst netip.AddrPort) []byte {
	sig := []byte("\r\n\r\n\x00\r\nQUIT\n")
	sa, da := src.Addr().Unmap(), dst.Addr().Unmap()
	var fam byte
	var addrs []byte
	if sa.Is4() && da.Is4() {
		fam = 0x11
		a, b := sa.As4(), da.As4()
		addrs = append(append(addrs, a[:]...), b[:]...)
	} else {
		fam = 0x21
		a, b := sa.As16(), da.As16()
		addrs = append(append(addrs, a[:]...), b[:]...)
	}
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[0:], src.Port())
	binary.BigEndian.PutUint16(ports[2:], dst.Port())
	addrs = append(addrs, ports[:]...)
	h := append(sig, 0x21, fam, byte(len(addrs)>>8), byte(len(addrs)))
	return append(h, addrs...)
}

// ownedName reports whether a name belongs to the gateway's namespace (unknown route there = close, never Caddy).
func (t Take443Config) ownedName(sni string) bool {
	for _, s := range t.OwnedSuffixes {
		if strings.HasSuffix(sni, s) {
			return true
		}
	}
	return false
}

// serveDefaultUpstream relays a connection whose SNI is not ours to Caddy. It returns true when it took the connection
// (served or closed it) and false when the caller must apply its normal refusal.
func (s *Server) serveDefaultUpstream(ctx context.Context, c *Conn, hello *Hello, raw []byte) bool {
	if !s.cfg.Take443.Enabled || c.PGClassic {
		return false
	}
	t := s.cfg.Take443.normalised(s.cfg.Zone)
	if addrPort(c.Listener) != addrPort(t.Addr) {
		return false // only the shared port forwards; 5432 or 8443 with an unknown name stay closed
	}
	if hello.Offers(tunnelALPN) || t.ownedName(hello.SNI) {
		return false
	}
	if hello.SNI == "" && !t.NoSNIUpstream {
		return false
	}
	c.Ev.RouteID = "default-upstream"
	bk, err := dialRetry(ctx, t.Upstream, s.cfg.DialTimeout)
	if err != nil {
		c.Ev.Result = "upstream_down"
		c.Conn.Close()
		return true
	}
	buf := raw
	if t.ProxyProto {
		var dst netip.AddrPort
		if ap, perr := netip.ParseAddrPort(c.Conn.LocalAddr().String()); perr == nil {
			dst = ap
		}
		buf = append(proxyV2Header(netip.AddrPortFrom(c.Src, c.SrcPort), dst), raw...)
	}
	bk.SetWriteDeadline(time.Now().Add(s.cfg.DialTimeout))
	if _, werr := bk.Write(buf); werr != nil {
		c.Ev.Result = "upstream_down"
		bk.Close()
		c.Conn.Close()
		return true
	}
	bk.SetWriteDeadline(time.Time{})
	c.Conn.SetDeadline(time.Time{})
	c.leavePreauth()
	s.relay(c, "default-upstream", c.Conn, bk, s.cfg.IdleTimeout)
	return true
}

// dialRetry connects to Caddy, retrying every 100 ms while it refuses (it restarts during the cut-over and on any Caddy
// reload) for at most `total`: a client that arrives meanwhile waits instead of failing.
func dialRetry(ctx context.Context, addr string, total time.Duration) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	d := &net.Dialer{KeepAlive: 30 * time.Second, Timeout: 2 * time.Second}
	for {
		c, err := d.DialContext(dctx, "tcp", addr)
		if err == nil {
			return c, nil
		}
		if dctx.Err() != nil || !connRefused(err) {
			return nil, err
		}
		select {
		case <-dctx.Done():
			return nil, err
		case <-time.After(100 * time.Millisecond):
		}
	}
}

var take443Bound atomic.Int64

// take443Pending reports whether a failed bind of sp is a port still held by its previous owner and may be retried.
func (s *Server) take443Pending(sp ListenerSpec, err error) bool {
	return s.cfg.Take443.BindRetry > 0 && addrInUse(err)
}

func (s *Server) registerTake443Gauge(boundNow bool) {
	if !s.cfg.Take443.Enabled {
		return
	}
	t := s.cfg.Take443.normalised(s.cfg.Zone)
	boundNow = boundNow || func() bool { // pending listeners other than the 443 do not make it unbound
		for _, l := range s.listeners {
			if addrPort(l.ln.Addr().String()) == addrPort(t.Addr) {
				return true
			}
		}
		return false
	}()
	if boundNow {
		take443Bound.Store(1)
	} else {
		take443Bound.Store(0)
	}
	s.metrics.Reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "gw_take443_bound", Help: "1 when the gateway owns the shared 443 listener."}, func() float64 { return float64(take443Bound.Load()) }))
}

// bindTake443Late retries the bind of the shared port every 100 ms until it succeeds, BindRetry passes or the server stops.
func (s *Server) bindTake443Late(sp ListenerSpec) {
	s.log.Warn("port busy: waiting for its previous owner to release it", "addr", sp.Addr, "retry_for", s.cfg.Take443.BindRetry.String())
	deadline := time.Now().Add(s.cfg.Take443.BindRetry)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
		}
		if s.draining.Load() {
			return
		}
		ln, err := listenTCP(s.ctx, sp.Addr, s.cfg.ReusePort)
		if err != nil {
			if time.Now().After(deadline) {
				s.log.Error("port still busy: giving up (the gateway keeps serving its other ports)", "addr", sp.Addr, "err", err.Error())
				return
			}
			continue
		}
		l := &listener{spec: sp, ln: ln, done: make(chan struct{})}
		if len(sp.Allow) > 0 {
			l.allow = map[Kind]bool{}
			for _, k := range sp.Allow {
				l.allow[k] = true
			}
		}
		s.mu.Lock()
		if s.draining.Load() {
			s.mu.Unlock()
			ln.Close()
			return
		}
		s.listeners = append(s.listeners, l)
		s.mu.Unlock()
		if s.cfg.Take443.Enabled && addrPort(sp.Addr) == addrPort(s.cfg.Take443.normalised(s.cfg.Zone).Addr) {
			take443Bound.Store(1)
		}
		s.log.Info("listening", "addr", ln.Addr().String(), "kinds", kindNames(sp.Allow), "late", true)
		s.acceptLoop(l)
		return
	}
}

// addrInUse recognises "address already in use" on Linux (EADDRINUSE) and on Windows (WSAEADDRINUSE, used by the tests).
func addrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	var en syscall.Errno
	return errors.As(err, &en) && en == 10048
}

func connRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var en syscall.Errno
	return errors.As(err, &en) && en == 10061 // WSAECONNREFUSED
}
