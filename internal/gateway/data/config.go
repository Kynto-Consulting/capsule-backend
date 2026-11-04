package data

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ListenerSpec is one listening address and the protocol kinds it accepts (empty = every registered kind).
type ListenerSpec struct {
	Addr  string
	Allow []Kind
}

// Config is the whole configuration of the data plane. Every field has an environment variable
// CAPSULE_GW_* (see ConfigFromEnv) and the defaults are the values of PROTOCOL.md section 9.3 where they exist.
type Config struct {
	Listeners   []ListenerSpec
	Zone        string   // zone of the tunnel entry points: tcp.<zone> and udp.<zone>
	TunnelHosts []string // extra tunnel host names

	ControlURL string
	Secret     string // never logged

	CertFiles, KeyFiles []string

	MetricsAddr string

	HelloTimeout    time.Duration // TLS handshake / first-bytes limit (10 s)
	DialTimeout     time.Duration // destination connect limit (5 s)
	DenyDelay       time.Duration // uniform delay before silent closes and status-2 replies (300 ms, +-50 ms jitter)
	IdleTimeout     time.Duration // inactivity after OK (1 h; 0 = none)
	HalfCloseIdle   time.Duration // inactivity after a half-close (5 min)
	MaxHelloBytes   int           // largest accepted ClientHello (16 KiB)
	MaxHTTPHead     int           // largest accepted clear-text HTTP head (16 KiB)
	MaxConns        int           // process-wide open connections
	MaxPreauthPerIP int           // concurrent unauthenticated connections per IP (100)
	NewConnsPerIP   float64       // per second (20)
	RouteConnRate   float64       // new authenticated connections per second per route (100)
	RouteMaxConns   int           // default per route (200), overridden by the control plane
	RouteMaxConnsIP int           // default per route and IP (50), overridden by the control plane

	RoutesWait   time.Duration // long-poll wait (25 s)
	RoutesMaxAge time.Duration // how long the last table may be served without contact (6 h; 0 = forever)
	RoutesCache  string        // optional file with the last table
	AuthTimeout  time.Duration // control plane call limit for authorize (3 s)
	AuthStale    time.Duration // grace for cached allow decisions when the control plane fails (0 = fail closed)

	DrainTimeout time.Duration // how long a draining process waits for open connections (24 h)
	DrainGrace   time.Duration // how long it keeps refusing new connections before closing listeners (2 s)
	ReusePort    bool          // SO_REUSEPORT so a new process can bind the same ports while this one drains

	CGCKeys []CGCKey // public keys that verify cgc_ tokens locally

	UDP  UDPConfig  // UDP over the capsule/1 tunnel (transport 2)
	Pool PoolConfig // random-port listeners

	ProtoMaxConns map[string]int // concurrent proxied connections per database protocol (mysql, redis, mongo; default 1500, 0 = none)

	Take443 Take443Config // shared 443: tunnel / routes / passthrough to Caddy (take443.go)

	AllowLoopbackDest bool // allow routes whose destination is a loopback address (tests, host-network setups)
	LogLevel          string
}

// DefaultConfig returns the defaults.
func DefaultConfig() Config {
	return Config{
		Listeners:       []ListenerSpec{{Addr: "[::]:8443"}},
		MetricsAddr:     "127.0.0.1:9102",
		HelloTimeout:    10 * time.Second,
		DialTimeout:     5 * time.Second,
		DenyDelay:       300 * time.Millisecond,
		IdleTimeout:     time.Hour,
		HalfCloseIdle:   5 * time.Minute,
		MaxHelloBytes:   16 << 10,
		MaxHTTPHead:     16 << 10,
		MaxConns:        50000,
		MaxPreauthPerIP: 100,
		NewConnsPerIP:   20,
		RouteConnRate:   100,
		RouteMaxConns:   200,
		RouteMaxConnsIP: 50,
		RoutesWait:      25 * time.Second,
		RoutesMaxAge:    6 * time.Hour,
		AuthTimeout:     3 * time.Second,
		DrainTimeout:    24 * time.Hour,
		DrainGrace:      2 * time.Second,
		ReusePort:       ReusePortSupported,
		LogLevel:        "info",
	}
}

// ParseListeners parses "addr[=kind+kind],addr..." (kinds: tls, pg-ssl, http, ssh; "pg" is an alias of pg-ssl).
func ParseListeners(s string) ([]ListenerSpec, error) {
	var out []ListenerSpec
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		addr, kinds, has := strings.Cut(item, "=")
		spec := ListenerSpec{Addr: strings.TrimSpace(addr)}
		if spec.Addr == "" {
			return nil, fmt.Errorf("empty listener address in %q", item)
		}
		if has {
			for _, k := range strings.Split(kinds, "+") {
				k = strings.TrimSpace(k)
				if k == "pg" {
					k = string(KindPGSSL)
				}
				if k == "" {
					return nil, fmt.Errorf("empty kind in %q", item)
				}
				spec.Allow = append(spec.Allow, Kind(k))
			}
		}
		out = append(out, spec)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no listeners")
	}
	return out, nil
}

// ConfigFromEnv overlays CAPSULE_GW_* variables on the defaults. getenv is os.Getenv in production.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	c := DefaultConfig()
	var errs []string
	str := func(name string, dst *string) {
		if v := getenv(name); v != "" {
			*dst = v
		}
	}
	dur := func(name string, dst *time.Duration) {
		if v := getenv(name); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				errs = append(errs, name+": "+err.Error())
				return
			}
			*dst = d
		}
	}
	num := func(name string, dst *int) {
		if v := getenv(name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				errs = append(errs, name+": "+err.Error())
				return
			}
			*dst = n
		}
	}
	flt := func(name string, dst *float64) {
		if v := getenv(name); v != "" {
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				errs = append(errs, name+": "+err.Error())
				return
			}
			*dst = n
		}
	}
	boolean := func(name string, dst *bool) {
		if v := getenv(name); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				errs = append(errs, name+": "+err.Error())
				return
			}
			*dst = b
		}
	}
	if v := getenv("CAPSULE_GW_LISTEN"); v != "" {
		l, err := ParseListeners(v)
		if err != nil {
			errs = append(errs, "CAPSULE_GW_LISTEN: "+err.Error())
		} else {
			c.Listeners = l
		}
	}
	str("CAPSULE_GW_ZONE", &c.Zone)
	if v := getenv("CAPSULE_GW_TUNNEL_HOSTS"); v != "" {
		for _, h := range strings.Split(v, ",") {
			if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
				c.TunnelHosts = append(c.TunnelHosts, h)
			}
		}
	}
	str("CAPSULE_GW_CONTROL_URL", &c.ControlURL)
	str("CAPSULE_GW_SECRET", &c.Secret)
	if f := getenv("CAPSULE_GW_SECRET_FILE"); f != "" && c.Secret == "" {
		b, err := os.ReadFile(f)
		if err != nil {
			errs = append(errs, "CAPSULE_GW_SECRET_FILE: cannot read")
		} else {
			c.Secret = strings.TrimSpace(string(b))
		}
	}
	if c.Secret == "" { // the OpenAPI contract names this variable on the control plane side
		c.Secret = getenv("CAPSULE_GATEWAY_SECRET")
	}
	splitList := func(v string) []string {
		var o []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				o = append(o, p)
			}
		}
		return o
	}
	c.CertFiles = splitList(getenv("CAPSULE_GW_TLS_CERT"))
	c.KeyFiles = splitList(getenv("CAPSULE_GW_TLS_KEY"))
	str("CAPSULE_GW_METRICS_ADDR", &c.MetricsAddr)
	dur("CAPSULE_GW_HELLO_TIMEOUT", &c.HelloTimeout)
	dur("CAPSULE_GW_DIAL_TIMEOUT", &c.DialTimeout)
	dur("CAPSULE_GW_DENY_DELAY", &c.DenyDelay)
	dur("CAPSULE_GW_IDLE_TIMEOUT", &c.IdleTimeout)
	dur("CAPSULE_GW_HALFCLOSE_IDLE", &c.HalfCloseIdle)
	num("CAPSULE_GW_MAX_HELLO_BYTES", &c.MaxHelloBytes)
	num("CAPSULE_GW_MAX_HTTP_HEAD", &c.MaxHTTPHead)
	num("CAPSULE_GW_MAX_CONNS", &c.MaxConns)
	num("CAPSULE_GW_PREAUTH_PER_IP", &c.MaxPreauthPerIP)
	flt("CAPSULE_GW_NEW_CONNS_PER_IP", &c.NewConnsPerIP)
	flt("CAPSULE_GW_ROUTE_CONN_RATE", &c.RouteConnRate)
	num("CAPSULE_GW_ROUTE_MAX_CONNS", &c.RouteMaxConns)
	num("CAPSULE_GW_ROUTE_MAX_CONNS_PER_IP", &c.RouteMaxConnsIP)
	dur("CAPSULE_GW_ROUTES_WAIT", &c.RoutesWait)
	dur("CAPSULE_GW_ROUTES_MAX_AGE", &c.RoutesMaxAge)
	str("CAPSULE_GW_ROUTES_CACHE", &c.RoutesCache)
	dur("CAPSULE_GW_AUTH_TIMEOUT", &c.AuthTimeout)
	dur("CAPSULE_GW_AUTH_STALE", &c.AuthStale)
	dur("CAPSULE_GW_DRAIN_TIMEOUT", &c.DrainTimeout)
	dur("CAPSULE_GW_DRAIN_GRACE", &c.DrainGrace)
	boolean("CAPSULE_GW_REUSEPORT", &c.ReusePort)
	boolean("CAPSULE_GW_ALLOW_LOOPBACK_DEST", &c.AllowLoopbackDest)
	str("CAPSULE_GW_LOG_LEVEL", &c.LogLevel)
	if v := getenv("CAPSULE_GW_CGC_KEYS"); v != "" { // [kid=]base64(std or url) of 32-byte Ed25519 public keys, comma separated
		for _, item := range splitList(v) {
			kid, b64, has := strings.Cut(item, "=")
			if !has {
				kid, b64 = "", item
			}
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				raw, err = base64.RawURLEncoding.DecodeString(b64)
			}
			if err != nil || len(raw) != ed25519.PublicKeySize {
				errs = append(errs, "CAPSULE_GW_CGC_KEYS: bad key")
				continue
			}
			c.CGCKeys = append(c.CGCKeys, CGCKey{KID: kid, Pub: raw})
		}
	}
	errs = append(errs, applyUDPEnv(&c, getenv)...)
	errs = append(errs, applyProtoEnv(&c, getenv)...)
	errs = append(errs, applyTake443Env(&c, getenv)...)
	if len(errs) > 0 {
		return c, fmt.Errorf("invalid configuration: %s", strings.Join(errs, "; "))
	}
	return c, nil
}

// Validate checks that the configuration can run.
func (c *Config) Validate() error {
	if len(c.Listeners) == 0 {
		return fmt.Errorf("no listeners")
	}
	if c.ControlURL == "" {
		return fmt.Errorf("CAPSULE_GW_CONTROL_URL is required")
	}
	if c.Secret == "" {
		return fmt.Errorf("the gateway secret is required (CAPSULE_GW_SECRET or CAPSULE_GW_SECRET_FILE)")
	}
	if len(c.CertFiles) != len(c.KeyFiles) {
		return fmt.Errorf("CAPSULE_GW_TLS_CERT and CAPSULE_GW_TLS_KEY must list the same number of files")
	}
	return nil
}

// TunnelHostSet returns tcp.<zone>, udp.<zone> and the extra tunnel hosts.
func (c *Config) TunnelHostSet() map[string]bool {
	m := map[string]bool{}
	if z := strings.ToLower(strings.Trim(c.Zone, ".")); z != "" {
		m["tcp."+z] = true
		m["udp."+z] = true
	}
	for _, h := range c.TunnelHosts {
		m[strings.ToLower(h)] = true
	}
	return m
}
