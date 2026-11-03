// Package api is the control plane of the universal gateway (docs/gateway/PLAN.md 5): the internal endpoints the
// data plane polls (routes, authorize, signing keys) and the user API (services, connection info, connection
// tokens, random-port fallback, service tokens, organisation policy).
//
// Everything is decided here, never in the data plane: the role comes from internal/authz (action
// project.connect), the IP list is the one internal/netaccess enforces on the firewall, and "does not exist" and
// "not authorised" are the same answer.
package api

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment variables read by ConfigFromEnv (the package keeps its own so config.go stays untouched).
const (
	EnvSecret        = "CAPSULE_GW_SECRET"           // shared secret of /internal/gateway/*; empty = endpoints closed
	EnvPool          = "CAPSULE_GW_POOL"             // random-port pool "lo-hi" (default 20000-29999); "off" disables
	EnvZone          = "CAPSULE_GW_ZONE"             // DNS zone of the names (default tumi-ai.com)
	EnvDestHost      = "CAPSULE_GW_DEST_HOST"        // host the data plane reaches published ports on (default 127.0.0.1)
	EnvSigningKey    = "CAPSULE_GW_SIGNING_KEY"      // base64 Ed25519 seed (32 bytes) that signs cgc_ tokens
	EnvSigningPrev   = "CAPSULE_GW_SIGNING_PREVIOUS" // base64 Ed25519 PUBLIC key of the previous signing key (rotation)
	EnvSweepInterval = "CAPSULE_GW_SWEEP_INTERVAL"   // lease/quarantine sweep period (default 1m)
)

// DefaultPool is the public random-port range (PLAN 3.4). The single security-group rule that opens it is
// managed by Terraform (deploy/terraform/gateway.tf); this package never touches AWS.
const (
	DefaultPoolLo = 20000
	DefaultPoolHi = 29999
)

// Port ranges that belong to the direct method and must never enter the pool.
const (
	directDBLo, directDBHi     = 40000, 40199
	directPortLo, directPortHi = 41000, 41999
)

// Config holds the tunables. Zero values mean "default" (see WithDefaults).
type Config struct {
	Secret   string
	PoolLo   int
	PoolHi   int // PoolHi == 0 after WithDefaults means the pool is disabled
	PoolOff  bool
	Zone     string
	DestHost string
	// TCPHost is the host of the direct (secondary) method, e.g. the one the ports API shows.
	TCPHost string

	SigningKey      string
	SigningPrevious string

	SweepInterval time.Duration
	// Lease policy (PLAN 3.4).
	Quarantine  time.Duration // default 24h
	IdleRelease time.Duration // default 30 days without a connection

	// Long-poll.
	PollInterval time.Duration // how often the revision is read while waiting (default 1s)
	MaxWait      time.Duration // upper bound of ?wait= (default 28s: below the 30s request timeout)
	DefaultWait  time.Duration // default 25s

	// Authorize limits.
	AuthCacheTTL    time.Duration // cache_ttl_seconds hint, hard-capped at 30s
	FailBurst       int           // failed authentications per IP per FailWindow before blocking (PROTOCOL 15.5: 10/min)
	FailWindow      time.Duration
	BlockFor        time.Duration // 5 min
	RatePerSecond   float64       // authorize calls per source IP
	RateBurst       int
	MaxConns        int
	MaxConnsPerIP   int
	IdleTimeout     time.Duration
	ServiceTokenMax int // active service tokens per project
}

// WithDefaults fills the zero values.
func (c Config) WithDefaults() Config {
	if c.PoolLo == 0 && c.PoolHi == 0 && !c.PoolOff {
		c.PoolLo, c.PoolHi = DefaultPoolLo, DefaultPoolHi
	}
	if c.Zone == "" {
		c.Zone = "tumi-ai.com"
	}
	if c.DestHost == "" {
		c.DestHost = "127.0.0.1"
	}
	if c.SweepInterval <= 0 {
		c.SweepInterval = time.Minute
	}
	if c.Quarantine <= 0 {
		c.Quarantine = 24 * time.Hour
	}
	if c.IdleRelease <= 0 {
		c.IdleRelease = 30 * 24 * time.Hour
	}
	if c.PollInterval <= 0 {
		c.PollInterval = time.Second
	}
	if c.MaxWait <= 0 {
		c.MaxWait = 28 * time.Second
	}
	if c.DefaultWait <= 0 {
		c.DefaultWait = 25 * time.Second
	}
	if c.DefaultWait > c.MaxWait {
		c.DefaultWait = c.MaxWait
	}
	if c.AuthCacheTTL <= 0 || c.AuthCacheTTL > 30*time.Second {
		c.AuthCacheTTL = 30 * time.Second
	}
	if c.FailBurst <= 0 {
		c.FailBurst = 10
	}
	if c.FailWindow <= 0 {
		c.FailWindow = time.Minute
	}
	if c.BlockFor <= 0 {
		c.BlockFor = 5 * time.Minute
	}
	if c.RatePerSecond <= 0 {
		c.RatePerSecond = 50
	}
	if c.RateBurst <= 0 {
		c.RateBurst = 100
	}
	if c.MaxConns <= 0 {
		c.MaxConns = 200 // PLAN 5.2
	}
	if c.MaxConnsPerIP <= 0 {
		c.MaxConnsPerIP = 50
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = time.Hour
	}
	if c.ServiceTokenMax <= 0 {
		c.ServiceTokenMax = 50
	}
	return c
}

// ConfigFromEnv reads the CAPSULE_GW_* variables. An invalid pool is reported as an error (the caller logs it and
// runs without a pool rather than guessing).
func ConfigFromEnv() (Config, error) {
	c := Config{
		Secret:          strings.TrimSpace(os.Getenv(EnvSecret)),
		Zone:            strings.TrimSpace(os.Getenv(EnvZone)),
		DestHost:        strings.TrimSpace(os.Getenv(EnvDestHost)),
		SigningKey:      strings.TrimSpace(os.Getenv(EnvSigningKey)),
		SigningPrevious: strings.TrimSpace(os.Getenv(EnvSigningPrev)),
	}
	if v := strings.TrimSpace(os.Getenv(EnvSweepInterval)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.SweepInterval = d
		}
	}
	var err error
	if v := strings.TrimSpace(os.Getenv(EnvPool)); v != "" {
		c.PoolLo, c.PoolHi, c.PoolOff, err = ParsePool(v)
	}
	return c.WithDefaults(), err
}

// ParsePool parses "lo-hi". "off", "none", "0" and "disabled" disable the pool. The range must stay inside
// 1024-65535 and must not overlap the direct-method ranges (40000-40199, 41000-41999).
func ParsePool(s string) (lo, hi int, off bool, err error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "off", "none", "0", "disabled":
		return 0, 0, true, nil
	}
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, false, fmt.Errorf("%s: want lo-hi, got %q", EnvPool, s)
	}
	lo, e1 := strconv.Atoi(strings.TrimSpace(a))
	hi, e2 := strconv.Atoi(strings.TrimSpace(b))
	if e1 != nil || e2 != nil {
		return 0, 0, false, fmt.Errorf("%s: want lo-hi, got %q", EnvPool, s)
	}
	if lo < 1024 || hi > 65535 || lo > hi {
		return 0, 0, false, fmt.Errorf("%s: range %d-%d must satisfy 1024 <= lo <= hi <= 65535", EnvPool, lo, hi)
	}
	if overlaps(lo, hi, directDBLo, directDBHi) || overlaps(lo, hi, directPortLo, directPortHi) {
		return 0, 0, false, fmt.Errorf("%s: range %d-%d overlaps the direct-port ranges 40000-40199 / 41000-41999", EnvPool, lo, hi)
	}
	return lo, hi, false, nil
}

func overlaps(a1, a2, b1, b2 int) bool { return a1 <= b2 && b1 <= a2 }
