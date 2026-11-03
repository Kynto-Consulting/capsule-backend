package gittokens

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config holds the tunables of the package. Its own ConfigFromEnv keeps config.go untouched
// (WORKBREAKDOWN 0.2). Zero values mean "default".
type Config struct {
	// AuthSecret is the shared secret Caddy sends in X-Capsule-Git-Auth on forward_auth
	// (CAPSULE_GIT_AUTH_SECRET). It is what proves a /internal/git-auth call comes from the edge.
	AuthSecret string
	// AllowUnsecured lets /internal/git-auth work without AuthSecret (CAPSULE_GIT_AUTH_ALLOW_UNSECURED=1).
	// Only for local development: the endpoint is otherwise closed (fail closed).
	AllowUnsecured bool

	CacheTTL           time.Duration // validation cache, hard-capped at 30 s
	EphemeralTTL       time.Duration // default 1 h
	EphemeralMax       time.Duration // 12 h
	PersonalMaxDays    int           // 90
	RenewBefore        time.Duration // 10 min: an ephemeral token with more left is reused
	MaxActiveEphemeral int           // per user, oldest are revoked beyond it
	MaxPersonal        int           // active personal tokens per user
	MaxServicePerRepo  int           // active service tokens per repo
	MaxSSHKeys         int           // per user
	RatePerSecond      float64       // /internal/git-auth requests per IP
	RateBurst          int
	FailBurst          int           // failed validations tolerated per IP before blocking
	FailRefill         time.Duration // one failure token back every FailRefill
	WarnBefore         time.Duration // expiry warning: 7 days
}

// Limits fixed by SPEC 6.5.
const (
	MaxCacheTTL = 30 * time.Second
)

// ConfigFromEnv reads CAPSULE_GIT_AUTH_SECRET, CAPSULE_GIT_AUTH_ALLOW_UNSECURED and the optional
// CAPSULE_GITTOKENS_* tunables.
func ConfigFromEnv() Config {
	c := Config{
		AuthSecret:     strings.TrimSpace(os.Getenv("CAPSULE_GIT_AUTH_SECRET")),
		AllowUnsecured: truthy(os.Getenv("CAPSULE_GIT_AUTH_ALLOW_UNSECURED")),
	}
	if n := envInt("CAPSULE_GITTOKENS_EPHEMERAL_TTL_MINUTES"); n > 0 {
		c.EphemeralTTL = time.Duration(n) * time.Minute
	}
	if n := envInt("CAPSULE_GITTOKENS_RATE_PER_SECOND"); n > 0 {
		c.RatePerSecond = float64(n)
	}
	if n := envInt("CAPSULE_GITTOKENS_RATE_BURST"); n > 0 {
		c.RateBurst = n
	}
	return c.withDefaults()
}

func (c Config) withDefaults() Config {
	if c.CacheTTL <= 0 || c.CacheTTL > MaxCacheTTL {
		c.CacheTTL = MaxCacheTTL
	}
	if c.EphemeralMax <= 0 {
		c.EphemeralMax = 12 * time.Hour
	}
	if c.EphemeralTTL <= 0 {
		c.EphemeralTTL = time.Hour
	}
	if c.EphemeralTTL > c.EphemeralMax {
		c.EphemeralTTL = c.EphemeralMax
	}
	if c.PersonalMaxDays <= 0 {
		c.PersonalMaxDays = 90
	}
	if c.RenewBefore <= 0 {
		c.RenewBefore = 10 * time.Minute
	}
	if c.MaxActiveEphemeral <= 0 {
		c.MaxActiveEphemeral = 50
	}
	if c.MaxPersonal <= 0 {
		c.MaxPersonal = 50
	}
	if c.MaxServicePerRepo <= 0 {
		c.MaxServicePerRepo = 25
	}
	if c.MaxSSHKeys <= 0 {
		c.MaxSSHKeys = 50
	}
	if c.RatePerSecond <= 0 {
		c.RatePerSecond = 50
	}
	if c.RateBurst <= 0 {
		c.RateBurst = 200
	}
	if c.FailBurst <= 0 {
		c.FailBurst = 10
	}
	if c.FailRefill <= 0 {
		c.FailRefill = 6 * time.Second
	}
	if c.WarnBefore <= 0 {
		c.WarnBefore = 7 * 24 * time.Hour
	}
	return c
}

func envInt(k string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(os.Getenv(k)))
	return n
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// ---- process-wide service (published by the wiring, read by the route mounts) --------------

var (
	sharedMu sync.RWMutex
	shared   *Service
)

// SetShared publishes the process-wide Service.
func SetShared(s *Service) {
	sharedMu.Lock()
	shared = s
	sharedMu.Unlock()
}

// Shared returns the published Service, or nil when the wiring did not run (routes then are not mounted).
func Shared() *Service {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return shared
}
