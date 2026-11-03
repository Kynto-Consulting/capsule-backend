package gitcore

import (
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is read from the same CAPSULE_GIT_* variables as the legacy forgejo package, plus
// optional CAPSULE_GITCORE_* tunables. The zero value of every tunable means "default".
type Config struct {
	URL     string // https://git.tumi-ai.com (no trailing slash)
	Token   string // service-account token (secret)
	SSHHost string

	// Web-session features (jobs, logs, cancel, re-run, artifacts): see websession.go.
	BotLogin    string   // CAPSULE_GIT_BOT_LOGIN (default capsule-bot)
	BotPassword string   // CAPSULE_GIT_BOT_PASSWORD (secret); empty = those features answer NOT_SUPPORTED
	WebVersions []string // CAPSULE_GIT_WEB_VERSIONS: Forgejo versions the web routes may be used with (default: TestedForgejoVersion; "*" = any)

	Timeout         time.Duration // per attempt (default 20s)
	MaxAttempts     int           // total tries for idempotent calls (default 3)
	BackoffBase     time.Duration // default 150ms; doubles per attempt with jitter
	BackoffMax      time.Duration // default 2s
	MaxConcurrent   int           // in-flight requests to Forgejo (default 16)
	BreakerFailures int           // consecutive upstream failures that open the circuit (default 5)
	BreakerOpenFor  time.Duration // default 30s
	ListTTL         time.Duration // cached lists (branches, pulls...) (default 30s)
	ImmutableTTL    time.Duration // SHA-addressed objects (default 24h)
}

// ConfigFromEnv reads CAPSULE_GIT_URL, CAPSULE_GIT_TOKEN, CAPSULE_GIT_SSH_HOST and the
// optional CAPSULE_GITCORE_TIMEOUT_SECONDS / _MAX_CONCURRENT / _LIST_TTL_SECONDS.
func ConfigFromEnv() Config {
	c := Config{
		URL:         strings.TrimRight(strings.TrimSpace(os.Getenv("CAPSULE_GIT_URL")), "/"),
		Token:       strings.TrimSpace(os.Getenv("CAPSULE_GIT_TOKEN")),
		SSHHost:     strings.TrimSpace(os.Getenv("CAPSULE_GIT_SSH_HOST")),
		BotLogin:    strings.TrimSpace(os.Getenv("CAPSULE_GIT_BOT_LOGIN")),
		BotPassword: os.Getenv("CAPSULE_GIT_BOT_PASSWORD"),
	}
	for _, v := range strings.Split(os.Getenv("CAPSULE_GIT_WEB_VERSIONS"), ",") {
		if v = strings.TrimSpace(v); v != "" {
			c.WebVersions = append(c.WebVersions, v)
		}
	}
	if n := envInt("CAPSULE_GITCORE_TIMEOUT_SECONDS"); n > 0 {
		c.Timeout = time.Duration(n) * time.Second
	}
	c.MaxConcurrent = envInt("CAPSULE_GITCORE_MAX_CONCURRENT")
	if n := envInt("CAPSULE_GITCORE_LIST_TTL_SECONDS"); n > 0 {
		c.ListTTL = time.Duration(n) * time.Second
	}
	return c
}

func envInt(k string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(os.Getenv(k)))
	return n
}

// Enabled reports whether URL and token are set.
func (c Config) Enabled() bool { return c.URL != "" && c.Token != "" }

// Host is the lower-case hostname of URL.
func (c Config) Host() string {
	u, err := url.Parse(c.URL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func (c Config) withDefaults() Config {
	if c.Timeout <= 0 {
		c.Timeout = 20 * time.Second
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 3
	}
	if c.BackoffBase <= 0 {
		c.BackoffBase = 150 * time.Millisecond
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = 2 * time.Second
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 16
	}
	if c.BreakerFailures <= 0 {
		c.BreakerFailures = 5
	}
	if c.BreakerOpenFor <= 0 {
		c.BreakerOpenFor = 30 * time.Second
	}
	if c.ListTTL <= 0 {
		c.ListTTL = 30 * time.Second
	}
	if c.ImmutableTTL <= 0 {
		c.ImmutableTTL = 24 * time.Hour
	}
	return c
}
