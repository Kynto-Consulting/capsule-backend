package domain

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Deployment health states reported in Deployment.Health.Status.
const (
	HealthUnknown   = "unknown"
	HealthChecking  = "checking"
	HealthHealthy   = "healthy"
	HealthUnhealthy = "unhealthy"
)

// DeploymentHealth is the "health" object exposed on a deployment.
// Example: {"status":"healthy","path":"/healthz","last_check":"2026-11-02T10:00:00Z","detail":"HTTP 200"}
type DeploymentHealth struct {
	Status    string     `json:"status"`
	Path      string     `json:"path,omitempty"`
	LastCheck *time.Time `json:"last_check,omitempty"`
	Detail    string     `json:"detail,omitempty"`
}

// Defaults for the per-project health settings.
const (
	DefaultHealthTimeoutSeconds  = 60
	DefaultHealthIntervalSeconds = 3
	DefaultHealthExpectedStatus  = "200-399"
	MaxHealthPathLen             = 200
	MinHealthTimeoutSeconds      = 5
	MaxHealthTimeoutSeconds      = 600
)

// ProjectHealthConfig is the per-project health-check configuration.
// An empty Path disables the HTTP check.
type ProjectHealthConfig struct {
	Path            string `json:"health_path"`
	TimeoutSeconds  int    `json:"health_timeout_seconds"`
	IntervalSeconds int    `json:"health_interval_seconds"`
	ExpectedStatus  string `json:"health_expected_status"`
}

// DefaultProjectHealthConfig returns the defaults (check disabled).
func DefaultProjectHealthConfig() ProjectHealthConfig {
	return ProjectHealthConfig{
		TimeoutSeconds:  DefaultHealthTimeoutSeconds,
		IntervalSeconds: DefaultHealthIntervalSeconds,
		ExpectedStatus:  DefaultHealthExpectedStatus,
	}
}

// ProjectHealthStore persists the health settings (implemented by the
// concrete project repository; kept separate so ProjectRepository fakes elsewhere
// are not affected).
type ProjectHealthStore interface {
	GetHealthConfig(ctx context.Context, projectID uuid.UUID) (ProjectHealthConfig, error)
	SetHealthConfig(ctx context.Context, projectID uuid.UUID, cfg ProjectHealthConfig) error
}

// DeploymentHealthStore persists health results and failure reasons.
type DeploymentHealthStore interface {
	SetHealth(ctx context.Context, id uuid.UUID, h DeploymentHealth) error
	SetErrorMessage(ctx context.Context, id uuid.UUID, msg string) error
}

// ValidateHealthPath checks a health path: must start with "/", no scheme or
// host, no whitespace/control chars, no fragment, bounded length. Empty is valid
// (disables the check).
func ValidateHealthPath(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > MaxHealthPathLen {
		return fmt.Errorf("health_path too long (max %d)", MaxHealthPathLen)
	}
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return fmt.Errorf("health_path must start with a single '/' and contain no scheme or host")
	}
	if strings.Contains(p, "://") || strings.Contains(p, "\\") || strings.Contains(p, "#") {
		return fmt.Errorf("health_path must be a path only (no scheme, host or fragment)")
	}
	for _, r := range p {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("health_path contains invalid characters")
		}
	}
	return nil
}

// ValidateHealthTimeout enforces 5..600 seconds.
func ValidateHealthTimeout(s int) error {
	if s < MinHealthTimeoutSeconds || s > MaxHealthTimeoutSeconds {
		return fmt.Errorf("health_timeout_seconds must be between %d and %d", MinHealthTimeoutSeconds, MaxHealthTimeoutSeconds)
	}
	return nil
}

// ValidateHealthInterval enforces 1..30 seconds.
func ValidateHealthInterval(s int) error {
	if s < 1 || s > 30 {
		return fmt.Errorf("health_interval_seconds must be between 1 and 30")
	}
	return nil
}

// statusRange is an inclusive HTTP status range.
type statusRange struct{ lo, hi int }

func parseExpectedStatus(spec string) ([]statusRange, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("health_expected_status is empty")
	}
	var out []statusRange
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		lo, hi := part, part
		if i := strings.Index(part, "-"); i >= 0 {
			lo, hi = strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+1:])
		}
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || a < 100 || b > 599 || a > b {
			return nil, fmt.Errorf("health_expected_status %q is invalid (use e.g. \"200\", \"200-399\" or \"200,204\")", spec)
		}
		out = append(out, statusRange{a, b})
	}
	return out, nil
}

// ValidateExpectedStatus validates a spec such as "200", "200-399" or "200,204,301-302".
func ValidateExpectedStatus(spec string) error {
	_, err := parseExpectedStatus(spec)
	return err
}

// StatusMatches reports whether code satisfies spec. An invalid spec falls back
// to the default range.
func StatusMatches(spec string, code int) bool {
	rs, err := parseExpectedStatus(spec)
	if err != nil {
		rs, _ = parseExpectedStatus(DefaultHealthExpectedStatus)
	}
	for _, r := range rs {
		if code >= r.lo && code <= r.hi {
			return true
		}
	}
	return false
}
