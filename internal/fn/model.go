// Package fn runs project functions inside a VPN tunnel: definitions, queue, cron, run tokens and the claim protocol of
// the work node (docs/vpn-connector.md). The backend only plans and audits; the agent on the work node executes.
package fn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
)

// Run states.
const (
	RunQueued    = "queued"
	RunRunning   = "running"
	RunSucceeded = "succeeded"
	RunFailed    = "failed"
	RunCancelled = "cancelled"
	RunTimeout   = "timeout"
)

// Runtimes: where a function executes.
const (
	RuntimeContainer = "container" // on the work node, in a limited container (hybrid default; no 15-minute cap)
	RuntimeLambda    = "lambda"    // as its own AWS Lambda, in resumable batches of at most 13 minutes
)

// Triggers.
const (
	TriggerCron  = "cron"
	TriggerAPI   = "api"
	TriggerQueue = "queue"
)

// Limits.
const (
	MaxMemoryMB   = 4096
	MaxTimeout    = 6 * time.Hour
	TokenGrace    = 5 * time.Minute
	TokenPrefix   = "capfn_"
	NodeTokPrefix = "capnode_"
)

var (
	nameRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)
	scopeRe = regexp.MustCompile(`^(api|storage|db):[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)
	memRe   = regexp.MustCompile(`^(\d+)([mg])$`)
)

// ErrInvalid wraps validation failures (HTTP 422).
var ErrInvalid = errors.New("invalid function")

func invalid(f string, a ...any) error { return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(f, a...)) }

// Function is a deployed function.
type Function struct {
	ID             uuid.UUID  `json:"id"`
	OrgID          uuid.UUID  `json:"org_id"`
	ProjectID      uuid.UUID  `json:"project_id"`
	Name           string     `json:"name"`
	Image          string     `json:"image"`
	Entry          string     `json:"entry"`
	Runtime        string     `json:"runtime"`
	VPNID          *uuid.UUID `json:"vpn_id,omitempty"`
	Cron           string     `json:"cron,omitempty"`
	MemoryMB       int        `json:"memory_mb"`
	CPUs           float64    `json:"cpus"`
	TimeoutSeconds int        `json:"timeout_seconds"`
	MaxConcurrency int        `json:"max_concurrency"`
	Scopes         []string   `json:"scopes"`
	Enabled        bool       `json:"enabled"`
	LastCronAt     *time.Time `json:"last_cron_at,omitempty"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Run is one execution.
type Run struct {
	ID          uuid.UUID       `json:"id"`
	FunctionID  uuid.UUID       `json:"function_id"`
	ProjectID   uuid.UUID       `json:"project_id"`
	Trigger     string          `json:"trigger"`
	TriggeredBy string          `json:"triggered_by"`
	Status      string          `json:"status"`
	QueuedAt    time.Time       `json:"queued_at"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
	ExitCode    *int            `json:"exit_code,omitempty"`
	Scopes      []string        `json:"scopes"`
	BytesIn     int64           `json:"bytes_in"`
	BytesOut    int64           `json:"bytes_out"`
	NodeID      string          `json:"node_id,omitempty"`
	Payload     json.RawMessage `json:"payload,omitempty"`
	LogTail     string          `json:"log_tail,omitempty"`
}

// Spec is the user input of `capsule fn deploy`.
type Spec struct {
	Name           string   `json:"name"`
	Image          string   `json:"image"`
	Entry          string   `json:"entry"`
	Runtime        string   `json:"runtime"`
	VPN            string   `json:"vpn"`
	Cron           string   `json:"cron"`
	Memory         string   `json:"memory"`
	CPUs           float64  `json:"cpus"`
	Timeout        string   `json:"timeout"`
	MaxConcurrency int      `json:"max_concurrency"`
	Scopes         []string `json:"scopes"`
	// SourceKey replaces Image: an uploaded directory (POST .../fn/uploads) that Capsule builds into an image (DeployFromSource).
	SourceKey string `json:"source_key,omitempty"`
}

// Normalize validates and fills defaults: 512m, 1 CPU, 1 h, one run at a time, no scopes.
func (s Spec) Normalize() (Spec, error) {
	s.Name = strings.ToLower(strings.TrimSpace(s.Name))
	if !nameRe.MatchString(s.Name) {
		return s, invalid("name must be 1-40 chars of a-z, 0-9 and '-'")
	}
	s.SourceKey = strings.TrimSpace(s.SourceKey)
	switch {
	case s.SourceKey != "" && strings.TrimSpace(s.Image) != "":
		return s, invalid("use either an image or a source to build, not both")
	case s.SourceKey == "" && strings.TrimSpace(s.Image) == "":
		return s, invalid("image (or a source to build) is required")
	case s.SourceKey != "" && !sourceKeyRe.MatchString(s.SourceKey):
		return s, invalid("source_key must be an upload of this project (POST .../fn/uploads)")
	}
	if strings.ContainsAny(s.Image, " \t\n;&|$`") {
		return s, invalid("image has invalid characters")
	}
	switch s.Runtime = strings.ToLower(strings.TrimSpace(s.Runtime)); s.Runtime {
	case "":
		s.Runtime = RuntimeContainer
	case RuntimeContainer, RuntimeLambda:
	default:
		return s, invalid("runtime must be %q or %q", RuntimeContainer, RuntimeLambda)
	}
	if s.Memory == "" {
		s.Memory = "512m"
	}
	if _, err := ParseMemoryMB(s.Memory); err != nil {
		return s, err
	}
	if s.Timeout == "" {
		s.Timeout = "1h"
	}
	if _, err := ParseTimeout(s.Timeout); err != nil {
		return s, err
	}
	if s.CPUs == 0 {
		s.CPUs = 1
	}
	if s.CPUs < 0.1 || s.CPUs > 4 {
		return s, invalid("cpus must be between 0.1 and 4")
	}
	if s.MaxConcurrency == 0 {
		s.MaxConcurrency = 1
	}
	if s.MaxConcurrency < 1 || s.MaxConcurrency > 8 {
		return s, invalid("max_concurrency must be between 1 and 8")
	}
	if s.Cron != "" {
		if _, err := ParseCron(s.Cron); err != nil {
			return s, invalid("cron: %v", err)
		}
	}
	seen := map[string]bool{}
	for _, sc := range s.Scopes {
		if !scopeRe.MatchString(sc) {
			return s, invalid("scope %q must look like api:<name>, storage:<name> or db:<name> (no wildcards)", sc)
		}
		if seen[sc] {
			return s, invalid("duplicate scope %q", sc)
		}
		seen[sc] = true
	}
	return s, nil
}

// ParseCron parses a standard 5-field expression.
func ParseCron(expr string) (cron.Schedule, error) {
	return cron.ParseStandard(expr)
}

// ParseMemoryMB reads 512m / 2g.
func ParseMemoryMB(v string) (int, error) {
	m := memRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(v)))
	if m == nil {
		return 0, invalid("memory must look like 512m or 2g")
	}
	n, _ := strconv.Atoi(m[1])
	if m[2] == "g" {
		n *= 1024
	}
	if n < 64 || n > MaxMemoryMB {
		return 0, invalid("memory must be between 64m and %dm", MaxMemoryMB)
	}
	return n, nil
}

// ParseTimeout reads 90s / 30m / 2h (Go durations).
func ParseTimeout(v string) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil || d < 10*time.Second || d > MaxTimeout {
		return 0, invalid("timeout must be a duration between 10s and %s", MaxTimeout)
	}
	return d, nil
}

// NewToken returns a random token with the given prefix and its SHA-256 hex hash (only the hash is stored).
func NewToken(prefix string) (plain, hash string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	plain = prefix + hex.EncodeToString(b)
	return plain, HashToken(plain)
}

// HashToken is the stored form of a token.
func HashToken(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}

// RunToken is the short-lived, scoped credential of one run.
type RunToken struct {
	Hash      string
	RunID     uuid.UUID
	ProjectID uuid.UUID
	Scopes    []string
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Claims is what the introspection endpoint returns to the customer's app.
type Claims struct {
	Active    bool      `json:"active"`
	ProjectID uuid.UUID `json:"project_id,omitempty"`
	Function  string    `json:"function,omitempty"`
	RunID     uuid.UUID `json:"run_id,omitempty"`
	Scopes    []string  `json:"scopes,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// HasScope reports whether the claims carry scope exactly (no wildcards, least privilege).
func (c Claims) HasScope(scope string) bool {
	if !c.Active {
		return false
	}
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}
