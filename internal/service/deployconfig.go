package service

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// DeployConfig holds the robustness knobs of the deploy worker: crash-loop
// detection, build resource limits and scheduled cleanup. Every field has a safe
// default so the worker behaves sensibly when LoadDeployConfig is never called.
type DeployConfig struct {
	// CAPSULE_DEPLOY_MIN_UPTIME_SECONDS: with no health_path the new container
	// must stay up this long before traffic is switched (default 5).
	MinUptime time.Duration

	// Build limits. Empty string = flag not passed. See buildlimits.go for what
	// each one really guarantees.
	BuildMemory        string        // CAPSULE_BUILD_MEMORY, e.g. 1500m
	BuildMemorySwap    string        // CAPSULE_BUILD_MEMORY_SWAP (default = BuildMemory: no swap)
	BuildCPUs          string        // CAPSULE_BUILD_CPUS, e.g. 1.5
	BuildTimeout       time.Duration // CAPSULE_BUILD_TIMEOUT_MINUTES (default 30)
	BuildMaxConcurrent int           // CAPSULE_BUILD_MAX_CONCURRENT (default 1)
	BuildBuilder       string        // CAPSULE_BUILD_BUILDER: optional pre-created buildx builder whose container carries the memory limit

	// Scheduled cleanup of build cache and orphan images.
	CleanupInterval  time.Duration // CAPSULE_CLEANUP_INTERVAL_HOURS (default 6; 0 disables)
	CacheMaxAge      time.Duration // CAPSULE_CLEANUP_CACHE_MAX_AGE_HOURS (default 168 = 7 days)
	CacheKeepStorage string        // CAPSULE_CLEANUP_KEEP_STORAGE (default 4GB)
	DiskPath         string        // CAPSULE_DISK_PATH (default /var/lib/docker if present, else /)
	DiskMaxPercent   int           // CAPSULE_DISK_MAX_PERCENT (default 85): above it cleanup becomes aggressive
	DiskWarnPercent  int           // fixed 80: log alert
}

// DefaultDeployConfig returns the defaults.
func DefaultDeployConfig() DeployConfig {
	return DeployConfig{
		MinUptime:          5 * time.Second,
		BuildTimeout:       30 * time.Minute,
		BuildMaxConcurrent: 1,
		CleanupInterval:    6 * time.Hour,
		CacheMaxAge:        168 * time.Hour,
		CacheKeepStorage:   "4GB",
		DiskPath:           "/",
		DiskMaxPercent:     85,
		DiskWarnPercent:    80,
	}
}

// LoadDeployConfig reads the CAPSULE_* variables; invalid values keep defaults.
func LoadDeployConfig() DeployConfig {
	return loadDeployConfig(os.Getenv)
}

func loadDeployConfig(get func(string) string) DeployConfig {
	c := DefaultDeployConfig()
	num := func(key string, min int) (int, bool) {
		v := strings.TrimSpace(get(key))
		if v == "" {
			return 0, false
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < min {
			return 0, false
		}
		return n, true
	}
	if n, ok := num("CAPSULE_DEPLOY_MIN_UPTIME_SECONDS", 0); ok {
		c.MinUptime = time.Duration(n) * time.Second
	}
	c.BuildMemory = cleanSize(get("CAPSULE_BUILD_MEMORY"))
	c.BuildMemorySwap = cleanSize(get("CAPSULE_BUILD_MEMORY_SWAP"))
	if c.BuildMemorySwap == "" {
		c.BuildMemorySwap = c.BuildMemory // equal => no swap for the build
	}
	c.BuildCPUs = cleanCPUs(get("CAPSULE_BUILD_CPUS"))
	if n, ok := num("CAPSULE_BUILD_TIMEOUT_MINUTES", 1); ok {
		c.BuildTimeout = time.Duration(n) * time.Minute
	}
	if n, ok := num("CAPSULE_BUILD_MAX_CONCURRENT", 1); ok {
		c.BuildMaxConcurrent = n
	}
	c.BuildBuilder = safeToken(get("CAPSULE_BUILD_BUILDER"))
	if n, ok := num("CAPSULE_CLEANUP_INTERVAL_HOURS", 0); ok {
		c.CleanupInterval = time.Duration(n) * time.Hour
	}
	if n, ok := num("CAPSULE_CLEANUP_CACHE_MAX_AGE_HOURS", 1); ok {
		c.CacheMaxAge = time.Duration(n) * time.Hour
	}
	if s := cleanSize(get("CAPSULE_CLEANUP_KEEP_STORAGE")); s != "" {
		c.CacheKeepStorage = s
	}
	if p := strings.TrimSpace(get("CAPSULE_DISK_PATH")); p != "" {
		c.DiskPath = p
	}
	if n, ok := num("CAPSULE_DISK_MAX_PERCENT", 50); ok && n <= 99 {
		c.DiskMaxPercent = n
	}
	return c
}

// cleanSize accepts docker size literals such as 1500m, 2g, 4GB (digits + optional unit).
func cleanSize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 12 {
		return ""
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return ""
	}
	switch strings.ToLower(s[i:]) {
	case "", "b", "k", "kb", "m", "mb", "g", "gb":
		return s
	}
	return ""
}

func cleanCPUs(s string) string {
	s = strings.TrimSpace(s)
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 || f > 256 {
		return ""
	}
	return s
}

func safeToken(s string) string {
	s = strings.TrimSpace(s)
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return ""
		}
	}
	return s
}

// ── docker execution seam (faked in tests) ───────────────────────────────────

// dockerCall is one invocation of the docker CLI.
type dockerCall struct {
	Dir   string
	Env   []string
	Args  []string
	Stdin io.Reader // e.g. the registry password of `docker login --password-stdin`
}

// dockerFunc runs the docker CLI and returns combined output.
type dockerFunc func(ctx context.Context, c dockerCall) ([]byte, error)

func execDocker(ctx context.Context, c dockerCall) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", c.Args...)
	cmd.Dir = c.Dir
	cmd.Stdin = c.Stdin
	if c.Env != nil {
		cmd.Env = c.Env
	}
	return cmd.CombinedOutput()
}

func (w *DeployWorker) dock(ctx context.Context, args ...string) ([]byte, error) {
	w.ext.init()
	f := w.ext.docker
	if f == nil {
		f = execDocker
	}
	return f(ctx, dockerCall{Args: args})
}
