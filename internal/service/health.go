package service

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

// httpDoer is the HTTP client seam used by the health probe (faked in tests).
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// workerExt carries the robustness extensions of DeployWorker. It is a single
// field of the worker so the shared worker.go stays almost untouched. Every
// member has a production default applied lazily by init().
type workerExt struct {
	once sync.Once

	cfg         DeployConfig
	cfgSet      bool
	healthStore domain.DeploymentHealthStore // nil: health/error are only logged
	projHealth  domain.ProjectHealthStore    // nil: health check disabled
	docker      dockerFunc
	httpc       httpDoer
	sleep       func(ctx context.Context, d time.Duration)
	now         func() time.Time

	buildSem chan struct{}

	// cleanup seams
	diskUsage func(ctx context.Context, path string) (int, error)
	protected func(ctx context.Context) (map[string]bool, int, error)
}

func (e *workerExt) init() {
	e.once.Do(func() {
		if !e.cfgSet {
			e.cfg = DefaultDeployConfig()
		}
		if e.cfg.BuildMaxConcurrent < 1 {
			e.cfg.BuildMaxConcurrent = 1
		}
		if e.docker == nil {
			e.docker = execDocker
		}
		if e.httpc == nil {
			e.httpc = &http.Client{
				Timeout: 5 * time.Second,
				// 3xx is a valid "alive" answer: never follow redirects.
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}
		}
		if e.sleep == nil {
			e.sleep = func(ctx context.Context, d time.Duration) {
				select {
				case <-ctx.Done():
				case <-time.After(d):
				}
			}
		}
		if e.now == nil {
			e.now = time.Now
		}
		e.buildSem = make(chan struct{}, e.cfg.BuildMaxConcurrent)
	})
}

// WithDeployConfig sets the deploy robustness configuration. Call before Run.
func (w *DeployWorker) WithDeployConfig(cfg DeployConfig) *DeployWorker {
	w.ext.cfg = cfg
	w.ext.cfgSet = true
	return w
}

// WithHealthStores wires persistence of health results (deployments) and the
// per-project health settings. Either may be nil.
func (w *DeployWorker) WithHealthStores(ds domain.DeploymentHealthStore, ps domain.ProjectHealthStore) *DeployWorker {
	w.ext.healthStore = ds
	w.ext.projHealth = ps
	return w
}

// recordFailure stores the failure reason (error_message) of a deployment.
func (w *DeployWorker) recordFailure(ctx context.Context, id uuid.UUID, msg string) {
	if w.ext.healthStore != nil {
		_ = w.ext.healthStore.SetErrorMessage(ctx, id, msg)
	}
}

// projectHealthConfig loads the project's health settings (defaults on any error).
func (w *DeployWorker) projectHealthConfig(ctx context.Context, projectID uuid.UUID) domain.ProjectHealthConfig {
	def := domain.DefaultProjectHealthConfig()
	if w.ext.projHealth == nil {
		return def
	}
	c, err := w.ext.projHealth.GetHealthConfig(ctx, projectID)
	if err != nil {
		w.logger.Warn("deploy worker: could not load health config, using defaults", "project_id", projectID, "error", err)
		return def
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = def.TimeoutSeconds
	}
	if c.IntervalSeconds <= 0 {
		c.IntervalSeconds = def.IntervalSeconds
	}
	if c.ExpectedStatus == "" {
		c.ExpectedStatus = def.ExpectedStatus
	}
	return c
}

// ── blue-green rollout ───────────────────────────────────────────────────────

// rolloutSpec describes one container replacement.
type rolloutSpec struct {
	Final         string // production container name, e.g. capsule-app-<short>
	Network       string // docker network shared with the backend proxy ("" = none)
	ContainerPort int
	// HostPorts are candidate host ports for the new container; the first one the
	// old container does not hold and that docker can bind is used.
	HostPorts []int
	// ExclusivePorts: the container publishes fixed extra host ports that the old and the
	// new container cannot hold at once, so the old one is removed BEFORE starting
	// the new one (no overlap, no automatic rollback possible).
	ExclusivePorts bool
	// RunArgs builds the full `docker run` argument list (without the leading
	// "docker") for the given container name and host port.
	RunArgs   func(name string, hostPort int) []string
	Health    domain.ProjectHealthConfig
	Secrets   []string // env values to redact from captured container logs
	Log       func(level, msg string)
	SetHealth func(h domain.DeploymentHealth)
}

// rolloutResult is the outcome of a rollout.
type rolloutResult struct {
	ContainerID string
	HostPort    int
	Err         error
	// KeptPrevious is true when the rollout failed and an older container is still serving.
	KeptPrevious bool
}

const (
	logTailLines   = 50
	logSnippetMax  = 600
	nextNameSuffix = "-next"
)

var (
	portInUseRe = regexp.MustCompile(`(?i)port is already allocated|address already in use|bind for .* failed`)
	heldPortRe  = regexp.MustCompile(`:(\d+)\s*$`)
)

// heldHostPorts parses `docker port <name>` output ("3000/tcp -> 0.0.0.0:20123").
func heldHostPorts(out string) map[int]bool {
	held := map[int]bool{}
	for _, line := range strings.Split(out, "\n") {
		if m := heldPortRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			if p, err := strconv.Atoi(m[1]); err == nil {
				held[p] = true
			}
		}
	}
	return held
}

// rollout performs the blue-green replacement:
//
//  1. start the NEW container under a temporary name and its own host port;
//  2. wait until it is healthy (HTTP probe) or has stayed up MinUptime;
//  3. only then remove the old container and rename the new one to the
//     production name; on any failure remove the new one and leave the old
//     container untouched.
//
// Traffic switches by container name (the proxy dials the production name on the
// docker network), so the only gap is the instant between removing the old
// container and renaming the new one (two docker API calls, normally
// milliseconds); it is not literally zero.
func (w *DeployWorker) rollout(ctx context.Context, s rolloutSpec) rolloutResult {
	w.ext.init()
	ro := &rolloutRun{w: w, s: s}
	return ro.execute(ctx)
}

type rolloutRun struct {
	w *DeployWorker
	s rolloutSpec
}

func (r *rolloutRun) docker(ctx context.Context, args ...string) ([]byte, error) {
	return r.w.ext.docker(ctx, dockerCall{Args: args})
}

func (r *rolloutRun) exists(ctx context.Context, name string) bool {
	_, err := r.docker(ctx, "inspect", "-f", "{{.Id}}", name)
	return err == nil
}

func (r *rolloutRun) execute(ctx context.Context) rolloutResult {
	s := r.s
	tmp := s.Final + nextNameSuffix
	// A leftover from a crashed worker would block the name.
	_, _ = r.docker(ctx, "rm", "-f", tmp)

	hadPrev := r.exists(ctx, s.Final)
	if hadPrev && s.ExclusivePorts {
		s.Log("warn", "Project publishes fixed extra ports: the previous container is removed before the new one starts (no overlap, no automatic rollback)")
		_, _ = r.docker(ctx, "rm", "-f", s.Final)
		hadPrev = false
	}
	held := map[int]bool{}
	if hadPrev {
		out, _ := r.docker(ctx, "port", s.Final)
		held = heldHostPorts(string(out))
	}

	// --- start the new container ---
	var containerID string
	var hostPort int
	var runErr error
	for _, p := range s.HostPorts {
		if held[p] {
			continue // held by the running (old) container
		}
		out, err := r.docker(ctx, s.RunArgs(tmp, p)...)
		if err == nil {
			containerID = strings.TrimSpace(string(out))
			hostPort = p
			runErr = nil
			break
		}
		runErr = fmt.Errorf("docker run failed: %s", truncate(strings.TrimSpace(string(out)), 400))
		_, _ = r.docker(ctx, "rm", "-f", tmp)
		if !portInUseRe.MatchString(string(out)) {
			break
		}
	}
	if containerID == "" {
		if runErr == nil {
			runErr = fmt.Errorf("no free host port available for the new container")
		}
		return rolloutResult{Err: runErr, KeptPrevious: hadPrev}
	}
	s.Log("info", fmt.Sprintf("New container started as %s (candidate, host port %d); verifying before switching traffic", tmp, hostPort))

	// --- attach to the proxy network (needed to probe by name and to serve) ---
	connected := false
	if s.Network != "" {
		if out, err := r.docker(ctx, "network", "connect", s.Network, tmp); err != nil {
			s.Log("warn", "Could not connect candidate to backend network: "+truncate(strings.TrimSpace(string(out)), 200))
		} else {
			connected = true
		}
	}

	// --- verify ---
	if reason := r.verify(ctx, tmp, hostPort, connected); reason != "" {
		return r.abort(ctx, tmp, reason, hadPrev)
	}

	// --- switch traffic ---
	if hadPrev {
		if out, err := r.docker(ctx, "rm", "-f", s.Final); err != nil {
			return r.abort(ctx, tmp, "could not remove the previous container: "+truncate(strings.TrimSpace(string(out)), 200), true)
		}
	}
	if out, err := r.docker(ctx, "rename", tmp, s.Final); err != nil {
		return rolloutResult{
			ContainerID: containerID, HostPort: hostPort,
			Err: fmt.Errorf("new container is healthy but could not be renamed to %s (service interrupted): %s", s.Final, truncate(strings.TrimSpace(string(out)), 200)),
		}
	}
	if hadPrev {
		s.Log("info", "Traffic switched to the new container; previous container removed")
	}
	return rolloutResult{ContainerID: containerID, HostPort: hostPort}
}

// verify waits for health. It returns "" when the candidate is acceptable,
// otherwise the human-readable reason.
func (r *rolloutRun) verify(ctx context.Context, tmp string, hostPort int, connected bool) string {
	s := r.s
	e := &r.w.ext
	hc := s.Health
	path := hc.Path
	timeout := time.Duration(hc.TimeoutSeconds) * time.Second
	interval := time.Duration(hc.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 3 * time.Second
	}
	if path == "" {
		timeout = e.cfg.MinUptime
		if interval > time.Second {
			interval = time.Second
		}
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", hostPort)
	if connected {
		base = fmt.Sprintf("http://%s:%d", tmp, s.ContainerPort)
	}
	report := func(status, detail string) {
		if s.SetHealth != nil {
			now := e.now()
			s.SetHealth(domain.DeploymentHealth{Status: status, Path: path, LastCheck: &now, Detail: detail})
		}
	}
	if path != "" {
		s.Log("info", fmt.Sprintf("Health check: GET %s (expect %s, timeout %ds)", path, hc.ExpectedStatus, hc.TimeoutSeconds))
		report(domain.HealthChecking, "waiting for the new container to answer")
	} else {
		s.Log("info", fmt.Sprintf("No health_path configured: verifying the container stays up for %s", e.cfg.MinUptime))
	}

	start := e.now()
	lastDetail := "no response yet"
	for {
		if ctx.Err() != nil {
			report(domain.HealthUnknown, "deployment cancelled")
			return "deployment cancelled while verifying"
		}
		if crashed, why := r.crashed(ctx, tmp); crashed {
			report(domain.HealthUnhealthy, why)
			return why
		}
		if path != "" {
			code, err := r.probe(ctx, base+path)
			switch {
			case err != nil:
				lastDetail = "no answer: " + truncate(err.Error(), 160)
			case domain.StatusMatches(hc.ExpectedStatus, code):
				report(domain.HealthHealthy, fmt.Sprintf("HTTP %d", code))
				s.Log("info", fmt.Sprintf("Health check passed: GET %s -> HTTP %d", path, code))
				return ""
			default:
				lastDetail = fmt.Sprintf("HTTP %d (expected %s)", code, hc.ExpectedStatus)
			}
		} else if e.now().Sub(start) >= timeout {
			report(domain.HealthHealthy, fmt.Sprintf("container stayed up for %s", e.cfg.MinUptime))
			s.Log("info", fmt.Sprintf("Container stayed up for %s", e.cfg.MinUptime))
			return ""
		}
		if e.now().Sub(start) >= timeout {
			why := fmt.Sprintf("health check GET %s did not succeed within %ds (last: %s)", path, hc.TimeoutSeconds, lastDetail)
			report(domain.HealthUnhealthy, why)
			return why
		}
		report(domain.HealthChecking, lastDetail)
		e.sleep(ctx, interval)
	}
}

// crashed detects an exited / restarting container (crash loop).
func (r *rolloutRun) crashed(ctx context.Context, name string) (bool, string) {
	out, err := r.docker(ctx, "inspect", "-f", "{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}", name)
	if err != nil {
		return true, "the new container disappeared during verification"
	}
	parts := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(parts) != 3 {
		return false, ""
	}
	status := parts[0]
	restarts, _ := strconv.Atoi(parts[2])
	switch {
	case status == "restarting" || restarts > 0:
		return true, fmt.Sprintf("the new container is crash-looping (restarted %d time(s), exit code %s)", restarts, parts[1])
	case status != "running":
		return true, fmt.Sprintf("the new container exited right after start (status %s, exit code %s)", status, parts[1])
	}
	return false, ""
}

func (r *rolloutRun) probe(ctx context.Context, url string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "capsule-healthcheck/1")
	resp, err := r.w.ext.httpc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// abort removes the candidate, records its last logs (redacted) and reports the
// failure. The previous container is never touched here.
func (r *rolloutRun) abort(ctx context.Context, tmp, reason string, hadPrev bool) rolloutResult {
	s := r.s
	snippet := ""
	if out, err := r.docker(ctx, "logs", "--tail", strconv.Itoa(logTailLines), tmp); err == nil || len(out) > 0 {
		lines := redactLogs(string(out), s.Secrets)
		if strings.TrimSpace(lines) != "" {
			s.Log("error", fmt.Sprintf("Last %d log lines of the failed container:\n%s", logTailLines, lines))
			snippet = lastLines(lines, 5, logSnippetMax)
		}
	}
	_, _ = r.docker(ctx, "rm", "-f", tmp)
	msg := reason
	if snippet != "" {
		msg += ". Last logs: " + snippet
	}
	if hadPrev {
		msg += ". The previous deployment keeps serving traffic (automatic rollback)."
	}
	return rolloutResult{Err: fmt.Errorf("%s", msg), KeptPrevious: hadPrev}
}

// ── log redaction ────────────────────────────────────────────────────────────

var (
	secretAssignRe = regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CREDENTIAL|DATABASE_URL|DSN)[A-Z0-9_]*)\s*[=:]\s*\S+`)
	urlCredRe      = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+):[^\s@/]+@`)
)

// redactLogs masks known secret values and common credential patterns.
func redactLogs(s string, secrets []string) string {
	for _, v := range secrets {
		if len(v) >= 4 {
			s = strings.ReplaceAll(s, v, "[REDACTED]")
		}
	}
	s = secretAssignRe.ReplaceAllString(s, "$1=[REDACTED]")
	s = urlCredRe.ReplaceAllString(s, "$1:[REDACTED]@")
	return strings.TrimRight(s, "\r\n ")
}

func lastLines(s string, n, maxLen int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := strings.Join(lines, " | ")
	return truncate(strings.TrimSpace(out), maxLen)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// envValues returns the values of KEY=VALUE pairs (for log redaction).
func envValues(pairs []string) []string {
	var out []string
	for _, kv := range pairs {
		if i := strings.IndexByte(kv, '=');  i >= 0 {
			out = append(out, kv[i+1:])
		}
	}
	return out
}
