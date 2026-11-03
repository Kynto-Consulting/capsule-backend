package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Build resource limits.
//
// Strategy (honest summary; see also docs/ "Despliegues y salud"):
//
//   - "classic-limited": when CAPSULE_BUILD_MEMORY / CAPSULE_BUILD_CPUS are set and
//     the Dockerfile does not need BuildKit-only syntax, the build runs on the
//     legacy builder (DOCKER_BUILDKIT=0) with --memory / --memory-swap /
//     --cpu-period+--cpu-quota. Docker applies those flags to the container of
//     EVERY RUN step, so a step that exceeds the limit is OOM-killed (exit 137),
//     the build fails and the other containers on the host are not touched.
//
//   - "buildx-builder": when CAPSULE_BUILD_BUILDER names a buildx builder that the
//     operator created with the docker-container driver and --driver-opt
//     memory=... (cpu-quota=... etc.), builds run through it (`docker buildx build
//     --builder X --load`). The limit then applies to the whole BuildKit daemon
//     container. Capsule does not create that builder.
//
//   - "buildkit-unlimited": the Dockerfile needs BuildKit (RUN --mount, heredocs,
//     # syntax=, BUILDPLATFORM ...) and no builder is configured. BuildKit running
//     inside dockerd IGNORES --memory/--cpu flags, so NO memory limit can be
//     enforced; only the timeout and the concurrency gate apply. A warning is
//     written to the build log.
//
// Always enforced, whatever the strategy: the wall-clock timeout
// (CAPSULE_BUILD_TIMEOUT_MINUTES) and the concurrency gate
// (CAPSULE_BUILD_MAX_CONCURRENT).
//
// NOT guaranteed: memory used by dockerd itself (context transfer, layer
// commit/unpack), the docker CLI, and page cache are outside the RUN-step
// cgroup; a cgroup limit also does not stop a build from filling the disk.
// None of this could be verified against a real Docker daemon from the
// development environment.

// Strategy names (also written to the build log).
const (
	StrategyClassicLimited   = "classic-limited"
	StrategyBuildxBuilder    = "buildx-builder"
	StrategyBuildkitUnlimted = "buildkit-unlimited"
)

// BuildError is a failed build with a user-facing explanation.
type BuildError struct {
	OOM      bool
	TimedOut bool
	Msg      string
	Cause    error
}

func (e *BuildError) Error() string { return e.Msg }
func (e *BuildError) Unwrap() error { return e.Cause }

// buildSpec describes one image build.
type buildSpec struct {
	Dir            string // build context
	Tag            string // image tag (-t)
	CacheFrom      string // image to reuse layers from ("" = none)
	DockerfilePath string // for BuildKit-syntax detection
	Platform       string // e.g. linux/amd64 ("" = host)
	Log            func(msg string)
}

type buildResult struct {
	Output   []byte
	Strategy string
	Err      error // nil or *BuildError / other
}

var (
	bkSyntaxRe  = regexp.MustCompile(`(?i)^\s*#\s*syntax\s*=`)
	bkFlagRe    = regexp.MustCompile(`(?i)^\s*(RUN|COPY|ADD)\s+(.*\s)?--(mount|network|security|link|parents|checksum|chmod)\b`)
	bkHeredocRe = regexp.MustCompile(`(?i)^\s*(RUN|COPY|ADD)\b.*<<-?\s*["']?\w+`)
	bkArgRe     = regexp.MustCompile(`\b(BUILDPLATFORM|TARGETPLATFORM|TARGETARCH|TARGETOS|TARGETVARIANT|BUILDOS|BUILDARCH)\b`)
	oomRe       = regexp.MustCompile(`(?im)(non-zero code: 137|exit code: 137|signal: killed|out of memory|\bOOM\b|^\s*killed\s*$|\bKilled\b\s*$)`)
)

// needsBuildKit reports whether the Dockerfile uses syntax the legacy builder
// cannot parse. A missing/unreadable Dockerfile returns false (the build will
// fail on its own with a clear message).
func needsBuildKit(dockerfilePath string) bool {
	f, err := os.Open(dockerfilePath)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if bkSyntaxRe.MatchString(line) || bkFlagRe.MatchString(line) || bkHeredocRe.MatchString(line) {
			return true
		}
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if bkArgRe.MatchString(t) {
			return true
		}
	}
	return false
}

// limitsConfigured reports whether any build resource limit is set.
func (c DeployConfig) limitsConfigured() bool { return c.BuildMemory != "" || c.BuildCPUs != "" }

// classicLimitFlags are the cgroup flags for the legacy builder.
func (c DeployConfig) classicLimitFlags() []string {
	var a []string
	if c.BuildMemory != "" {
		a = append(a, "--memory", c.BuildMemory)
		swap := c.BuildMemorySwap
		if swap == "" {
			swap = c.BuildMemory // equal => no swap
		}
		a = append(a, "--memory-swap", swap)
	}
	if c.BuildCPUs != "" {
		if f, err := strconv.ParseFloat(c.BuildCPUs, 64); err == nil && f > 0 {
			const period = 100000
			a = append(a, "--cpu-period", strconv.Itoa(period), "--cpu-quota", strconv.Itoa(int(f*period)))
		}
	}
	return a
}

// chooseStrategy picks the build strategy and builds the docker arguments/env.
func (w *DeployWorker) chooseStrategy(s buildSpec) (strategy string, args, env []string, note string) {
	cfg := w.ext.cfg
	base := os.Environ()
	bk := needsBuildKit(s.DockerfilePath)

	switch {
	case cfg.BuildBuilder != "":
		args = []string{"buildx", "build", "--builder", cfg.BuildBuilder, "--load", "-t", s.Tag}
		if s.Platform != "" {
			args = append(args, "--platform", s.Platform)
		}
		args = append(args, ".")
		return StrategyBuildxBuilder, args, append(base, "BUILDKIT_PROGRESS=plain"),
			fmt.Sprintf("Build runs on buildx builder %q (limits are those configured on that builder)", cfg.BuildBuilder)

	case cfg.limitsConfigured() && !bk && classicPlatformOK(s.Platform):
		args = []string{"build", "--force-rm"}
		args = append(args, cfg.classicLimitFlags()...)
		if s.CacheFrom != "" {
			args = append(args, "--cache-from", s.CacheFrom)
		}
		args = append(args, "-t", s.Tag, ".")
		return StrategyClassicLimited, args, append(base, "DOCKER_BUILDKIT=0"),
			fmt.Sprintf("Build limits enforced per RUN step (legacy builder): memory=%s swap=%s cpus=%s",
				orDash(cfg.BuildMemory), orDash(cfg.BuildMemorySwap), orDash(cfg.BuildCPUs))

	default:
		args = []string{"build", "--build-arg", "BUILDKIT_INLINE_CACHE=1"}
		if s.CacheFrom != "" {
			args = append(args, "--cache-from", s.CacheFrom)
		}
		if s.Platform != "" {
			args = append(args, "--platform", s.Platform)
		}
		args = append(args, "-t", s.Tag, ".")
		if cfg.limitsConfigured() {
			why := "this Dockerfile needs BuildKit"
			if !bk {
				why = "the build targets a non-host platform"
			}
			note = fmt.Sprintf("WARNING: memory/cpu limits NOT enforced: %s and BuildKit ignores --memory/--cpu-quota. Only the %s timeout and concurrency gate apply.",
				why, cfg.BuildTimeout)
		}
		return StrategyBuildkitUnlimted, args, append(base, "DOCKER_BUILDKIT=1", "BUILDKIT_PROGRESS=plain"), note
	}
}

// classicPlatformOK: the legacy builder cannot cross-build; only allow it when
// no platform is requested or the request is linux/amd64 on an amd64 host.
func classicPlatformOK(platform string) bool {
	if platform == "" {
		return true
	}
	return platform == "linux/amd64" && runtime.GOARCH == "amd64"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// runLimitedBuild runs a docker build under the configured limits. It blocks on
// the concurrency gate, applies the timeout and classifies OOM/timeout failures.
func (w *DeployWorker) runLimitedBuild(ctx context.Context, s buildSpec) buildResult {
	w.ext.init()
	logf := s.Log
	if logf == nil {
		logf = func(string) {}
	}

	// concurrency gate
	select {
	case w.ext.buildSem <- struct{}{}:
		defer func() { <-w.ext.buildSem }()
	case <-ctx.Done():
		return buildResult{Err: &BuildError{Msg: "build cancelled while waiting for a free build slot", Cause: ctx.Err()}}
	}

	strategy, args, env, note := w.chooseStrategy(s)
	if note != "" {
		logf(note)
	}
	logf(fmt.Sprintf("Build strategy: %s (timeout %s, max concurrent builds %d)", strategy, w.ext.cfg.BuildTimeout, w.ext.cfg.BuildMaxConcurrent))

	bctx := ctx
	if t := w.ext.cfg.BuildTimeout; t > 0 {
		var cancel context.CancelFunc
		bctx, cancel = context.WithTimeout(ctx, t)
		defer cancel()
	}
	out, err := w.ext.docker(bctx, dockerCall{Dir: s.Dir, Env: env, Args: args})

	// Legacy fallback kept from the original flow: buildx missing -> classic builder.
	if err != nil && strategy == StrategyBuildkitUnlimted && strings.Contains(string(out), "buildx") && bctx.Err() == nil {
		logf("BuildKit unavailable, falling back to legacy builder")
		legacy := []string{"build"}
		if s.CacheFrom != "" {
			legacy = append(legacy, "--cache-from", s.CacheFrom)
		}
		legacy = append(legacy, "-t", s.Tag, ".")
		out, err = w.ext.docker(bctx, dockerCall{Dir: s.Dir, Env: append(os.Environ(), "DOCKER_BUILDKIT=0"), Args: legacy})
		strategy = "legacy-fallback"
	}
	if err == nil {
		return buildResult{Output: out, Strategy: strategy}
	}
	return buildResult{Output: out, Strategy: strategy, Err: w.classifyBuildError(bctx, strategy, out, err)}
}

func (w *DeployWorker) classifyBuildError(bctx context.Context, strategy string, out []byte, err error) error {
	cfg := w.ext.cfg
	if errors.Is(bctx.Err(), context.DeadlineExceeded) {
		return &BuildError{TimedOut: true, Cause: err,
			Msg: fmt.Sprintf("docker build exceeded the time limit of %s and was cancelled (CAPSULE_BUILD_TIMEOUT_MINUTES)", cfg.BuildTimeout)}
	}
	tail := string(out)
	if len(tail) > 4000 {
		tail = tail[len(tail)-4000:]
	}
	if oomRe.MatchString(tail) {
		switch {
		case strategy == StrategyClassicLimited:
			return &BuildError{OOM: true, Cause: err, Msg: fmt.Sprintf(
				"docker build failed: a build step was killed for exceeding the memory limit (%s, exit 137 / OOM). Reduce the memory used by the build or raise CAPSULE_BUILD_MEMORY. Other containers were not affected",
				cfg.BuildMemory)}
		default:
			return &BuildError{OOM: true, Cause: err, Msg: "docker build failed: a build step was killed (exit 137, probably out of memory). No memory limit was enforced for this build, so the host may have been under memory pressure"}
		}
	}
	return &BuildError{Cause: err, Msg: "docker build failed: " + err.Error()}
}

