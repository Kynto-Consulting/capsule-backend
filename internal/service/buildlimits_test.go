package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func writeDockerfile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadDeployConfigDefaultsAndValues(t *testing.T) {
	d := loadDeployConfig(envMap(nil))
	if d.MinUptime != 5*time.Second || d.BuildTimeout != 30*time.Minute || d.BuildMaxConcurrent != 1 || d.BuildMemory != "" {
		t.Fatalf("defaults: %+v", d)
	}
	c := loadDeployConfig(envMap(map[string]string{
		"CAPSULE_DEPLOY_MIN_UPTIME_SECONDS": "9",
		"CAPSULE_BUILD_MEMORY":              "1500m",
		"CAPSULE_BUILD_CPUS":                "1.5",
		"CAPSULE_BUILD_TIMEOUT_MINUTES":     "10",
		"CAPSULE_BUILD_MAX_CONCURRENT":      "2",
		"CAPSULE_CLEANUP_KEEP_STORAGE":      "2GB",
		"CAPSULE_DISK_MAX_PERCENT":          "90",
	}))
	if c.MinUptime != 9*time.Second || c.BuildMemory != "1500m" || c.BuildMemorySwap != "1500m" || c.BuildCPUs != "1.5" ||
		c.BuildTimeout != 10*time.Minute || c.BuildMaxConcurrent != 2 || c.CacheKeepStorage != "2GB" || c.DiskMaxPercent != 90 {
		t.Fatalf("values: %+v", c)
	}
	// invalid values fall back to defaults / are dropped (never reach the docker command line)
	bad := loadDeployConfig(envMap(map[string]string{
		"CAPSULE_BUILD_MEMORY": "1500m; rm -rf /", "CAPSULE_BUILD_CPUS": "abc", "CAPSULE_BUILD_TIMEOUT_MINUTES": "0",
		"CAPSULE_BUILD_MAX_CONCURRENT": "-3", "CAPSULE_BUILD_BUILDER": "x y;z", "CAPSULE_DISK_MAX_PERCENT": "150",
	}))
	if bad.BuildMemory != "" || bad.BuildCPUs != "" || bad.BuildTimeout != 30*time.Minute || bad.BuildMaxConcurrent != 1 || bad.BuildBuilder != "" || bad.DiskMaxPercent != 85 {
		t.Fatalf("bad values accepted: %+v", bad)
	}
	s := loadDeployConfig(envMap(map[string]string{"CAPSULE_BUILD_MEMORY": "1g", "CAPSULE_BUILD_MEMORY_SWAP": "3g"}))
	if s.BuildMemorySwap != "3g" {
		t.Fatalf("explicit swap: %+v", s)
	}
}

func TestNeedsBuildKit(t *testing.T) {
	plain := "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\nEXPOSE 3000\nCMD [\"node\",\"index.js\"]\n"
	if needsBuildKit(writeDockerfile(t, plain)) {
		t.Fatal("plain Dockerfile does not need BuildKit")
	}
	for name, body := range map[string]string{
		"syntax":    "# syntax=docker/dockerfile:1\nFROM a\n",
		"mount":     "FROM a\nRUN --mount=type=cache,target=/root/.npm npm ci\n",
		"link":      "FROM a\nCOPY --link a b\n",
		"heredoc":   "FROM a\nRUN <<EOF\necho hi\nEOF\n",
		"platform":  "FROM --platform=$BUILDPLATFORM golang AS b\n",
		"targetarc": "FROM a\nARG TARGETARCH\nRUN echo $TARGETARCH\n",
	} {
		if !needsBuildKit(writeDockerfile(t, body)) {
			t.Errorf("%s: should need BuildKit", name)
		}
	}
	if needsBuildKit("/nonexistent/Dockerfile") {
		t.Fatal("missing file must not claim BuildKit")
	}
}

func buildWorker(cfg DeployConfig, fn dockerFunc) *DeployWorker {
	w := &DeployWorker{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w.ext.cfg = cfg
	w.ext.cfgSet = true
	w.ext.docker = fn
	return w
}

func hasSeq(args []string, seq ...string) bool {
	for i := 0; i+len(seq) <= len(args); i++ {
		if strings.Join(args[i:i+len(seq)], " ") == strings.Join(seq, " ") {
			return true
		}
	}
	return false
}

func TestBuildFlagsClassicLimited(t *testing.T) {
	cfg := DefaultDeployConfig()
	cfg.BuildMemory, cfg.BuildMemorySwap, cfg.BuildCPUs = "1500m", "1500m", "1.5"
	var got dockerCall
	w := buildWorker(cfg, func(_ context.Context, c dockerCall) ([]byte, error) { got = c; return []byte("ok"), nil })
	df := writeDockerfile(t, "FROM node\nRUN npm ci\n")
	var logs []string
	res := w.runLimitedBuild(context.Background(), buildSpec{Dir: "/b", Tag: "img", CacheFrom: "img", DockerfilePath: df, Log: func(m string) { logs = append(logs, m) }})
	if res.Err != nil || res.Strategy != StrategyClassicLimited {
		t.Fatalf("%+v", res)
	}
	for _, seq := range [][]string{{"--memory", "1500m"}, {"--memory-swap", "1500m"}, {"--cpu-period", "100000"}, {"--cpu-quota", "150000"}, {"--cache-from", "img"}, {"-t", "img"}} {
		if !hasSeq(got.Args, seq...) {
			t.Errorf("missing %v in %v", seq, got.Args)
		}
	}
	if got.Args[0] != "build" || got.Dir != "/b" {
		t.Fatalf("%+v", got)
	}
	if !contains(got.Env, "DOCKER_BUILDKIT=0") || contains(got.Env, "DOCKER_BUILDKIT=1") {
		t.Fatal("classic strategy must disable BuildKit")
	}
}

func TestBuildFlagsBuildKitDockerfileGetsNoLimitsAndWarns(t *testing.T) {
	cfg := DefaultDeployConfig()
	cfg.BuildMemory, cfg.BuildMemorySwap = "1500m", "1500m"
	var got dockerCall
	w := buildWorker(cfg, func(_ context.Context, c dockerCall) ([]byte, error) { got = c; return nil, nil })
	df := writeDockerfile(t, "# syntax=docker/dockerfile:1\nFROM a\nRUN --mount=type=cache,target=/c make\n")
	var logs []string
	res := w.runLimitedBuild(context.Background(), buildSpec{Dir: "/b", Tag: "img", DockerfilePath: df, Log: func(m string) { logs = append(logs, m) }})
	if res.Strategy != StrategyBuildkitUnlimted {
		t.Fatalf("%+v", res)
	}
	if hasSeq(got.Args, "--memory", "1500m") {
		t.Fatal("BuildKit ignores --memory: must not pretend to pass it")
	}
	if !strings.Contains(strings.Join(logs, "\n"), "NOT enforced") {
		t.Fatalf("honest warning missing: %v", logs)
	}
	if !contains(got.Env, "DOCKER_BUILDKIT=1") {
		t.Fatal("BuildKit env expected")
	}
}

func TestBuildFlagsNoLimitsConfiguredKeepsBuildKit(t *testing.T) {
	var got dockerCall
	w := buildWorker(DefaultDeployConfig(), func(_ context.Context, c dockerCall) ([]byte, error) { got = c; return nil, nil })
	df := writeDockerfile(t, "FROM a\n")
	res := w.runLimitedBuild(context.Background(), buildSpec{Dir: "/b", Tag: "img", CacheFrom: "img", DockerfilePath: df})
	if res.Strategy != StrategyBuildkitUnlimted || !hasSeq(got.Args, "--build-arg", "BUILDKIT_INLINE_CACHE=1") {
		t.Fatalf("%+v %v", res, got.Args)
	}
}

func TestBuildFlagsBuildxBuilder(t *testing.T) {
	cfg := DefaultDeployConfig()
	cfg.BuildBuilder = "capped"
	var got dockerCall
	w := buildWorker(cfg, func(_ context.Context, c dockerCall) ([]byte, error) { got = c; return nil, nil })
	res := w.runLimitedBuild(context.Background(), buildSpec{Dir: "/b", Tag: "img", Platform: "linux/amd64", DockerfilePath: writeDockerfile(t, "FROM a\n")})
	if res.Strategy != StrategyBuildxBuilder || !hasSeq(got.Args, "buildx", "build", "--builder", "capped", "--load") || !hasSeq(got.Args, "--platform", "linux/amd64") {
		t.Fatalf("%+v %v", res, got.Args)
	}
}

func TestBuildOOMIsReportedClearly(t *testing.T) {
	cfg := DefaultDeployConfig()
	cfg.BuildMemory, cfg.BuildMemorySwap = "1500m", "1500m"
	w := buildWorker(cfg, func(context.Context, dockerCall) ([]byte, error) {
		return []byte("Step 5/9 : RUN npm run build\nThe command '/bin/sh -c npm run build' returned a non-zero code: 137\n"), fmt.Errorf("exit status 1")
	})
	res := w.runLimitedBuild(context.Background(), buildSpec{Dir: "/b", Tag: "img", DockerfilePath: writeDockerfile(t, "FROM a\nRUN npm run build\n")})
	be, ok := res.Err.(*BuildError)
	if !ok || !be.OOM || !strings.Contains(be.Msg, "memory limit (1500m") || !strings.Contains(be.Msg, "Other containers were not affected") {
		t.Fatalf("%#v", res.Err)
	}
	// without enforced limit the message must not claim a limit was hit
	w2 := buildWorker(DefaultDeployConfig(), func(context.Context, dockerCall) ([]byte, error) {
		return []byte("process did not complete successfully: exit code: 137"), fmt.Errorf("exit status 1")
	})
	res2 := w2.runLimitedBuild(context.Background(), buildSpec{Dir: "/b", Tag: "img", DockerfilePath: writeDockerfile(t, "FROM a\n")})
	be2, _ := res2.Err.(*BuildError)
	if be2 == nil || !be2.OOM || !strings.Contains(be2.Msg, "No memory limit was enforced") {
		t.Fatalf("%#v", res2.Err)
	}
}

func TestBuildPlainFailureIsNotOOM(t *testing.T) {
	w := buildWorker(DefaultDeployConfig(), func(context.Context, dockerCall) ([]byte, error) {
		return []byte("npm ERR! missing script: build"), fmt.Errorf("exit status 1")
	})
	res := w.runLimitedBuild(context.Background(), buildSpec{Dir: "/b", Tag: "img", DockerfilePath: writeDockerfile(t, "FROM a\n")})
	be, _ := res.Err.(*BuildError)
	if be == nil || be.OOM || be.TimedOut || !strings.HasPrefix(be.Msg, "docker build failed:") {
		t.Fatalf("%#v", res.Err)
	}
}

func TestBuildTimeout(t *testing.T) {
	cfg := DefaultDeployConfig()
	cfg.BuildTimeout = 50 * time.Millisecond
	w := buildWorker(cfg, func(ctx context.Context, _ dockerCall) ([]byte, error) {
		<-ctx.Done() // a hung build: only the timeout can end it
		return []byte("partial output"), ctx.Err()
	})
	start := time.Now()
	res := w.runLimitedBuild(context.Background(), buildSpec{Dir: "/b", Tag: "img", DockerfilePath: writeDockerfile(t, "FROM a\n")})
	be, _ := res.Err.(*BuildError)
	if be == nil || !be.TimedOut || !strings.Contains(be.Msg, "time limit") {
		t.Fatalf("%#v", res.Err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout did not cut the build")
	}
}

func TestBuildMaxConcurrentGate(t *testing.T) {
	cfg := DefaultDeployConfig()
	cfg.BuildMaxConcurrent = 1
	var cur, peak int32
	w := buildWorker(cfg, func(context.Context, dockerCall) ([]byte, error) {
		n := atomic.AddInt32(&cur, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&cur, -1)
		return nil, nil
	})
	df := writeDockerfile(t, "FROM a\n")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.runLimitedBuild(context.Background(), buildSpec{Dir: "/b", Tag: "img", DockerfilePath: df})
		}()
	}
	wg.Wait()
	if peak != 1 {
		t.Fatalf("peak concurrent builds = %d, want 1", peak)
	}

	// cancelled while waiting for the slot
	w2 := buildWorker(cfg, func(context.Context, dockerCall) ([]byte, error) { return nil, nil })
	w2.ext.init()
	w2.ext.buildSem <- struct{}{} // slot taken
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if res := w2.runLimitedBuild(ctx, buildSpec{Dir: "/b", Tag: "img", DockerfilePath: df}); res.Err == nil {
		t.Fatal("expected cancellation while waiting")
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ── cleanup ──────────────────────────────────────────────────────────────────

type cleanupDocker struct {
	mu      sync.Mutex
	calls   []string
	ps      string
	images  string
	rmiFail map[string]bool
}

func (c *cleanupDocker) run(_ context.Context, call dockerCall) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	line := strings.Join(call.Args, " ")
	c.calls = append(c.calls, line)
	switch call.Args[0] {
	case "ps":
		return []byte(c.ps), nil
	case "images":
		return []byte(c.images), nil
	case "rmi":
		if c.rmiFail[call.Args[1]] {
			return []byte("conflict: image is being used by running container"), fmt.Errorf("exit 1")
		}
	}
	return nil, nil
}

func (c *cleanupDocker) rmi() []string {
	var out []string
	for _, l := range c.calls {
		if strings.HasPrefix(l, "rmi ") {
			out = append(out, strings.TrimPrefix(l, "rmi "))
		}
	}
	return out
}

func cleanupWorker(cd *cleanupDocker, protected map[string]bool, active int, disk int, logBuf *bytes.Buffer) *DeployWorker {
	var h slog.Handler = slog.NewTextHandler(io.Discard, nil)
	if logBuf != nil {
		h = slog.NewTextHandler(logBuf, nil)
	}
	w := &DeployWorker{logger: slog.New(h)}
	w.ext.cfg = DefaultDeployConfig()
	w.ext.cfgSet = true
	w.ext.docker = cd.run
	w.ext.diskUsage = func(context.Context, string) (int, error) { return disk, nil }
	w.ext.protected = func(context.Context) (map[string]bool, int, error) { return protected, active, nil }
	return w
}

const (
	pActive  = "aaaaaaaaaaaa" // has a successful deployment and a running container
	pLast    = "bbbbbbbbbbbb" // last successful deployment, container stopped/removed
	pOrphan  = "cccccccccccc" // never succeeded / project deleted, no container
	pStopped = "dddddddddddd" // orphan image but used by a stopped container
)

func imagesListing() string {
	return strings.Join([]string{
		"capsule-app-" + pActive + "|latest|sha256:1111",
		"capsule-app-" + pLast + "|latest|sha256:2222",
		"capsule-app-" + pOrphan + "|latest|sha256:3333",
		"capsule-app-" + pStopped + "|latest|sha256:4444",
		"redis|7|sha256:5555",
		"<none>|<none>|sha256:6666",
		"123.dkr.ecr.us-east-1.amazonaws.com/capsule-apps/" + pActive + "|deadbeef|sha256:7777", // newest
		"123.dkr.ecr.us-east-1.amazonaws.com/capsule-apps/" + pActive + "|cafe0001|sha256:8888", // older
	}, "\n")
}

func TestCleanupRespectsImagesInUseAndLastSuccessful(t *testing.T) {
	cd := &cleanupDocker{
		ps:     "capsule-app-" + pActive + "\ncapsule-app-" + pStopped + "\nredis:7\n",
		images: imagesListing(),
	}
	w := cleanupWorker(cd, map[string]bool{pActive: true, pLast: true}, 0, 40, nil)
	rep := w.CleanupOnce(context.Background())

	removed := strings.Join(cd.rmi(), ",")
	if removed != "capsule-app-"+pOrphan+":latest,123.dkr.ecr.us-east-1.amazonaws.com/capsule-apps/"+pActive+":cafe0001" {
		t.Fatalf("removed unexpected images: %v", cd.rmi())
	}
	for _, keep := range []string{pActive, pLast, pStopped, "redis"} {
		if strings.Contains(removed, "capsule-app-"+keep+":") || keep == "redis" && strings.Contains(removed, "redis") {
			t.Errorf("image %s must be kept", keep)
		}
	}
	if len(rep.RemovedImages) != 2 || rep.SkippedActive {
		t.Fatalf("%+v", rep)
	}
	for _, l := range cd.calls {
		if strings.HasPrefix(l, "rmi") && strings.Contains(l, "-f") {
			t.Fatalf("never force-remove: %s", l)
		}
	}
	// age + size thresholds on the cache prune
	if !containsLine(cd.calls, "builder prune -f --filter until=168h --keep-storage 4GB") {
		t.Fatalf("builder prune call: %v", cd.calls)
	}
}

func TestCleanupSkipsOrphanImagesDuringActiveDeployment(t *testing.T) {
	cd := &cleanupDocker{ps: "", images: imagesListing()}
	w := cleanupWorker(cd, map[string]bool{}, 1, 10, nil)
	rep := w.CleanupOnce(context.Background())
	if len(cd.rmi()) != 0 || !rep.SkippedActive {
		t.Fatalf("a building deployment's fresh image must not be removed: %v %+v", cd.rmi(), rep)
	}
}

func TestCleanupDockerRefusalIsTolerated(t *testing.T) {
	cd := &cleanupDocker{ps: "", images: "capsule-app-" + pOrphan + "|latest|sha256:3333", rmiFail: map[string]bool{"capsule-app-" + pOrphan + ":latest": true}}
	w := cleanupWorker(cd, map[string]bool{}, 0, 10, nil)
	if rep := w.CleanupOnce(context.Background()); len(rep.RemovedImages) != 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestCleanupDiskAlertAndAggressiveMode(t *testing.T) {
	var buf bytes.Buffer
	cd := &cleanupDocker{}
	w := cleanupWorker(cd, map[string]bool{}, 0, 82, &buf)
	rep := w.CleanupOnce(context.Background())
	if !strings.Contains(buf.String(), "DISK ALERT") || rep.Aggressive {
		t.Fatalf("82%% must alert but not be aggressive: %s %+v", buf.String(), rep)
	}

	buf.Reset()
	cd2 := &cleanupDocker{}
	w2 := cleanupWorker(cd2, map[string]bool{}, 0, 91, &buf)
	rep2 := w2.CleanupOnce(context.Background())
	if !rep2.Aggressive || !containsLine(cd2.calls, "builder prune -f --keep-storage 1GB") {
		t.Fatalf("91%% must prune hard: %v %+v", cd2.calls, rep2)
	}

	buf.Reset()
	w3 := cleanupWorker(&cleanupDocker{}, map[string]bool{}, 0, 50, &buf)
	w3.CleanupOnce(context.Background())
	if strings.Contains(buf.String(), "DISK ALERT") {
		t.Fatal("no alert at 50%")
	}
}

func TestParseDfPercent(t *testing.T) {
	out := "Filesystem     1024-blocks     Used Available Capacity Mounted on\n/dev/nvme0n1p1    41152736 33000000   8152736      81% /\n"
	if p, err := parseDfPercent(out); err != nil || p != 81 {
		t.Fatalf("%d %v", p, err)
	}
	if _, err := parseDfPercent("garbage"); err == nil {
		t.Fatal("expected error")
	}
}

// pgx rule: every Scan needs a column/destination count test. cleanupState scans
// 1 column in each query.
func TestCleanupStateQueriesScanOneColumn(t *testing.T) {
	for name, q := range map[string]string{"protected": protectedProjectsSQL, "active": activeDeploymentsSQL} {
		sel := strings.TrimSpace(q)
		sel = strings.TrimPrefix(sel, "SELECT DISTINCT")
		sel = strings.TrimPrefix(strings.TrimSpace(sel), "SELECT")
		sel = sel[:strings.Index(sel, "FROM")]
		depth, cols := 0, 1
		for _, r := range sel {
			switch r {
			case '(':
				depth++
			case ')':
				depth--
			case ',':
				if depth == 0 {
					cols++
				}
			}
		}
		if cols != 1 {
			t.Errorf("%s query selects %d columns but the Scan has 1 destination", name, cols)
		}
	}
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}
