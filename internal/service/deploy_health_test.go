package service

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kynto/capsule/backend/internal/domain"
)

// ── fakes ────────────────────────────────────────────────────────────────────

type fakeContainer struct {
	port  int
	state string // "<status>|<exit>|<restarts>" returned by inspect
	logs  string
}

// fakeDocker is an in-memory docker CLI.
type fakeDocker struct {
	mu         sync.Mutex
	containers map[string]*fakeContainer
	ops        []string
	runFail    map[int]string // host port -> output of a failing `docker run`
	newState   string         // state of containers created by `docker run`
	newLogs    string
	calls      [][]string
}

func newFakeDocker() *fakeDocker {
	return &fakeDocker{containers: map[string]*fakeContainer{}, runFail: map[int]string{}, newState: "running|0|0"}
}

func (f *fakeDocker) addOld(name string, hostPort int) {
	f.containers[name] = &fakeContainer{port: hostPort, state: "running|0|0"}
}

func (f *fakeDocker) run(_ context.Context, c dockerCall) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := c.Args
	f.calls = append(f.calls, a)
	op := strings.Join(a, " ")
	switch a[0] {
	case "rm":
		name := a[len(a)-1]
		f.ops = append(f.ops, "rm "+name)
		delete(f.containers, name)
		return nil, nil
	case "inspect":
		name := a[len(a)-1]
		ct, ok := f.containers[name]
		if !ok {
			return []byte("Error: No such object"), fmt.Errorf("exit 1")
		}
		if strings.Contains(op, "State.Status") {
			return []byte(ct.state), nil
		}
		return []byte("sha256:abc"), nil
	case "port":
		ct, ok := f.containers[a[1]]
		if !ok {
			return nil, fmt.Errorf("exit 1")
		}
		return []byte(fmt.Sprintf("3000/tcp -> 0.0.0.0:%d\n", ct.port)), nil
	case "run":
		var name string
		var hp int
		for i, x := range a {
			if x == "--name" {
				name = a[i+1]
			}
			if x == "-p" {
				fmt.Sscanf(a[i+1], "%d:", &hp)
			}
		}
		f.ops = append(f.ops, fmt.Sprintf("run %s:%d", name, hp))
		if out, bad := f.runFail[hp]; bad {
			return []byte(out), fmt.Errorf("exit 125")
		}
		f.containers[name] = &fakeContainer{port: hp, state: f.newState, logs: f.newLogs}
		return []byte("cid-" + name + "\n"), nil
	case "network":
		f.ops = append(f.ops, "network "+op)
		return nil, nil
	case "logs":
		ct := f.containers[a[len(a)-1]]
		if ct == nil {
			return nil, fmt.Errorf("no such container")
		}
		return []byte(ct.logs), nil
	case "stop":
		return nil, nil
	case "rename":
		f.ops = append(f.ops, "rename "+a[1]+" "+a[2])
		ct := f.containers[a[1]]
		delete(f.containers, a[1])
		f.containers[a[2]] = ct
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected docker call: %s", op)
}

type fakeHTTP struct {
	mu    sync.Mutex
	codes []int // consumed in order; the last one repeats; <=0 = connection error
	urls  []string
}

func (h *fakeHTTP) Do(r *http.Request) (*http.Response, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.urls = append(h.urls, r.URL.String())
	code := h.codes[0]
	if len(h.codes) > 1 {
		h.codes = h.codes[1:]
	}
	if code <= 0 {
		return nil, fmt.Errorf("dial tcp: connection refused")
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(""))}, nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time                            { return c.t }
func (c *clock) sleep(_ context.Context, d time.Duration) { c.t = c.t.Add(d) }

func testWorker(fd *fakeDocker, fh *fakeHTTP, cfg DeployConfig) (*DeployWorker, *clock) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	w := &DeployWorker{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w.ext.cfg = cfg
	w.ext.cfgSet = true
	w.ext.docker = fd.run
	if fh != nil {
		w.ext.httpc = fh
	}
	w.ext.now = clk.now
	w.ext.sleep = clk.sleep
	return w, clk
}

type specRecorder struct {
	logs   []string
	health []domain.DeploymentHealth
}

func baseSpec(rec *specRecorder, hc domain.ProjectHealthConfig, ports ...int) rolloutSpec {
	if len(ports) == 0 {
		ports = []int{20100, 30100, 40100}
	}
	return rolloutSpec{
		Final: "capsule-app-aaaaaaaaaaaa", Network: "capsule-prod_capsule-net", ContainerPort: 3000,
		HostPorts: ports,
		RunArgs: func(name string, hp int) []string {
			return []string{"run", "-d", "--name", name, "-p", fmt.Sprintf("%d:3000", hp), "img"}
		},
		Health:  hc,
		Secrets: []string{"s3cr3t-value"},
		Log:     func(level, msg string) { rec.logs = append(rec.logs, level+": "+msg) },
		SetHealth: func(h domain.DeploymentHealth) {
			rec.health = append(rec.health, h)
		},
	}
}

func healthCfg(path string, timeout int) domain.ProjectHealthConfig {
	c := domain.DefaultProjectHealthConfig()
	c.Path = path
	c.TimeoutSeconds = timeout
	return c
}

const final = "capsule-app-aaaaaaaaaaaa"

// ── rollout tests ────────────────────────────────────────────────────────────

func TestRolloutHealthyBlueGreen(t *testing.T) {
	fd := newFakeDocker()
	fd.addOld(final, 20100)
	fh := &fakeHTTP{codes: []int{0, 503, 200}}
	w, _ := testWorker(fd, fh, DefaultDeployConfig())
	rec := &specRecorder{}

	res := w.rollout(context.Background(), baseSpec(rec, healthCfg("/healthz", 60)))
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if res.HostPort != 30100 {
		t.Fatalf("new container must not use the port held by the old one, got %d", res.HostPort)
	}
	// order: new container started BEFORE the old one is removed; rename last.
	runIdx, rmIdx, renIdx := indexOf(fd.ops, "run "+final+"-next:30100"), indexOf(fd.ops, "rm "+final), indexOf(fd.ops, "rename "+final+"-next "+final)
	if runIdx < 0 || rmIdx < 0 || renIdx < 0 || !(runIdx < rmIdx && rmIdx < renIdx) {
		t.Fatalf("bad blue-green order: %v", fd.ops)
	}
	if _, ok := fd.containers[final]; !ok || fd.containers[final].port != 30100 {
		t.Fatalf("final container must be the new one: %+v", fd.containers)
	}
	if _, ok := fd.containers[final+"-next"]; ok {
		t.Fatal("temporary container must be gone")
	}
	if len(fh.urls) != 3 || fh.urls[0] != "http://"+final+"-next:3000/healthz" {
		t.Fatalf("probe URLs: %v", fh.urls)
	}
	last := rec.health[len(rec.health)-1]
	if last.Status != domain.HealthHealthy || last.Path != "/healthz" || last.LastCheck == nil {
		t.Fatalf("final health: %+v", last)
	}
	if rec.health[0].Status != domain.HealthChecking {
		t.Fatalf("first state should be checking: %+v", rec.health[0])
	}
}

func TestRolloutUnhealthyKeepsOldAndRedactsLogs(t *testing.T) {
	fd := newFakeDocker()
	fd.addOld(final, 20100)
	fd.newLogs = "starting\nDATABASE_URL=postgres://user:hunter2@db/app\nconnecting with s3cr3t-value\nError: boom\n"
	fh := &fakeHTTP{codes: []int{500}}
	w, _ := testWorker(fd, fh, DefaultDeployConfig())
	rec := &specRecorder{}

	res := w.rollout(context.Background(), baseSpec(rec, healthCfg("/healthz", 10)))
	if res.Err == nil || !res.KeptPrevious {
		t.Fatalf("expected failure keeping the previous container: %+v", res)
	}
	if !strings.Contains(res.Err.Error(), "health check GET /healthz did not succeed within 10s") || !strings.Contains(res.Err.Error(), "HTTP 500") {
		t.Fatalf("reason: %v", res.Err)
	}
	if !strings.Contains(res.Err.Error(), "previous deployment keeps serving") {
		t.Fatalf("must mention the kept deployment: %v", res.Err)
	}
	if c, ok := fd.containers[final]; !ok || c.port != 20100 {
		t.Fatalf("old container must be untouched: %+v", fd.containers)
	}
	if _, ok := fd.containers[final+"-next"]; ok {
		t.Fatal("failed candidate must be removed")
	}
	if indexOf(fd.ops, "rm "+final) >= 0 {
		t.Fatalf("old container must never be removed: %v", fd.ops)
	}
	all := strings.Join(rec.logs, "\n") + res.Err.Error()
	for _, leak := range []string{"hunter2", "s3cr3t-value"} {
		if strings.Contains(all, leak) {
			t.Fatalf("secret %q leaked into logs/error: %s", leak, all)
		}
	}
	if !strings.Contains(all, "Last 50 log lines") || !strings.Contains(all, "Error: boom") {
		t.Fatalf("container logs must be recorded: %s", all)
	}
	if rec.health[len(rec.health)-1].Status != domain.HealthUnhealthy {
		t.Fatalf("final health: %+v", rec.health[len(rec.health)-1])
	}
}

func TestRolloutImmediateCrashNoHealthPath(t *testing.T) {
	fd := newFakeDocker()
	fd.addOld(final, 20100)
	fd.newState = "exited|1|0"
	fd.newLogs = "Error: Cannot find module '/app/server.js'\n"
	w, _ := testWorker(fd, nil, DefaultDeployConfig())
	rec := &specRecorder{}

	res := w.rollout(context.Background(), baseSpec(rec, healthCfg("", 60)))
	if res.Err == nil || !res.KeptPrevious {
		t.Fatalf("crash must fail and keep the old one: %+v", res)
	}
	if !strings.Contains(res.Err.Error(), "exited right after start") || !strings.Contains(res.Err.Error(), "Cannot find module") {
		t.Fatalf("reason: %v", res.Err)
	}
	if _, ok := fd.containers[final]; !ok {
		t.Fatal("old container must survive")
	}
}

func TestRolloutCrashLoopByRestartCount(t *testing.T) {
	fd := newFakeDocker()
	fd.newState = "running|1|2" // restart policy keeps it "running" between crashes
	w, _ := testWorker(fd, nil, DefaultDeployConfig())
	res := w.rollout(context.Background(), baseSpec(&specRecorder{}, healthCfg("", 60)))
	if res.Err == nil || !strings.Contains(res.Err.Error(), "crash-looping") || res.KeptPrevious {
		t.Fatalf("crash loop on first deploy: %+v", res)
	}
	if len(fd.containers) != 0 {
		t.Fatalf("candidate must be removed: %+v", fd.containers)
	}
}

func TestRolloutRestartingStatusIsCrashLoop(t *testing.T) {
	fd := newFakeDocker()
	fd.newState = "restarting|1|0"
	w, _ := testWorker(fd, nil, DefaultDeployConfig())
	res := w.rollout(context.Background(), baseSpec(&specRecorder{}, healthCfg("/x", 30)))
	if res.Err == nil || !strings.Contains(res.Err.Error(), "crash-looping") {
		t.Fatalf("%+v", res)
	}
}

func TestRolloutTimeoutWhenNeverAnswers(t *testing.T) {
	fd := newFakeDocker()
	fd.addOld(final, 20100)
	fh := &fakeHTTP{codes: []int{0}}
	w, clk := testWorker(fd, fh, DefaultDeployConfig())
	start := clk.t
	res := w.rollout(context.Background(), baseSpec(&specRecorder{}, healthCfg("/ready", 12)))
	if res.Err == nil || !strings.Contains(res.Err.Error(), "within 12s") || !strings.Contains(res.Err.Error(), "no answer") {
		t.Fatalf("%+v", res)
	}
	if got := clk.t.Sub(start); got < 12*time.Second {
		t.Fatalf("gave up too early: %s", got)
	}
	if !res.KeptPrevious {
		t.Fatal("old must be kept")
	}
}

func TestRolloutNoHealthPathWaitsMinUptime(t *testing.T) {
	fd := newFakeDocker()
	cfg := DefaultDeployConfig()
	cfg.MinUptime = 5 * time.Second
	w, clk := testWorker(fd, nil, cfg)
	start := clk.t
	rec := &specRecorder{}
	res := w.rollout(context.Background(), baseSpec(rec, healthCfg("", 60)))
	if res.Err != nil {
		t.Fatalf("%v", res.Err)
	}
	if clk.t.Sub(start) < 5*time.Second {
		t.Fatalf("returned before the minimum uptime: %s", clk.t.Sub(start))
	}
	if _, ok := fd.containers[final]; !ok {
		t.Fatalf("container not renamed to the final name: %+v", fd.containers)
	}
	if rec.health[len(rec.health)-1].Status != domain.HealthHealthy {
		t.Fatalf("%+v", rec.health)
	}
}

func TestRolloutAcceptsRedirectsRejectsClientErrors(t *testing.T) {
	for code, wantOK := range map[int]bool{200: true, 302: true, 399: true, 404: false, 500: false} {
		fd := newFakeDocker()
		w, _ := testWorker(fd, &fakeHTTP{codes: []int{code}}, DefaultDeployConfig())
		res := w.rollout(context.Background(), baseSpec(&specRecorder{}, healthCfg("/", 6)))
		if (res.Err == nil) != wantOK {
			t.Errorf("status %d: ok=%v err=%v", code, wantOK, res.Err)
		}
	}
	// custom expectation
	fd := newFakeDocker()
	w, _ := testWorker(fd, &fakeHTTP{codes: []int{204}}, DefaultDeployConfig())
	hc := healthCfg("/", 6)
	hc.ExpectedStatus = "204"
	if res := w.rollout(context.Background(), baseSpec(&specRecorder{}, hc)); res.Err != nil {
		t.Fatalf("custom status: %v", res.Err)
	}
}

func TestRolloutFirstDeployFailureHasNothingToKeep(t *testing.T) {
	fd := newFakeDocker()
	fd.newState = "exited|2|0"
	w, _ := testWorker(fd, nil, DefaultDeployConfig())
	res := w.rollout(context.Background(), baseSpec(&specRecorder{}, healthCfg("", 60)))
	if res.Err == nil || res.KeptPrevious {
		t.Fatalf("%+v", res)
	}
	if strings.Contains(res.Err.Error(), "keeps serving") {
		t.Fatalf("must not claim a previous deployment: %v", res.Err)
	}
}

func TestRolloutPortConflictTriesNextCandidate(t *testing.T) {
	fd := newFakeDocker()
	fd.runFail[20100] = "docker: Error response from daemon: driver failed programming external connectivity: Bind for 0.0.0.0:20100 failed: port is already allocated."
	w, _ := testWorker(fd, nil, DefaultDeployConfig())
	cfg := DefaultDeployConfig()
	cfg.MinUptime = 0
	w.ext.cfg = cfg
	res := w.rollout(context.Background(), baseSpec(&specRecorder{}, healthCfg("", 60)))
	if res.Err != nil || res.HostPort != 30100 {
		t.Fatalf("%+v", res)
	}
}

func TestRolloutRunFailureKeepsOld(t *testing.T) {
	fd := newFakeDocker()
	fd.addOld(final, 20100)
	fd.runFail[30100] = "docker: invalid reference format"
	w, _ := testWorker(fd, nil, DefaultDeployConfig())
	res := w.rollout(context.Background(), baseSpec(&specRecorder{}, healthCfg("", 60)))
	if res.Err == nil || !res.KeptPrevious || !strings.Contains(res.Err.Error(), "docker run failed") {
		t.Fatalf("%+v", res)
	}
	if _, ok := fd.containers[final]; !ok {
		t.Fatal("old container must survive a failed run")
	}
}

func TestRolloutExclusivePortsRemovesOldFirst(t *testing.T) {
	fd := newFakeDocker()
	fd.addOld(final, 20100)
	cfg := DefaultDeployConfig()
	cfg.MinUptime = 0
	w, _ := testWorker(fd, nil, cfg)
	rec := &specRecorder{}
	s := baseSpec(rec, healthCfg("", 60))
	s.ExclusivePorts = true
	res := w.rollout(context.Background(), s)
	if res.Err != nil {
		t.Fatalf("%v", res.Err)
	}
	if rm, run := indexOf(fd.ops, "rm "+final), indexOf(fd.ops, "run "+final+"-next:20100"); rm < 0 || run < 0 || rm > run {
		t.Fatalf("old must be removed before the new one starts: %v", fd.ops)
	}
	if !strings.Contains(strings.Join(rec.logs, "\n"), "no automatic rollback") {
		t.Fatalf("must warn: %v", rec.logs)
	}
}

func TestRolloutStaleCandidateIsCleanedFirst(t *testing.T) {
	fd := newFakeDocker()
	fd.containers[final+"-next"] = &fakeContainer{port: 1, state: "running|0|0"}
	cfg := DefaultDeployConfig()
	cfg.MinUptime = 0
	w, _ := testWorker(fd, nil, cfg)
	if res := w.rollout(context.Background(), baseSpec(&specRecorder{}, healthCfg("", 60))); res.Err != nil {
		t.Fatalf("%v", res.Err)
	}
	if fd.ops[0] != "rm "+final+"-next" {
		t.Fatalf("stale candidate must be removed first: %v", fd.ops)
	}
}

func TestHeldHostPorts(t *testing.T) {
	got := heldHostPorts("3000/tcp -> 0.0.0.0:20100\n3000/tcp -> [::]:20100\n9000/tcp -> 0.0.0.0:41001\n")
	if !got[20100] || !got[41001] || len(got) != 2 {
		t.Fatalf("%v", got)
	}
}

func TestRedactLogs(t *testing.T) {
	in := "PASSWORD=abc123 token: xyz\nconn postgres://admin:hunter2@db:5432/x\nAPI_KEY=k-1 ok line\nraw super-secret-val"
	out := redactLogs(in, []string{"super-secret-val"})
	for _, leak := range []string{"abc123", "xyz", "hunter2", "k-1", "super-secret-val"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q leaked: %s", leak, out)
		}
	}
	if !strings.Contains(out, "ok line") {
		t.Errorf("normal text must survive: %s", out)
	}
}

func indexOf(ops []string, want string) int {
	for i, o := range ops {
		if o == want {
			return i
		}
	}
	return -1
}
