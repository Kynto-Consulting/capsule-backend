package fnagent

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ContainerSpec is one function execution.
type ContainerSpec struct {
	Name     string
	Image    string
	Entry    []string
	Env      map[string]string // CAPSULE_* only; never the tunnel credentials
	MemoryMB int
	CPUs     float64
	SocksDir string // host dir with the run's SOCKS socket; "" when the function has no tunnel
}

// ContainerRunner executes a function and returns its exit code. The context deadline is the run timeout.
type ContainerRunner interface {
	Run(ctx context.Context, spec ContainerSpec, logs io.Writer) (int, error)
}

// SocksInContainer is where the function finds the tunnel proxy.
const SocksInContainer = "/capsule/vpn/socks.sock"

// DockerArgs builds the `docker run` arguments: memory without swap, CPU, pids, read-only root, no capabilities,
// no privilege escalation. The only network it can reach besides the tunnel proxy is the Capsule API and
// host.docker.internal (same-server databases), exactly like project containers.
func DockerArgs(s ContainerSpec) []string {
	a := []string{"run", "--rm", "--name", s.Name,
		"--memory", fmt.Sprintf("%dm", s.MemoryMB), "--memory-swap", fmt.Sprintf("%dm", s.MemoryMB),
		"--cpus", strconv.FormatFloat(s.CPUs, 'f', -1, 64),
		"--pids-limit", "256", "--read-only", "--tmpfs", "/tmp:rw,size=256m",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--add-host", "host.docker.internal:host-gateway", "--label", "capsule.fn=1"}
	keys := make([]string, 0, len(s.Env))
	for k := range s.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a = append(a, "-e", k+"="+s.Env[k])
	}
	if s.SocksDir != "" {
		a = append(a, "-v", s.SocksDir+":"+strings.TrimSuffix(SocksInContainer, "/socks.sock")+":ro", "-e", "CAPSULE_VPN_SOCKS="+SocksInContainer)
	}
	a = append(a, s.Image)
	return append(a, s.Entry...)
}

// DockerRunner runs `docker run`. Killing on timeout/cancel uses `docker kill`.
type DockerRunner struct{ Bin string }

func (d DockerRunner) Run(ctx context.Context, s ContainerSpec, logs io.Writer) (int, error) {
	bin := d.Bin
	if bin == "" {
		bin = "docker"
	}
	cmd := exec.Command(bin, DockerArgs(s)...)
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		return -1, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return exitCode(err), nil
	case <-ctx.Done():
		kctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = exec.CommandContext(kctx, bin, "kill", s.Name).Run()
		<-done
		return -1, ctx.Err()
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}
