package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Idle sleep: app containers that receive no traffic for CAPSULE_IDLE_SLEEP_HOURS
// (default 12, 0 disables) are stopped to free memory/CPU on the builder host. The
// proxy starts them again on the next request. Containers are created with
// --restart unless-stopped, so a manual `docker stop` also survives a host reboot.

var idle = &idleTracker{last: map[string]time.Time{}, waking: map[string]*sync.Mutex{}}

type idleTracker struct {
	mu     sync.Mutex
	last   map[string]time.Time
	waking map[string]*sync.Mutex
}

func (t *idleTracker) touch(name string) {
	t.mu.Lock()
	t.last[name] = time.Now()
	t.mu.Unlock()
}

func (t *idleTracker) lockFor(name string) *sync.Mutex {
	t.mu.Lock()
	defer t.mu.Unlock()
	m, ok := t.waking[name]
	if !ok {
		m = &sync.Mutex{}
		t.waking[name] = m
	}
	return m
}

func idleAfter() time.Duration {
	h := 12.0
	if v := os.Getenv("CAPSULE_IDLE_SLEEP_HOURS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			h = f
		}
	}
	return time.Duration(h * float64(time.Hour))
}

func containerRunning(ctx context.Context, name string) (running, exists bool) {
	out, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Running}}", name).Output()
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(string(out)) == "true", true
}

// wakeApp records activity for the container and starts it if it is asleep. When
// port > 0 it waits until the app accepts TCP connections (up to 90s).
func wakeApp(ctx context.Context, name string, port int) error {
	idle.touch(name)
	if running, exists := containerRunning(ctx, name); running || !exists {
		return nil
	}

	m := idle.lockFor(name)
	m.Lock()
	defer m.Unlock()
	// Another request may have woken it while we waited for the lock.
	if running, _ := containerRunning(ctx, name); !running {
		if out, err := exec.CommandContext(ctx, "docker", "start", name).CombinedOutput(); err != nil {
			return fmt.Errorf("docker start %s: %v: %s", name, err, strings.TrimSpace(string(out)))
		}
	}
	if port <= 0 {
		return nil
	}
	deadline := time.Now().Add(90 * time.Second)
	addr := net.JoinHostPort(name, strconv.Itoa(port))
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
			c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}
	return fmt.Errorf("%s did not accept connections on port %d in time", name, port)
}

// RunIdleReaper stops app containers with no traffic for the idle window. It blocks
// until ctx is cancelled. After a backend restart every running container gets a
// fresh window, so nothing is stopped before it has been observed idle for a full period.
func RunIdleReaper(ctx context.Context, logger *slog.Logger) {
	after := idleAfter()
	if after <= 0 {
		logger.Info("idle sleep disabled")
		return
	}
	logger.Info("idle sleep enabled", "after", after.String())

	tick := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		out, err := exec.CommandContext(ctx, "docker", "ps", "--filter", "name=^capsule-app-", "--format", "{{.Names}}").Output()
		if err != nil {
			logger.Warn("idle reaper: docker ps failed", "error", err)
			continue
		}
		for _, name := range strings.Fields(string(out)) {
			idle.mu.Lock()
			last, seen := idle.last[name]
			if !seen {
				idle.last[name] = time.Now()
			}
			idle.mu.Unlock()
			if !seen || time.Since(last) < after {
				continue
			}
			if o, err := exec.CommandContext(ctx, "docker", "stop", name).CombinedOutput(); err != nil {
				logger.Warn("idle reaper: docker stop failed", "container", name, "error", strings.TrimSpace(string(o)))
				continue
			}
			logger.Info("idle reaper: container put to sleep", "container", name, "idle", time.Since(last).Round(time.Minute).String())
		}
	}
}
