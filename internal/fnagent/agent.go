package fnagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/vpn"
)

const logTailMax = 16 << 10

// tailWriter keeps the last bytes of the function output with secrets masked.
type tailWriter struct {
	mu   sync.Mutex
	red  *vpn.Redactor
	buf  []byte
	pend []byte
}

func (t *tailWriter) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pend = append(t.pend, p...)
	for {
		i := bytes.IndexByte(t.pend, '\n')
		if i < 0 {
			break
		}
		t.buf = append(t.buf, t.red.Mask(string(t.pend[:i+1]))...)
		t.pend = t.pend[i+1:]
	}
	if len(t.pend) > 8<<10 { // an endless line: mask and flush
		t.buf = append(t.buf, t.red.Mask(string(t.pend))...)
		t.pend = nil
	}
	if len(t.buf) > logTailMax {
		t.buf = t.buf[len(t.buf)-logTailMax:]
	}
	return len(p), nil
}

func (t *tailWriter) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf) + t.red.Mask(string(t.pend))
}

// Agent is the work node loop.
type Agent struct {
	Client      *Client
	Runner      ContainerRunner
	Mgr         *Manager
	SocksRoot   string
	Poll        time.Duration
	MaxParallel int
	Log         *slog.Logger

	mu      sync.Mutex
	running map[uuid.UUID]context.CancelFunc
}

func (a *Agent) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

// Loop claims and runs until ctx ends. It only makes outbound calls.
func (a *Agent) Loop(ctx context.Context) {
	if a.Poll == 0 {
		a.Poll = 10 * time.Second
	}
	if a.MaxParallel == 0 {
		a.MaxParallel = 2
	}
	a.running = map[uuid.UUID]context.CancelFunc{}
	var wg sync.WaitGroup
	t := time.NewTicker(a.Poll)
	defer t.Stop()
	for {
		a.Tick(ctx, &wg)
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-t.C:
		}
	}
}

// Tick does one sync + claim round (exported for tests).
func (a *Agent) Tick(ctx context.Context, wg *sync.WaitGroup) {
	a.mu.Lock()
	ids := make([]uuid.UUID, 0, len(a.running))
	for id := range a.running {
		ids = append(ids, id)
	}
	a.mu.Unlock()
	if rep, err := a.Client.Sync(ctx, ids, a.Mgr.IDs()); err == nil {
		for _, id := range rep.CancelRuns {
			a.mu.Lock()
			if c := a.running[id]; c != nil {
				c()
			}
			a.mu.Unlock()
		}
		for _, id := range rep.StopTunnels {
			a.Mgr.Stop(id)
		}
	} else if ctx.Err() == nil {
		a.log().Warn("sync failed", "error", err)
	}
	a.Mgr.ReportHealth(ctx, a.Client)
	for {
		a.mu.Lock()
		full := len(a.running) >= a.MaxParallel
		a.mu.Unlock()
		if full || ctx.Err() != nil {
			return
		}
		asg, err := a.Client.Claim(ctx)
		if err != nil {
			if ctx.Err() == nil {
				a.log().Warn("claim failed", "error", err)
			}
			return
		}
		if asg == nil {
			return
		}
		rctx, cancel := context.WithCancel(ctx)
		a.mu.Lock()
		a.running[asg.Run.ID] = cancel
		a.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			a.Execute(rctx, asg)
			a.mu.Lock()
			delete(a.running, asg.Run.ID)
			a.mu.Unlock()
		}()
	}
}

// Execute runs one assignment and reports the result.
func (a *Agent) Execute(ctx context.Context, asg *fn.Assignment) {
	run, f := asg.Run, asg.Function
	red := vpn.NewRedactor(asg.Token)
	if asg.Tunnel != nil {
		red.AddJSONValues(asg.Tunnel.Secret)
	}
	for k, v := range asg.Env { // database URLs granted by a db:<name> scope are secrets too
		if strings.HasPrefix(k, "CAPSULE_DB_") {
			red.Add(v)
			if u, err := url.Parse(v); err == nil && u.User != nil {
				if pw, ok := u.User.Password(); ok {
					red.Add(pw)
				}
			}
		}
	}
	for k, v := range asg.Env {
		if strings.HasPrefix(k, "CAPSULE_STORAGE_") && (strings.HasSuffix(k, "SECRET_ACCESS_KEY") || strings.HasSuffix(k, "ACCESS_KEY_ID")) {
			red.Add(v)
		}
	}
	logs := &tailWriter{red: red}
	finish := func(status string, exit *int, in, out int64, msg string) {
		if msg != "" {
			fmt.Fprintln(logs, msg)
		}
		fctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := a.Client.Finish(fctx, run.ID, FinishReport{Status: status, ExitCode: exit, BytesIn: in, BytesOut: out, LogTail: logs.String()}); err != nil {
			a.log().Error("finish failed", "run", run.ID, "error", err)
		}
	}
	spec := ContainerSpec{Name: "capsule-fn-" + run.ID.String(), Image: f.Image, MemoryMB: f.MemoryMB, CPUs: f.CPUs, Env: map[string]string{}}
	for k, v := range asg.Env {
		spec.Env[k] = v
	}
	if f.Entry != "" {
		spec.Entry = strings.Fields(f.Entry)
	}
	var proxy *RunProxy
	if asg.Tunnel != nil {
		g, err := a.Mgr.Ensure(*asg.Tunnel)
		if err != nil {
			finish(fn.RunFailed, nil, 0, 0, "tunnel could not be opened: "+err.Error())
			return
		}
		proxy, err = g.OpenRun(a.SocksRoot, run.ID.String())
		if err != nil {
			finish(fn.RunFailed, nil, 0, 0, "tunnel proxy failed: "+err.Error())
			return
		}
		defer proxy.Close()
		spec.SocksDir = proxy.Dir
	}
	tctx, cancel := context.WithTimeout(ctx, time.Duration(f.TimeoutSeconds)*time.Second)
	defer cancel()
	exit, err := a.Runner.Run(tctx, spec, logs)
	var in, out int64
	if proxy != nil {
		in, out = proxy.Bytes()
		a.Mgr.ReportHealth(context.Background(), a.Client) // the first handshake just happened: tell the panel
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(tctx.Err(), context.DeadlineExceeded):
		finish(fn.RunTimeout, nil, in, out, "run exceeded its timeout and was stopped")
	case ctx.Err() != nil:
		finish(fn.RunCancelled, nil, in, out, "run cancelled")
	case err != nil:
		finish(fn.RunFailed, nil, in, out, "runner error: "+err.Error())
	case exit != 0:
		finish(fn.RunFailed, &exit, in, out, "")
	default:
		finish(fn.RunSucceeded, &exit, in, out, "")
	}
}

var _ io.Writer = (*tailWriter)(nil)
