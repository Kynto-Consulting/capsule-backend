package backup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Cmd is one docker invocation. Secrets go in Env (never in Args): the docker client
// forwards variables named with `-e NAME` (no value) from its own environment.
type Cmd struct {
	Args  []string
	Env   []string // extra KEY=VALUE for the docker client process
	Stdin io.Reader
}

// Docker abstracts the docker CLI so the service can be tested with a fake.
type Docker interface {
	// Stream starts the command and returns its stdout. Close waits for the process and
	// returns its exit error (with a short stderr tail); read to EOF before Close.
	Stream(ctx context.Context, c Cmd) (io.ReadCloser, error)
	// Run executes the command and returns combined stdout/stderr (callers must keep it small).
	Run(ctx context.Context, c Cmd) ([]byte, error)
}

type CLIDocker struct{}

type tail struct{ buf []byte }

func (t *tail) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > 2048 {
		t.buf = t.buf[len(t.buf)-2048:]
	}
	return len(p), nil
}

type proc struct {
	io.ReadCloser
	cmd *exec.Cmd
	err *tail
}

func (p *proc) Close() error {
	p.ReadCloser.Close()
	if err := p.cmd.Wait(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(p.err.buf)))
	}
	return nil
}

func prepare(ctx context.Context, c Cmd) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "docker", c.Args...)
	if len(c.Env) > 0 {
		cmd.Env = append(os.Environ(), c.Env...)
	}
	cmd.Stdin = c.Stdin
	return cmd
}

func (CLIDocker) Stream(ctx context.Context, c Cmd) (io.ReadCloser, error) {
	cmd := prepare(ctx, c)
	t := &tail{}
	cmd.Stderr = t
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &proc{ReadCloser: out, cmd: cmd, err: t}, nil
}

func (CLIDocker) Run(ctx context.Context, c Cmd) ([]byte, error) {
	cmd := prepare(ctx, c)
	var b bytes.Buffer
	lw := &limitedWriter{w: &b, n: 1 << 20}
	cmd.Stdout = lw
	cmd.Stderr = lw
	err := cmd.Run()
	return b.Bytes(), err
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := len(p)
		if k > l.n {
			k = l.n
		}
		l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}
