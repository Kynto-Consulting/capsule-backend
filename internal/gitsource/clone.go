package gitsource

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Auth describes how to authenticate against the remote.
type Auth struct {
	Kind       string // token | ssh_key | none
	Credential string // token or PEM private key
}

// Limits bound resource use of a clone.
type Limits struct {
	MaxRepoBytes int64         // max uncompressed size of the checkout (excluding .git)
	Timeout      time.Duration // wall-clock timeout of the whole clone
	SSHStrict    string        // StrictHostKeyChecking value: yes | accept-new | no
	KnownHosts   string        // optional known_hosts file used with SSHStrict=yes
}

// LimitsFromEnv reads CAPSULE_GIT_MAX_REPO_MB (default 200), CAPSULE_GIT_CLONE_TIMEOUT_SECONDS
// (default 120), CAPSULE_GIT_SSH_STRICT (default accept-new) and CAPSULE_GIT_KNOWN_HOSTS.
func LimitsFromEnv() Limits {
	l := Limits{MaxRepoBytes: 200 << 20, Timeout: 120 * time.Second, SSHStrict: "accept-new"}
	if v, err := strconv.Atoi(os.Getenv("CAPSULE_GIT_MAX_REPO_MB")); err == nil && v > 0 {
		l.MaxRepoBytes = int64(v) << 20
	}
	if v, err := strconv.Atoi(os.Getenv("CAPSULE_GIT_CLONE_TIMEOUT_SECONDS")); err == nil && v > 0 {
		l.Timeout = time.Duration(v) * time.Second
	}
	switch s := os.Getenv("CAPSULE_GIT_SSH_STRICT"); s {
	case "yes", "accept-new", "no":
		l.SSHStrict = s
	}
	l.KnownHosts = os.Getenv("CAPSULE_GIT_KNOWN_HOSTS")
	return l
}

// Snapshot is a packaged checkout. Close MUST be called (use defer): it
// removes every temporary file including the working tree.
type Snapshot struct {
	TarPath string // tar.gz in the same layout as a CLI upload
	SHA     string
	Message string // first line of the commit message
	Size    int64  // bytes of the tar.gz
	dir     string
}

// Close deletes the temporary directory.
func (s *Snapshot) Close() {
	if s != nil && s.dir != "" {
		_ = os.RemoveAll(s.dir)
		s.dir = ""
	}
}

// Fetcher obtains a snapshot of a branch (abstracted for tests).
type Fetcher interface {
	Fetch(ctx context.Context, repoURL, branch string, auth Auth) (*Snapshot, error)
	ListBranches(ctx context.Context, repoURL string, auth Auth) ([]string, error)
}

// GitFetcher runs the git binary with hardened settings. It never executes
// anything from the repository (no hooks, no submodules, no filters; builds
// happen later inside docker build).
type GitFetcher struct {
	Policy Policy
	Limits Limits
	// GitBin overrides the git executable (tests).
	GitBin string
}

func (g *GitFetcher) bin() string {
	if g.GitBin != "" {
		return g.GitBin
	}
	return "git"
}

type gitCmd struct {
	args   []string
	env    []string
	secret string
}

// prepare validates inputs and builds a base command environment inside tmp.
func (g *GitFetcher) prepare(ctx context.Context, tmp, repoURL string, auth Auth) (*gitCmd, error) {
	ref, ips, err := g.Policy.ValidateRepoURL(ctx, repoURL)
	if err != nil {
		return nil, err
	}
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_ASKPASS=",
		"SSH_ASKPASS=",
		"LC_ALL=C",
	}
	if sr := os.Getenv("SystemRoot"); sr != "" { // Windows needs it to run at all
		env = append(env, "SystemRoot="+sr)
	}
	cfg := []string{
		"core.hooksPath=" + os.DevNull,
		"core.fsmonitor=false",
		"protocol.allow=never",
		"protocol.https.allow=always",
		"protocol.ssh.allow=always",
		"http.followRedirects=false",
		"http.lowSpeedLimit=1000",
		"http.lowSpeedTime=30",
		"submodule.recurse=false",
		"credential.helper=",
	}
	c := &gitCmd{}
	var secretCfg []string
	switch ref.Scheme {
	case "https":
		if len(ips) > 0 { // pin the validated address: defeats DNS rebinding between check and clone
			port := ref.Port
			if port == "" {
				port = "443"
			}
			cfg = append(cfg, "http.curloptResolve="+ref.Host+":"+port+":"+ips[0].String())
		}
		if auth.Kind == "token" && auth.Credential != "" {
			basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + auth.Credential))
			// carried in the environment, not argv, so it is not visible in `ps`
			secretCfg = append(secretCfg, "http.extraHeader=Authorization: Basic "+basic)
			c.secret = auth.Credential
		}
	case "ssh":
		sshCmd := "ssh -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=15 -o LogLevel=ERROR"
		known := filepath.Join(tmp, "known_hosts")
		strict := g.Limits.SSHStrict
		if strict == "" {
			strict = "accept-new"
		}
		if strict == "yes" && g.Limits.KnownHosts != "" {
			known = g.Limits.KnownHosts
		}
		sshCmd += " -o StrictHostKeyChecking=" + strict + " -o UserKnownHostsFile=" + shellQuote(known)
		if auth.Kind == "ssh_key" && auth.Credential != "" {
			keyPath := filepath.Join(tmp, "id_key")
			key := strings.ReplaceAll(auth.Credential, "\r\n", "\n")
			if !strings.HasSuffix(key, "\n") {
				key += "\n"
			}
			if err := os.WriteFile(keyPath, []byte(key), 0o600); err != nil {
				return nil, err
			}
			sshCmd += " -i " + shellQuote(keyPath)
			c.secret = auth.Credential
		}
		env = append(env, "GIT_SSH_COMMAND="+sshCmd)
	}
	for _, kv := range cfg {
		c.args = append(c.args, "-c", kv)
	}
	env = append(env, "GIT_CONFIG_COUNT="+strconv.Itoa(len(secretCfg)))
	for i, kv := range secretCfg {
		k, v, _ := strings.Cut(kv, "=")
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, k), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, v))
	}
	c.env = env
	return c, nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// run executes git with resource limits and returns stdout. stderr is scrubbed
// of secrets and truncated in the returned error.
func (g *GitFetcher) run(ctx context.Context, c *gitCmd, dir string, args ...string) ([]byte, error) {
	full := append(append([]string{}, c.args...), args...)
	var cmd *exec.Cmd
	if runtime.GOOS == "linux" {
		if sh, err := exec.LookPath("sh"); err == nil {
			// CPU seconds, address space and max file size caps for the git process.
			script := `ulimit -t 300 2>/dev/null; ulimit -v 4194304 2>/dev/null; ulimit -f 4194304 2>/dev/null; exec "$@"`
			cmd = exec.CommandContext(ctx, sh, append([]string{"-c", script, "sh", g.bin()}, full...)...)
		}
	}
	if cmd == nil {
		cmd = exec.CommandContext(ctx, g.bin(), full...)
	}
	cmd.Dir = dir
	cmd.Env = c.env
	cmd.WaitDelay = 5 * time.Second
	var out, errb limitedBuffer
	out.max, errb.max = 4<<20, 16<<10
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("git %s: %w", args[0], ctx.Err())
		}
		return nil, fmt.Errorf("git %s failed: %s", args[0], scrub(errb.String(), c.secret))
	}
	return out.Bytes(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

func scrub(s, secret string) string {
	if secret != "" {
		s = strings.ReplaceAll(s, secret, "***")
	}
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		s = s[:500] + "..."
	}
	return s
}

// ListBranches runs `git ls-remote --heads` (used by "test connection").
func (g *GitFetcher) ListBranches(ctx context.Context, repoURL string, auth Auth) ([]string, error) {
	tmp, err := os.MkdirTemp("", "capsule-lsremote-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, err := g.prepare(ctx, tmp, repoURL, auth)
	if err != nil {
		return nil, err
	}
	out, err := g.run(ctx, c, tmp, "ls-remote", "--heads", "--", repoURL)
	if err != nil {
		return nil, err
	}
	var branches []string
	for _, line := range strings.Split(string(out), "\n") {
		if _, ref, ok := strings.Cut(strings.TrimSpace(line), "\t"); ok && strings.HasPrefix(ref, "refs/heads/") {
			if b := strings.TrimPrefix(ref, "refs/heads/"); ValidBranch(b) {
				branches = append(branches, b)
			}
		}
	}
	sort.Strings(branches)
	if len(branches) > 200 {
		branches = branches[:200]
	}
	return branches, nil
}

// Fetch clones branch (depth 1) and packages it. The returned snapshot must be closed.
func (g *GitFetcher) Fetch(ctx context.Context, repoURL, branch string, auth Auth) (snap *Snapshot, err error) {
	if !ValidBranch(branch) {
		return nil, errors.New("invalid branch name")
	}
	tmp, err := os.MkdirTemp("", "capsule-git-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(tmp)
		}
	}()
	timeout := g.Limits.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	c, err := g.prepare(ctx, tmp, repoURL, auth)
	if err != nil {
		return nil, err
	}
	work := filepath.Join(tmp, "work")
	maxRepo := g.Limits.MaxRepoBytes
	if maxRepo <= 0 {
		maxRepo = 200 << 20
	}

	// Abort early if the clone grows far beyond the limit.
	var tooBig atomic.Bool
	wctx, wcancel := context.WithCancel(ctx)
	defer wcancel()
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-wctx.Done():
				return
			case <-t.C:
				if dirSize(work, 3*maxRepo) > 2*maxRepo {
					tooBig.Store(true)
					cancel()
					return
				}
			}
		}
	}()

	_, err = g.run(ctx, c, tmp, "clone", "--depth", "1", "--single-branch", "--no-tags",
		"--branch", branch, "--", repoURL, work)
	wcancel()
	if tooBig.Load() {
		return nil, fmt.Errorf("repository exceeds the %d MB limit", maxRepo>>20)
	}
	if err != nil {
		return nil, err
	}
	info, err := g.run(ctx, c, work, "log", "-1", "--format=%H%x00%s")
	if err != nil {
		return nil, err
	}
	sha, msg, _ := strings.Cut(strings.TrimSpace(string(info)), "\x00")
	if !ValidSHA(sha) {
		return nil, errors.New("could not determine commit")
	}
	tarPath := filepath.Join(tmp, "source.tar.gz")
	size, err := PackageTarGz(work, tarPath, maxRepo)
	if err != nil {
		return nil, err
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return &Snapshot{TarPath: tarPath, SHA: sha, Message: msg, Size: size, dir: tmp}, nil
}

// dirSize sums file sizes under dir, stopping once it exceeds stopAt.
func dirSize(dir string, stopAt int64) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, e := d.Info(); e == nil {
			total += info.Size()
		}
		if total > stopAt {
			return io.EOF
		}
		return nil
	})
	return total
}

// PackageTarGz writes src (excluding .git, symlinks and special files) as a
// gzip tar with relative paths, the layout the deploy worker extracts for
// uploads. maxBytes caps the total uncompressed size. Returns the tarball size.
func PackageTarGz(src, dst string, maxBytes int64) (int64, error) {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	var total int64
	walkErr := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == ".git" || strings.HasPrefix(rel, ".git/") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Name: rel + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		}
		if !d.Type().IsRegular() { // symlinks, devices, sockets: skipped
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		if total > maxBytes {
			return fmt.Errorf("repository exceeds the %d MB limit", maxBytes>>20)
		}
		mode := int64(0o644)
		if info.Mode()&0o111 != 0 {
			mode = 0o755
		}
		if err := tw.WriteHeader(&tar.Header{Name: rel, Typeflag: tar.TypeReg, Mode: mode, Size: info.Size(), ModTime: info.ModTime()}); err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(tw, io.LimitReader(in, info.Size()))
		return err
	})
	if walkErr == nil {
		walkErr = tw.Close()
	}
	if walkErr == nil {
		walkErr = gz.Close()
	}
	if cerr := f.Close(); walkErr == nil {
		walkErr = cerr
	}
	if walkErr != nil {
		_ = os.Remove(dst)
		return 0, walkErr
	}
	st, err := os.Stat(dst)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}
