package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/backup"
)

// ---------------------------------------------------------------------------------------------
// Data restore into a directory (ephemeral target, local drill, tests)
// ---------------------------------------------------------------------------------------------

// Restorer restores one snapshot. Implementations: DirRestorer (a directory) and
// ServiceRestorer (in place, through backup.Service).
type Restorer interface {
	Check(ctx context.Context, sn SnapshotRef) (done bool, detail string, err error)
	Restore(ctx context.Context, sn SnapshotRef, force bool, runID uuid.UUID) (string, error)
	Verify(ctx context.Context, sn SnapshotRef) (string, error)
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// DirRestorer writes the plaintext of a snapshot to Dir/<project|platform>/<kind>/<source>.
// The write is atomic and verified BEFORE it replaces anything: the stream is decrypted into a
// temporary file while hashing; on a checksum or authentication failure the temporary file is
// deleted and the destination is untouched ("never restored halfway"). An existing destination
// with different content needs force and is first moved to <dest>.pre-restore-<runID>.
type DirRestorer struct {
	V   *Verifier
	Dir string
}

func (d *DirRestorer) dest(sn SnapshotRef) string {
	owner := "platform"
	if sn.ProjectID != nil {
		owner = sn.ProjectID.String()
	}
	name := sn.Source
	if sn.SourceID != "" {
		name += "-" + sn.SourceID
	}
	return filepath.Join(d.Dir, owner, sn.Kind, unsafeName.ReplaceAllString(name, "_"))
}

func fileSum(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// expected returns the checksum the destination must have (from the catalog, else by streaming).
func (d *DirRestorer) expected(ctx context.Context, sn SnapshotRef) (string, error) {
	if sn.Checksum != "" {
		return sn.Checksum, nil
	}
	_, sum, err := d.V.Stream(ctx, sn, nil)
	return sum, err
}

func (d *DirRestorer) Check(ctx context.Context, sn SnapshotRef) (bool, string, error) {
	got, err := fileSum(d.dest(sn))
	if errors.Is(err, os.ErrNotExist) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	want, err := d.expected(ctx, sn)
	if err != nil {
		return false, "", err
	}
	if got == want {
		return true, "destination checksum equals the backup", nil
	}
	return false, "", nil
}

func (d *DirRestorer) Restore(ctx context.Context, sn SnapshotRef, force bool, runID uuid.UUID) (string, error) {
	dest := d.dest(sn)
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return "", err
	}
	tmp := dest + ".tmp-" + runID.String()
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	n, _, err := d.V.Stream(ctx, sn, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("snapshot failed verification, nothing was restored: %w", err)
	}
	if _, serr := os.Stat(dest); serr == nil {
		if !force {
			_ = os.Remove(tmp)
			return "", ErrNeedOverwrite
		}
		if err := os.Rename(dest, dest+".pre-restore-"+runID.String()); err != nil {
			_ = os.Remove(tmp)
			return "", err
		}
	}
	if err := os.Rename(tmp, dest); err != nil {
		return "", err
	}
	return fmt.Sprintf("restored %d bytes to %s", n, filepath.ToSlash(dest)), nil
}

func (d *DirRestorer) Verify(ctx context.Context, sn SnapshotRef) (string, error) {
	got, err := fileSum(d.dest(sn))
	if err != nil {
		return "", err
	}
	want, err := d.expected(ctx, sn)
	if err != nil {
		return "", err
	}
	if got != want {
		return "", ErrChecksum
	}
	return "sha256 " + got[:12], nil
}

// DataExec adapts a Restorer to database, volume and platform-files steps.
type DataExec struct {
	R Restorer
	// Force is only taken from the request (--force-overwrite); kept here for tests.
}

func (x DataExec) Check(ctx context.Context, st Step, rc RunCtx) (bool, string, error) {
	if st.Snapshot == nil {
		return false, "", errors.New("step has no snapshot")
	}
	return x.R.Check(ctx, *st.Snapshot)
}
func (x DataExec) Apply(ctx context.Context, st Step, rc RunCtx) (string, error) {
	return x.R.Restore(ctx, *st.Snapshot, rc.Request.ForceOverwrite, rc.RunID)
}
func (x DataExec) Verify(ctx context.Context, st Step, rc RunCtx) (string, error) {
	return x.R.Verify(ctx, *st.Snapshot)
}

// ---------------------------------------------------------------------------------------------
// In place through backup.Service
// ---------------------------------------------------------------------------------------------

// BackupRestorer is the part of backup.Service used by ServiceRestorer.
type BackupRestorer interface {
	StartRestore(ctx context.Context, projectID, snapshotID uuid.UUID, target string, user *uuid.UUID) (uuid.UUID, error)
}

// RunLister is the part of backup.Repo used to wait for the restore run.
type RunLister interface {
	ListRuns(ctx context.Context, projectID *uuid.UUID, limit int) ([]backup.Run, error)
}

// ServiceRestorer restores in place by delegating to backup.Service (which verifies the checksum
// first, then restores). Check cannot cheaply compare a live database with a dump, so a database
// or volume restored in place is not detected as "done": idempotence there comes from the journal
// (`--resume` skips steps already `ok`); re-running the same snapshot is a restore of identical
// data, and --force-overwrite is the operator's explicit consent.
type ServiceRestorer struct {
	Svc  BackupRestorer
	Runs RunLister
	V    *Verifier
	Poll time.Duration
}

func (s *ServiceRestorer) Check(context.Context, SnapshotRef) (bool, string, error) {
	return false, "", nil
}

func (s *ServiceRestorer) Restore(ctx context.Context, sn SnapshotRef, force bool, runID uuid.UUID) (string, error) {
	if !force {
		return "", ErrNeedOverwrite
	}
	if sn.ProjectID == nil {
		return "", errors.New("in-place restore needs a project snapshot")
	}
	if _, _, err := s.V.Stream(ctx, sn, nil); err != nil { // verify before touching anything
		return "", fmt.Errorf("snapshot failed verification, nothing was restored: %w", err)
	}
	id, err := s.Svc.StartRestore(ctx, *sn.ProjectID, sn.ID, "", nil)
	if err != nil {
		return "", err
	}
	poll := s.Poll
	if poll <= 0 {
		poll = 2 * time.Second
	}
	for {
		runs, err := s.Runs.ListRuns(ctx, sn.ProjectID, 20)
		if err != nil {
			return "", err
		}
		for _, r := range runs {
			if r.ID != id {
				continue
			}
			switch r.Status {
			case "success":
				return "restore run " + id.String() + " finished", nil
			case "failed":
				return "", errors.New("restore run failed: " + r.Error)
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(poll):
		}
	}
}

func (s *ServiceRestorer) Verify(ctx context.Context, sn SnapshotRef) (string, error) {
	_, sum, err := s.V.Stream(ctx, sn, nil)
	if err != nil {
		return "", err
	}
	return "backup intact, sha256 " + sum[:12], nil
}

// ---------------------------------------------------------------------------------------------
// Preflight, project (manifest), report
// ---------------------------------------------------------------------------------------------

// PreflightExec is F0: encryption key present and able to decrypt, object store reachable.
type PreflightExec struct {
	V      *Verifier
	Probe  *SnapshotRef // a snapshot to decrypt as the key test (the newest manifest/platform file); nil = skip the decrypt test
	Tools  []string     // executables that must exist in PATH (terraform, aws, ...), only for bootstrap/infra runs
	LookUp func(string) (string, error)
}

func (p PreflightExec) Check(context.Context, Step, RunCtx) (bool, string, error) {
	return false, "", nil
}
func (p PreflightExec) Apply(ctx context.Context, st Step, rc RunCtx) (string, error) {
	return p.Verify(ctx, st, rc)
}
func (p PreflightExec) Verify(ctx context.Context, _ Step, _ RunCtx) (string, error) {
	if p.V == nil || p.V.Secret == "" {
		return "", errors.New("encryption key (CAPSULE_SECRET_KEY) is not available: backups cannot be decrypted")
	}
	look := p.LookUp
	if look == nil {
		look = exec.LookPath
	}
	var missing []string
	for _, t := range p.Tools {
		if _, err := look(t); err != nil {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("missing tools: %s", strings.Join(missing, ", "))
	}
	if p.Probe != nil {
		if _, _, err := p.V.Stream(ctx, *p.Probe, nil); err != nil {
			return "", fmt.Errorf("decrypt test with the encryption key failed: %w", err)
		}
	}
	return "key decrypts a real backup; tools present", nil
}

// ProjectExec is F6. It re-verifies the project manifest (a manipulated manifest fails here even
// if the plan was made earlier) and hands the rebuild to Rebuilder. Without a Rebuilder (ephemeral
// or file target) Apply writes the verified rebuild specification to Dir/<project>/rebuild.json.
type ProjectExec struct {
	V         *Verifier
	Dir       string
	Rebuilder interface {
		Rebuild(ctx context.Context, projectID uuid.UUID, m *backup.Manifest) error
	}
}

func (p ProjectExec) manifest(ctx context.Context, st Step) (*backup.Manifest, error) {
	if st.Snapshot == nil {
		return nil, errors.New("step has no manifest snapshot")
	}
	return p.V.Manifest(ctx, *st.Snapshot)
}

func (p ProjectExec) specPath(st Step) string {
	return filepath.Join(p.Dir, st.ProjectID.String(), "rebuild.json")
}

func (p ProjectExec) Check(ctx context.Context, st Step, _ RunCtx) (bool, string, error) {
	if p.Rebuilder != nil {
		return false, "", nil
	}
	m, err := p.manifest(ctx, st)
	if err != nil {
		return false, "", err
	}
	want, _ := json.MarshalIndent(m, "", "  ")
	got, err := os.ReadFile(p.specPath(st))
	return err == nil && bytes.Equal(got, want), "rebuild spec already written", nil
}

func (p ProjectExec) Apply(ctx context.Context, st Step, _ RunCtx) (string, error) {
	m, err := p.manifest(ctx, st)
	if err != nil {
		return "", err
	}
	if p.Rebuilder != nil {
		return "containers re-created from the manifest", p.Rebuilder.Rebuild(ctx, *st.ProjectID, m)
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.MkdirAll(filepath.Dir(p.specPath(st)), 0o700); err != nil {
		return "", err
	}
	return "rebuild spec written", os.WriteFile(p.specPath(st), b, 0o600)
}

func (p ProjectExec) Verify(ctx context.Context, st Step, _ RunCtx) (string, error) {
	m, err := p.manifest(ctx, st)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("manifest schema %d verified (%d databases, %d volumes)", m.Schema, len(m.Databases), len(m.Volumes)), nil
}

// ---------------------------------------------------------------------------------------------
// Scripts (deploy/recovery/*.sh): network, core, git, dns, smoke
// ---------------------------------------------------------------------------------------------

// Runner executes a process. Output is truncated and never contains the environment.
type Runner interface {
	Run(ctx context.Context, name string, args []string, env []string) (out []byte, exitCode int, err error)
}

// OSRunner runs real processes.
type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, name string, args []string, env []string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &limitW{w: &buf, max: 64 << 10}, &limitW{w: &buf, max: 64 << 10}
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return buf.Bytes(), ee.ExitCode(), nil
	}
	return buf.Bytes(), 0, err
}

type limitW struct {
	w   *bytes.Buffer
	max int
}

func (l *limitW) Write(p []byte) (int, error) {
	if l.w.Len() < l.max {
		l.w.Write(p)
	}
	return len(p), nil
}

// ScriptExec runs `<Dir>/<script> check|apply|verify` for a step kind. Contract of the scripts
// (deploy/recovery/README.md): check exits 0 when already done and 10 when not; apply and verify
// exit 0 on success; context goes in RECOVERY_* environment variables, never in arguments.
type ScriptExec struct {
	Runner Runner
	Dir    string
	Script string
	Env    []string // extra KEY=VALUE (credentials come from the process environment, never logged)
}

func (s ScriptExec) call(ctx context.Context, verb string, st Step, rc RunCtx) ([]byte, int, error) {
	env := append([]string{
		"RECOVERY_RUN_ID=" + rc.RunID.String(),
		"RECOVERY_STEP=" + st.ID,
		"RECOVERY_TARGET=" + string(rc.Request.Target),
	}, s.Env...)
	if st.Dump != nil {
		env = append(env, "RECOVERY_DUMP_KEY="+st.Dump.Key, "RECOVERY_DUMP_SHA256="+st.Dump.Sha256)
	}
	return s.Runner.Run(ctx, "bash", []string{filepath.ToSlash(filepath.Join(s.Dir, s.Script)), verb}, env)
}

func lastLine(b []byte) string {
	l := strings.Split(strings.TrimSpace(string(b)), "\n")
	return l[len(l)-1]
}

func (s ScriptExec) Check(ctx context.Context, st Step, rc RunCtx) (bool, string, error) {
	out, code, err := s.call(ctx, "check", st, rc)
	switch {
	case err != nil:
		return false, "", err
	case code == 0:
		return true, lastLine(out), nil
	case code == 10:
		return false, "", nil
	}
	return false, "", fmt.Errorf("check exited %d: %s", code, lastLine(out))
}

func (s ScriptExec) Apply(ctx context.Context, st Step, rc RunCtx) (string, error) {
	return s.verb(ctx, "apply", st, rc)
}
func (s ScriptExec) Verify(ctx context.Context, st Step, rc RunCtx) (string, error) {
	return s.verb(ctx, "verify", st, rc)
}
func (s ScriptExec) verb(ctx context.Context, v string, st Step, rc RunCtx) (string, error) {
	out, code, err := s.call(ctx, v, st, rc)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("%s exited %d: %s", v, code, lastLine(out))
	}
	return lastLine(out), nil
}

// ---------------------------------------------------------------------------------------------
// Report step
// ---------------------------------------------------------------------------------------------

// ReportExec is F9. Build is called with the final journal; it writes the report (S3 drills/ or
// recoveries/) and returns its location.
type ReportExec struct {
	Build func(ctx context.Context, rc RunCtx) (location string, err error)
}

func (r ReportExec) Check(context.Context, Step, RunCtx) (bool, string, error) { return false, "", nil }
func (r ReportExec) Apply(ctx context.Context, _ Step, rc RunCtx) (string, error) {
	if r.Build == nil {
		return "no report destination configured", nil
	}
	return r.Build(ctx, rc)
}
func (r ReportExec) Verify(context.Context, Step, RunCtx) (string, error) { return "", nil }
