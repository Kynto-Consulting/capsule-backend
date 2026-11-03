package gitcore_test

import (
	"context"
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitcore/fake"
)

func svcWith(t *testing.T, mod func(*gitcore.Config)) (*gitcore.Service, *fake.Server) {
	t.Helper()
	fs := fake.New()
	t.Cleanup(fs.Close)
	c := cfgFor(fs.URL)
	mod(&c)
	return gitcore.New(c, nil, nil), fs
}

// Without CAPSULE_GIT_BOT_PASSWORD nothing breaks: the web-only features answer NOT_SUPPORTED with
// the reason and the Forgejo link, and re-run falls back to workflow_dispatch.
func TestWebDegradesWithoutPassword(t *testing.T) {
	s, fs := svcWith(t, func(c *gitcore.Config) { c.BotPassword = "" })
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	run, job := fs.AddRun("acme", "web", "failure", "boom")
	if s.WebEnabled() {
		t.Fatal("web must be off")
	}
	for name, err := range map[string]error{
		"ListJobs":      func() error { _, e := s.ListJobs(ctx, R, run); return e }(),
		"JobLogs":       func() error { _, e := s.JobLogs(ctx, R, job, 0); return e }(),
		"CancelRun":     s.CancelRun(ctx, R, run),
		"ListArtifacts": func() error { _, e := s.ListArtifacts(ctx, R, run); return e }(),
		"ListJobSteps":  func() error { _, e := s.ListJobSteps(ctx, R, run); return e }(),
		"RerunFailed":   func() error { _, e := s.RerunRun(ctx, R, run, true); return e }(),
	} {
		if !gitcore.IsUnsupported(err) || !strings.Contains(err.Error(), fs.URL) || !strings.Contains(err.Error(), "CAPSULE_GIT_BOT_PASSWORD") {
			t.Errorf("%s: want NOT_SUPPORTED with reason and Forgejo link, got %v", name, err)
		}
	}
	nw, err := s.RerunRun(ctx, R, run, false)
	if err != nil || nw.ID <= run {
		t.Fatalf("dispatch fallback: %+v %v", nw, err)
	}
	if n := fs.Count("POST", "/user/login"); n != 0 {
		t.Fatalf("no password must never hit /user/login (%d)", n)
	}
}

func TestWebJobsStepsLogsCursor(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	run, job := fs.AddRun("acme", "web", "running", "a\nb\n")
	js, err := s.ListJobs(ctx, R, run)
	if err != nil || len(js) != 1 || js[0].ID != job || js[0].Name != "build" || js[0].Status != "running" || js[0].RunsOn == nil {
		t.Fatalf("%+v %v", js, err)
	}
	steps, err := s.ListJobSteps(ctx, R, run)
	if err != nil || len(steps[job]) != 1 || steps[job][0].Name != "build" {
		t.Fatalf("%+v %v", steps, err)
	}
	l1, err := s.JobLogs(ctx, R, job, 0)
	if err != nil || l1.Content != "##[step] build\na\nb\n" {
		t.Fatalf("%q %v", l1.Content, err)
	}
	// the job keeps writing: only the NEW lines are fetched (per-step cursor), the result is the whole log
	fs.SetLog("acme", "web", job, "a\nb\nc\nd\n")
	fs.Reset()
	l2, err := s.JobLogs(ctx, R, job, 0)
	if err != nil || l2.Content != "##[step] build\na\nb\nc\nd\n" {
		t.Fatalf("%q %v", l2.Content, err)
	}
	var cursors []string
	for _, rq := range fs.Requests() {
		if strings.Contains(rq.Path, "/jobs/0/attempt/1") {
			cursors = append(cursors, rq.Body)
		}
	}
	if len(cursors) != 1 || !strings.Contains(cursors[0], `"cursor":2`) {
		t.Fatalf("second read must resume at cursor 2: %v", cursors)
	}
	// tail kept when cut
	tl, _ := s.JobLogs(ctx, R, job, 6)
	if !tl.Truncated || !strings.HasSuffix(tl.Content, "c\nd\n") || len(tl.Content) > 6 {
		t.Fatalf("%+v", tl)
	}
	// a job of another run / unknown job
	if _, err := s.JobLogs(ctx, R, 987654, 0); code(err) != gitcore.CodeNotFound {
		t.Fatalf("unknown job: %v", err)
	}
	// a re-run starts a new attempt: the buffered log of the old attempt must be dropped
	if err := s.CancelRun(ctx, R, run); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RerunRun(ctx, R, run, false); err != nil {
		t.Fatal(err)
	}
	fs.SetLog("acme", "web", job, "x\n")
	fs.SetRunStatus("acme", "web", run, "running")
	l3, err := s.JobLogs(ctx, R, job, 0)
	if err != nil || l3.Content != "##[step] build\nx\n" {
		t.Fatalf("new attempt must not mix with the old log: %q %v", l3.Content, err)
	}
}

func TestWebCancelAndRerunFailedOnly(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	run, _ := fs.AddRun("acme", "web", "running", "x")
	if err := s.CancelRun(ctx, R, run); err != nil {
		t.Fatal(err)
	}
	g, _ := s.GetRun(ctx, R, run)
	if g.Status != "cancelled" {
		t.Fatalf("%+v", g)
	}
	if err := s.CancelRun(ctx, R, 999); code(err) != gitcore.CodeNotFound {
		t.Fatalf("unknown run: %v", err)
	}
	ok, _ := fs.AddRun("acme", "web", "success", "fine")
	if _, err := s.RerunRun(ctx, R, ok, true); code(err) != gitcore.CodeConflict {
		t.Fatalf("no failed job to re-run: %v", err)
	}
	nw, err := s.RerunRun(ctx, R, run, true) // cancelled counts as not-successful
	if err != nil || nw.ID != run {
		t.Fatalf("%+v %v", nw, err)
	}
}

func TestWebArtifacts(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	run, _ := fs.AddRun("acme", "web", "success", "x")
	fs.AddArtifact("acme", "web", run, "bundle", "hello")
	l, err := s.ListArtifacts(ctx, R, run)
	if err != nil || len(l) != 1 || l[0].Name != "bundle" || l[0].Size != 5 || !strings.HasSuffix(l[0].DownloadURL, "/artifacts/bundle") {
		t.Fatalf("%+v %v", l, err)
	}
	b, err := s.DownloadArtifact(ctx, R, run, "bundle")
	if err != nil || len(b) < 4 || string(b[:2]) != "PK" {
		t.Fatalf("zip: %d %v", len(b), err)
	}
	if _, err := s.DownloadArtifact(ctx, R, run, "../x"); code(err) != gitcore.CodeInvalid {
		t.Fatalf("name: %v", err)
	}
	if _, err := s.DownloadArtifact(ctx, R, run, "nope"); code(err) != gitcore.CodeNotFound {
		t.Fatalf("missing: %v", err)
	}
}

func TestWebSessionRenewalAndCredentials(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	run, _ := fs.AddRun("acme", "web", "success", "x")
	for i := 0; i < 3; i++ {
		if _, err := s.ListJobs(ctx, R, run); err != nil {
			t.Fatal(err)
		}
	}
	if fs.WebLogins() != 1 {
		t.Fatalf("the session must be cached: %d logins", fs.WebLogins())
	}
	fs.ExpireSessions() // Forgejo answers 404 to the expired session: it is renewed and the call retried
	if _, err := s.ListJobs(ctx, R, run); err != nil {
		t.Fatalf("expired session: %v", err)
	}
	if fs.WebLogins() != 2 {
		t.Fatalf("expected one re-login: %d", fs.WebLogins())
	}
	// a genuine 404 (unknown run) with a live session does not log in again
	if _, err := s.ListJobs(ctx, R, 999); code(err) != gitcore.CodeNotFound {
		t.Fatalf("%v", err)
	}
	if fs.WebLogins() != 2 {
		t.Fatalf("404 must not re-login: %d", fs.WebLogins())
	}
	// credentials and cookies never reach errors
	bad, bfs := svcWith(t, func(c *gitcore.Config) { c.BotPassword = "wrong-secret-pw" })
	bfs.AddRepo("acme", "web")
	r2, _ := bfs.AddRun("acme", "web", "success", "x")
	_, err := bad.ListJobs(ctx, R, r2)
	if !gitcore.IsUnsupported(err) || strings.Contains(err.Error(), "wrong-secret-pw") {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err2 := bad.ListJobs(ctx, R, r2); err2 == nil || bfs.Count("POST", "/user/login") != 1 {
		t.Fatalf("a rejected login must be remembered for a while, not retried per call: %d", bfs.Count("POST", "/user/login"))
	}
}

func TestWebVersionGate(t *testing.T) {
	s, fs := svcWith(t, func(c *gitcore.Config) { c.WebVersions = []string{"14.0.1"} })
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	run, _ := fs.AddRun("acme", "web", "success", "x")
	_, err := s.ListJobs(ctx, R, run)
	if !gitcore.IsUnsupported(err) || !strings.Contains(err.Error(), "15.0.11") || !strings.Contains(err.Error(), "CAPSULE_GIT_WEB_VERSIONS") {
		t.Fatalf("untested version must degrade with the reason: %v", err)
	}
	if n := fs.Count("POST", "/user/login"); n != 0 {
		t.Fatalf("must not log in on an untested version")
	}
	exact, efs := svcWith(t, func(c *gitcore.Config) { c.WebVersions = []string{"15.0.11"} })
	efs.AddRepo("acme", "web")
	r3, _ := efs.AddRun("acme", "web", "success", "x")
	if _, err := exact.ListJobs(ctx, R, r3); err != nil {
		t.Fatalf("exact version: %v", err)
	}
}

func TestWebShapeChangeFailsLoudly(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	run, _ := fs.AddRun("acme", "web", "success", "x")
	if _, err := s.ListJobs(ctx, R, run); err != nil {
		t.Fatal(err)
	}
	fs.BreakWebShape(true)
	_, err := s.ListJobs(ctx, R, run)
	if e, ok := gitcore.AsError(err); !ok || e.Code != gitcore.CodeUpstream || !strings.Contains(e.Message, "response shape") || !strings.Contains(e.Message, "15.0.11") {
		t.Fatalf("a changed shape must be an UPSTREAM error naming the problem: %v", err)
	}
}
