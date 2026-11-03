package gitimport_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitcore/fake"
	"github.com/kynto/capsule/backend/internal/gitimport"
	"github.com/kynto/capsule/backend/internal/gitimport/gitimporttest"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

const ghToken = "ghp_SECRETTOKENabcdefghijklmnop1234"

type rig struct {
	t     *testing.T
	svc   *gitimport.Service
	mem   *gitimporttest.Mem
	proj  *gitimporttest.Projects
	gh    *gitimporttest.GitHub
	fj    *fake.Server
	forge *spyForge
	logs  *bytes.Buffer
	org   uuid.UUID
	after []uuid.UUID
}

// spyForge wraps the real gitcore.Service (against the fake Forgejo) so a test can inject a Migrate
// error that echoes the token, as a careless upstream could.
type spyForge struct {
	*gitcore.Service
	mu          sync.Mutex
	migrations  []gitcore.MigrateSpec
	migrateErr  func(spec gitcore.MigrateSpec) error
	migrateWait chan struct{}
}

func (f *spyForge) Migrate(ctx context.Context, m gitcore.MigrateSpec) (*gitcore.Repository, error) {
	f.mu.Lock()
	f.migrations = append(f.migrations, m)
	fn := f.migrateErr
	f.mu.Unlock()
	if fn != nil {
		if err := fn(m); err != nil {
			return nil, err
		}
	}
	return f.Service.Migrate(ctx, m)
}

func publicLookup(_ context.Context, _ string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("140.82.112.3")}, nil
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, mem: gitimporttest.NewMem(), proj: gitimporttest.NewProjects(), org: uuid.New(), logs: &bytes.Buffer{}}
	r.gh = gitimporttest.NewGitHub(ghToken)
	t.Cleanup(r.gh.Close)
	r.fj = fake.New()
	t.Cleanup(r.fj.Close)
	r.forge = &spyForge{Service: gitcore.New(gitcore.Config{URL: r.fj.URL, Token: fake.Token, Timeout: 5 * time.Second, BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond}, nil, nil)}
	r.build(gitsource.Policy{Lookup: publicLookup})
	return r
}

func (r *rig) build(p gitsource.Policy) {
	lg := slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r.svc = gitimport.New(context.Background(), gitimport.Config{GitHubAPI: r.gh.URL, RepoTimeout: time.Minute}, gitimport.Deps{
		Store: r.mem, Forge: r.forge, GitHub: &gitimport.GitHub{BaseURL: r.gh.URL, HTTP: http.DefaultClient},
		Projects: r.proj, Linker: r.mem, Audit: r.mem, Policy: p, Logger: lg,
		AfterImport: func(_ context.Context, id uuid.UUID) error { r.after = append(r.after, id); return nil },
	})
}

func (r *rig) in(repos ...string) gitimport.StartInput {
	return gitimport.StartInput{OrgID: r.org, OrgSlug: "acme", UserID: uuid.New(), IP: "203.0.113.9", Token: ghToken, Repos: repos, CreateProjects: true}
}

func (r *rig) start(in gitimport.StartInput) *gitimport.Import {
	r.t.Helper()
	im, _, err := r.svc.Start(context.Background(), in)
	if err != nil {
		r.t.Fatalf("Start: %v", err)
	}
	r.svc.Wait()
	got, err := r.svc.Get(context.Background(), r.org, im.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	return got
}

func repoByName(im *gitimport.Import, name string) gitimport.RepoState {
	for _, r := range im.Repos {
		if r.Name == name {
			return r
		}
	}
	return gitimport.RepoState{}
}

func TestImportSuccessWithCodeOwnersAndWorkflows(t *testing.T) {
	r := newRig(t)
	r.gh.Add("octo/Web_App", gitimporttest.GitHubRepo{Private: true, DefaultBranch: "trunk", Description: "the web", Files: map[string]string{
		".github/CODEOWNERS":           "*.go @alice\n/docs/ @octo/writers @bob\n",
		".github/workflows/ci.yml":     "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./local\n      - uses: some/thing@abc\n",
		".github/workflows/readme.txt": "x",
	}})
	im := r.start(r.in("octo/Web_App"))
	if im.Status != gitimport.StatusSuccess || len(im.Repos) != 1 {
		t.Fatalf("import: %+v", im)
	}
	row := im.Repos[0]
	if row.Status != gitimport.StatusSuccess || row.ProjectID == nil || row.Slug != "web-app" || !row.CreatedProject {
		t.Fatalf("repo: %+v", row)
	}
	// project created with GitHub's default branch
	p, err := r.proj.GetBySlug(context.Background(), r.org, "web-app")
	if err != nil || p.Branch != "trunk" || p.ID != *row.ProjectID {
		t.Fatalf("project: %+v %v", p, err)
	}
	// Forgejo got a private migration with the token and the policy flags
	if len(r.forge.migrations) != 1 {
		t.Fatalf("migrations: %+v", r.forge.migrations)
	}
	m := r.forge.migrations[0]
	if m.Owner != "acme" || m.Repo != "web-app" || m.CloneAddr != "https://github.com/octo/Web_App.git" || m.Service != "github" || !m.Private || m.AuthToken != ghToken || m.Mirror {
		t.Fatalf("migrate spec: %+v", m)
	}
	if !r.mem.Ready[p.ID] || len(r.after) != 1 || r.after[0] != p.ID {
		t.Fatalf("linker/after: %v %v", r.mem.Ready, r.after)
	}
	// CODEOWNERS converted, team dropped, reported (not committed)
	if row.CodeOwners == nil || row.CodeOwners.Path != ".github/CODEOWNERS" {
		t.Fatalf("codeowners: %+v", row.CodeOwners)
	}
	if !strings.Contains(row.CodeOwners.Converted, `(?:.*/)?[^/]*\.go @alice`) || !strings.Contains(row.CodeOwners.Converted, `docs/.* @bob`) || strings.Contains(row.CodeOwners.Converted, "writers") {
		t.Fatalf("converted: %q", row.CodeOwners.Converted)
	}
	joined := strings.Join(row.Warnings, "\n")
	for _, want := range []string{"converted to Forgejo syntax", "Forgejo does not read .github/CODEOWNERS", "kept: the runner executes it", "actions/checkout@v4", "some/thing@abc"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings miss %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "./local") {
		t.Errorf("local action must not be flagged:\n%s", joined)
	}
	if got := r.mem.AuditActions(); len(got) != 2 || got[0] != gitimport.AuditImportStart || got[1] != gitimport.AuditImportFinish {
		t.Fatalf("audit: %v", got)
	}
	if r.mem.Audits[0].IP != "203.0.113.9" || r.mem.Audits[0].UserID == nil {
		t.Fatalf("audit actor: %+v", r.mem.Audits[0])
	}
}

func TestImportTokenNeverPersistedNorLogged(t *testing.T) {
	r := newRig(t)
	r.gh.Add("octo/a", gitimporttest.GitHubRepo{})
	r.gh.Add("octo/b", gitimporttest.GitHubRepo{})
	r.gh.Add("octo/c", gitimporttest.GitHubRepo{})
	// a careless upstream that echoes the token inside its error text, and a panic carrying it
	r.forge.migrateErr = func(m gitcore.MigrateSpec) error {
		switch m.Repo {
		case "b":
			return &gitcore.Error{Code: gitcore.CodeUnprocessed, Message: "clone failed for https://x-access-token:" + m.AuthToken + "@github.com/octo/b.git"}
		case "c":
			panic("boom " + m.AuthToken)
		}
		return nil
	}
	im, _, err := r.svc.Start(context.Background(), r.in("octo/a", "octo/b", "octo/c"))
	if err != nil {
		t.Fatal(err)
	}
	r.svc.Wait()
	got, _ := r.svc.Get(context.Background(), r.org, im.ID)
	b := repoByName(got, "octo/b")
	if b.Status != gitimport.StatusFailed || !strings.Contains(b.Error, "the migration failed") {
		t.Fatalf("b: %+v", b)
	}
	// search every place the token could have landed
	if d := r.mem.Dump(); strings.Contains(d, ghToken) || strings.Contains(d, "SECRETTOKEN") {
		t.Fatalf("token persisted:\n%s", d)
	}
	if l := r.logs.String(); strings.Contains(l, ghToken) || strings.Contains(l, "SECRETTOKEN") {
		t.Fatalf("token logged:\n%s", l)
	}
	if strings.Contains(b.Error, "SECRETTOKEN") {
		t.Fatalf("token in the visible error: %s", b.Error)
	}
	// the response model has no field for it either
	if got.Status != gitimport.StatusFailed && got.Status != gitimport.StatusPartial {
		t.Fatalf("status %s", got.Status)
	}
}

func TestImportPartialThenResume(t *testing.T) {
	r := newRig(t)
	r.gh.Add("octo/one", gitimporttest.GitHubRepo{})
	// octo/two does not exist yet on GitHub
	in := r.in("octo/one", "octo/two")
	in.IdemKey = "key-1"
	im := r.start(in)
	if im.Status != gitimport.StatusPartial {
		t.Fatalf("status %s: %+v", im.Status, im.Repos)
	}
	one, two := repoByName(im, "octo/one"), repoByName(im, "octo/two")
	if one.Status != gitimport.StatusSuccess || two.Status != gitimport.StatusFailed || !strings.Contains(two.Error, "not found") || two.ProjectID != nil {
		t.Fatalf("rows: %+v / %+v", one, two)
	}
	if len(r.forge.migrations) != 1 {
		t.Fatalf("migrations before resume: %d", len(r.forge.migrations))
	}

	// the repository appears; the SAME request with the same key resumes only what is missing
	r.gh.Add("octo/two", gitimporttest.GitHubRepo{})
	im2, resumed, err := r.svc.Start(context.Background(), in)
	if err != nil || !resumed || im2.ID != im.ID {
		t.Fatalf("resume: %+v %v %v", im2, resumed, err)
	}
	r.svc.Wait()
	final, _ := r.svc.Get(context.Background(), r.org, im.ID)
	if final.Status != gitimport.StatusSuccess || final.Attempts != 2 {
		t.Fatalf("final: %s attempts=%d %+v", final.Status, final.Attempts, final.Repos)
	}
	if len(r.forge.migrations) != 2 || r.forge.migrations[1].Repo != "two" {
		t.Fatalf("resume must migrate only the missing repo: %+v", r.forge.migrations)
	}
	if got := r.mem.AuditActions(); len(got) != 4 {
		t.Fatalf("audit: %v", got)
	}

	// a finished import replays without work
	before := len(r.gh.Hits)
	im3, resumed, err := r.svc.Start(context.Background(), in)
	if err != nil || resumed || im3.ID != im.ID || im3.Status != gitimport.StatusSuccess {
		t.Fatalf("replay: %+v %v %v", im3, resumed, err)
	}
	r.svc.Wait()
	if len(r.gh.Hits) != before {
		t.Fatal("a replay must not call GitHub")
	}
}

func TestImportIdempotencyConflicts(t *testing.T) {
	r := newRig(t)
	r.gh.Add("octo/one", gitimporttest.GitHubRepo{})
	r.gh.Add("octo/two", gitimporttest.GitHubRepo{})
	in := r.in("octo/one")
	in.IdemKey = "k"
	r.start(in)
	other := r.in("octo/two")
	other.IdemKey = "k"
	if _, _, err := r.svc.Start(context.Background(), other); !errors.Is(err, gitimport.ErrIdempotencyConflict) {
		t.Fatalf("same key, other repos: %v", err)
	}
	// other org, same key: independent
	o2 := r.in("octo/one")
	o2.OrgID, o2.IdemKey = uuid.New(), "k"
	if _, _, err := r.svc.Start(context.Background(), o2); err != nil {
		t.Fatalf("other org: %v", err)
	}
	r.svc.Wait()
}

func TestImportWhileRunningConflicts(t *testing.T) {
	r := newRig(t)
	r.gh.Add("octo/one", gitimporttest.GitHubRepo{})
	gate := make(chan struct{})
	r.forge.migrateErr = func(gitcore.MigrateSpec) error { <-gate; return nil }
	in := r.in("octo/one")
	in.IdemKey = "k"
	if _, _, err := r.svc.Start(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.svc.Start(context.Background(), in); !errors.Is(err, gitimport.ErrIdempotencyConflict) {
		t.Fatalf("running with the same key: %v", err)
	}
	// another import of the same name is refused while it is queued/running
	in2 := r.in("octo/one")
	if _, _, err := r.svc.Start(context.Background(), in2); !errors.Is(err, gitimport.ErrSlugBusy) {
		t.Fatalf("busy slug: %v", err)
	}
	close(gate)
	r.svc.Wait()
}

func TestImportBadTokenIsRefusedUpFront(t *testing.T) {
	r := newRig(t)
	r.gh.Add("octo/one", gitimporttest.GitHubRepo{})
	in := r.in("octo/one")
	in.Token = "ghp_wrongwrongwrongwrongwrong123456"
	if _, _, err := r.svc.Start(context.Background(), in); !errors.Is(err, gitimport.ErrBadToken) {
		t.Fatalf("err: %v", err)
	}
	if strings.Contains(r.mem.Dump(), "wrongwrong") || strings.Contains(r.logs.String(), "wrongwrong") {
		t.Fatal("token leaked")
	}
	if len(r.forge.migrations) != 0 {
		t.Fatal("nothing may be migrated")
	}
}

func TestImportNeverAdoptsForeignRepositories(t *testing.T) {
	r := newRig(t)
	r.gh.Add("octo/taken", gitimporttest.GitHubRepo{})
	r.gh.Add("octo/inforgejo", gitimporttest.GitHubRepo{})
	r.gh.Add("octo/fine", gitimporttest.GitHubRepo{})
	r.proj.Add(r.org, "taken")        // a project with that name exists
	r.fj.AddRepo("acme", "inforgejo") // Forgejo already has a repository nobody linked
	im := r.start(r.in("octo/taken", "octo/inforgejo", "octo/fine"))
	if im.Status != gitimport.StatusPartial {
		t.Fatalf("status %s", im.Status)
	}
	if e := repoByName(im, "octo/taken").Error; !strings.Contains(e, "already exists in this organization") {
		t.Fatalf("taken: %q", e)
	}
	if e := repoByName(im, "octo/inforgejo").Error; !strings.Contains(e, "already has a repository named inforgejo") {
		t.Fatalf("inforgejo: %q", e)
	}
	if repoByName(im, "octo/fine").Status != gitimport.StatusSuccess {
		t.Fatalf("fine: %+v", repoByName(im, "octo/fine"))
	}
	// the project created for the refused repo must not be left linked: only "fine" and "inforgejo" got one
	if len(r.forge.migrations) != 1 {
		t.Fatalf("only the clean repo is migrated: %+v", r.forge.migrations)
	}
}

func TestImportIntoExistingProjectWhenCreateProjectsIsFalse(t *testing.T) {
	r := newRig(t)
	r.gh.Add("octo/exists", gitimporttest.GitHubRepo{})
	r.gh.Add("octo/absent", gitimporttest.GitHubRepo{})
	p := r.proj.Add(r.org, "exists")
	in := r.in("octo/exists", "octo/absent")
	in.CreateProjects = false
	im := r.start(in)
	ex := repoByName(im, "octo/exists")
	if ex.Status != gitimport.StatusSuccess || ex.ProjectID == nil || *ex.ProjectID != p.ID || ex.CreatedProject {
		t.Fatalf("exists: %+v", ex)
	}
	if e := repoByName(im, "octo/absent").Error; !strings.Contains(e, "create_projects is false") {
		t.Fatalf("absent: %q", e)
	}
}

func TestImportSSRFPolicyIsApplied(t *testing.T) {
	r := newRig(t)
	r.gh.Add("octo/one", gitimporttest.GitHubRepo{})
	// DNS answers a private address for the clone host: refused, nothing is migrated
	r.build(gitsource.Policy{Lookup: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.7")}, nil }})
	im := r.start(r.in("octo/one"))
	if im.Status != gitimport.StatusFailed || !strings.Contains(repoByName(im, "octo/one").Error, "clone address is not allowed") {
		t.Fatalf("private: %+v", im.Repos)
	}
	// an allow-list that excludes github.com
	r2 := newRig(t)
	r2.gh.Add("octo/one", gitimporttest.GitHubRepo{})
	r2.build(gitsource.Policy{AllowedHosts: []string{"git.example.org"}, Lookup: publicLookup})
	im = r2.start(r2.in("octo/one"))
	if im.Status != gitimport.StatusFailed || len(r2.forge.migrations) != 0 {
		t.Fatalf("allow-list: %+v", im.Repos)
	}
}

func TestImportValidation(t *testing.T) {
	r := newRig(t)
	cases := map[string]gitimport.StartInput{
		"no repos":    r.in(),
		"bad name":    r.in("justaname"),
		"traversal":   r.in("octo/.."),
		"extra slash": r.in("a/b/c"),
		"flag":        r.in("-x/y"),
		"same slug":   r.in("a/Web.App", "b/web-app"),
	}
	for name, in := range cases {
		if _, _, err := r.svc.Start(context.Background(), in); !errors.Is(err, gitimport.ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	in := r.in("octo/a")
	in.Include = []string{"secrets"}
	if _, _, err := r.svc.Start(context.Background(), in); !errors.Is(err, gitimport.ErrValidation) {
		t.Errorf("include: %v", err)
	}
	in = r.in("octo/a")
	in.Token = " "
	if _, _, err := r.svc.Start(context.Background(), in); !errors.Is(err, gitimport.ErrValidation) {
		t.Errorf("token: %v", err)
	}
	many := make([]string, 51)
	for i := range many {
		many[i] = "octo/r" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	if _, _, err := r.svc.Start(context.Background(), r.in(many...)); !errors.Is(err, gitimport.ErrValidation) {
		t.Errorf("max repos: %v", err)
	}
	// URLs and .git suffixes are accepted
	r.gh.Add("octo/ok", gitimporttest.GitHubRepo{})
	im := r.start(r.in("https://github.com/octo/ok.git"))
	if im.Status != gitimport.StatusSuccess || im.Repos[0].Name != "octo/ok" {
		t.Fatalf("url form: %+v", im)
	}
}

func TestImportIncludeFlagsReachForgejo(t *testing.T) {
	r := newRig(t)
	r.gh.Add("octo/one", gitimporttest.GitHubRepo{})
	in := r.in("octo/one")
	in.Include = []string{"issues", "pull_requests", "wiki", "releases", "labels"}
	im := r.start(in)
	m := r.forge.migrations[0]
	if !m.Issues || !m.PullRequests || !m.Wiki || !m.Releases || m.LFS {
		t.Fatalf("spec: %+v", m)
	}
	if !strings.Contains(strings.Join(im.Repos[0].Warnings, "\n"), "issues are stored in Forgejo") {
		t.Fatalf("warnings: %v", im.Repos[0].Warnings)
	}
}

func TestImportRecoverMarksInterruptedAndResumeWorks(t *testing.T) {
	r := newRig(t)
	r.gh.Add("octo/one", gitimporttest.GitHubRepo{})
	gate := make(chan struct{})
	r.forge.migrateErr = func(gitcore.MigrateSpec) error { <-gate; return errors.New("killed") }
	in := r.in("octo/one")
	in.IdemKey = "k"
	im, _, err := r.svc.Start(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	close(gate)
	r.svc.Wait()
	// simulate a crash: the row says running with an old heartbeat, no goroutine is alive
	_ = r.mem.SetStatus(context.Background(), im.ID, gitimport.StatusRunning, false)
	r.mem.SetUpdatedAt(im.ID, time.Now().Add(-2*time.Hour))
	r.svc.Recover(context.Background())
	got, _ := r.svc.Get(context.Background(), r.org, im.ID)
	if got.Status != gitimport.StatusFailed || !strings.Contains(got.Repos[0].Error, "interrupted") {
		t.Fatalf("recover: %+v", got)
	}
	r.forge.migrateErr = nil
	if _, resumed, err := r.svc.Start(context.Background(), in); err != nil || !resumed {
		t.Fatalf("resume after recover: %v %v", resumed, err)
	}
	r.svc.Wait()
	got, _ = r.svc.Get(context.Background(), r.org, im.ID)
	if got.Status != gitimport.StatusSuccess {
		t.Fatalf("after resume: %+v", got)
	}
}

func TestImportAuditFailureDoesNotBreakIt(t *testing.T) {
	r := newRig(t)
	r.gh.Add("octo/one", gitimporttest.GitHubRepo{})
	r.mem.FailAudit = true
	if im := r.start(r.in("octo/one")); im.Status != gitimport.StatusSuccess {
		t.Fatalf("%+v", im)
	}
}

func TestImportRefusesWhenGitIsOff(t *testing.T) {
	r := newRig(t)
	r.forge.Service = gitcore.New(gitcore.Config{}, nil, nil) // not configured
	if _, _, err := r.svc.Start(context.Background(), r.in("octo/one")); !errors.Is(err, gitimport.ErrNotConfigured) {
		t.Fatalf("err: %v", err)
	}
}

func TestImportProjectCreateFailureIsReported(t *testing.T) {
	r := newRig(t)
	r.gh.Add("octo/one", gitimporttest.GitHubRepo{})
	r.proj.FailCreate = errors.New("duplicate key value violates unique constraint")
	im := r.start(r.in("octo/one"))
	if e := im.Repos[0].Error; im.Status != gitimport.StatusFailed || !strings.Contains(e, "already exists in this organization") {
		t.Fatalf("%+v", im)
	}
	var _ = domain.ErrNotFound
}
