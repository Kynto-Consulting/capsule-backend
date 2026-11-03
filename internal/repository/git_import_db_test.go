//go:build dbtest

package repository

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
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

const dbImportToken = "ghp_DBSECRETTOKENabcdefghijklmnop777"

func TestGitImportStoreDB(t *testing.T) {
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	r := NewGitImportRepository(pool, "k")
	ctx := context.Background()
	u := f.user("", time.Now())
	org, org2 := f.org(u), f.org(u)
	proj := f.project(org, "")
	now := time.Now().UTC()

	im := &gitimport.Import{ID: uuid.New(), OrgID: org, CreatedBy: &u, Source: "github", Status: gitimport.StatusQueued, Include: []string{"issues"},
		CreateProjects: true, IdemKey: "key-1", RequestHash: "h", Attempts: 1, CreatedAt: now, UpdatedAt: now,
		Repos: []gitimport.RepoState{{Name: "o/a", Slug: "a", Status: gitimport.StatusQueued}, {Name: "o/b", Slug: "b", Status: gitimport.StatusQueued}}}
	if err := r.CreateImport(ctx, im); err != nil {
		t.Fatal(err)
	}
	// idempotency key is unique per org, free in another org, optional
	dup := *im
	dup.ID = uuid.New()
	if err := r.CreateImport(ctx, &dup); !errors.Is(err, gitimport.ErrDuplicateKey) {
		t.Fatalf("duplicate key: %v", err)
	}
	dup.ID, dup.OrgID = uuid.New(), org2
	if err := r.CreateImport(ctx, &dup); err != nil {
		t.Fatalf("same key in another org: %v", err)
	}
	nokey := *im
	nokey.ID, nokey.IdemKey = uuid.New(), ""
	nokey.Repos = []gitimport.RepoState{{Name: "o/z", Slug: "z", Status: gitimport.StatusQueued}}
	nokey2 := nokey
	nokey2.ID = uuid.New()
	if err := r.CreateImport(ctx, &nokey); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateImport(ctx, &nokey2); err != nil {
		t.Fatalf("two imports without a key: %v", err)
	}
	if err := r.SetStatus(ctx, nokey.ID, gitimport.StatusSuccess, true); err != nil {
		t.Fatal(err)
	}
	if err := r.SetStatus(ctx, nokey2.ID, gitimport.StatusSuccess, true); err != nil {
		t.Fatal(err)
	}

	got, err := r.GetImport(ctx, org, im.ID)
	if err != nil || got.IdemKey != "key-1" || len(got.Repos) != 2 || got.Repos[0].Name != "o/a" || got.Include[0] != "issues" || got.CreatedBy == nil || *got.CreatedBy != u {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := r.GetImport(ctx, org2, im.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("an import is scoped to its org: %v", err)
	}
	if f, err := r.FindByIdem(ctx, org, "key-1"); err != nil || f.ID != im.ID {
		t.Fatalf("find: %+v %v", f, err)
	}
	if _, err := r.FindByIdem(ctx, org, "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("find missing: %v", err)
	}

	// busy names: queued/running of ANOTHER import
	if busy, err := r.BusySlugs(ctx, org, []string{"a", "b", "c"}, uuid.New()); err != nil || strings.Join(busy, ",") != "a,b" && strings.Join(busy, ",") != "b,a" {
		t.Fatalf("busy: %v %v", busy, err)
	}
	if busy, _ := r.BusySlugs(ctx, org, []string{"a"}, im.ID); len(busy) != 0 {
		t.Fatalf("own import is not busy: %v", busy)
	}
	if busy, _ := r.BusySlugs(ctx, org2, []string{"a"}, uuid.New()); len(busy) != 1 {
		t.Fatalf("org2 has its own copy: %v", busy)
	}

	// repo lifecycle
	rs, err := r.BeginRepo(ctx, im.ID, "o/a")
	if err != nil || rs.Status != gitimport.StatusRunning || rs.Attempts != 1 || rs.StartedAt == nil {
		t.Fatalf("begin: %+v %v", rs, err)
	}
	created := true
	if err := r.UpdateRepo(ctx, im.ID, "o/a", gitimport.RepoUpdate{Status: gitimport.StatusRunning, ProjectID: &proj, CreatedProject: &created, Warnings: []string{"w1"}}); err != nil {
		t.Fatal(err)
	}
	co := &gitimport.CodeOwnersReport{Path: ".github/CODEOWNERS", Converted: "docs/.* @a\n", Warnings: []string{"x"}}
	if err := r.UpdateRepo(ctx, im.ID, "o/a", gitimport.RepoUpdate{Status: gitimport.StatusSuccess, Warnings: []string{"w1", "w2"}, CodeOwners: co, Finished: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateRepo(ctx, im.ID, "o/b", gitimport.RepoUpdate{Status: gitimport.StatusFailed, Error: "boom", Finished: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateRepo(ctx, im.ID, "o/missing", gitimport.RepoUpdate{Status: gitimport.StatusFailed}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	got, _ = r.GetImport(ctx, org, im.ID)
	a, b := got.Repos[0], got.Repos[1]
	if a.Status != gitimport.StatusSuccess || a.ProjectID == nil || *a.ProjectID != proj || !a.CreatedProject || len(a.Warnings) != 2 || a.CodeOwners == nil ||
		a.CodeOwners.Converted != "docs/.* @a\n" || a.Error != "" || a.FinishedAt == nil {
		t.Fatalf("repo a: %+v", a)
	}
	if b.Status != gitimport.StatusFailed || b.Error != "boom" || b.ProjectID != nil || b.CodeOwners != nil || len(b.Warnings) != 0 {
		t.Fatalf("repo b: %+v", b)
	}

	// resume: only the failed repo goes back to queued
	if err := r.SetStatus(ctx, im.ID, gitimport.StatusPartial, true); err != nil {
		t.Fatal(err)
	}
	if err := r.Resume(ctx, im.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetImport(ctx, org, im.ID)
	if got.Status != gitimport.StatusQueued || got.Attempts != 2 || got.FinishedAt != nil || got.Repos[0].Status != gitimport.StatusSuccess || got.Repos[1].Status != gitimport.StatusQueued || got.Repos[1].Error != "" {
		t.Fatalf("resume: %+v", got)
	}
	if err := r.Resume(ctx, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("resume unknown: %v", err)
	}

	// interrupted: heartbeat older than the cut-off; partial when something succeeded, failed when not
	if _, err := pool.Exec(ctx, `UPDATE git_imports SET status = 'running', updated_at = now() - interval '3 hours' WHERE id = $1`, im.ID); err != nil {
		t.Fatal(err)
	}
	only := &gitimport.Import{ID: uuid.New(), OrgID: org, Source: "github", Status: gitimport.StatusRunning, CreateProjects: true, Attempts: 1, CreatedAt: now, UpdatedAt: now,
		Repos: []gitimport.RepoState{{Name: "o/q", Slug: "q", Status: gitimport.StatusRunning}}}
	if err := r.CreateImport(ctx, only); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE git_imports SET updated_at = now() - interval '3 hours' WHERE id = $1`, only.ID); err != nil {
		t.Fatal(err)
	}
	alive := &gitimport.Import{ID: uuid.New(), OrgID: org, Source: "github", Status: gitimport.StatusRunning, CreateProjects: true, Attempts: 1, CreatedAt: now, UpdatedAt: now,
		Repos: []gitimport.RepoState{{Name: "o/live", Slug: "live", Status: gitimport.StatusRunning}}}
	if err := r.CreateImport(ctx, alive); err != nil {
		t.Fatal(err)
	}
	n, err := r.FailInterrupted(ctx, time.Now().Add(-time.Hour), "interrupted")
	if err != nil || n != 2 {
		t.Fatalf("interrupted: %d %v", n, err)
	}
	g1, _ := r.GetImport(ctx, org, im.ID)
	g2, _ := r.GetImport(ctx, org, only.ID)
	g3, _ := r.GetImport(ctx, org, alive.ID)
	if g1.Status != gitimport.StatusPartial || g1.Repos[0].Status != gitimport.StatusSuccess || g1.Repos[1].Status != gitimport.StatusFailed || g1.Repos[1].Error != "interrupted" {
		t.Fatalf("partial recover: %+v", g1)
	}
	if g2.Status != gitimport.StatusFailed || g2.Repos[0].Error != "interrupted" || g2.FinishedAt == nil {
		t.Fatalf("failed recover: %+v", g2)
	}
	if g3.Status != gitimport.StatusRunning {
		t.Fatalf("a live import must be left alone: %+v", g3)
	}
	// the heartbeat keeps it alive
	if err := r.Touch(ctx, alive.ID); err != nil {
		t.Fatal(err)
	}

	// constraints
	if _, err := pool.Exec(ctx, `UPDATE git_imports SET status = 'weird' WHERE id = $1`, im.ID); err == nil {
		t.Fatal("status check constraint missing")
	}
	if _, err := pool.Exec(ctx, `UPDATE git_import_repos SET status = 'partial' WHERE import_id = $1`, im.ID); err == nil {
		t.Fatal("repo status check constraint missing")
	}
	// deleting the org removes imports and their repos; deleting a project only unlinks it
	if _, err := pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, proj); err != nil {
		t.Fatal(err)
	}
	g1, _ = r.GetImport(ctx, org, im.ID)
	if g1.Repos[0].ProjectID != nil {
		t.Fatalf("project link must be nulled: %+v", g1.Repos[0])
	}
	if _, err := pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org2); err != nil {
		t.Fatal(err)
	}
	var left int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM git_imports WHERE org_id = $1`, org2).Scan(&left)
	if left != 0 {
		t.Fatal("imports must cascade with the organization")
	}
}

func TestGitMirrorStoreDB(t *testing.T) {
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	r := NewGitImportRepository(pool, "mirror-key")
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)
	proj := f.project(org, "")

	if _, err := r.GetMirror(ctx, proj); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("none: %v", err)
	}
	secret := "ghp_DBMIRRORSECRETabcdefghijklmnop1"
	m := &gitimport.Mirror{ProjectID: proj, OrgID: org, RemoteURL: "https://github.com/a/b.git", Branches: []string{"main", "rel/*"}, Interval: "hourly", ForgejoRemoteName: "remote_mirror_1", CreatedBy: &u}
	if err := r.PutMirror(ctx, m, &secret); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetMirror(ctx, proj)
	if err != nil || !got.HasCredential || strings.Join(got.Branches, ",") != "main,rel/*" || got.Interval != "hourly" || got.ForgejoRemoteName != "remote_mirror_1" || got.LastSyncAt != nil {
		t.Fatalf("get: %+v %v", got, err)
	}
	// the credential is encrypted at rest
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT credential_enc FROM git_mirrors WHERE project_id = $1`, proj).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || bytes.Contains(raw, []byte("DBMIRRORSECRET")) {
		t.Fatalf("credential not encrypted: %q", raw)
	}
	var dump string
	if err := pool.QueryRow(ctx, `SELECT row_to_json(g)::text FROM git_mirrors g WHERE project_id = $1`, proj).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dump, "DBMIRRORSECRET") {
		t.Fatalf("credential visible in the row: %s", dump)
	}
	if c, err := r.Credential(ctx, proj); err != nil || c != secret {
		t.Fatalf("credential round trip: %q %v", c, err)
	}
	// another key cannot read it
	if _, err := NewGitImportRepository(pool, "other-key").Credential(ctx, proj); err == nil {
		t.Fatal("a different key must not decrypt")
	}

	// replace keeping the credential (nil), then removing it ("")
	m.Branches, m.ForgejoRemoteName = []string{"dev"}, "remote_mirror_2"
	if err := r.PutMirror(ctx, m, nil); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetMirror(ctx, proj)
	if !got.HasCredential || got.Branches[0] != "dev" || got.ForgejoRemoteName != "remote_mirror_2" {
		t.Fatalf("replace keeps the credential: %+v", got)
	}
	empty := ""
	if err := r.PutMirror(ctx, m, &empty); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetMirror(ctx, proj)
	if got.HasCredential {
		t.Fatalf("credential must be removed: %+v", got)
	}
	if c, _ := r.Credential(ctx, proj); c != "" {
		t.Fatalf("credential: %q", c)
	}

	// sync flag: claimed once, stale claims can be taken over
	if ok, err := r.BeginSync(ctx, proj, time.Now().Add(-time.Minute)); err != nil || !ok {
		t.Fatalf("begin: %v %v", ok, err)
	}
	if ok, _ := r.BeginSync(ctx, proj, time.Now().Add(-time.Minute)); ok {
		t.Fatal("second claim must fail")
	}
	if ok, _ := r.BeginSync(ctx, proj, time.Now().Add(time.Minute)); !ok {
		t.Fatal("a claim older than the cut-off is stale and can be taken")
	}
	if _, err := r.BeginSync(ctx, uuid.New(), time.Now()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("begin unknown: %v", err)
	}
	if err := r.EndSync(ctx, proj); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	if err := r.RecordSync(ctx, proj, &at, ""); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetMirror(ctx, proj)
	if got.LastSyncAt == nil || !got.LastSyncAt.Equal(at) || got.SyncingSince != nil {
		t.Fatalf("record: %+v", got)
	}
	if err := r.RecordSync(ctx, proj, nil, "push failed"); err != nil {
		t.Fatal(err)
	}
	// a replaced remote has never synced
	if err := r.PutMirror(ctx, m, nil); err != nil {
		t.Fatal(err)
	}
	got, _ = r.GetMirror(ctx, proj)
	if got.LastSyncAt != nil || got.LastError != "" {
		t.Fatalf("replace resets the sync state: %+v", got)
	}

	// constraints and cascade
	bad := *m
	bad.Interval = "weekly"
	if err := r.PutMirror(ctx, &bad, nil); err == nil {
		t.Fatal("interval check constraint missing")
	}
	if err := r.DeleteMirror(ctx, proj); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteMirror(ctx, proj); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if err := r.PutMirror(ctx, m, &secret); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, proj); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetMirror(ctx, proj); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("mirror must go with the project: %v", err)
	}
}

func TestGitImportAuditAndMarkReadyDB(t *testing.T) {
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	r := NewGitImportRepository(pool, "k")
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)
	proj := f.project(org, "")

	rid := uuid.New()
	for _, ip := range []string{"203.0.113.7", "", "not-an-ip"} {
		if err := r.Audit(ctx, gitimport.AuditRecord{OrgID: org, UserID: &u, Action: gitimport.AuditMirrorSet, ResourceType: "git_mirror", ResourceID: &rid, IP: ip,
			Values: map[string]any{"remote_host": "github.com", "branches": []string{"main"}, "credential_set": true}}); err != nil {
			t.Fatalf("audit ip=%q: %v", ip, err)
		}
	}
	if err := r.Audit(ctx, gitimport.AuditRecord{OrgID: org, Action: gitimport.AuditImportFinish, ResourceType: "git_import", Values: map[string]any{"status": "partial"}}); err != nil {
		t.Fatalf("audit without user and resource: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id = $1 AND action LIKE 'git.%'`, org).Scan(&n); err != nil || n != 4 {
		t.Fatalf("audit rows: %d %v", n, err)
	}
	var vals string
	if err := pool.QueryRow(ctx, `SELECT new_values::text FROM audit_logs WHERE org_id = $1 AND action = 'git.mirror.set' LIMIT 1`, org).Scan(&vals); err != nil || !strings.Contains(vals, "github.com") {
		t.Fatalf("values: %q %v", vals, err)
	}

	for i := 0; i < 2; i++ { // idempotent, and it overrides a pending provisioning state
		if err := r.MarkReady(ctx, proj); err != nil {
			t.Fatal(err)
		}
	}
	st, err := NewGitCoreRepository(pool).GetState(ctx, proj)
	if err != nil || st.Status != "ready" || st.ImportURL != "" {
		t.Fatalf("state: %+v %v", st, err)
	}
	if err := NewGitCoreRepository(pool).PutState(ctx, &domain.GitCoreState{ProjectID: proj, Status: "pending", ImportURL: "https://x/y.git", NextAttemptAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := r.MarkReady(ctx, proj); err != nil {
		t.Fatal(err)
	}
	if st, _ = NewGitCoreRepository(pool).GetState(ctx, proj); st.Status != "ready" || st.ImportURL != "" {
		t.Fatalf("ready must replace pending: %+v", st)
	}
}

// The service against REAL Postgres (projects, imports, audit, git_core_state): the token must be in
// no column of any table.
func TestGitImportServiceTokenIsNotInTheDatabaseDB(t *testing.T) {
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)

	gh := gitimporttest.NewGitHub(dbImportToken)
	defer gh.Close()
	gh.Add("octo/alpha", gitimporttest.GitHubRepo{Private: true, Files: map[string]string{"CODEOWNERS": "*.go @alice\n"}})
	gh.Add("octo/beta", gitimporttest.GitHubRepo{})
	fj := fake.New()
	defer fj.Close()
	core := gitcore.New(gitcore.Config{URL: fj.URL, Token: fake.Token, Timeout: 5 * time.Second, BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond}, nil, nil)

	repo := NewGitImportRepository(pool, "k")
	logs := &bytes.Buffer{}
	lg := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc := gitimport.New(ctx, gitimport.Config{GitHubAPI: gh.URL, RepoTimeout: time.Minute}, gitimport.Deps{
		Store: repo, Forge: core, GitHub: &gitimport.GitHub{BaseURL: gh.URL, HTTP: http.DefaultClient},
		Projects: NewProjectRepository(pool), Linker: repo, Audit: repo,
		Policy: gitsource.Policy{Lookup: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("140.82.112.3")}, nil }},
		Logger: lg,
	})
	// "gamma" does not exist: partial. Then resume with the same key.
	in := gitimport.StartInput{OrgID: org, OrgSlug: "acme", UserID: u, IP: "203.0.113.1", Token: dbImportToken,
		Repos: []string{"octo/alpha", "octo/beta", "octo/gamma"}, CreateProjects: true, IdemKey: "db-key"}
	im, _, err := svc.Start(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	svc.Wait()
	got, _ := svc.Get(ctx, org, im.ID)
	if got.Status != gitimport.StatusPartial {
		t.Fatalf("status %s: %+v", got.Status, got.Repos)
	}
	gh.Add("octo/gamma", gitimporttest.GitHubRepo{})
	if _, resumed, err := svc.Start(ctx, in); err != nil || !resumed {
		t.Fatalf("resume: %v %v", resumed, err)
	}
	svc.Wait()
	got, _ = svc.Get(ctx, org, im.ID)
	if got.Status != gitimport.StatusSuccess || got.Attempts != 2 {
		t.Fatalf("after resume: %s %d %+v", got.Status, got.Attempts, got.Repos)
	}
	var projects int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM projects WHERE org_id = $1`, org).Scan(&projects)
	var ready int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM git_core_state s JOIN projects p ON p.id = s.project_id WHERE p.org_id = $1 AND s.status = 'ready'`, org).Scan(&ready)
	if projects != 3 || ready != 3 {
		t.Fatalf("projects=%d ready=%d", projects, ready)
	}

	// search EVERY table for the token (and its distinctive part)
	rows, err := pool.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	for _, tb := range tables {
		var hits int
		q := `SELECT count(*) FROM "` + tb + `" t WHERE t::text ILIKE '%DBSECRETTOKEN%'`
		if err := pool.QueryRow(ctx, q).Scan(&hits); err != nil {
			t.Fatalf("scanning %s: %v", tb, err)
		}
		if hits != 0 {
			t.Fatalf("the GitHub token is stored in table %s", tb)
		}
	}
	if strings.Contains(logs.String(), "DBSECRETTOKEN") {
		t.Fatalf("token in logs:\n%s", logs.String())
	}
	var audits int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id = $1 AND action IN ('git.import.start', 'git.import.finish')`, org).Scan(&audits)
	if audits != 4 { // start+finish, then start (resumed)+finish
		t.Fatalf("audit rows: %d", audits)
	}
}
