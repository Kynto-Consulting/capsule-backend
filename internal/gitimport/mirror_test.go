package gitimport_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitcore/fake"
	"github.com/kynto/capsule/backend/internal/gitimport"
	"github.com/kynto/capsule/backend/internal/gitimport/gitimporttest"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

const mirrorSecret = "ghp_MIRRORSECRETabcdefghijklmnop99"

type mrig struct {
	t    *testing.T
	svc  *gitimport.MirrorService
	mem  *gitimporttest.Mem
	fj   *fake.Server
	tgt  gitimport.Target
	act  gitimport.Actor
	logs *bytes.Buffer
	vf   *verdictForge
}

type failPutStore struct {
	*gitimporttest.Mem
	fail bool
}

func (f *failPutStore) PutMirror(ctx context.Context, m *gitimport.Mirror, c *string) error {
	if f.fail {
		return errors.New("db down")
	}
	return f.Mem.PutMirror(ctx, m, c)
}

func newMRig(t *testing.T) *mrig {
	t.Helper()
	r := &mrig{t: t, mem: gitimporttest.NewMem(), fj: fake.New(), logs: &bytes.Buffer{}}
	t.Cleanup(r.fj.Close)
	r.fj.AddRepo("acme", "web")
	r.tgt = gitimport.Target{OrgID: uuid.New(), ProjectID: uuid.New(), Repo: gitcore.RepoRef{Owner: "acme", Repo: "web"}}
	r.act = gitimport.Actor{UserID: uuid.New(), IP: "198.51.100.4"}
	r.build(r.mem)
	return r
}

func (r *mrig) build(store gitimport.MirrorStore) {
	core := gitcore.New(gitcore.Config{URL: r.fj.URL, Token: fake.Token, Timeout: 5 * time.Second, BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond}, nil, nil)
	r.vf = &verdictForge{Service: core}
	r.svc = gitimport.NewMirrors(context.Background(), gitimport.Config{SyncTimeout: time.Minute}, gitimport.MirrorDeps{
		Store: store, Forge: r.vf, Policy: gitsource.Policy{Lookup: publicLookup}, Audit: r.mem,
		Logger: slog.New(slog.NewTextHandler(r.logs, nil)), PollEvery: 5 * time.Millisecond, PollTimeout: 300 * time.Millisecond,
	})
}

// verdictForge mimics real Forgejo, which only QUEUES a push and reports its outcome later through
// last_update / last_error of the push mirror (the fake never sets them).
type verdictForge struct {
	*gitcore.Service
	mu      sync.Mutex
	pushed  int
	lastErr string
	silent  bool // never reports an outcome
}

func (v *verdictForge) SyncPushMirrors(ctx context.Context, r gitcore.RepoRef) error {
	if err := v.Service.SyncPushMirrors(ctx, r); err != nil {
		return err
	}
	v.mu.Lock()
	v.pushed++
	v.mu.Unlock()
	return nil
}

func (v *verdictForge) ListPushMirrors(ctx context.Context, r gitcore.RepoRef) ([]gitcore.PushMirror, error) {
	l, err := v.Service.ListPushMirrors(ctx, r)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.pushed > 0 && !v.silent {
		for i := range l {
			l[i].LastUpdate = time.Date(2026, 11, 2, 12, 0, v.pushed, 0, time.UTC)
			l[i].LastError = v.lastErr
		}
	}
	return l, err
}

func secret(s string) *string { return &s }

func (r *mrig) put(in gitimport.MirrorInput) (*gitimport.MirrorView, error) {
	return r.svc.Put(context.Background(), r.tgt, r.act, in)
}

// pushMirrorBodies returns the bodies of the POST push_mirrors calls the fake Forgejo saw.
func (r *mrig) pushMirrorBodies() []map[string]any {
	var out []map[string]any
	for _, q := range r.fj.Requests() {
		if q.Method == "POST" && strings.HasSuffix(q.Path, "/repos/acme/web/push_mirrors") {
			var m map[string]any
			_ = json.Unmarshal([]byte(q.Body), &m)
			out = append(out, m)
		}
	}
	return out
}

func TestMirrorPutStoresEncryptedCredentialAndAudits(t *testing.T) {
	r := newMRig(t)
	v, err := r.put(gitimport.MirrorInput{RemoteURL: "https://github.com/acme/web-backup.git", Credential: secret(mirrorSecret), Branches: []string{"main", "release/*"}, Interval: gitimport.IntervalHourly})
	if err != nil {
		t.Fatal(err)
	}
	if v.RemoteURL != "https://github.com/acme/web-backup.git" || !v.HasCredential || v.Interval != "hourly" || v.RemoteHost != "github.com" ||
		strings.Join(v.Branches, ",") != "main,release/*" || !strings.Contains(v.Notice, "github.com") || !strings.Contains(v.Notice, "tercero") {
		t.Fatalf("view: %+v", v)
	}
	bodies := r.pushMirrorBodies()
	if len(bodies) != 1 {
		t.Fatalf("forgejo calls: %v", bodies)
	}
	b := bodies[0]
	if b["remote_address"] != "https://github.com/acme/web-backup.git" || b["remote_username"] != gitimport.MirrorUsername || b["remote_password"] != mirrorSecret ||
		b["branch_filter"] != "main,release/*" || b["interval"] != "1h0m0s" || b["sync_on_commit"] != false {
		t.Fatalf("spec sent to forgejo: %v", b)
	}
	// stored encrypted: not in the dump, not in logs, not in the audit row; decrypts back
	d := r.mem.Dump()
	if strings.Contains(d, mirrorSecret) || strings.Contains(d, "MIRRORSECRET") || strings.Contains(r.logs.String(), "MIRRORSECRET") {
		t.Fatal("credential stored or logged in the clear")
	}
	if got, _ := r.mem.Credential(context.Background(), r.tgt.ProjectID); got != mirrorSecret {
		t.Fatalf("credential does not round-trip: %q", got)
	}
	if acts := r.mem.AuditActions(); len(acts) != 1 || acts[0] != gitimport.AuditMirrorSet {
		t.Fatalf("audit: %v", acts)
	}
	a := r.mem.Audits[0]
	if a.UserID == nil || *a.UserID != r.act.UserID || a.IP != "198.51.100.4" || a.OrgID != r.tgt.OrgID || a.Values["credential_set"] != true {
		t.Fatalf("audit row: %+v", a)
	}
	if j, _ := json.Marshal(a.Values); strings.Contains(string(j), "MIRRORSECRET") {
		t.Fatal("secret in audit values")
	}
}

func TestMirrorDefaultsAndIntervals(t *testing.T) {
	r := newMRig(t)
	// no branches: only the default branch of the repository leaves, never "all"
	v, err := r.put(gitimport.MirrorInput{RemoteURL: "https://github.com/acme/x.git"})
	if err != nil || strings.Join(v.Branches, ",") != "main" || v.Interval != gitimport.IntervalDaily {
		t.Fatalf("defaults: %+v %v", v, err)
	}
	if b := r.pushMirrorBodies()[0]; b["branch_filter"] != "main" || b["interval"] != "24h0m0s" || b["sync_on_commit"] != false {
		t.Fatalf("daily: %v", b)
	}
	if _, err := r.put(gitimport.MirrorInput{RemoteURL: "https://github.com/acme/x.git", Interval: gitimport.IntervalOnPush}); err != nil {
		t.Fatal(err)
	}
	if b := r.pushMirrorBodies()[1]; b["interval"] != "0" || b["sync_on_commit"] != true {
		t.Fatalf("on_push: %v", b)
	}
}

func TestMirrorReplaceReusesCredentialAndRemovesOldRemote(t *testing.T) {
	r := newMRig(t)
	if _, err := r.put(gitimport.MirrorInput{RemoteURL: "https://github.com/acme/a.git", Credential: secret(mirrorSecret)}); err != nil {
		t.Fatal(err)
	}
	// change the branches only: the stored credential is reused, and Forgejo keeps ONE mirror
	v, err := r.put(gitimport.MirrorInput{RemoteURL: "https://github.com/acme/a.git", Branches: []string{"dev"}})
	if err != nil || !v.HasCredential {
		t.Fatalf("replace: %+v %v", v, err)
	}
	bodies := r.pushMirrorBodies()
	if len(bodies) != 2 || bodies[1]["remote_password"] != mirrorSecret || bodies[1]["branch_filter"] != "dev" {
		t.Fatalf("second add: %v", bodies)
	}
	list, _ := gitcore.New(gitcore.Config{URL: r.fj.URL, Token: fake.Token}, nil, nil).ListPushMirrors(context.Background(), r.tgt.Repo)
	if len(list) != 1 {
		t.Fatalf("forgejo must keep one mirror: %+v", list)
	}
	// an explicit empty credential removes it
	v, err = r.put(gitimport.MirrorInput{RemoteURL: "https://github.com/acme/a.git", Credential: secret("")})
	if err != nil || v.HasCredential {
		t.Fatalf("remove credential: %+v %v", v, err)
	}
	if got, _ := r.mem.Credential(context.Background(), r.tgt.ProjectID); got != "" {
		t.Fatalf("credential must be gone: %q", got)
	}
}

func TestMirrorValidation(t *testing.T) {
	r := newMRig(t)
	bad := map[string]gitimport.MirrorInput{
		"http":         {RemoteURL: "http://github.com/a/b.git"},
		"ssh":          {RemoteURL: "ssh://git@github.com/a/b.git"},
		"userinfo":     {RemoteURL: "https://u:p@github.com/a/b.git"},
		"query":        {RemoteURL: "https://github.com/a/b.git?x=1"},
		"empty":        {RemoteURL: ""},
		"ip literal":   {RemoteURL: "https://127.0.0.1/a/b.git"},
		"private ip":   {RemoteURL: "https://10.1.2.3/a/b.git"},
		"metadata":     {RemoteURL: "https://169.254.169.254/latest"},
		"bad branch":   {RemoteURL: "https://github.com/a/b.git", Branches: []string{"ok", "bad branch"}},
		"brace":        {RemoteURL: "https://github.com/a/b.git", Branches: []string{"{main,dev}"}},
		"dotdot":       {RemoteURL: "https://github.com/a/b.git", Branches: []string{"a/../b"}},
		"flag":         {RemoteURL: "https://github.com/a/b.git", Branches: []string{"--force"}},
		"bad interval": {RemoteURL: "https://github.com/a/b.git", Interval: "weekly"},
	}
	for name, in := range bad {
		if _, err := r.put(in); !errors.Is(err, gitimport.ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	many := make([]string, 21)
	for i := range many {
		many[i] = "b" + string(rune('a'+i))
	}
	if _, err := r.put(gitimport.MirrorInput{RemoteURL: "https://github.com/a/b.git", Branches: many}); !errors.Is(err, gitimport.ErrValidation) {
		t.Errorf("21 branches: %v", err)
	}
	if n := len(r.pushMirrorBodies()); n != 0 {
		t.Fatalf("nothing may reach Forgejo on invalid input: %d calls", n)
	}
	if len(r.mem.Audits) != 0 {
		t.Fatalf("no audit for refused requests: %v", r.mem.AuditActions())
	}
}

func TestMirrorSSRFResolvesAndRefusesPrivateHosts(t *testing.T) {
	r := newMRig(t)
	core := gitcore.New(gitcore.Config{URL: r.fj.URL, Token: fake.Token}, nil, nil)
	svc := gitimport.NewMirrors(context.Background(), gitimport.Config{}, gitimport.MirrorDeps{Store: r.mem, Forge: core,
		Policy: gitsource.Policy{Lookup: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("192.168.1.10")}, nil }}})
	if _, err := svc.Put(context.Background(), r.tgt, r.act, gitimport.MirrorInput{RemoteURL: "https://git.evil.example/a/b.git"}); !errors.Is(err, gitimport.ErrValidation) {
		t.Fatalf("host resolving to a private address: %v", err)
	}
	// allow-list
	svc = gitimport.NewMirrors(context.Background(), gitimport.Config{}, gitimport.MirrorDeps{Store: r.mem, Forge: core,
		Policy: gitsource.Policy{AllowedHosts: []string{"github.com"}, Lookup: publicLookup}})
	if _, err := svc.Put(context.Background(), r.tgt, r.act, gitimport.MirrorInput{RemoteURL: "https://gitlab.com/a/b.git"}); !errors.Is(err, gitimport.ErrValidation) {
		t.Fatalf("host outside the allow-list: %v", err)
	}
	if n := len(r.pushMirrorBodies()); n != 0 {
		t.Fatal("must not reach Forgejo")
	}
}

func TestMirrorForgejo401MeansBadAddressNotBrokenService(t *testing.T) {
	r := newMRig(t)
	r.fj.Fail = func(q fake.Request) int {
		if q.Method == "POST" && strings.HasSuffix(q.Path, "/push_mirrors") {
			return 401 // what Forgejo 15.0.11 answers for a private/loopback remote
		}
		return 0
	}
	if _, err := r.put(gitimport.MirrorInput{RemoteURL: "https://github.com/a/b.git"}); !errors.Is(err, gitimport.ErrValidation) || !strings.Contains(err.Error(), "private and loopback") {
		t.Fatalf("err: %v", err)
	}
	if _, err := r.svc.Get(context.Background(), r.tgt); !errors.Is(err, gitimport.ErrNotFound) {
		t.Fatalf("nothing may be stored: %v", err)
	}
}

func TestMirrorPutRollsBackForgejoWhenTheDatabaseFails(t *testing.T) {
	r := newMRig(t)
	st := &failPutStore{Mem: r.mem, fail: true}
	r.build(st)
	if _, err := r.put(gitimport.MirrorInput{RemoteURL: "https://github.com/a/b.git", Credential: secret(mirrorSecret)}); err == nil {
		t.Fatal("expected the store error")
	}
	list, _ := gitcore.New(gitcore.Config{URL: r.fj.URL, Token: fake.Token}, nil, nil).ListPushMirrors(context.Background(), r.tgt.Repo)
	if len(list) != 0 {
		t.Fatalf("orphan remote left in Forgejo: %+v", list)
	}
	if strings.Contains(r.logs.String(), "MIRRORSECRET") {
		t.Fatal("secret logged")
	}
}

func TestMirrorGetRefreshesFromForgejoAndDetectsMissingRemote(t *testing.T) {
	r := newMRig(t)
	if _, err := r.svc.Get(context.Background(), r.tgt); !errors.Is(err, gitimport.ErrNotFound) {
		t.Fatalf("no mirror yet: %v", err)
	}
	if _, err := r.put(gitimport.MirrorInput{RemoteURL: "https://github.com/a/b.git"}); err != nil {
		t.Fatal(err)
	}
	v, err := r.svc.Get(context.Background(), r.tgt)
	if err != nil || v.LastError != "" || v.LastSyncAt != nil {
		t.Fatalf("get: %+v %v", v, err)
	}
	// somebody removed the remote in Forgejo: Capsule says so instead of pretending
	core := gitcore.New(gitcore.Config{URL: r.fj.URL, Token: fake.Token}, nil, nil)
	list, _ := core.ListPushMirrors(context.Background(), r.tgt.Repo)
	if err := core.DeletePushMirror(context.Background(), r.tgt.Repo, list[0].RemoteName); err != nil {
		t.Fatal(err)
	}
	v, err = r.svc.Get(context.Background(), r.tgt)
	if err != nil || !strings.Contains(v.LastError, "missing in the Git service") {
		t.Fatalf("missing remote: %+v %v", v, err)
	}
}

func TestMirrorDelete(t *testing.T) {
	r := newMRig(t)
	if err := r.svc.Delete(context.Background(), r.tgt, r.act); !errors.Is(err, gitimport.ErrNotFound) {
		t.Fatalf("delete without mirror: %v", err)
	}
	if _, err := r.put(gitimport.MirrorInput{RemoteURL: "https://github.com/a/b.git", Credential: secret(mirrorSecret)}); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.Delete(context.Background(), r.tgt, r.act); err != nil {
		t.Fatal(err)
	}
	list, _ := gitcore.New(gitcore.Config{URL: r.fj.URL, Token: fake.Token}, nil, nil).ListPushMirrors(context.Background(), r.tgt.Repo)
	if len(list) != 0 {
		t.Fatalf("forgejo still has it: %+v", list)
	}
	if got, _ := r.mem.Credential(context.Background(), r.tgt.ProjectID); got != "" {
		t.Fatal("credential must be deleted with the mirror")
	}
	acts := r.mem.AuditActions()
	if len(acts) != 2 || acts[1] != gitimport.AuditMirrorDelete {
		t.Fatalf("audit: %v", acts)
	}
}

func TestMirrorSyncRunsInBackgroundRecordsOutcomeAndRefusesOverlap(t *testing.T) {
	r := newMRig(t)
	if _, err := r.svc.Sync(context.Background(), r.tgt, r.act); !errors.Is(err, gitimport.ErrNotFound) {
		t.Fatalf("sync without mirror: %v", err)
	}
	if _, err := r.put(gitimport.MirrorInput{RemoteURL: "https://github.com/a/b.git", Credential: secret(mirrorSecret)}); err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	r.fj.Delay = func(q fake.Request) time.Duration {
		if strings.HasSuffix(q.Path, "/push_mirrors-sync") {
			<-gate
		}
		return 0
	}
	job, err := r.svc.Sync(context.Background(), r.tgt, r.act)
	if err != nil || job.ID == uuid.Nil || job.Status != gitimport.StatusQueued {
		t.Fatalf("job: %+v %v", job, err)
	}
	if v, _ := r.svc.Get(context.Background(), r.tgt); !v.Syncing {
		t.Fatal("the view must say it is syncing")
	}
	if _, err := r.svc.Sync(context.Background(), r.tgt, r.act); !errors.Is(err, gitimport.ErrBusy) {
		t.Fatalf("overlap: %v", err)
	}
	close(gate)
	r.svc.Wait()
	v, _ := r.svc.Get(context.Background(), r.tgt)
	if v.Syncing || v.LastSyncAt == nil || v.LastError != "" {
		t.Fatalf("after sync: %+v", v)
	}
	if acts := r.mem.AuditActions(); acts[len(acts)-1] != gitimport.AuditMirrorSync {
		t.Fatalf("audit: %v", acts)
	}

	// a failing push is recorded, scrubbed, and the flag is released
	r.fj.Delay = nil
	r.fj.Fail = func(q fake.Request) int {
		if strings.HasSuffix(q.Path, "/push_mirrors-sync") {
			return 422
		}
		return 0
	}
	if _, err := r.svc.Sync(context.Background(), r.tgt, r.act); err != nil {
		t.Fatal(err)
	}
	r.svc.Wait()
	v, _ = r.svc.Get(context.Background(), r.tgt)
	if v.Syncing || v.LastError == "" {
		t.Fatalf("failure not recorded: %+v", v)
	}
	if strings.Contains(r.mem.Dump(), "MIRRORSECRET") {
		t.Fatal("secret persisted")
	}
	if _, err := r.svc.Sync(context.Background(), r.tgt, r.act); err != nil {
		t.Fatalf("the flag must be released after a failure: %v", err)
	}
	r.svc.Wait()
}

func TestMirrorOffWhenGitIsOff(t *testing.T) {
	r := newMRig(t)
	svc := gitimport.NewMirrors(context.Background(), gitimport.Config{}, gitimport.MirrorDeps{Store: r.mem, Forge: gitcore.New(gitcore.Config{}, nil, nil),
		Policy: gitsource.Policy{Lookup: publicLookup}})
	if _, err := svc.Put(context.Background(), r.tgt, r.act, gitimport.MirrorInput{RemoteURL: "https://github.com/a/b.git"}); !errors.Is(err, gitimport.ErrNotConfigured) {
		t.Fatalf("put: %v", err)
	}
	if _, err := svc.Sync(context.Background(), r.tgt, r.act); !errors.Is(err, gitimport.ErrNotConfigured) {
		t.Fatalf("sync: %v", err)
	}
}

func TestMirrorSyncRecordsForgejosVerdictOfTheQueuedPush(t *testing.T) {
	r := newMRig(t)
	if _, err := r.put(gitimport.MirrorInput{RemoteURL: "https://github.com/a/b.git", Credential: secret(mirrorSecret)}); err != nil {
		t.Fatal(err)
	}
	// the push fails remotely and Forgejo's own message even echoes a token: it is stored scrubbed
	r.vf.lastErr = "remote: Permission denied for https://x-access-token:" + mirrorSecret + "@github.com/a/b.git"
	if _, err := r.svc.Sync(context.Background(), r.tgt, r.act); err != nil {
		t.Fatal(err)
	}
	r.svc.Wait()
	v, _ := r.svc.Get(context.Background(), r.tgt)
	if v.LastSyncAt == nil || !strings.Contains(v.LastError, "Permission denied") || strings.Contains(v.LastError, "MIRRORSECRET") {
		t.Fatalf("verdict: %+v", v)
	}
	if strings.Contains(r.mem.Dump(), "MIRRORSECRET") || strings.Contains(r.logs.String(), "MIRRORSECRET") {
		t.Fatal("secret persisted or logged")
	}

	// Forgejo never reports an outcome within the wait: no invented success, the flag is released
	r2 := newMRig(t)
	r2.vf.silent = true
	if _, err := r2.put(gitimport.MirrorInput{RemoteURL: "https://github.com/a/b.git"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.svc.Sync(context.Background(), r2.tgt, r2.act); err != nil {
		t.Fatal(err)
	}
	r2.svc.Wait()
	v, _ = r2.svc.Get(context.Background(), r2.tgt)
	if v.Syncing || v.LastSyncAt != nil || v.LastError != "" {
		t.Fatalf("no verdict must leave the state alone: %+v", v)
	}
}
