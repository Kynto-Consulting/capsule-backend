package service

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

// ---- env layering with the parent-project layer --------------------------------

func TestEnvPrecedenceWithParentLayer(t *testing.T) {
	org := map[string]EnvEntry{"A": {"org-a", "both"}, "B": {"org-b", "both"}, "C": {"org-c", "both"}, "D": {"org-d", "both"}}
	parent := map[string]EnvEntry{"B": {"parent-b", "both"}, "C": {"parent-c", "both"}, "D": {"parent-d", "runtime"}, "E": {"parent-e", "both"}}
	proj := map[string]EnvEntry{"C": {"child-c", "both"}, "F": {"child-f", "both"}}
	deploy := map[string]EnvEntry{"D": {"deploy-d", "both"}}
	got := FilterEnvByScope(MergeEnvLayers(org, parent, proj, deploy), "runtime")
	want := []KV{{"A", "org-a"}, {"B", "parent-b"}, {"C", "child-c"}, {"D", "deploy-d"}, {"E", "parent-e"}, {"F", "child-f"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	// A normal (non-preview) project has an empty parent layer: unchanged behaviour.
	got = FilterEnvByScope(MergeEnvLayers(org, map[string]EnvEntry{}, proj, deploy), "runtime")
	want = []KV{{"A", "org-a"}, {"B", "org-b"}, {"C", "child-c"}, {"D", "deploy-d"}, {"F", "child-f"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestCoalescer(t *testing.T) {
	var c Coalescer
	a := c.Begin("k")
	if !a() {
		t.Fatal("first must be current")
	}
	b := c.Begin("k")
	other := c.Begin("other")
	if a() || !b() || !other() {
		t.Fatal("newest per key wins, other keys unaffected")
	}
}

// ---- fakes ---------------------------------------------------------------------------

type fakeStore struct {
	mu          sync.Mutex
	link        *domain.ProjectGit
	previews    map[string]*domain.Preview // key parent:pr
	projects    map[uuid.UUID]*domain.Project
	deps        []*domain.Deployment
	depStatus   map[uuid.UUID]string
	destroyed   []uuid.UUID
	superseded  [][2]uuid.UUID
	commentSets map[uuid.UUID]int64
	seq         int
}

func newStore(link *domain.ProjectGit) *fakeStore {
	return &fakeStore{link: link, previews: map[string]*domain.Preview{}, projects: map[uuid.UUID]*domain.Project{},
		depStatus: map[uuid.UUID]string{}, commentSets: map[uuid.UUID]int64{}}
}

func pkey(parent uuid.UUID, pr int) string { return fmt.Sprintf("%s:%d", parent, pr) }

// domain.GitRepository
func (f *fakeStore) Get(_ context.Context, id uuid.UUID) (*domain.ProjectGit, error) {
	if f.link != nil && f.link.ProjectID == id {
		return f.link, nil
	}
	return nil, domain.ErrNotFound
}
func (f *fakeStore) Upsert(context.Context, *domain.ProjectGit) (*domain.ProjectGit, error) {
	return nil, errors.New("unused")
}
func (f *fakeStore) Delete(context.Context, uuid.UUID) error                      { return nil }
func (f *fakeStore) RotateWebhookSecret(context.Context, uuid.UUID, string) error { return nil }
func (f *fakeStore) GetPreview(_ context.Context, parent uuid.UUID, pr int) (*domain.Preview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.previews[pkey(parent, pr)]; ok {
		return p, nil
	}
	return nil, domain.ErrNotFound
}
func (f *fakeStore) CreatePreview(_ context.Context, parent *domain.Project, pr int, slug string, exp time.Time) (*domain.Preview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	id := uuid.New()
	f.projects[id] = &domain.Project{ID: id, OrgID: parent.OrgID, Slug: slug, DeployType: parent.DeployType, Runtime: parent.Runtime}
	p := &domain.Preview{ProjectID: id, ParentProjectID: parent.ID, OrgID: parent.OrgID, Slug: slug, PR: pr,
		ExpiresAt: &exp, CreatedAt: time.Unix(int64(1000+f.seq), 0)}
	f.previews[pkey(parent.ID, pr)] = p
	return p, nil
}
func (f *fakeStore) TouchPreview(_ context.Context, id uuid.UUID, exp time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.previews {
		if p.ProjectID == id {
			p.ExpiresAt = &exp
		}
	}
	return nil
}
func (f *fakeStore) SetPreviewComment(_ context.Context, id uuid.UUID, c int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commentSets[id] = c
	return nil
}
func (f *fakeStore) ListPreviews(_ context.Context, parent uuid.UUID) ([]*domain.Preview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*domain.Preview
	for _, p := range f.previews {
		if p.ParentProjectID == parent {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (f *fakeStore) ListExpiredPreviews(_ context.Context, now time.Time) ([]*domain.Preview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*domain.Preview
	for _, p := range f.previews {
		if p.ExpiresAt != nil && p.ExpiresAt.Before(now) {
			out = append(out, p)
		}
	}
	return out, nil
}
func (f *fakeStore) DestroyPreview(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, p := range f.previews {
		if p.ProjectID == id {
			delete(f.previews, k)
			f.destroyed = append(f.destroyed, id)
			return nil
		}
	}
	return domain.ErrNotFound
}
func (f *fakeStore) IsPreview(context.Context, uuid.UUID) (bool, error) { return false, nil }
func (f *fakeStore) CancelSupersededGit(_ context.Context, projectID, keep uuid.UUID) ([]uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []uuid.UUID
	for _, d := range f.deps {
		if d.ProjectID == projectID && d.ID != keep && d.Trigger == "git" && f.depStatus[d.ID] == "queued" {
			f.depStatus[d.ID] = "cancelled"
			ids = append(ids, d.ID)
			f.superseded = append(f.superseded, [2]uuid.UUID{d.ID, keep})
		}
	}
	return ids, nil
}
func (f *fakeStore) DeploymentStatus(_ context.Context, id uuid.UUID) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.depStatus[id], nil
}

// domain.ProjectRepository (only GetByID is used)
func (f *fakeStore) PGetByID(id uuid.UUID) (*domain.Project, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.projects[id]; ok {
		return p, nil
	}
	return nil, domain.ErrNotFound
}

type fakeProjects struct {
	domain.ProjectRepository
	s *fakeStore
}

func (p fakeProjects) GetByID(_ context.Context, id uuid.UUID) (*domain.Project, error) {
	return p.s.PGetByID(id)
}

type fakeDeployments struct {
	domain.DeploymentRepository
	s *fakeStore
}

func (d fakeDeployments) Create(_ context.Context, dep *domain.Deployment) (*domain.Deployment, error) {
	d.s.mu.Lock()
	defer d.s.mu.Unlock()
	c := *dep
	c.ID = uuid.New()
	c.Status = "queued"
	d.s.deps = append(d.s.deps, &c)
	d.s.depStatus[c.ID] = "queued"
	return &c, nil
}
func (d fakeDeployments) GetLatestSuccessfulByProject(context.Context, uuid.UUID) (*domain.Deployment, error) {
	return nil, domain.ErrNotFound
}
func (d fakeDeployments) GetByID(_ context.Context, id uuid.UUID) (*domain.Deployment, error) {
	return &domain.Deployment{ID: id}, nil
}
func (d fakeDeployments) AppendLog(context.Context, *domain.BuildLog) error { return nil }

type fakeFetcher struct {
	mu       sync.Mutex
	calls    []string // branch names
	gate     chan struct{}
	gateOnce map[string]chan struct{}
	err      error
	n        int
}

func (f *fakeFetcher) Fetch(_ context.Context, repoURL, branch string, _ gitsource.Auth) (*gitsource.Snapshot, error) {
	f.mu.Lock()
	f.calls = append(f.calls, branch)
	f.n++
	n := f.n
	gate := f.gateOnce[fmt.Sprint(n)]
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if f.err != nil {
		return nil, f.err
	}
	dir, _ := os.MkdirTemp("", "fake-snap-*")
	tp := filepath.Join(dir, "s.tar.gz")
	_ = os.WriteFile(tp, []byte("x"), 0o600)
	// Snapshot.dir is private to gitsource; leaking a tiny temp dir in tests is fine.
	return &gitsource.Snapshot{TarPath: tp, SHA: fmt.Sprintf("%040x", n), Message: "msg\nmore"}, nil
}
func (f *fakeFetcher) ListBranches(context.Context, string, gitsource.Auth) ([]string, error) {
	return nil, nil
}

type fakeUploader struct {
	mu   sync.Mutex
	keys []string
}

func (u *fakeUploader) Upload(_ context.Context, key, _ string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.keys = append(u.keys, key)
	return nil
}

type statusCall struct{ SHA, State, Target string }
type fakeProvider struct {
	mu       sync.Mutex
	statuses []statusCall
	comments []string
	nextID   int64
	updates  int
}

func (p *fakeProvider) SetStatus(_ context.Context, sha, state, target, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.statuses = append(p.statuses, statusCall{sha, state, target})
	return nil
}
func (p *fakeProvider) UpsertComment(_ context.Context, _ int, existing int64, body string) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.comments = append(p.comments, body)
	if existing > 0 {
		p.updates++
		return existing, nil
	}
	p.nextID++
	return 500 + p.nextID, nil
}
func (p *fakeProvider) states() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var s []string
	for _, c := range p.statuses {
		s = append(s, c.State)
	}
	return s
}

type fakeRuntime struct {
	mu      sync.Mutex
	removed []uuid.UUID
}

func (r *fakeRuntime) Remove(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removed = append(r.removed, id)
	return nil
}

type rig struct {
	svc    *GitService
	store  *fakeStore
	fetch  *fakeFetcher
	up     *fakeUploader
	prov   *fakeProvider
	rt     *fakeRuntime
	parent *domain.Project
	link   *domain.ProjectGit
	now    time.Time
	nowMu  sync.Mutex
}

func newRig(t *testing.T, mutate func(*domain.ProjectGit)) *rig {
	t.Helper()
	parent := &domain.Project{ID: uuid.New(), OrgID: uuid.New(), Slug: "shop", DeployType: "docker", Runtime: "node"}
	link := &domain.ProjectGit{ProjectID: parent.ID, Provider: "forgejo", RepoURL: "https://git.example.com/acme/shop.git",
		Branch: "main", AuthKind: "token", Credential: "tok", AutoDeploy: true, PreviewEnabled: true, PreviewMax: 3, PreviewTTLHours: 24}
	if mutate != nil {
		mutate(link)
	}
	st := newStore(link)
	st.projects[parent.ID] = parent
	r := &rig{store: st, fetch: &fakeFetcher{gateOnce: map[string]chan struct{}{}}, up: &fakeUploader{}, prov: &fakeProvider{},
		rt: &fakeRuntime{}, parent: parent, link: link, now: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
	r.svc = &GitService{
		Git: st, Projects: fakeProjects{s: st}, Deployments: fakeDeployments{s: st},
		Uploader: r.up, Fetcher: r.fetch, Runtime: r.rt,
		Provider:      func(*domain.ProjectGit) (StatusClient, error) { return r.prov, nil },
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		AppsDomain:    "apps.example.com",
		Now:           func() time.Time { r.nowMu.Lock(); defer r.nowMu.Unlock(); return r.now },
		WatchInterval: 5 * time.Millisecond, WatchTimeout: 400 * time.Millisecond,
	}
	return r
}

func (r *rig) advance(d time.Duration) { r.nowMu.Lock(); r.now = r.now.Add(d); r.nowMu.Unlock() }

func pushEv(branch string) *gitsource.Event {
	return &gitsource.Event{Kind: gitsource.EventPush, Branch: branch, Actor: "ana", Message: "hello", CommitURL: "https://git.example.com/acme/shop/commit/abc"}
}

func prEv(action string, pr int, branch string) *gitsource.Event {
	return &gitsource.Event{Kind: gitsource.EventPullRequest, Action: action, PR: pr, Branch: branch, Actor: "bob",
		PRURL: fmt.Sprintf("https://git.example.com/acme/shop/pulls/%d", pr)}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func (r *rig) setStatus(id uuid.UUID, st string) {
	r.store.mu.Lock()
	r.store.depStatus[id] = st
	r.store.mu.Unlock()
}
func (r *rig) depCount() int { r.store.mu.Lock(); defer r.store.mu.Unlock(); return len(r.store.deps) }

// ---- auto-deploy --------------------------------------------------------------------

func TestPushCreatesGitDeploymentAndReportsStatus(t *testing.T) {
	r := newRig(t, nil)
	if err := r.svc.HandlePush(context.Background(), r.link, r.parent, pushEv("main")); err != nil {
		t.Fatal(err)
	}
	if r.depCount() != 1 {
		t.Fatalf("want 1 deployment, got %d", r.depCount())
	}
	d := r.store.deps[0]
	if d.Trigger != "git" || d.SourceKey == nil || !strings.HasPrefix(*d.SourceKey, "deployments/"+r.parent.ID.String()+"/") || !strings.HasSuffix(*d.SourceKey, ".tar.gz") {
		t.Fatalf("bad deployment %+v", d)
	}
	wantSHA := fmt.Sprintf("%040x", 1)
	for k, v := range map[string]string{"source": "git", "ref": "main", "sha": wantSHA, "actor": "ana", "commit_message": "msg",
		"repo": r.link.RepoURL, "run_url": "https://git.example.com/acme/shop/commit/abc"} {
		if d.Meta[k] != v {
			t.Errorf("meta[%s]=%q want %q", k, d.Meta[k], v)
		}
	}
	if d.GitSHA != wantSHA || d.BuildStrategy != "docker" {
		t.Fatalf("sha/strategy: %+v", d)
	}
	if len(r.up.keys) != 1 || r.up.keys[0] != *d.SourceKey {
		t.Fatalf("upload keys %v", r.up.keys)
	}
	// the clone received the configured branch and credentials never end up in meta
	for _, v := range d.Meta {
		if strings.Contains(v, "tok") && v != "git" {
			t.Fatalf("credential leaked in meta: %q", v)
		}
	}

	// the deployment later succeeds: commit status goes pending -> success
	r.setStatus(d.ID, "success")
	waitFor(t, "success status", func() bool { return strings.Join(r.prov.states(), ",") == "pending,success" })
	r.svc.Wait()
	if got := r.prov.statuses[1]; got.Target != "https://shop.apps.example.com" || got.SHA != wantSHA {
		t.Fatalf("status target %+v", got)
	}
}

func TestPushIgnoredWhenNotConfigured(t *testing.T) {
	r := newRig(t, nil)
	ctx := context.Background()
	_ = r.svc.HandlePush(ctx, r.link, r.parent, pushEv("other-branch"))
	del := pushEv("main")
	del.Deleted = true
	_ = r.svc.HandlePush(ctx, r.link, r.parent, del)
	r.link.AutoDeploy = false
	_ = r.svc.HandlePush(ctx, r.link, r.parent, pushEv("main"))
	if r.depCount() != 0 || len(r.fetch.calls) != 0 {
		t.Fatalf("nothing must be cloned: deps=%d clones=%v", r.depCount(), r.fetch.calls)
	}
}

func TestPushFetchFailureReportsFailureAndNoDeployment(t *testing.T) {
	r := newRig(t, nil)
	r.fetch.err = errors.New("clone exploded")
	err := r.svc.HandlePush(context.Background(), r.link, r.parent, pushEv("main"))
	if err == nil || r.depCount() != 0 {
		t.Fatalf("err=%v deps=%d", err, r.depCount())
	}
}

func TestCoalescingNewestPushWins(t *testing.T) {
	r := newRig(t, nil)
	gate := make(chan struct{})
	r.fetch.gateOnce["1"] = gate // first clone blocks until released
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = r.svc.HandlePush(ctx, r.link, r.parent, pushEv("main")) }()
	waitFor(t, "first clone to start", func() bool { r.fetch.mu.Lock(); defer r.fetch.mu.Unlock(); return r.fetch.n >= 1 })

	if err := r.svc.HandlePush(ctx, r.link, r.parent, pushEv("main")); err != nil { // second push completes first
		t.Fatal(err)
	}
	close(gate)
	wg.Wait()

	if r.depCount() != 1 {
		t.Fatalf("the superseded push must not create a deployment, got %d", r.depCount())
	}
	if r.store.deps[0].GitSHA != fmt.Sprintf("%040x", 2) {
		t.Fatalf("the newest push must win, got sha %s", r.store.deps[0].GitSHA)
	}
}

func TestQueuedGitDeploymentIsCancelledByNewer(t *testing.T) {
	r := newRig(t, nil)
	ctx := context.Background()
	if err := r.svc.HandlePush(ctx, r.link, r.parent, pushEv("main")); err != nil {
		t.Fatal(err)
	}
	first := r.store.deps[0].ID
	if err := r.svc.HandlePush(ctx, r.link, r.parent, pushEv("main")); err != nil {
		t.Fatal(err)
	}
	if r.depCount() != 2 {
		t.Fatal("two deployments expected")
	}
	st, _ := r.store.DeploymentStatus(ctx, first)
	if st != "cancelled" {
		t.Fatalf("older queued git deployment must be cancelled, status=%s", st)
	}
	second := r.store.deps[1].ID
	if st, _ := r.store.DeploymentStatus(ctx, second); st != "queued" {
		t.Fatalf("newest must stay queued, status=%s", st)
	}
	r.setStatus(second, "failed")
	r.svc.Wait()
}

// ---- previews --------------------------------------------------------------------------

func TestPreviewLifecycleCreateUpdateClose(t *testing.T) {
	r := newRig(t, nil)
	ctx := context.Background()

	if err := r.svc.HandlePullRequest(ctx, r.link, r.parent, prEv("opened", 7, "feat/x")); err != nil {
		t.Fatal(err)
	}
	pv, err := r.store.GetPreview(ctx, r.parent.ID, 7)
	if err != nil || pv.Slug != "shop-pr-7" {
		t.Fatalf("preview %+v %v", pv, err)
	}
	child := r.store.projects[pv.ProjectID]
	if child == nil || child.DeployType != "docker" || child.Runtime != "node" {
		t.Fatalf("child project must inherit deploy settings: %+v", child)
	}
	wantExp := r.now.Add(24 * time.Hour)
	if !pv.ExpiresAt.Equal(wantExp) {
		t.Fatalf("expires %v want %v", pv.ExpiresAt, wantExp)
	}
	if r.depCount() != 1 || r.store.deps[0].ProjectID != pv.ProjectID || r.store.deps[0].Meta["pr"] != "7" || r.store.deps[0].Meta["ref"] != "feat/x" {
		t.Fatalf("deployment for the preview project expected: %+v", r.store.deps)
	}
	if len(r.prov.comments) != 1 || !strings.Contains(r.prov.comments[0], "building") || !strings.Contains(r.prov.comments[0], "https://shop-pr-7.apps.example.com") {
		t.Fatalf("comments %q", r.prov.comments)
	}
	if r.store.commentSets[pv.ProjectID] == 0 {
		t.Fatal("comment id must be stored to edit it later")
	}

	// synchronize: same preview reused, TTL renewed, comment EDITED (not duplicated)
	r.advance(2 * time.Hour)
	if err := r.svc.HandlePullRequest(ctx, r.link, r.parent, prEv("synchronize", 7, "feat/x")); err != nil {
		t.Fatal(err)
	}
	if n := len(r.store.previews); n != 1 {
		t.Fatalf("no second preview project expected, got %d", n)
	}
	if !pv.ExpiresAt.Equal(r.now.Add(24 * time.Hour)) {
		t.Fatal("TTL must be renewed on update")
	}
	if r.prov.updates < 1 {
		t.Fatal("existing comment must be updated in place")
	}
	// older queued deployment of that preview superseded by the new one
	if st, _ := r.store.DeploymentStatus(ctx, r.store.deps[0].ID); st != "cancelled" {
		t.Fatalf("old preview build must be cancelled, got %s", st)
	}

	// success updates the same comment with the URL
	r.setStatus(r.store.deps[1].ID, "success")
	waitFor(t, "success comment", func() bool {
		r.prov.mu.Lock()
		defer r.prov.mu.Unlock()
		return strings.Contains(r.prov.comments[len(r.prov.comments)-1], "preview ready")
	})
	r.svc.Wait()

	// close: runtime + project destroyed
	if err := r.svc.HandlePullRequest(ctx, r.link, r.parent, prEv("closed", 7, "feat/x")); err != nil {
		t.Fatal(err)
	}
	if len(r.rt.removed) != 1 || r.rt.removed[0] != pv.ProjectID {
		t.Fatalf("runtime must be removed: %v", r.rt.removed)
	}
	if len(r.store.destroyed) != 1 || len(r.store.previews) != 0 {
		t.Fatal("preview project must be destroyed")
	}
	if last := r.prov.comments[len(r.prov.comments)-1]; !strings.Contains(last, "removed") {
		t.Fatalf("final comment %q", last)
	}
	// closing an unknown PR is a no-op
	if err := r.svc.HandlePullRequest(ctx, r.link, r.parent, prEv("closed", 99, "x")); err != nil {
		t.Fatal(err)
	}
}

func TestPreviewDisabledForkAndBadBranch(t *testing.T) {
	r := newRig(t, func(g *domain.ProjectGit) { g.PreviewEnabled = false })
	ctx := context.Background()
	_ = r.svc.HandlePullRequest(ctx, r.link, r.parent, prEv("opened", 1, "feat"))
	if len(r.store.previews) != 0 {
		t.Fatal("previews disabled: nothing may be created")
	}
	r.link.PreviewEnabled = true
	fork := prEv("opened", 2, "feat")
	fork.HeadFork = true
	_ = r.svc.HandlePullRequest(ctx, r.link, r.parent, fork)
	if len(r.store.previews) != 0 || r.depCount() != 0 {
		t.Fatal("fork pull requests must never be built")
	}
	if err := r.svc.HandlePullRequest(ctx, r.link, r.parent, prEv("opened", 3, "--upload-pack=x")); err == nil {
		t.Fatal("option-like branch must be refused")
	}
	if len(r.fetch.calls) != 0 {
		t.Fatal("no clone for refused events")
	}
}

func TestPreviewMaxRemovesOldest(t *testing.T) {
	r := newRig(t, nil) // PreviewMax = 3
	ctx := context.Background()
	for pr := 1; pr <= 3; pr++ {
		if err := r.svc.HandlePullRequest(ctx, r.link, r.parent, prEv("opened", pr, fmt.Sprintf("b%d", pr))); err != nil {
			t.Fatal(err)
		}
	}
	oldest, _ := r.store.GetPreview(ctx, r.parent.ID, 1)
	oldestID := oldest.ProjectID
	if err := r.svc.HandlePullRequest(ctx, r.link, r.parent, prEv("opened", 4, "b4")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.store.GetPreview(ctx, r.parent.ID, 1); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("oldest preview must be removed when preview_max is exceeded")
	}
	if len(r.store.previews) != 3 {
		t.Fatalf("exactly preview_max previews expected, got %d", len(r.store.previews))
	}
	if len(r.rt.removed) != 1 || r.rt.removed[0] != oldestID {
		t.Fatalf("oldest runtime removed: %v", r.rt.removed)
	}
	r.svc.Wait()
}

func TestReapExpiredPreviews(t *testing.T) {
	r := newRig(t, nil)
	ctx := context.Background()
	for pr := 1; pr <= 2; pr++ {
		_ = r.svc.HandlePullRequest(ctx, r.link, r.parent, prEv("opened", pr, fmt.Sprintf("b%d", pr)))
	}
	// make PR 1 expire, keep PR 2 alive
	p1, _ := r.store.GetPreview(ctx, r.parent.ID, 1)
	past := r.now.Add(-time.Minute)
	p1.ExpiresAt = &past
	n, err := r.svc.ReapExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("reaped %d %v", n, err)
	}
	if _, err := r.store.GetPreview(ctx, r.parent.ID, 1); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("expired preview must be gone")
	}
	if _, err := r.store.GetPreview(ctx, r.parent.ID, 2); err != nil {
		t.Fatal("live preview must stay")
	}
	// after the TTL elapses for everyone
	r.advance(48 * time.Hour)
	if n, _ := r.svc.ReapExpired(ctx); n != 1 || len(r.store.previews) != 0 {
		t.Fatalf("second reap n=%d left=%d", n, len(r.store.previews))
	}
	r.svc.Wait()
}

// ---- packaging layout is what the worker's extractor understands ----------------------

func TestSnapshotTarballIsExtractableByWorker(t *testing.T) {
	src := t.TempDir()
	_ = os.WriteFile(filepath.Join(src, "Dockerfile"), []byte("FROM scratch\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(src, "pkg"), 0o755)
	_ = os.WriteFile(filepath.Join(src, "pkg", "a.txt"), []byte("hi"), 0o644)
	dst := filepath.Join(t.TempDir(), "o.tar.gz")
	if _, err := gitsource.PackageTarGz(src, dst, 1<<20); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(dst)
	defer f.Close()
	out := t.TempDir()
	if err := extractTarGz(f, out); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(out, "pkg", "a.txt")); err != nil || string(b) != "hi" {
		t.Fatalf("extracted content: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(out, "Dockerfile")); err != nil {
		t.Fatal(err)
	}
	// sanity: it is a real gzip tar
	f.Seek(0, io.SeekStart)
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tar.NewReader(gz).Next(); err != nil {
		t.Fatal(err)
	}
}
