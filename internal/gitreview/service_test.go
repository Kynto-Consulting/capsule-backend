package gitreview

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

// ---- doubles ---------------------------------------------------------------------------------

type stubCore struct {
	gitcore.Core // nil: any method the tests did not stub panics, which flags a missed dependency
	mu           sync.Mutex
	pull         gitcore.Pull
	rule         *gitcore.ProtectionSpec
	checks       []gitcore.Check
	reviews      []gitcore.Review
	files        map[string]string // CODEOWNERS contents by path
	diff         []string
	mergeErr     []error // consumed one per MergePull call
	merges       []gitcore.MergeRequest
	mergeActors  []string
	setChecks    []gitcore.CheckInput
	removed      []string
	dismissed    []int64
	requested    []string
	mergeDelay   time.Duration
	onMerge      func() // runs under the lock, before the scripted error: a push racing the merge
}

func (c *stubCore) GetPull(context.Context, gitcore.RepoRef, int) (*gitcore.Pull, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pull
	return &p, nil
}
func (c *stubCore) GetRepo(context.Context, gitcore.RepoRef) (*gitcore.Repository, error) {
	return &gitcore.Repository{DefaultBranch: "main", AllowedMergeStyles: []string{"merge", "squash"}}, nil
}
func (c *stubCore) ListProtections(context.Context, gitcore.RepoRef) ([]gitcore.Protection, error) {
	if c.rule == nil {
		return nil, nil
	}
	r := *c.rule
	r.RuleName = "main"
	return []gitcore.Protection{{ProtectionSpec: r}}, nil
}
func (c *stubCore) ListChecks(context.Context, gitcore.RepoRef, string) (*gitcore.CheckSet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cs := &gitcore.CheckSet{State: gitcore.CheckSuccess, Items: append([]gitcore.Check(nil), c.checks...)}
	for _, k := range c.checks {
		if k.State == gitcore.CheckPending {
			cs.State = gitcore.CheckPending
		}
	}
	return cs, nil
}
func (c *stubCore) ListReviews(context.Context, gitcore.RepoRef, int) ([]gitcore.Review, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]gitcore.Review(nil), c.reviews...), nil
}
func (c *stubCore) PullDiff(context.Context, gitcore.RepoRef, int) (*gitcore.Diff, error) {
	d := &gitcore.Diff{}
	for _, f := range c.diff {
		d.Files = append(d.Files, gitcore.FileDiff{Path: f})
	}
	return d, nil
}
func (c *stubCore) GetFile(_ context.Context, _ gitcore.RepoRef, _, path string) (*gitcore.Blob, error) {
	if s, ok := c.files[path]; ok {
		return &gitcore.Blob{Path: path, Content: s, Encoding: "utf-8"}, nil
	}
	return nil, gitcore.ErrNotFound
}
func (c *stubCore) MergePull(ctx context.Context, _ gitcore.RepoRef, _ int, in gitcore.MergeRequest) (*gitcore.MergeResult, error) {
	if c.mergeDelay > 0 {
		time.Sleep(c.mergeDelay)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.merges = append(c.merges, in)
	c.mergeActors = append(c.mergeActors, gitcore.ActorFrom(ctx))
	if c.onMerge != nil {
		c.onMerge()
	}
	if len(c.mergeErr) > 0 {
		e := c.mergeErr[0]
		c.mergeErr = c.mergeErr[1:]
		if e != nil {
			return nil, e
		}
	}
	c.pull.Merged, c.pull.State = true, gitcore.PullMerged
	return &gitcore.MergeResult{Merged: true}, nil
}
func (c *stubCore) SetCheck(_ context.Context, _ gitcore.RepoRef, _ string, in gitcore.CheckInput) (*gitcore.Check, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setChecks = append(c.setChecks, in)
	c.checks = append(c.checks, gitcore.Check{Context: in.Context, State: in.State, Description: in.Description})
	return &gitcore.Check{}, nil
}
func (c *stubCore) RequestReviewers(_ context.Context, _ gitcore.RepoRef, _ int, users, teams []string) error {
	c.requested = append(append(c.requested, users...), teams...)
	return nil
}
func (c *stubCore) PatchPull(_ context.Context, _ gitcore.RepoRef, _ int, in gitcore.PullPatch) (*gitcore.Pull, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if in.Draft != nil {
		c.pull.Draft = *in.Draft
	}
	p := c.pull
	return &p, nil
}
func (c *stubCore) ListPulls(context.Context, gitcore.RepoRef, gitcore.PullQuery, gitcore.Page) (gitcore.List[gitcore.Pull], error) {
	return gitcore.List[gitcore.Pull]{Items: []gitcore.Pull{c.pull}}, nil
}
func (c *stubCore) DismissReview(_ context.Context, _ gitcore.RepoRef, _ int, id int64, _ string) (*gitcore.Review, error) {
	c.dismissed = append(c.dismissed, id)
	return &gitcore.Review{ID: id, State: "dismissed"}, nil
}
func (c *stubCore) RemoveReviewRequest(_ context.Context, _ gitcore.RepoRef, _ int, users, _ []string) error {
	c.removed = append(c.removed, users...)
	return nil
}

type fixedProjects struct{ p Project }

func (f fixedProjects) ByID(context.Context, uuid.UUID) (*Project, error) { p := f.p; return &p, nil }
func (f fixedProjects) ByRef(context.Context, gitcore.RepoRef) (*Project, error) {
	p := f.p
	return &p, nil
}

type fixedRoster []Member

func (f fixedRoster) Members(context.Context, Project) ([]Member, error) { return f, nil }

type authzFn func(uuid.UUID) bool

func (f authzFn) Can(_ context.Context, u, _, _ uuid.UUID, _ authz.Action) (bool, error) {
	return f(u), nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

const sha1h = "1111111111111111111111111111111111111111"
const sha2h = "2222222222222222222222222222222222222222"

type rig struct {
	core  *stubCore
	svc   *Service
	store *MemStore
	proj  Project
	clk   *clock
	alice Member
	bob   Member
	carol Member
	eve   Member
}

func newRig(t *testing.T) *rig {
	t.Helper()
	proj := Project{ID: uuid.New(), OrgID: uuid.New(), Ref: gitcore.RepoRef{Owner: "acme", Repo: "web"}}
	mk := func(login string, role authz.Role) Member {
		return Member{UserID: uuid.New(), Login: login, Role: role}
	}
	r := &rig{proj: proj, clk: &clock{t: time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)},
		alice: mk("alice", authz.RoleAdmin), bob: mk("bob", authz.RoleDeployer), carol: mk("carol", authz.RoleDeployer), eve: mk("eve", authz.RoleViewer)}
	r.core = &stubCore{pull: gitcore.Pull{Number: 7, State: gitcore.PullOpen, Head: "feat", Base: "main", HeadSHA: sha1h, Mergeable: true,
		Author: gitcore.Person{Login: "carol"}}, files: map[string]string{}}
	r.store = NewMemStore()
	r.store.Now = r.clk.now
	r.svc = New(r.core, fixedProjects{proj}, fixedRoster{r.alice, r.bob, r.carol, r.eve}, r.store, Config{}, nil)
	r.svc.Now = r.clk.now
	r.svc.Publisher = gitevents.Discard
	return r
}

func (r *rig) enable(t *testing.T) {
	t.Helper()
	if _, _, err := r.svc.EnableAutoMerge(context.Background(), r.proj, Actor{UserID: r.bob.UserID, Login: "bob"}, 7, MergeInput{Style: gitcore.MergeSquash}); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) row(t *testing.T) *AutoMerge {
	t.Helper()
	a, err := r.store.Get(context.Background(), r.proj.ID, 7)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// ---- ComputeStatus ---------------------------------------------------------------------------

func TestComputeStatusTable(t *testing.T) {
	rule := &gitcore.ProtectionSpec{RequiredApprovals: 2, BlockOnOfficialReviewRequest: true, DismissStaleApprovals: true}
	owners := Parse("CODEOWNERS", []byte(`^api/ @bob @ghost`+"\n"+`^web/ @carol`+"\n"+`^docs/ @eve`))
	p := Project{ID: uuid.New(), Ref: gitcore.RepoRef{Owner: "acme", Repo: "web"}}
	roster := []Member{{Login: "alice", Role: authz.RoleAdmin}, {Login: "bob", Role: authz.RoleDeployer}, {Login: "carol", Role: authz.RoleDeployer}, {Login: "eve", Role: authz.RoleViewer}}
	rawAll := []string{"@bob", "@ghost", "@carol", "@eve"}
	resolved := ResolveOwners(rawAll, p, roster)
	if resolved["@ghost"].Status != OwnerUnknownUser || resolved["@eve"].Status != OwnerNoReview || resolved["@bob"].Status != OwnerOK {
		t.Fatalf("resolve: %+v", resolved)
	}
	rv := func(id int64, login, state string, stale bool) gitcore.Review {
		return gitcore.Review{ID: id, State: state, Author: gitcore.Person{Login: login}, Stale: stale, Official: true}
	}
	base := gitcore.Pull{Author: gitcore.Person{Login: "carol"}, Reviewers: []gitcore.Person{{Login: "alice"}, {Login: "bob"}}}
	cases := []struct {
		name        string
		reviews     []gitcore.Review
		files       []string
		approvals   int
		pending     []string
		changes     []string
		stale       []string
		ownerPend   []string
		unsatisfied bool
	}{
		{"nothing yet", nil, []string{"api/x.go"}, 0, []string{"alice", "bob"}, []string{}, []string{}, []string{"bob"}, true},
		{"owner approved", []gitcore.Review{rv(1, "bob", "approved", false)}, []string{"api/x.go"}, 1, []string{"alice"}, []string{}, []string{}, []string{}, false},
		{"owner approval stale is dropped by the rule", []gitcore.Review{rv(1, "bob", "approved", true)}, []string{"api/x.go"}, 1, []string{"alice"}, []string{}, []string{"bob"}, []string{"bob"}, true},
		{"later changes request wins", []gitcore.Review{rv(1, "bob", "approved", false), rv(2, "bob", "changes_requested", false)}, []string{"api/x.go"}, 0, []string{"alice"}, []string{"bob"}, []string{}, []string{"bob"}, true},
		{"author is the only owner of web/", nil, []string{"web/a.js"}, 0, []string{"alice", "bob"}, []string{}, []string{}, []string{}, true},
		{"owner without review role and unknown owner are ignored", nil, []string{"docs/a.md"}, 0, []string{"alice", "bob"}, []string{}, []string{}, []string{}, false},
		{"unowned file needs nothing", nil, []string{"misc/a"}, 0, []string{"alice", "bob"}, []string{}, []string{}, []string{}, false},
	}
	for _, c := range cases {
		pl := base
		st := ComputeStatus(StatusInput{Pull: pl, Reviews: c.reviews, Rule: rule, Owners: owners, Files: c.files, Resolved: resolved})
		if st.Approvals != c.approvals || !reflect.DeepEqual(st.Pending, c.pending) || !reflect.DeepEqual(st.ChangesRequestedBy, c.changes) ||
			!reflect.DeepEqual(st.StaleApprovals, c.stale) || !reflect.DeepEqual(st.CodeOwnerPending, c.ownerPend) || st.Unsatisfied() != c.unsatisfied {
			t.Errorf("%s: %+v", c.name, st)
		}
		if st.RequiredApprovals != 2 || !st.CodeOwnerRequired {
			t.Errorf("%s: required fields %+v", c.name, st)
		}
	}
	// without the rule flag there are no owner groups
	st := ComputeStatus(StatusInput{Pull: base, Rule: &gitcore.ProtectionSpec{}, Owners: owners, Files: []string{"api/x"}, Resolved: resolved})
	if st.CodeOwnerRequired || len(st.CodeOwnerGroups) != 0 {
		t.Fatalf("flag off: %+v", st)
	}
}

func TestResolveOwnersTeams(t *testing.T) {
	p := Project{Ref: gitcore.RepoRef{Owner: "acme", Repo: "web"}}
	roster := []Member{{Login: "bob", Role: authz.RoleDeployer}, {Login: "eve", Role: authz.RoleViewer}}
	got := ResolveOwners([]string{"@acme/web-deployer", "@acme/web-viewer", "@acme/other", "@other/web-deployer"}, p, roster)
	want := map[string]string{"@acme/web-deployer": OwnerOK, "@acme/web-viewer": OwnerNoReview, "@acme/other": OwnerUnknownTeam, "@other/web-deployer": OwnerUnknownTeam}
	for k, v := range want {
		if got[k].Status != v {
			t.Errorf("%s: %s want %s", k, got[k].Status, v)
		}
	}
}

// ---- blocker and policy ----------------------------------------------------------------------

func TestBlockerSourceAndPolicy(t *testing.T) {
	r := newRig(t)
	r.core.rule = &gitcore.ProtectionSpec{BlockOnOfficialReviewRequest: true}
	r.core.files["CODEOWNERS"] = "^api/ @bob\n"
	r.core.diff = []string{"api/main.go"}
	ctx := context.Background()
	pr := r.core.pull
	bl, err := r.svc.BlockerSource(ctx, r.proj.Ref, pr)
	if err != nil || len(bl) != 1 || bl[0].Code != "CODEOWNER_REQUIRED" || !strings.Contains(bl[0].Message, "@bob") {
		t.Fatalf("blockers %+v %v", bl, err)
	}
	if err := r.svc.RefreshPolicy(ctx, r.proj, pr); err != nil {
		t.Fatal(err)
	}
	if n := len(r.core.setChecks); n != 1 || r.core.setChecks[0].State != gitcore.CheckPending || r.core.setChecks[0].Context != PolicyContext {
		t.Fatalf("policy checks: %+v", r.core.setChecks)
	}
	// same state again: no new status (this is what keeps the status-event loop from spinning)
	_ = r.svc.RefreshPolicy(ctx, r.proj, pr)
	if len(r.core.setChecks) != 1 {
		t.Fatalf("policy was republished: %+v", r.core.setChecks)
	}
	r.core.reviews = []gitcore.Review{{ID: 1, State: "approved", Author: gitcore.Person{Login: "bob"}}}
	r.svc.owners = nil // drop the CODEOWNERS cache; reviews are never cached
	bl, _ = r.svc.BlockerSource(ctx, r.proj.Ref, pr)
	if len(bl) != 0 {
		t.Fatalf("approved by owner but blocked: %+v", bl)
	}
	_ = r.svc.RefreshPolicy(ctx, r.proj, pr)
	if last := r.core.setChecks[len(r.core.setChecks)-1]; last.State != gitcore.CheckSuccess {
		t.Fatalf("policy after approval: %+v", last)
	}
	// draft blocks through the policy check
	pr.Draft = true
	if st, _ := PolicyState(pr, nil); st != gitcore.CheckPending {
		t.Fatal("draft must be pending")
	}
	// no CODEOWNERS file: nothing to enforce
	r2 := newRig(t)
	r2.core.rule = &gitcore.ProtectionSpec{BlockOnOfficialReviewRequest: true}
	if bl, err := r2.svc.BlockerSource(ctx, r2.proj.Ref, r2.core.pull); err != nil || len(bl) != 0 {
		t.Fatalf("no CODEOWNERS: %+v %v", bl, err)
	}
}

func TestCodeownersView(t *testing.T) {
	r := newRig(t)
	r.core.files[".gitea/CODEOWNERS"] = "^api/ @bob @ghost\n*.js @alice\n"
	doc, err := r.svc.CodeownersView(context.Background(), r.proj, "")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Path != ".gitea/CODEOWNERS" || len(doc.Rules) != 1 || len(doc.Rules[0].ResolvedUsers) != 1 || doc.Rules[0].ResolvedUsers[0].Login != "bob" {
		t.Fatalf("doc %+v", doc)
	}
	w := strings.Join(doc.Warnings, "|")
	if !strings.Contains(w, "@ghost") || !strings.Contains(w, "expresion regular invalida") {
		t.Fatalf("warnings %v", doc.Warnings)
	}
	empty, err := newRig(t).svc.CodeownersView(context.Background(), r.proj, "main")
	if err != nil || len(empty.Rules) != 0 || empty.Warnings == nil {
		t.Fatalf("no file: %+v %v", empty, err)
	}
}

// ---- auto-merge ------------------------------------------------------------------------------

func TestAutoMergeWaitsThenMergesWithHeadSHA(t *testing.T) {
	r := newRig(t)
	r.core.checks = []gitcore.Check{{Context: "ci", State: gitcore.CheckPending}}
	r.core.rule = &gitcore.ProtectionSpec{EnableStatusCheck: true, StatusCheckContexts: []string{"ci"}}
	r.enable(t)
	if len(r.core.merges) != 0 || r.row(t).State != StateArmed {
		t.Fatalf("must wait: merges=%d state=%s", len(r.core.merges), r.row(t).State)
	}
	r.core.checks = []gitcore.Check{{Context: "ci", State: gitcore.CheckSuccess}}
	// the status event wakes the worker
	_ = r.svc.Handle(context.Background(), gitevents.Event{ProjectID: r.proj.ID, Name: gitevents.CheckCompleted, Data: map[string]any{"sha": sha1h, "context": "ci"}})
	if len(r.core.merges) != 1 {
		t.Fatalf("merges: %d", len(r.core.merges))
	}
	m := r.core.merges[0]
	if m.HeadSHA != sha1h || m.Style != gitcore.MergeSquash || r.core.mergeActors[0] != "bob" {
		t.Fatalf("merge request %+v actor %v", m, r.core.mergeActors)
	}
	if r.row(t).State != StateMerged {
		t.Fatalf("state %s", r.row(t).State)
	}
	// a replayed event is a no-op
	_ = r.svc.Handle(context.Background(), gitevents.Event{ProjectID: r.proj.ID, Name: gitevents.CheckCompleted, Data: map[string]any{"sha": sha1h}})
	if len(r.core.merges) != 1 {
		t.Fatal("double merge")
	}
}

func TestAutoMergeDoubleTriggerMergesOnce(t *testing.T) {
	r := newRig(t)
	r.core.checks = []gitcore.Check{{Context: "ci", State: gitcore.CheckPending}}
	r.core.rule = &gitcore.ProtectionSpec{EnableStatusCheck: true, StatusCheckContexts: []string{"ci"}}
	r.enable(t)
	r.core.checks = []gitcore.Check{{Context: "ci", State: gitcore.CheckSuccess}}
	r.core.mergeDelay = 50 * time.Millisecond
	var wg sync.WaitGroup
	var merged, busy int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, err := r.svc.Attempt(context.Background(), r.proj, 7)
			if err != nil {
				t.Error(err)
			}
			switch o {
			case OutcomeMerged:
				atomic.AddInt32(&merged, 1)
			case OutcomeBusy:
				atomic.AddInt32(&busy, 1)
			}
		}()
	}
	wg.Wait()
	if len(r.core.merges) != 1 || merged < 1 {
		t.Fatalf("merges=%d merged=%d busy=%d", len(r.core.merges), merged, busy)
	}
}

func TestAutoMergeHeadChangedCancelsAndEnableChecksHead(t *testing.T) {
	r := newRig(t)
	r.core.checks = []gitcore.Check{{Context: "ci", State: gitcore.CheckPending}}
	r.core.rule = &gitcore.ProtectionSpec{EnableStatusCheck: true, StatusCheckContexts: []string{"ci"}}
	r.enable(t)
	r.core.pull.HeadSHA = sha2h // somebody pushed
	r.core.checks = []gitcore.Check{{Context: "ci", State: gitcore.CheckSuccess}}
	o, err := r.svc.Attempt(context.Background(), r.proj, 7)
	if err != nil || o != OutcomeCancelled || len(r.core.merges) != 0 {
		t.Fatalf("outcome %s err %v merges %d", o, err, len(r.core.merges))
	}
	if a := r.row(t); a.State != StateCancelled || a.Reason != "head_changed" {
		t.Fatalf("row %+v", a)
	}
	// enabling with a stale head_sha is refused (HTTP 409)
	_, _, err = r.svc.EnableAutoMerge(context.Background(), r.proj, Actor{UserID: r.bob.UserID, Login: "bob"}, 7, MergeInput{Style: gitcore.MergeCommit, HeadSHA: sha1h})
	if !errors.Is(err, ErrHeadChanged) {
		t.Fatalf("want ErrHeadChanged, got %v", err)
	}
}

func TestAutoMergeForgejoLockedAndHeadMovedDuringMerge(t *testing.T) {
	r := newRig(t)
	r.enable(t) // nothing blocks: first attempt happens inside enable
	// first attempt merged already; re-arm to test failures
	r.core.pull.Merged, r.core.pull.State = false, gitcore.PullOpen
	r.core.mergeErr = []error{&gitcore.Error{Code: gitcore.CodeConflict, Status: 423, Message: "locked", Retry: true}}
	r.enable(t)
	a := r.row(t)
	if a.State != StateArmed || a.Attempts != 0 || !a.NextAttemptAt.After(r.clk.now()) {
		t.Fatalf("423 must reschedule without counting a failure: %+v", a)
	}
	r.clk.add(10 * time.Second)
	if n := r.svc.Sweep(context.Background()); n != 1 {
		t.Fatalf("sweep handled %d", n)
	}
	if r.row(t).State != StateMerged {
		t.Fatalf("after retry: %+v", r.row(t))
	}
	// 409 because the head moved between the read and the merge
	r2 := newRig(t)
	r2.core.checks = []gitcore.Check{{Context: "ci", State: gitcore.CheckPending}}
	r2.core.rule = &gitcore.ProtectionSpec{EnableStatusCheck: true, StatusCheckContexts: []string{"ci"}}
	r2.enable(t)
	r2.core.checks = []gitcore.Check{{Context: "ci", State: gitcore.CheckSuccess}}
	r2.core.mergeErr = []error{&gitcore.Error{Code: gitcore.CodeConflict, Status: 409, Message: "head moved"}}
	r2.core.onMerge = func() { r2.core.pull.HeadSHA = sha2h }
	o, err := r2.svc.Attempt(context.Background(), r2.proj, 7)
	if err != nil || o != OutcomeCancelled || r2.row(t).Reason != "head_changed" {
		t.Fatalf("outcome %s err %v row %+v", o, err, r2.row(t))
	}
}

func TestAutoMergeRoleLostAndFailuresGiveUp(t *testing.T) {
	r := newRig(t)
	r.core.checks = []gitcore.Check{{Context: "ci", State: gitcore.CheckPending}}
	r.core.rule = &gitcore.ProtectionSpec{EnableStatusCheck: true, StatusCheckContexts: []string{"ci"}}
	r.svc.Authz = authzFn(func(uuid.UUID) bool { return true })
	r.enable(t)
	r.core.checks = []gitcore.Check{{Context: "ci", State: gitcore.CheckSuccess}}
	r.svc.Authz = authzFn(func(uuid.UUID) bool { return false })
	o, _ := r.svc.Attempt(context.Background(), r.proj, 7)
	if o != OutcomeCancelled || r.row(t).Reason != "requester_lost_access" || len(r.core.merges) != 0 {
		t.Fatalf("role lost: %s %+v", o, r.row(t))
	}
	// repeated protected-branch failures end in cancellation, not an endless loop
	r3 := newRig(t)
	r3.svc.Cfg.MaxAttempts = 3
	r3.core.mergeErr = []error{&gitcore.Error{Code: gitcore.CodeForbidden, Message: "protected"}, &gitcore.Error{Code: gitcore.CodeForbidden, Message: "protected"}, &gitcore.Error{Code: gitcore.CodeForbidden, Message: "protected"}}
	r3.enable(t)
	for i := 0; i < 3 && r3.row(t).Active(); i++ {
		r3.clk.add(2 * time.Minute)
		r3.svc.Sweep(context.Background())
	}
	if a := r3.row(t); a.State != StateCancelled || a.Reason != "too_many_failures" {
		t.Fatalf("row %+v", a)
	}
}

func TestAutoMergeEnableRules(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.core.pull.Draft = true
	if _, _, err := r.svc.EnableAutoMerge(ctx, r.proj, Actor{}, 7, MergeInput{Style: gitcore.MergeSquash}); !errors.Is(err, ErrDraft) {
		t.Fatalf("draft: %v", err)
	}
	r.core.pull.Draft = false
	var ve *ValidationError
	if _, _, err := r.svc.EnableAutoMerge(ctx, r.proj, Actor{}, 7, MergeInput{Style: "octopus"}); !errors.As(err, &ve) {
		t.Fatalf("style: %v", err)
	}
	if _, _, err := r.svc.EnableAutoMerge(ctx, r.proj, Actor{}, 7, MergeInput{Style: gitcore.MergeRebase}); !errors.As(err, &ve) {
		t.Fatalf("style not allowed by the repo: %v", err)
	}
	r.core.pull.State = gitcore.PullClosed
	if _, _, err := r.svc.EnableAutoMerge(ctx, r.proj, Actor{}, 7, MergeInput{Style: gitcore.MergeSquash}); !errors.Is(err, ErrNotOpen) {
		t.Fatalf("closed: %v", err)
	}
	// disable is idempotent
	if err := r.svc.DisableAutoMerge(ctx, r.proj, 7); err != nil {
		t.Fatal(err)
	}
	r2 := newRig(t)
	r2.core.checks = []gitcore.Check{{Context: "ci", State: gitcore.CheckPending}}
	r2.core.rule = &gitcore.ProtectionSpec{EnableStatusCheck: true, StatusCheckContexts: []string{"ci"}}
	r2.enable(t)
	if r2.svc.Active(ctx, r2.proj.ID, 7) == nil {
		t.Fatal("must be active")
	}
	for i := 0; i < 2; i++ {
		if err := r2.svc.DisableAutoMerge(ctx, r2.proj, 7); err != nil {
			t.Fatal(err)
		}
	}
	if r2.svc.Active(ctx, r2.proj.ID, 7) != nil {
		t.Fatal("must be inactive")
	}
}

func TestHandleIgnoresOutOfOrderAndClosedEvents(t *testing.T) {
	r := newRig(t)
	r.core.checks = []gitcore.Check{{Context: "ci", State: gitcore.CheckPending}}
	r.core.rule = &gitcore.ProtectionSpec{EnableStatusCheck: true, StatusCheckContexts: []string{"ci"}}
	r.enable(t)
	ctx := context.Background()
	// a stale "success" event arrives while the truth is still pending: nothing may be merged
	_ = r.svc.Handle(ctx, gitevents.Event{ProjectID: r.proj.ID, Name: gitevents.CheckCompleted, Data: map[string]any{"sha": sha1h, "state": "success"}})
	_ = r.svc.Handle(ctx, gitevents.Event{ProjectID: r.proj.ID, Name: gitevents.PRReviewSubmitted, Data: map[string]any{"pr": float64(7)}})
	if len(r.core.merges) != 0 {
		t.Fatal("merged on a stale event")
	}
	// events of other heads or unknown names do nothing
	_ = r.svc.Handle(ctx, gitevents.Event{ProjectID: r.proj.ID, Name: gitevents.CheckCompleted, Data: map[string]any{"sha": sha2h}})
	_ = r.svc.Handle(ctx, gitevents.Event{ProjectID: r.proj.ID, Name: gitevents.GitPush})
	// the policy check was published on the PR events
	if len(r.core.setChecks) == 0 || r.core.setChecks[0].Context != PolicyContext {
		t.Fatalf("policy not published: %+v", r.core.setChecks)
	}
	// closing the PR disarms
	_ = r.svc.Handle(ctx, gitevents.Event{ProjectID: r.proj.ID, Name: gitevents.PRClosed, Data: map[string]any{"pr": 7}})
	if r.row(t).State != StateCancelled {
		t.Fatalf("state %s", r.row(t).State)
	}
}

// ---- actions ---------------------------------------------------------------------------------

func TestRequestReviewersValidation(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	var ve *ValidationError
	for _, c := range []struct{ users, teams []string }{
		{[]string{"ghost"}, nil},
		{[]string{"eve"}, nil},   // viewer cannot review
		{[]string{"carol"}, nil}, // author
		{nil, []string{"web-viewer"}},
		{nil, []string{"someone-else"}},
		{nil, nil},
	} {
		if _, err := r.svc.RequestReviewers(ctx, r.proj, 7, c.users, c.teams); !errors.As(err, &ve) {
			t.Errorf("%v: want validation error, got %v", c, err)
		}
	}
	if _, err := r.svc.RequestReviewers(ctx, r.proj, 7, []string{"Bob", "bob", "alice"}, []string{"web-deployer"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.core.requested, []string{"bob", "alice", "web-deployer"}) {
		t.Fatalf("requested %v", r.core.requested)
	}
}

type memDismissals struct{ got []Dismissal }

func (m *memDismissals) Record(_ context.Context, d Dismissal) error {
	m.got = append(m.got, d)
	return nil
}
func (m *memDismissals) List(context.Context, uuid.UUID, int) ([]Dismissal, error) {
	return m.got, nil
}

func TestMarkReadyAndDismiss(t *testing.T) {
	r := newRig(t)
	dl := &memDismissals{}
	r.svc.Dismissals = dl
	ctx := context.Background()
	r.core.pull.Draft = true
	pr, err := r.svc.MarkReady(ctx, r.proj, 7)
	if err != nil || pr.Draft {
		t.Fatalf("ready: %+v %v", pr, err)
	}
	if _, err := r.svc.MarkReady(ctx, r.proj, 7); err != nil { // idempotent
		t.Fatal(err)
	}
	r.core.reviews = []gitcore.Review{
		{ID: 1, State: "approved", Author: gitcore.Person{Login: "bob"}},
		{ID: 2, State: "commented", Author: gitcore.Person{Login: "bob"}},
	}
	if _, err := r.svc.DismissReview(ctx, r.proj, 7, 1, Actor{Login: "alice"}, "ok"); err == nil {
		t.Fatal("reason shorter than 3 must fail")
	}
	rv, err := r.svc.DismissReview(ctx, r.proj, 7, 1, Actor{UserID: r.alice.UserID, Login: "alice"}, "obsoleta tras refactor")
	if err != nil || rv.State != "dismissed" || rv.Author.Login != "bob" || !reflect.DeepEqual(r.core.dismissed, []int64{1}) {
		t.Fatalf("dismiss: %+v %v %v", rv, err, r.core.dismissed)
	}
	if len(dl.got) != 1 || dl.got[0].Reviewer != "bob" || dl.got[0].DismissedBy != r.alice.UserID || dl.got[0].ReviewState != "approved" {
		t.Fatalf("dismissal log: %+v", dl.got)
	}
	if _, err := r.svc.DismissReview(ctx, r.proj, 7, 2, Actor{Login: "alice"}, "no es dismissable"); !errors.Is(err, ErrReviewNotDismissable) {
		t.Fatalf("comment review: %v", err)
	}
	if _, err := r.svc.DismissReview(ctx, r.proj, 7, 99, Actor{Login: "alice"}, "no existe"); !errors.Is(err, gitcore.ErrNotFound) {
		t.Fatalf("missing review: %v", err)
	}
}

func TestJanitorWithdrawsRequestsOfTheUserWhoLostAccess(t *testing.T) {
	r := newRig(t)
	r.core.pull.Reviewers = []gitcore.Person{{Login: "Bob"}, {Login: "alice"}}
	j := Janitor{Svc: r.svc}
	n, err := j.DropPendingReviews(context.Background(), r.proj.Ref, "bob")
	if err != nil || n != 1 || !reflect.DeepEqual(r.core.removed, []string{"bob"}) {
		t.Fatalf("dropped %d %v removed %v", n, err, r.core.removed)
	}
	if n, _ := j.DropPendingReviews(context.Background(), r.proj.Ref, "zed"); n != 0 {
		t.Fatalf("user without requests: %d", n)
	}
}
