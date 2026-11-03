package gitprotect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitcore/fake"
)

// ---- in-memory Store ----------------------------------------------------------------------

type memStore struct {
	mu      sync.Mutex
	rules   map[uuid.UUID]Rule
	syncs   map[uuid.UUID]SyncState
	audits  []AuditEntry
	targets []Target
	clock   int
}

func newMemStore() *memStore {
	return &memStore{rules: map[uuid.UUID]Rule{}, syncs: map[uuid.UUID]SyncState{}}
}

func (m *memStore) ListRules(_ context.Context, p uuid.UUID) ([]Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Rule
	for _, r := range m.rules {
		if r.ProjectID == p {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *memStore) GetRule(_ context.Context, p, id uuid.UUID) (*Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rules[id]; ok && r.ProjectID == p {
		return &r, nil
	}
	return nil, ErrNotFound
}

func (m *memStore) dup(p uuid.UUID, pattern string, except uuid.UUID) bool {
	for _, r := range m.rules {
		if r.ProjectID == p && r.Pattern == pattern && r.ID != except {
			return true
		}
	}
	return false
}

func (m *memStore) CreateRule(_ context.Context, r *Rule, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dup(r.ProjectID, r.Pattern, uuid.Nil) {
		return ErrDuplicate
	}
	m.clock++
	r.CreatedAt = time.Date(2026, 11, 1, 0, 0, m.clock, 0, time.UTC)
	r.UpdatedAt = r.CreatedAt
	m.rules[r.ID] = *r
	m.syncs[r.ID] = SyncState{RuleID: r.ID, ProjectID: r.ProjectID, Status: SyncPending}
	m.audits = append(m.audits, a)
	return nil
}

func (m *memStore) UpdateRule(_ context.Context, r *Rule, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.rules[r.ID]
	if !ok || old.ProjectID != r.ProjectID {
		return ErrNotFound
	}
	if m.dup(r.ProjectID, r.Pattern, r.ID) {
		return ErrDuplicate
	}
	r.CreatedAt = old.CreatedAt
	m.rules[r.ID] = *r
	m.audits = append(m.audits, a)
	return nil
}

func (m *memStore) DeleteRule(_ context.Context, p, id uuid.UUID, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rules[id]; !ok || r.ProjectID != p {
		return ErrNotFound
	}
	delete(m.rules, id)
	delete(m.syncs, id)
	m.audits = append(m.audits, a)
	return nil
}

func (m *memStore) ListSync(_ context.Context, p uuid.UUID) (map[uuid.UUID]SyncState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[uuid.UUID]SyncState{}
	for id, s := range m.syncs {
		if s.ProjectID == p {
			out[id] = s
		}
	}
	return out, nil
}

func (m *memStore) PutSync(_ context.Context, s SyncState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rules[s.RuleID]; !ok {
		return errors.New("rule gone")
	}
	m.syncs[s.RuleID] = s
	return nil
}

func (m *memStore) ProjectsWithRules(context.Context) ([]Target, error) { return m.targets, nil }

func (m *memStore) WriteAudit(_ context.Context, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audits = append(m.audits, a)
	return nil
}

func (m *memStore) auditActions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, a := range m.audits {
		out = append(out, a.Action)
	}
	return out
}

func (m *memStore) count(action string) int {
	n := 0
	for _, a := range m.auditActions() {
		if a == action {
			n++
		}
	}
	return n
}

// ---- rig ----------------------------------------------------------------------------------

type rig struct {
	t     *testing.T
	fs    *fake.Server
	core  *gitcore.Service
	store *memStore
	svc   *Service
	tgt   Target
	actor Actor
}

func gcfg(url string) gitcore.Config {
	return gitcore.Config{URL: url, Token: fake.Token, Timeout: 2 * time.Second, BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond, BreakerOpenFor: 20 * time.Millisecond}
}

func newRig(t *testing.T) *rig {
	t.Helper()
	fs := fake.New()
	t.Cleanup(fs.Close)
	fs.AddRepo("acme", "web")
	core := gitcore.New(gcfg(fs.URL), nil, nil)
	st := newMemStore()
	r := &rig{t: t, fs: fs, core: core, store: st,
		tgt:   Target{ProjectID: uuid.New(), OrgID: uuid.New(), OrgSlug: "acme", ProjectSlug: "web"},
		actor: Actor{UserID: uuid.New(), IP: "203.0.113.7"}}
	r.svc = New(st, core, DefaultConfig(), nil)
	st.targets = []Target{r.tgt}
	return r
}

func (r *rig) create(in Input) *Protection {
	r.t.Helper()
	p, err := r.svc.Create(context.Background(), r.tgt, r.actor, in)
	if err != nil {
		r.t.Fatalf("Create(%q): %v", in.Pattern, err)
	}
	return p
}

func (r *rig) raw(rule string) map[string]any {
	r.t.Helper()
	m := r.fs.Protection("acme", "web", rule)
	if m == nil {
		r.t.Fatalf("Forgejo has no rule %q", rule)
	}
	return m
}

func strs(v any) []string {
	var out []string
	if a, ok := v.([]any); ok {
		for _, x := range a {
			out = append(out, x.(string))
		}
	}
	return out
}

func writes(fs *fake.Server) int {
	n := 0
	for _, q := range fs.Requests() {
		if q.Method != http.MethodGet {
			n++
		}
	}
	return n
}

// ---- create / projection --------------------------------------------------------------------

func TestCreateProjectsEveryFieldToForgejo(t *testing.T) {
	r := newRig(t)
	p := r.create(Input{Pattern: "release/*", RequiredApprovals: ip(2), RequireCodeOwnerReview: bp(true), RequiredChecks: []string{"ci/build"},
		RequireUpToDate: bp(true), RequireSignedCommits: bp(true), PushAllowRoles: []string{"admin"}, MergeAllowRoles: []string{"admin", "deployer"},
		BlockOnSecurityPolicy: bp(true)})
	if !p.ForgejoSynced || p.SyncStatus != SyncSynced || p.SyncError != "" || p.LastSyncedAt == nil {
		t.Fatalf("not synced: %+v", p)
	}
	m := r.raw("release/*")
	checks := map[string]any{
		"rule_name": "release/*", "enable_push": true, "enable_push_whitelist": true, "enable_merge_whitelist": true, "enable_status_check": true,
		"required_approvals": float64(2), "block_on_official_review_requests": true, "block_on_outdated_branch": true, "require_signed_commits": true,
		"apply_to_admins": true, "dismiss_stale_approvals": true, "block_on_rejected_reviews": true,
	}
	for k, want := range checks {
		if m[k] != want {
			t.Errorf("Forgejo %s = %v, want %v", k, m[k], want)
		}
	}
	if got := strs(m["push_whitelist_teams"]); !reflect.DeepEqual(got, []string{"web-admin"}) {
		t.Errorf("push whitelist teams = %v", got)
	}
	if got := strs(m["merge_whitelist_teams"]); !reflect.DeepEqual(got, []string{"web-admin", "web-deployer"}) {
		t.Errorf("merge whitelist teams = %v", got)
	}
	if got := strs(m["status_check_contexts"]); !reflect.DeepEqual(got, []string{"capsule/policy", "capsule/security", "ci/build"}) {
		t.Errorf("status contexts = %v", got)
	}
	if n := r.store.count(ActionProtectionChange); n != 1 {
		t.Errorf("audit entries = %d, want 1", n)
	}
	a := r.store.audits[0]
	if a.UserID != r.actor.UserID || a.IP != "203.0.113.7" || a.OrgID != r.tgt.OrgID || a.NewValues["op"] != "create" || a.ResourceID != p.ID {
		t.Errorf("audit entry: %+v", a)
	}
}

func TestCreateSafeDefaultsReachForgejo(t *testing.T) {
	r := newRig(t)
	p := r.create(Input{Pattern: "main"})
	m := r.raw("main")
	if m["enable_push"] != false || m["enable_push_whitelist"] != false || m["apply_to_admins"] != true || m["required_approvals"] != float64(0) ||
		m["enable_status_check"] != false || m["block_on_rejected_reviews"] != true || m["dismiss_stale_approvals"] != true {
		t.Fatalf("defaults in Forgejo: %v", m)
	}
	if !p.BlockForcePush || !p.BlockDeletion || !p.RequirePullRequest || !p.EnforceForAdmins {
		t.Fatalf("defaults in rule: %+v", p.Rule)
	}
}

func TestEnforceForAdminsFalseIsProjectedAndWarned(t *testing.T) {
	r := newRig(t)
	p := r.create(Input{Pattern: "main", EnforceForAdmins: bp(false)})
	if r.raw("main")["apply_to_admins"] != false {
		t.Fatal("apply_to_admins must be false in Forgejo")
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "ADMINS_EXEMPT") {
		t.Fatalf("warnings: %v", p.Warnings)
	}
	p = r.create(Input{Pattern: "other", EnforceForAdmins: bp(true)})
	if r.raw("other")["apply_to_admins"] != true || len(p.Warnings) != 0 {
		t.Fatal("enforce_for_admins=true must set apply_to_admins and not warn")
	}
}

func TestCreateDuplicateAndLimit(t *testing.T) {
	r := newRig(t)
	r.create(Input{Pattern: "main"})
	_, err := r.svc.Create(context.Background(), r.tgt, r.actor, Input{Pattern: "main"})
	var ce *ConflictError
	if !errors.As(err, &ce) || ce.Code != "DUPLICATE_PATTERN" {
		t.Fatalf("duplicate: %v", err)
	}
	for i := 0; i < MaxRulesPerProject-1; i++ {
		id := uuid.New()
		r.store.rules[id] = Rule{ID: id, ProjectID: r.tgt.ProjectID, Pattern: "p" + id.String()}
	}
	_, err = r.svc.Create(context.Background(), r.tgt, r.actor, Input{Pattern: "one-more"})
	if !errors.As(err, &ce) || ce.Code != "RULE_LIMIT" {
		t.Fatalf("limit: %v", err)
	}
}

func TestCreateValidationDoesNotTouchForgejoOrStore(t *testing.T) {
	r := newRig(t)
	_, err := r.svc.Create(context.Background(), r.tgt, r.actor, Input{Pattern: "a["})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError: %v", err)
	}
	if len(r.store.rules) != 0 || len(r.fs.Requests()) != 0 {
		t.Fatal("an invalid rule must not reach the store or Forgejo")
	}
}

func TestReconcileAfterCreateIsIdempotent(t *testing.T) {
	r := newRig(t)
	r.create(Input{Pattern: "main", RequiredChecks: []string{"ci/build"}})
	r.create(Input{Pattern: "release/*"})
	if err := r.svc.ProjectTags(context.Background(), r.tgt); err != nil { // the first pass projects the tag rule once
		t.Fatal(err)
	}
	r.fs.Reset()
	for i := 0; i < 3; i++ {
		rep, err := r.svc.ReconcileProject(context.Background(), r.tgt)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Fixed != 0 || rep.Synced != 2 || len(rep.Drifts) != 0 || rep.Errors != 0 {
			t.Fatalf("run %d: %+v", i, rep)
		}
	}
	if n := writes(r.fs); n != 0 {
		t.Fatalf("a clean reconcile must not write to Forgejo (%d writes)", n)
	}
	if n := r.store.count(ActionProtectionDrift); n != 0 {
		t.Fatalf("clean reconcile audited %d drifts", n)
	}
	// re-projecting the same rule is a no-op on the Forgejo side
	snap := func() string {
		m := map[string]any{}
		for k, v := range r.raw("main") {
			if k != "updated_at" {
				m[k] = v
			}
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	before := snap()
	var rule Rule
	for _, x := range r.store.rules {
		if x.Pattern == "main" {
			rule = x
		}
	}
	st := SyncState{}
	r.svc.project(context.Background(), r.tgt, rule, &st)
	r.svc.project(context.Background(), r.tgt, rule, &st)
	if after := snap(); before != after {
		t.Fatalf("projecting twice changed the Forgejo rule: %s != %s", before, after)
	}
}

// ---- replace / delete -----------------------------------------------------------------------

func TestReplaceRenamesPatternWithoutLeavingTheOldRule(t *testing.T) {
	r := newRig(t)
	p := r.create(Input{Pattern: "dev"})
	got, err := r.svc.Replace(context.Background(), r.tgt, r.actor, p.ID, Input{Pattern: "develop", RequiredApprovals: ip(1)})
	if err != nil {
		t.Fatal(err)
	}
	if !got.ForgejoSynced || got.Pattern != "develop" || got.RequiredApprovals != 1 {
		t.Fatalf("replace: %+v", got)
	}
	if r.fs.HasProtection("acme", "web", "dev") || !r.fs.HasProtection("acme", "web", "develop") {
		t.Fatal("Forgejo must hold only the new rule name")
	}
	if r.raw("develop")["required_approvals"] != float64(1) {
		t.Fatal("new values not projected")
	}
	if !got.CreatedAt.Equal(p.CreatedAt) {
		t.Fatal("created_at must survive a replace")
	}
	a := r.store.audits[len(r.store.audits)-1]
	if a.NewValues["op"] != "update" || a.OldValues["pattern"] != "dev" || a.NewValues["pattern"] != "develop" {
		t.Fatalf("audit of replace: %+v", a)
	}
	// unknown id and duplicate pattern
	if _, err := r.svc.Replace(context.Background(), r.tgt, r.actor, uuid.New(), Input{Pattern: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	other := r.create(Input{Pattern: "staging"})
	var ce *ConflictError
	if _, err := r.svc.Replace(context.Background(), r.tgt, r.actor, other.ID, Input{Pattern: "develop"}); !errors.As(err, &ce) {
		t.Fatalf("duplicate on replace: %v", err)
	}
}

func TestReplaceUsesSafeDefaultsForOmittedFields(t *testing.T) {
	r := newRig(t)
	p := r.create(Input{Pattern: "main", RequiredApprovals: ip(3), EnforceForAdmins: bp(false)})
	got, err := r.svc.Replace(context.Background(), r.tgt, r.actor, p.ID, Input{Pattern: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if got.RequiredApprovals != 0 || !got.EnforceForAdmins || r.raw("main")["apply_to_admins"] != true {
		t.Fatalf("PUT replaces: omitted fields take the safe defaults, got %+v", got.Rule)
	}
}

func TestDeleteRemovesForgejoRuleFirst(t *testing.T) {
	r := newRig(t)
	p := r.create(Input{Pattern: "main"})
	// Forgejo refuses the DELETE: the Capsule rule must stay
	r.fs.Fail = func(q fake.Request) int {
		if q.Method == http.MethodDelete {
			return 500
		}
		return 0
	}
	if _, err := r.svc.Delete(context.Background(), r.tgt, r.actor, p.ID); err == nil {
		t.Fatal("delete must fail when Forgejo fails")
	} else if _, ok := gitcore.AsError(err); !ok {
		t.Fatalf("want a gitcore error, got %v", err)
	}
	if _, err := r.store.GetRule(context.Background(), r.tgt.ProjectID, p.ID); err != nil {
		t.Fatal("the rule must remain after a failed delete")
	}
	r.fs.Fail = nil
	time.Sleep(30 * time.Millisecond) // breaker half-open window
	warns, err := r.svc.Delete(context.Background(), r.tgt, r.actor, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r.fs.HasProtection("acme", "web", "main") {
		t.Fatal("Forgejo rule must be gone")
	}
	if len(r.store.rules) != 0 {
		t.Fatal("Capsule rule must be gone")
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "DEFAULT_BRANCH_UNPROTECTED") {
		t.Fatalf("deleting the rule of the default branch must warn: %v", warns)
	}
	if last := r.store.audits[len(r.store.audits)-1]; last.NewValues["op"] != "delete" || last.OldValues["pattern"] != "main" {
		t.Fatalf("audit of delete: %+v", last)
	}
	if _, err := r.svc.Delete(context.Background(), r.tgt, r.actor, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestDeleteWithAnotherRuleCoveringDefaultDoesNotWarn(t *testing.T) {
	r := newRig(t)
	r.create(Input{Pattern: "**"})
	p := r.create(Input{Pattern: "main"})
	warns, err := r.svc.Delete(context.Background(), r.tgt, r.actor, p.ID)
	if err != nil || len(warns) != 0 {
		t.Fatalf("warns=%v err=%v", warns, err)
	}
}

// ---- Forgejo failures and disabled integration ------------------------------------------------

func TestForgejoDownKeepsRuleAndReconcilerHealsIt(t *testing.T) {
	r := newRig(t)
	r.fs.Fail = func(fake.Request) int { return 500 }
	p := r.create(Input{Pattern: "main"})
	if p.ForgejoSynced || p.SyncStatus != SyncError || p.SyncError == "" {
		t.Fatalf("want an error state: %+v", p)
	}
	if strings.Contains(p.SyncError, fake.Token) {
		t.Fatal("sync_error leaks the service token")
	}
	if len(r.store.rules) != 1 {
		t.Fatal("the rule must be kept (source of truth)")
	}
	listed, _ := r.svc.List(context.Background(), r.tgt)
	if len(listed) != 1 || listed[0].ForgejoSynced || listed[0].SyncError == "" {
		t.Fatalf("list must expose the sync error: %+v", listed)
	}
	r.fs.Fail = nil
	time.Sleep(30 * time.Millisecond)
	rep, err := r.svc.ReconcileProject(context.Background(), r.tgt)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Fixed != 1 || len(rep.Drifts) != 0 {
		t.Fatalf("report: %+v (first sync is not drift)", rep)
	}
	if !r.fs.HasProtection("acme", "web", "main") {
		t.Fatal("reconcile must create the rule")
	}
	listed, _ = r.svc.List(context.Background(), r.tgt)
	if !listed[0].ForgejoSynced || listed[0].SyncError != "" {
		t.Fatalf("after reconcile: %+v", listed[0])
	}
}

func TestDisabledIntegrationStoresRuleAsPending(t *testing.T) {
	r := newRig(t)
	r.svc = New(r.store, gitcore.New(gitcore.Config{}, nil, nil), DefaultConfig(), nil)
	p := r.create(Input{Pattern: "main"})
	if p.ForgejoSynced || p.SyncStatus != SyncPending || !strings.Contains(p.SyncError, "GIT_NOT_READY") {
		t.Fatalf("%+v", p)
	}
	if _, err := r.svc.ReconcileProject(context.Background(), r.tgt); !errors.Is(err, gitcore.ErrNotReady) {
		t.Fatalf("reconcile while disabled: %v", err)
	}
	if _, err := r.svc.Delete(context.Background(), r.tgt, r.actor, p.ID); err != nil {
		t.Fatalf("a never-projected rule can be deleted while Git is off: %v", err)
	}
	// a rule that was projected cannot be removed without Forgejo
	q := r.svc
	r.svc = New(r.store, r.core, DefaultConfig(), nil)
	p = r.create(Input{Pattern: "dev"})
	r.svc = q
	if _, err := r.svc.Delete(context.Background(), r.tgt, r.actor, p.ID); !errors.Is(err, gitcore.ErrNotReady) {
		t.Fatalf("deleting a synced rule with Git off must be refused: %v", err)
	}
}

// ---- drift ----------------------------------------------------------------------------------

func TestDriftModifiedInForgejoIsCorrectedAndAudited(t *testing.T) {
	r := newRig(t)
	r.create(Input{Pattern: "main", RequiredApprovals: ip(2)})
	// somebody opens the Forgejo UI and weakens the rule, adding a user to the push whitelist
	if _, err := r.core.UpsertProtection(context.Background(), gitcore.RepoRef{Owner: "acme", Repo: "web"}, gitcore.ProtectionSpec{
		RuleName: "main", EnablePush: true, EnablePushWhitelist: true, PushWhitelistUsers: []string{"mallory"}, RequiredApprovals: 0}); err != nil {
		t.Fatal(err)
	}
	rep, err := r.svc.ReconcileProject(context.Background(), r.tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Drifts) != 1 || rep.Drifts[0].Kind != "modified" || !rep.Drifts[0].Corrected || rep.Fixed != 1 {
		t.Fatalf("report: %+v", rep)
	}
	for _, f := range []string{"enable_push", "enable_push_whitelist", "push_whitelist_users", "required_approvals"} {
		if !contains(rep.Drifts[0].Fields, f) {
			t.Errorf("drift fields %v lack %s", rep.Drifts[0].Fields, f)
		}
	}
	m := r.raw("main")
	if m["required_approvals"] != float64(2) || m["enable_push"] != false || len(strs(m["push_whitelist_users"])) != 0 {
		t.Fatalf("Forgejo not corrected: %v", m)
	}
	if r.store.count(ActionProtectionDrift) != 1 {
		t.Fatalf("drift must be audited once: %v", r.store.auditActions())
	}
	a := r.store.audits[len(r.store.audits)-1]
	if a.Action != ActionProtectionDrift || a.UserID != uuid.Nil || a.NewValues["kind"] != "modified" || a.NewValues["corrected"] != true || a.OldValues == nil {
		t.Fatalf("drift audit: %+v", a)
	}
	listed, _ := r.svc.List(context.Background(), r.tgt)
	if listed[0].DriftCount != 1 || !listed[0].ForgejoSynced {
		t.Fatalf("sync state: %+v", listed[0])
	}
	// second pass: nothing left to do, nothing new audited
	rep, _ = r.svc.ReconcileProject(context.Background(), r.tgt)
	if rep.Fixed != 0 || len(rep.Drifts) != 0 || r.store.count(ActionProtectionDrift) != 1 {
		t.Fatalf("not idempotent: %+v", rep)
	}
}

func TestDriftMissingRuleIsRecreated(t *testing.T) {
	r := newRig(t)
	r.create(Input{Pattern: "main"})
	if err := r.core.DeleteProtection(context.Background(), gitcore.RepoRef{Owner: "acme", Repo: "web"}, "main"); err != nil {
		t.Fatal(err)
	}
	rep, err := r.svc.ReconcileProject(context.Background(), r.tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Drifts) != 1 || rep.Drifts[0].Kind != "missing" || !rep.Drifts[0].Corrected {
		t.Fatalf("report: %+v", rep)
	}
	if !r.fs.HasProtection("acme", "web", "main") || r.store.count(ActionProtectionDrift) != 1 {
		t.Fatal("rule not recreated or drift not audited")
	}
}

func TestUnmanagedForgejoRuleIsAuditedOnceAndKeptByDefault(t *testing.T) {
	r := newRig(t)
	r.create(Input{Pattern: "main"})
	ref := gitcore.RepoRef{Owner: "acme", Repo: "web"}
	if _, err := r.core.UpsertProtection(context.Background(), ref, gitcore.ProtectionSpec{RuleName: "hotfix/*", RequiredApprovals: 1}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		rep, err := r.svc.ReconcileProject(context.Background(), r.tgt)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Drifts) != 1 || rep.Drifts[0].Kind != "unmanaged" || rep.Drifts[0].Corrected {
			t.Fatalf("run %d: %+v", i, rep)
		}
	}
	if !r.fs.HasProtection("acme", "web", "hotfix/*") {
		t.Fatal("by default a reconciliation must never remove a protection")
	}
	if n := r.store.count(ActionProtectionDrift); n != 1 {
		t.Fatalf("unmanaged rule audited %d times, want 1", n)
	}
	// with pruning on, the stray rule is removed and audited
	r.svc.cfg.PruneUnmanaged = true
	rep, _ := r.svc.ReconcileProject(context.Background(), r.tgt)
	if len(rep.Drifts) != 1 || !rep.Drifts[0].Corrected || r.fs.HasProtection("acme", "web", "hotfix/*") {
		t.Fatalf("prune: %+v", rep)
	}
	if n := r.store.count(ActionProtectionDrift); n != 2 {
		t.Fatalf("prune must audit: %d", n)
	}
	if !r.fs.HasProtection("acme", "web", "main") {
		t.Fatal("the managed rule must survive pruning")
	}
}

func TestReconcileAllUsesStoreTargets(t *testing.T) {
	r := newRig(t)
	r.create(Input{Pattern: "main"})
	_ = r.core.DeleteProtection(context.Background(), gitcore.RepoRef{Owner: "acme", Repo: "web"}, "main")
	r.svc.reconcileAll(context.Background())
	if !r.fs.HasProtection("acme", "web", "main") {
		t.Fatal("the loop pass must recreate the missing rule")
	}
}

// ---- evaluate -------------------------------------------------------------------------------

func TestEvaluateExplainsPrecedence(t *testing.T) {
	r := newRig(t)
	r.create(Input{Pattern: "**"})
	r.create(Input{Pattern: "release/*"})
	r.create(Input{Pattern: "main"})
	ev := func(b string) *Evaluation {
		e, err := r.svc.Evaluate(context.Background(), r.tgt, b)
		if err != nil {
			t.Fatalf("Evaluate(%s): %v", b, err)
		}
		return e
	}
	e := ev("main")
	if e.Rule == nil || e.Rule.Pattern != "main" || len(e.Matches) != 2 || !strings.Contains(e.Reason, "sin glob") ||
		e.Matches[0].Glob || !e.Matches[0].Applies || e.Matches[1].Pattern != "**" || e.Matches[1].Applies || !strings.Contains(e.Matches[1].Why, "sin glob") {
		t.Fatalf("main: %+v", e)
	}
	if len(e.Requirements) == 0 {
		t.Fatal("evaluate must list what the rule enforces")
	}
	// '**' was created first, so it wins over release/* among globs
	e = ev("release/1.0")
	if e.Rule.Pattern != "**" || !strings.Contains(e.Reason, "más antigua") {
		t.Fatalf("release/1.0: %+v", e)
	}
	e = ev("feature/x/y")
	if e.Rule == nil || e.Rule.Pattern != "**" || len(e.Matches) != 1 {
		t.Fatalf("feature/x/y: %+v", e)
	}
	if e.Forgejo == nil || !e.Forgejo.InSync || e.Forgejo.Rule != "**" {
		t.Fatalf("Forgejo view: %+v", e.Forgejo)
	}
	// invalid branch name
	var ve *ValidationError
	if _, err := r.svc.Evaluate(context.Background(), r.tgt, "a..b"); !errors.As(err, &ve) {
		t.Fatalf("invalid branch: %v", err)
	}
	if _, err := r.svc.Evaluate(context.Background(), r.tgt, ""); !errors.As(err, &ve) {
		t.Fatalf("empty branch: %v", err)
	}
}

func TestEvaluateNoRuleAndForgejoDivergence(t *testing.T) {
	r := newRig(t)
	e, err := r.svc.Evaluate(context.Background(), r.tgt, "main")
	if err != nil || e.Rule != nil || !strings.Contains(e.Reason, "no está protegida") || e.Forgejo == nil || !e.Forgejo.InSync {
		t.Fatalf("no rules: %+v %v", e, err)
	}
	r.create(Input{Pattern: "release/*"})
	ref := gitcore.RepoRef{Owner: "acme", Repo: "web"}
	// Forgejo holds a rule Capsule does not know, and it would win for "main"
	if _, err := r.core.UpsertProtection(context.Background(), ref, gitcore.ProtectionSpec{RuleName: "main", RequiredApprovals: 1}); err != nil {
		t.Fatal(err)
	}
	e, _ = r.svc.Evaluate(context.Background(), r.tgt, "main")
	if e.Forgejo.InSync || e.Forgejo.Rule != "main" || !strings.Contains(e.Forgejo.Note, "no conoce") {
		t.Fatalf("stray rule: %+v", e.Forgejo)
	}
	// a rule changed in Forgejo: same name, different fields
	if _, err := r.core.UpsertProtection(context.Background(), ref, gitcore.ProtectionSpec{RuleName: "release/*", RequiredApprovals: 9}); err != nil {
		t.Fatal(err)
	}
	e, _ = r.svc.Evaluate(context.Background(), r.tgt, "release/2")
	if e.Forgejo.InSync || !contains(e.Forgejo.Fields, "required_approvals") {
		t.Fatalf("modified rule: %+v", e.Forgejo)
	}
	// Forgejo down: evaluate still answers from Capsule's database
	r.fs.Fail = func(fake.Request) int { return 500 }
	e, err = r.svc.Evaluate(context.Background(), r.tgt, "release/2")
	if err != nil || e.Rule == nil || e.Forgejo == nil || e.Forgejo.InSync || e.Forgejo.Note == "" {
		t.Fatalf("Forgejo down: %+v %v", e, err)
	}
}

// ---- repo-wide effects ----------------------------------------------------------------------

type repoStub struct {
	*gitcore.Service
	repo    gitcore.Repository
	patches []gitcore.RepoPatch
}

func (s *repoStub) GetRepo(context.Context, gitcore.RepoRef) (*gitcore.Repository, error) {
	c := s.repo
	return &c, nil
}

func (s *repoStub) PatchRepo(_ context.Context, _ gitcore.RepoRef, p gitcore.RepoPatch) (*gitcore.Repository, error) {
	s.patches = append(s.patches, p)
	if p.AllowedMergeStyles != nil {
		s.repo.AllowedMergeStyles = p.AllowedMergeStyles
	}
	if p.DeleteBranchOnPR != nil {
		s.repo.DeleteBranchOnPR = *p.DeleteBranchOnPR
	}
	c := s.repo
	return &c, nil
}

func TestLinearHistoryRestrictsMergeStylesAndIsEnforcedOnRepoUpdate(t *testing.T) {
	r := newRig(t)
	stub := &repoStub{Service: r.core, repo: gitcore.Repository{DefaultBranch: "main", AllowedMergeStyles: []string{"merge", "squash", "rebase"}}}
	r.svc = New(r.store, stub, DefaultConfig(), nil)

	p := r.create(Input{Pattern: "main", RequireLinearHistory: bp(true), DeleteBranchOnMerge: bp(true)})
	if !p.ForgejoSynced {
		t.Fatalf("%+v", p)
	}
	if len(stub.patches) != 1 || !reflect.DeepEqual(stub.patches[0].AllowedMergeStyles, []string{"rebase"}) ||
		stub.patches[0].DeleteBranchOnPR == nil || !*stub.patches[0].DeleteBranchOnPR {
		t.Fatalf("repo patches: %+v", stub.patches)
	}
	if r.store.count(ActionRepoSettings) != 1 {
		t.Fatalf("restricting merge styles must be audited: %v", r.store.auditActions())
	}
	if a := r.store.audits[len(r.store.audits)-1]; !reflect.DeepEqual(a.OldValues["allowed_merge_styles"], []string{"merge", "squash", "rebase"}) {
		t.Fatalf("audit must keep the previous styles to allow a restore: %+v", a)
	}
	// reconcile is idempotent: nothing more to patch
	if _, err := r.svc.ReconcileProject(context.Background(), r.tgt); err != nil {
		t.Fatal(err)
	}
	if len(stub.patches) != 1 {
		t.Fatalf("reconcile re-patched: %+v", stub.patches)
	}
	// repoUpdate hook
	var pe *PolicyError
	if err := r.svc.CheckMergeStyles(context.Background(), r.tgt, []string{"merge", "rebase"}); !errors.As(err, &pe) || pe.Code != "POLICY_BLOCKED" || !strings.Contains(pe.Message, "«main»") {
		t.Fatalf("merge must be refused naming the rule: %v", err)
	}
	if err := r.svc.CheckMergeStyles(context.Background(), r.tgt, []string{"squash"}); !errors.As(err, &pe) {
		t.Fatalf("squash must be refused: %v", err)
	}
	if err := r.svc.CheckMergeStyles(context.Background(), r.tgt, []string{"rebase", "fast-forward"}); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.CheckMergeStyles(context.Background(), r.tgt, nil); err != nil {
		t.Fatal(err)
	}
	// removing the rule never relaxes the repository by itself
	if _, err := r.svc.Delete(context.Background(), r.tgt, r.actor, p.ID); err != nil {
		t.Fatal(err)
	}
	if len(stub.patches) != 1 || !reflect.DeepEqual(stub.repo.AllowedMergeStyles, []string{"rebase"}) {
		t.Fatalf("styles must stay restricted: %+v", stub.repo)
	}
	if err := r.svc.CheckMergeStyles(context.Background(), r.tgt, []string{"merge"}); err != nil {
		t.Fatalf("without a linear rule any style is allowed: %v", err)
	}
}

func TestLinearHistoryWithNoCompatibleStyleFallsBackToRebaseAndFastForward(t *testing.T) {
	r := newRig(t)
	stub := &repoStub{Service: r.core, repo: gitcore.Repository{DefaultBranch: "main", AllowedMergeStyles: []string{"merge"}}}
	r.svc = New(r.store, stub, DefaultConfig(), nil)
	r.create(Input{Pattern: "main", RequireLinearHistory: bp(true)})
	if len(stub.patches) != 1 || !sameSet(stub.patches[0].AllowedMergeStyles, []string{"rebase", "fast-forward"}) {
		t.Fatalf("%+v", stub.patches)
	}
}

// ---- tags -----------------------------------------------------------------------------------

func TestGuardTag(t *testing.T) {
	r := newRig(t)
	var fe *ForbiddenError
	if err := r.svc.GuardTag("v1.2.0", false, "crearla"); !errors.As(err, &fe) || fe.Code != "PROTECTED_TAG" {
		t.Fatalf("v* protected by default: %v", err)
	}
	if err := r.svc.GuardTag("v1.2.0", true, "crearla"); err != nil {
		t.Fatalf("admin may: %v", err)
	}
	if err := r.svc.GuardTag("nightly-1", false, "crearla"); err != nil {
		t.Fatalf("unprotected tag: %v", err)
	}
	var ve *ValidationError
	if err := r.svc.GuardTag("a..b", true, "crearla"); !errors.As(err, &ve) {
		t.Fatalf("invalid name: %v", err)
	}
	r.svc.cfg.TagPatterns = []string{"release-*", "[bad"}
	if err := r.svc.GuardTag("release-1", false, "borrarla"); err == nil || !strings.Contains(err.Error(), "borrarla") {
		t.Fatalf("custom pattern: %v", err)
	}
	if err := r.svc.GuardTag("v1", false, "crearla"); err != nil {
		t.Fatalf("default pattern replaced: %v", err)
	}
	r.svc.cfg.TagPatterns = nil
	if err := r.svc.GuardTag("release-1", false, "crearla"); err != nil {
		t.Fatalf("no patterns: %v", err)
	}
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func TestProjectTagsProjectsAndHealsTagProtection(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.svc.ProjectTags(ctx, r.tgt); err != nil {
		t.Fatal(err)
	}
	ref := gitcore.RepoRef{Owner: "acme", Repo: "web"}
	l, err := r.core.ListTagProtections(ctx, ref)
	if err != nil || len(l) != 1 || l[0].Pattern != "v*" || len(l[0].WhitelistTeams) != 1 || l[0].WhitelistTeams[0] != "web-admin" {
		t.Fatalf("projected: %+v %v", l, err)
	}
	if err := r.svc.ProjectTags(ctx, r.tgt); err != nil { // idempotent
		t.Fatal(err)
	}
	if got := r.fs.Count("POST", "/api/v1/repos/acme/web/tag_protections"); got != 1 {
		t.Fatalf("created %d times", got)
	}
	// somebody widens the whitelist in Forgejo: edited back in place, never deleted
	if _, err := r.core.EditTagProtection(ctx, ref, l[0].ID, gitcore.TagProtectionSpec{Pattern: "v*", WhitelistTeams: []string{"web-admin", "web-viewer"}, WhitelistUsers: []string{"mallory"}}); err != nil {
		t.Fatal(err)
	}
	if err := r.svc.ProjectTags(ctx, r.tgt); err != nil {
		t.Fatal(err)
	}
	l, _ = r.core.ListTagProtections(ctx, ref)
	if len(l) != 1 || len(l[0].WhitelistTeams) != 1 || len(l[0].WhitelistUsers) != 0 || r.fs.Count("DELETE", "/api/v1/repos/acme/web/tag_protections") != 0 {
		t.Fatalf("healed: %+v", l)
	}
	// the drift reconciler covers it as well
	if _, err := r.core.EditTagProtection(ctx, ref, l[0].ID, gitcore.TagProtectionSpec{Pattern: "v*"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.ReconcileProject(ctx, r.tgt); err != nil {
		t.Fatal(err)
	}
	if l, _ = r.core.ListTagProtections(ctx, ref); len(l[0].WhitelistTeams) != 1 {
		t.Fatalf("reconcile did not heal tag protection: %+v", l)
	}
}
