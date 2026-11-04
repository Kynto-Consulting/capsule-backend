//go:build dbtest

package repository

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kynto/capsule/backend/internal/domain"
)

func timeNow() time.Time { return time.Now().Add(-time.Hour) }

func TestAccessStoreTemplatesLifecycle(t *testing.T) {
	x := newTfx(t)
	ctx := context.Background()
	s := NewAccessStore(x.pool)

	e0 := epochOf(t, x.pool, x.org)
	ct, err := s.CreateTemplate(ctx, x.org, NewTemplate{Kind: "project", Slug: "deployer-no-sql", Name: "Deployer sin SQL",
		Permissions: []string{"project:view", "project:read", "deployment:read"}, CreatedBy: &x.owner, ClonedFrom: ptr(SystemTemplateID("project", "deployer"))})
	if err != nil {
		t.Fatal(err)
	}
	if ct.CurrentVersion != 1 || ct.System || ct.OrgID == nil || *ct.OrgID != x.org {
		t.Fatalf("template: %+v", ct)
	}
	if epochOf(t, x.pool, x.org) <= e0 {
		t.Errorf("CreateTemplate did not bump the epoch")
	}
	// reserved slug, bad slug, wildcard, duplicate slug, bad kind
	for name, in := range map[string]NewTemplate{
		"reserved": {Kind: "project", Slug: "viewer", Name: "x", Permissions: []string{"project:view"}},
		"slug":     {Kind: "project", Slug: "Bad Slug", Name: "x"},
		"wildcard": {Kind: "project", Slug: "wild", Name: "x", Permissions: []string{"*"}},
		"wild2":    {Kind: "project", Slug: "wild2", Name: "x", Permissions: []string{"git:*"}},
		"dup":      {Kind: "project", Slug: "deployer-no-sql", Name: "x", Permissions: []string{"project:view"}},
		"kind":     {Kind: "weird", Slug: "k", Name: "x"},
		"repeated": {Kind: "project", Slug: "rep", Name: "x", Permissions: []string{"git:read", "git:read"}},
	} {
		if _, err := s.CreateTemplate(ctx, x.org, in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := s.CreateTemplate(ctx, x.org, NewTemplate{Kind: "project", Slug: "viewer", Name: "x", Permissions: []string{"project:view"}}); !errors.Is(err, ErrReservedSlug) {
		t.Errorf("reserved slug: %v", err)
	}
	if _, err := s.CreateTemplate(ctx, x.org, NewTemplate{Kind: "project", Slug: "deployer-no-sql", Name: "x", Permissions: []string{"project:view"}}); !errors.Is(err, ErrAccessConflict) {
		t.Errorf("duplicate slug: %v", err)
	}
	// system templates cannot be published, archived or deleted
	for _, op := range []func() error{
		func() error {
			_, err := s.PublishVersion(ctx, x.org, x.viewerTpl, NewTemplateVersion{Permissions: []string{"project:view"}})
			return err
		},
		func() error { return s.ArchiveTemplate(ctx, x.org, x.viewerTpl) },
		func() error { return s.DeleteTemplate(ctx, x.org, x.viewerTpl) },
	} {
		if err := op(); !errors.Is(err, ErrSystemTemplate) {
			t.Errorf("system template write: %v", err)
		}
	}
	// publish: versions n+1, current moves, old versions stay
	v, err := s.PublishVersion(ctx, x.org, ct.ID, NewTemplateVersion{Permissions: []string{"project:view", "project:read"}, Note: "adds read", CreatedBy: &x.owner})
	if err != nil || v != 2 {
		t.Fatalf("publish: %d %v", v, err)
	}
	m, err := s.LoadTemplateVersions(ctx, []TemplateRef{{ct.ID, 0}, {ct.ID, 1}, {ct.ID, 2}, {ct.ID, 9}, {x.viewerTpl, 0}})
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 4 || m[TemplateRef{ct.ID, 0}].Version != 2 || len(m[TemplateRef{ct.ID, 1}].Permissions) != 3 || m[TemplateRef{ct.ID, 9}] != nil {
		t.Errorf("LoadTemplateVersions: %d entries, cur=%v", len(m), m[TemplateRef{ct.ID, 0}])
	}
	if sv := m[TemplateRef{x.viewerTpl, 0}]; sv == nil || !sv.System || sv.Slug != "viewer" || len(sv.Permissions) == 0 {
		t.Errorf("system version: %+v", sv)
	}
	// another organization cannot touch it
	other := x.f.org(x.owner)
	if _, err := s.PublishVersion(ctx, other, ct.ID, NewTemplateVersion{Permissions: []string{"project:view"}}); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("cross-org publish: %v", err)
	}
	if err := s.DeleteTemplate(ctx, other, ct.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("cross-org delete: %v", err)
	}
	if _, err := s.GetTemplate(ctx, other, ct.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("cross-org get: %v", err)
	}
	// in use: not deletable; archived: not assignable nor publishable, live assignments keep loading
	a, created, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: x.user, ScopeType: "project", ScopeID: x.p1, TemplateID: ct.ID, PinnedVersion: ptr(1)})
	if err != nil || !created {
		t.Fatalf("assign custom: %v created=%v", err, created)
	}
	if err := s.DeleteTemplate(ctx, x.org, ct.ID); !errors.Is(err, ErrTemplateInUse) {
		t.Errorf("delete in use: %v", err)
	}
	if err := s.ArchiveTemplate(ctx, x.org, ct.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PublishVersion(ctx, x.org, ct.ID, NewTemplateVersion{Permissions: []string{"project:view"}}); !errors.Is(err, ErrTemplateArchived) {
		t.Errorf("publish archived: %v", err)
	}
	if _, _, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: x.owner, ScopeType: "project", ScopeID: x.p1, TemplateID: ct.ID}); !errors.Is(err, ErrTemplateArchived) {
		t.Errorf("assign archived: %v", err)
	}
	got, err := s.LoadUserAssignments(ctx, x.org, x.user)
	if err != nil || len(got) != 1 || got[0].ID != a.ID || got[0].PinnedVersion == nil || *got[0].PinnedVersion != 1 {
		t.Errorf("live assignment of archived template: %+v %v", got, err)
	}
	if err := s.Revoke(ctx, x.org, a.ID, &x.owner); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTemplate(ctx, x.org, ct.ID); !errors.Is(err, ErrTemplateInUse) {
		// revoked rows still reference the template (FK, audit trail): archiving is the way out
		t.Logf("delete after revoke: %v", err)
	}
	// a template with no references deletes
	free, err := s.CreateTemplate(ctx, x.org, NewTemplate{Kind: "repo", Slug: "free", Name: "Free", Permissions: []string{"project:view", "git:read"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTemplate(ctx, x.org, free.ID); err != nil {
		t.Errorf("delete free: %v", err)
	}
	list, err := s.ListTemplates(ctx, x.org)
	if err != nil || len(list) < 9 || !list[0].System {
		t.Errorf("ListTemplates: %d %v", len(list), err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestAccessStoreTemplateLimit(t *testing.T) {
	x := newTfx(t)
	ctx := context.Background()
	s := NewAccessStore(x.pool)
	mustExec(t, x.pool, `INSERT INTO role_templates (org_id,kind,slug,name) SELECT $1,'project','t'||g,'T' FROM generate_series(1,$2) g`, x.org, MaxTemplatesPerOrg)
	if _, err := s.CreateTemplate(ctx, x.org, NewTemplate{Kind: "project", Slug: "one-too-many", Name: "x", Permissions: []string{"project:view"}}); !errors.Is(err, ErrAccessLimit) {
		t.Errorf("template limit: %v", err)
	}
	big := make([]string, MaxPermsPerTemplate+1)
	for i := range big {
		big[i] = fmt.Sprintf("res%d:read", i)
	}
	other := x.f.org(x.owner)
	if _, err := s.CreateTemplate(ctx, other, NewTemplate{Kind: "project", Slug: "big", Name: "x", Permissions: big}); !errors.Is(err, ErrAccessLimit) {
		t.Errorf("permission limit: %v", err)
	}
}

func TestAccessStoreAssignmentsAndGroups(t *testing.T) {
	x := newTfx(t)
	ctx := context.Background()
	s := NewAccessStore(x.pool)
	other := x.f.org(x.owner)
	otherProj := x.f.project(other, "")

	// scope of another organization is rejected by the trigger (confused deputy), also for repo scope
	for _, sc := range []struct{ typ string }{{"project"}, {"repo"}} {
		_, _, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: x.user, ScopeType: sc.typ, ScopeID: otherProj, TemplateID: x.viewerTpl})
		if !errors.Is(err, ErrAccessInvalid) {
			t.Errorf("foreign %s scope: %v", sc.typ, err)
		}
	}
	// org scope must be the org itself; org-kind template can not be assigned
	if _, _, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: x.user, ScopeType: "org", ScopeID: other, TemplateID: x.viewerTpl}); !errors.Is(err, ErrAccessInvalid) {
		t.Errorf("foreign org scope: %v", err)
	}
	if _, _, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: x.user, ScopeType: "project", ScopeID: x.p1, TemplateID: SystemTemplateID("org", "admin")}); !errors.Is(err, ErrAccessInvalid) {
		t.Errorf("org template as assignment: %v", err)
	}
	if _, _, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: x.user, ScopeType: "project", ScopeID: x.p1, TemplateID: x.viewerTpl, PinnedVersion: ptr(5)}); !errors.Is(err, ErrAccessInvalid) {
		t.Errorf("pin to missing version: %v", err)
	}
	// a template of another organization cannot be used
	ot, err := s.CreateTemplate(ctx, other, NewTemplate{Kind: "project", Slug: "mine", Name: "m", Permissions: []string{"project:view"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: x.user, ScopeType: "project", ScopeID: x.p1, TemplateID: ot.ID}); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("foreign template: %v", err)
	}

	// idempotent assign: same row, updated expiry
	exp := time.Now().Add(8 * time.Hour).Truncate(time.Microsecond)
	a1, c1, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: x.user, ScopeType: "project", ScopeID: x.p1, TemplateID: x.depl, Source: "temporary", ExpiresAt: &exp, CreatedBy: &x.owner})
	if err != nil || !c1 {
		t.Fatalf("assign: %v %v", err, c1)
	}
	exp2 := exp.Add(time.Hour)
	a2, c2, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: x.user, ScopeType: "project", ScopeID: x.p1, TemplateID: x.depl, ExpiresAt: &exp2})
	if err != nil || c2 || a2.ID != a1.ID || a2.ExpiresAt == nil || !a2.ExpiresAt.Equal(exp2) {
		t.Fatalf("re-assign: %+v created=%v %v", a2, c2, err)
	}

	// groups: archived groups stop counting; group rows carry ViaGroup
	g, err := s.CreateGroup(ctx, x.org, NewGroup{Slug: "pagos", Name: "Pagos", CreatedBy: &x.owner})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateGroup(ctx, x.org, NewGroup{Slug: "pagos", Name: "dup"}); !errors.Is(err, ErrAccessConflict) {
		t.Errorf("dup group: %v", err)
	}
	if _, err := s.CreateGroup(ctx, x.org, NewGroup{Slug: "UP", Name: "x"}); !errors.Is(err, ErrAccessInvalid) {
		t.Errorf("bad group slug: %v", err)
	}
	outsider := x.f.user("", timeNow())
	if err := s.AddGroupMember(ctx, x.org, g.ID, outsider, "", &x.owner, nil); !errors.Is(err, ErrAccessInvalid) {
		t.Errorf("non-member in group: %v", err)
	}
	if err := s.AddGroupMember(ctx, other, g.ID, x.user, "", nil, nil); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("cross-org group add: %v", err)
	}
	gexp := time.Now().Add(2 * time.Hour).Truncate(time.Microsecond)
	if err := s.AddGroupMember(ctx, x.org, g.ID, x.user, "", &x.owner, &gexp); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "group", SubjectID: g.ID, ScopeType: "org", ScopeID: x.org, TemplateID: x.viewerTpl}); err != nil {
		t.Fatal(err)
	}
	// group of another organization as subject: rejected
	if _, _, err := s.Assign(ctx, other, NewAssignment{SubjectType: "group", SubjectID: g.ID, ScopeType: "org", ScopeID: other, TemplateID: x.viewerTpl}); !errors.Is(err, ErrAccessInvalid) {
		t.Errorf("foreign group subject: %v", err)
	}
	ass, err := s.LoadUserAssignments(ctx, x.org, x.user)
	if err != nil || len(ass) != 2 {
		t.Fatalf("LoadUserAssignments: %d %v", len(ass), err)
	}
	var viaGroup, direct int
	for _, a := range ass {
		if a.ViaGroup != nil {
			viaGroup++
			if *a.ViaGroup != g.ID || a.GroupExpiresAt == nil || !a.GroupExpiresAt.Equal(gexp) || a.SubjectType != "group" {
				t.Errorf("group row: %+v", a)
			}
		} else {
			direct++
		}
	}
	if viaGroup != 1 || direct != 1 {
		t.Errorf("rows: %d via group, %d direct", viaGroup, direct)
	}
	if err := s.ArchiveGroup(ctx, x.org, g.ID); err != nil {
		t.Fatal(err)
	}
	if ass, _ = s.LoadUserAssignments(ctx, x.org, x.user); len(ass) != 1 {
		t.Errorf("archived group still contributes: %d rows", len(ass))
	}
	if err := s.AddGroupMember(ctx, x.org, g.ID, x.owner, "", nil, nil); !errors.Is(err, ErrAccessInvalid) {
		t.Errorf("add to archived group: %v", err)
	}
	if err := s.RemoveGroupMember(ctx, x.org, g.ID, x.user); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveGroupMember(ctx, x.org, g.ID, x.user); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("remove twice: %v", err)
	}
	// who has access to X
	list, err := s.ListScopeAssignments(ctx, x.org, "project", x.p1)
	if err != nil || len(list) != 1 {
		t.Errorf("ListScopeAssignments: %d %v", len(list), err)
	}
	// revoke
	if err := s.Revoke(ctx, x.org, a1.ID, &x.owner); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, x.org, a1.ID, &x.owner); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("revoke twice: %v", err)
	}
	if err := s.Revoke(ctx, other, uuid.New(), nil); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("revoke unknown: %v", err)
	}
	// revoke then assign again creates a fresh row (partial unique index only covers live rows)
	a3, c3, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: x.user, ScopeType: "project", ScopeID: x.p1, TemplateID: x.depl})
	if err != nil || !c3 || a3.ID == a1.ID {
		t.Errorf("re-assign after revoke: %+v %v %v", a3, c3, err)
	}
}

func TestAccessStorePolicyMembershipEpochs(t *testing.T) {
	x := newTfx(t)
	ctx := context.Background()
	s := NewAccessStore(x.pool)

	m, err := s.LoadMembership(ctx, x.org, x.user)
	if err != nil || m == nil || m.LegacyRole != "member" || m.Status != "active" || m.UserStatus != "active" || m.PlatformRole != "user" ||
		m.TemplateID == nil || *m.TemplateID != SystemTemplateID("org", "member") || m.TemplateVersion != nil {
		t.Fatalf("membership: %+v %v", m, err)
	}
	if m, err := s.LoadMembership(ctx, x.org, uuid.New()); err != nil || m != nil {
		t.Errorf("non-member: %+v %v", m, err)
	}
	p, err := s.LoadOrgPolicy(ctx, x.org)
	if err != nil || p.Mode != "open" {
		t.Fatalf("policy: %+v %v", p, err)
	}
	if _, err := s.LoadOrgPolicy(ctx, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("missing org policy: %v", err)
	}
	oe0, ue0, err := s.Epochs(ctx, x.org, x.user)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetOrgAccessMode(ctx, x.org, "restricted"); err != nil {
		t.Fatal(err)
	}
	mode := "restricted"
	if err := s.SetProjectAccessOverride(ctx, x.org, x.p1, &mode); err != nil {
		t.Fatal(err)
	}
	if err := s.MergeOrgAccessSettings(ctx, x.org, map[string]any{"custom_roles": true, "temp_access_max_days": 30}); err != nil {
		t.Fatal(err)
	}
	if err := s.MergeOrgAccessSettings(ctx, x.org, map[string]any{"engine": "shadow"}); err != nil {
		t.Fatal(err)
	}
	p, _ = s.LoadOrgPolicy(ctx, x.org)
	if p.Mode != "restricted" || !strings.Contains(string(p.Settings), `"custom_roles": true`) || !strings.Contains(string(p.Settings), `"engine": "shadow"`) {
		t.Errorf("policy after writes: %+v %s", p, p.Settings)
	}
	ov, err := s.LoadProjectOverrides(ctx, x.org)
	if err != nil || ov[x.p1] != "restricted" || len(ov) != 1 {
		t.Errorf("overrides: %v %v", ov, err)
	}
	if err := s.SetProjectAccessOverride(ctx, x.org, x.p1, nil); err != nil {
		t.Fatal(err)
	}
	if ov, _ = s.LoadProjectOverrides(ctx, x.org); len(ov) != 0 {
		t.Errorf("override not cleared: %v", ov)
	}
	otherProj := x.f.project(x.f.org(x.owner), "")
	if err := s.SetProjectAccessOverride(ctx, x.org, otherProj, &mode); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("override on foreign project: %v", err)
	}
	if err := s.SetProjectAccessOverride(ctx, x.org, x.p1, ptr("bogus")); !errors.Is(err, ErrAccessInvalid) {
		t.Errorf("bad override value: %v", err)
	}
	oe1, _, _ := s.Epochs(ctx, x.org, x.user)
	// 4 successful commands (mode, override, 2 merges) + 1 clear = 5 bumps; the failed ones must not bump
	if oe1-oe0 != 5 {
		t.Errorf("org epoch delta %d, want 5 (failed commands must not bump)", oe1-oe0)
	}
	if err := s.BumpUser(ctx, x.user); err != nil {
		t.Fatal(err)
	}
	if _, ue1, _ := s.Epochs(ctx, x.org, x.user); ue1 != ue0+1 {
		t.Errorf("user epoch %d -> %d", ue0, ue1)
	}
	if err := s.BumpUser(ctx, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("bump unknown user: %v", err)
	}
	// suspended user/member surface in the membership (the engine decides what that means)
	mustExec(t, x.pool, `UPDATE users SET role='suspended' WHERE id=$1`, x.user)
	mustExec(t, x.pool, `UPDATE org_members SET status='suspended' WHERE org_id=$1 AND user_id=$2`, x.org, x.user)
	if m, _ = s.LoadMembership(ctx, x.org, x.user); m.UserStatus != "suspended" || m.Status != "suspended" {
		t.Errorf("suspension not visible: %+v", m)
	}
	// soft-deleted organization is invisible
	mustExec(t, x.pool, `UPDATE organizations SET deleted_at=now() WHERE id=$1`, x.org)
	if m, _ = s.LoadMembership(ctx, x.org, x.owner); m != nil {
		t.Errorf("membership of a deleted organization: %+v", m)
	}
	if err := s.SetOrgAccessMode(ctx, x.org, "open"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("write to a deleted organization: %v", err)
	}
}

func TestAccessStoreEnvReviewers(t *testing.T) {
	x := newTfx(t)
	ctx := context.Background()
	s := NewAccessStore(x.pool)
	var env uuid.UUID
	if err := x.pool.QueryRow(ctx, `INSERT INTO environments (project_id,name,target_project_id,reviewers) VALUES ($1,'prod',$1,$2::jsonb) RETURNING id`,
		x.p1, fmt.Sprintf(`[{"type":"user","user_id":"%s"}]`, x.user)).Scan(&env); err != nil {
		t.Fatal(err)
	}
	pid, rev, err := s.EnvReviewers(ctx, env)
	if err != nil || pid != x.p1 || !strings.Contains(string(rev), x.user.String()) {
		t.Errorf("EnvReviewers: %s %s %v", pid, rev, err)
	}
	// env scope assignments validate against the environment's project
	if _, _, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: x.user, ScopeType: "env", ScopeID: env, TemplateID: x.viewerTpl, Source: "approver"}); err != nil {
		t.Errorf("env assignment: %v", err)
	}
	if _, _, err := s.Assign(ctx, x.f.org(x.owner), NewAssignment{SubjectType: "user", SubjectID: x.user, ScopeType: "env", ScopeID: env, TemplateID: x.viewerTpl}); err == nil {
		t.Errorf("env of another org accepted")
	}
	mustExec(t, x.pool, `DELETE FROM environments WHERE id=$1`, env)
	if n := qInt(t, x.pool, `SELECT count(*) FROM access_assignments WHERE scope_id=$1`, env); n != 0 {
		t.Errorf("assignments of a deleted environment survived: %d", n)
	}
	if _, _, err := s.EnvReviewers(ctx, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("unknown env: %v", err)
	}
}

// Concurrent commands: no lost updates, exactly one live row for identical assignments, and the organization epoch advances once
// per committed command and never goes backwards as seen by any reader.
func TestAccessStoreConcurrentAssignAndEpoch(t *testing.T) {
	x := newTfx(t)
	ctx := context.Background()
	s := NewAccessStore(x.pool)
	const n = 40
	users := make([]uuid.UUID, n)
	for i := range users {
		users[i] = x.f.user("", timeNow())
		x.f.member(x.org, users[i], "member")
	}
	// legacy writes above bumped the epoch through the triggers: take the baseline now
	e0 := epochOf(t, x.pool, x.org)

	var stop atomic.Bool
	var readerErr atomic.Value
	var wgR sync.WaitGroup
	wgR.Add(1)
	go func() { // monotonic reader
		defer wgR.Done()
		last := int64(-1)
		for !stop.Load() {
			e, _, err := s.Epochs(ctx, x.org, x.user)
			if err != nil {
				readerErr.Store(err)
				return
			}
			if e < last {
				readerErr.Store(fmt.Errorf("epoch went backwards: %d -> %d", last, e))
				return
			}
			last = e
		}
	}()

	var wg sync.WaitGroup
	var created atomic.Int32
	var errs atomic.Int32
	same := users[0]
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) { // distinct assignment per goroutine
			defer wg.Done()
			if _, c, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: users[i], ScopeType: "project", ScopeID: x.p1, TemplateID: x.viewerTpl}); err != nil {
				errs.Add(1)
			} else if c {
				created.Add(1)
			}
		}(i)
		go func() { // identical assignment from every goroutine
			defer wg.Done()
			if _, c, err := s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: same, ScopeType: "repo", ScopeID: x.p1, TemplateID: SystemTemplateID("repo", "repo-read")}); err != nil {
				errs.Add(1)
			} else if c {
				created.Add(1)
			}
		}()
	}
	wg.Wait()
	stop.Store(true)
	wgR.Wait()
	if v := readerErr.Load(); v != nil {
		t.Fatal(v)
	}
	if errs.Load() != 0 {
		t.Fatalf("%d commands failed", errs.Load())
	}
	if created.Load() != n+1 {
		t.Errorf("created rows %d, want %d (n distinct + exactly one of the identical)", created.Load(), n+1)
	}
	if got := qInt(t, x.pool, `SELECT count(*) FROM access_assignments WHERE scope_id=$1 AND source='manual' AND revoked_at IS NULL`, x.p1); got != n+1 {
		t.Errorf("live rows %d, want %d", got, n+1)
	}
	// every command bumps exactly once (manual assignments are not mirrored, so no trigger bumps)
	if d := epochOf(t, x.pool, x.org) - e0; d != 2*n {
		t.Errorf("epoch delta %d, want %d", d, 2*n)
	}
	// concurrent last-write on the same assignment: one winner row, no duplicates
	var wg2 sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			exp := time.Now().Add(time.Duration(i+1) * time.Hour)
			_, _, _ = s.Assign(ctx, x.org, NewAssignment{SubjectType: "user", SubjectID: same, ScopeType: "repo", ScopeID: x.p1, TemplateID: SystemTemplateID("repo", "repo-read"), ExpiresAt: &exp})
		}(i)
	}
	wg2.Wait()
	if got := qInt(t, x.pool, `SELECT count(*) FROM access_assignments WHERE subject_id=$1 AND scope_type='repo' AND revoked_at IS NULL`, same); got != 1 {
		t.Errorf("duplicates after concurrent updates: %d", got)
	}
	// concurrent legacy writes (project_members trigger path) and new-path writes on the same project
	var wg3 sync.WaitGroup
	for i := 0; i < n; i++ {
		wg3.Add(1)
		go func(i int) {
			defer wg3.Done()
			role := []string{"viewer", "deployer", "admin"}[i%3]
			_, _ = x.pool.Exec(ctx, `INSERT INTO project_members (project_id,user_id,role) VALUES ($1,$2,$3) ON CONFLICT (project_id,user_id) DO UPDATE SET role=EXCLUDED.role`, x.p1, users[i], role)
		}(i)
	}
	wg3.Wait()
	// every legacy row has exactly one live assignment of its role (a manual one of the same template counts: unique per template)
	if bad := qInt(t, x.pool, `
		SELECT count(*) FROM project_members pm WHERE (
		  SELECT count(*) FROM access_assignments a JOIN role_templates t ON t.id=a.template_id
		   WHERE a.subject_id=pm.user_id AND a.scope_id=pm.project_id AND a.revoked_at IS NULL AND t.kind='project' AND t.slug=pm.role) <> 1`); bad != 0 {
		t.Errorf("%d project_members rows without exactly one mirrored assignment after concurrent writes", bad)
	}
}

// ---------------------------------------------------------------- NOTIFY

func TestAccessNotifyTransactionalAndLatency(t *testing.T) {
	x := newTfx(t)
	s := NewAccessStore(x.pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type ev struct {
		org uuid.UUID
		at  time.Time
	}
	events := make(chan ev, 4096)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Listen(ctx, func(id uuid.UUID) { events <- ev{id, time.Now()} })
	}()
	// the first callback is the "flush everything" of the (re)connection
	select {
	case e := <-events:
		if e.org != uuid.Nil {
			t.Fatalf("first event must be uuid.Nil, got %s", e.org)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not start")
	}
	expectNone := func(d time.Duration, why string) {
		t.Helper()
		select {
		case e := <-events:
			t.Fatalf("%s: unexpected event %v", why, e)
		case <-time.After(d):
		}
	}
	// 1. a rolled back command emits nothing; the NOTIFY is only delivered on commit
	tx, err := x.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT access_bump_org($1)`, x.org); err != nil {
		t.Fatal(err)
	}
	expectNone(300*time.Millisecond, "before commit")
	_ = tx.Rollback(ctx)
	expectNone(300*time.Millisecond, "after rollback")
	failing := s.InTx(ctx, x.org, func(tx pgx.Tx) error { return errors.New("boom") })
	if failing == nil {
		t.Fatal("InTx must propagate the error")
	}
	expectNone(300*time.Millisecond, "failed command")

	// 2. a committed command delivers its organization id
	if err := s.SetOrgAccessMode(ctx, x.org, "restricted"); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-events:
		if e.org != x.org {
			t.Fatalf("event for %s, want %s", e.org, x.org)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event after commit")
	}
	// legacy write through a trigger notifies too
	mustExec(t, x.pool, `UPDATE org_members SET role='admin' WHERE org_id=$1 AND user_id=$2`, x.org, x.user)
	select {
	case e := <-events:
		if e.org != x.org {
			t.Fatalf("trigger event for %s", e.org)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event from legacy write")
	}
	// suspension of an account notifies each of its organizations
	mustExec(t, x.pool, `UPDATE users SET role='suspended' WHERE id=$1`, x.user)
	select {
	case e := <-events:
		if e.org != x.org {
			t.Fatalf("user event for %s", e.org)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event from account suspension")
	}
	for len(events) > 0 {
		<-events
	}

	// 3. latency of 1 000 events delivered to an independent connection: p99 < 1 s (measured; expected few ms)
	const n = 1000
	lat := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		if _, err := x.pool.Exec(ctx, `SELECT access_bump_org($1)`, x.org); err != nil {
			t.Fatal(err)
		}
		select {
		case e := <-events:
			lat = append(lat, e.at.Sub(start))
		case <-time.After(3 * time.Second):
			t.Fatalf("event %d lost", i)
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p50, p99, mx := lat[n/2], lat[n*99/100], lat[n-1]
	t.Logf("NOTIFY latency over %d events (independent listener connection): p50=%v p99=%v max=%v", n, p50, p99, mx)
	if p99 >= time.Second {
		t.Errorf("p99 %v >= 1s", p99)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("listener did not stop on cancel")
	}
}

// ---------------------------------------------------------------- seed

func TestSeedFailsClosedOnDrift(t *testing.T) {
	pool := accessDB(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// bypass the immutability trigger as a superuser would, to simulate a database that disagrees with the file
	if _, err := tx.Exec(ctx, `ALTER TABLE role_template_versions DISABLE TRIGGER role_template_versions_immutable`); err != nil {
		t.Skipf("cannot disable trigger: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE role_template_versions SET permissions = array_append(permissions, 'git:admin') WHERE template_id = $1`, SystemTemplateID("project", "viewer")); err != nil {
		t.Fatal(err)
	}
	if _, err := SeedSystemTemplatesTx(ctx, tx); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Errorf("seed over drifted version: %v", err)
	}
}
