package gitsync

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

func TestTeamSpecsOwnerDecisions(t *testing.T) {
	s := TeamSpecs("api")
	if s[authz.RoleAdmin].Permission != "write" || s[authz.RoleDeployer].Permission != "write" || s[authz.RoleViewer].Permission != "read" {
		t.Fatalf("permissions: %+v", s)
	}
	for role, sp := range s {
		if sp.Permission == "admin" {
			t.Errorf("%s team must not be admin: only the Capsule service account administers repos", role)
		}
		for _, u := range sp.Units {
			for _, bad := range []string{"issues", "wiki", "projects", "settings", "packages"} {
				if strings.Contains(u, bad) {
					t.Errorf("%s team has unit %s", role, u)
				}
			}
		}
		if !strings.HasPrefix(sp.Name, "api-") {
			t.Errorf("bad team name %s", sp.Name)
		}
	}
}

func TestMatrixOrgRoleModeExplicit(t *testing.T) {
	type tc struct{ org, mode, explicit, team string } // team "" = in no team
	cases := []tc{
		{"owner", authz.ModeOpen, "", "api-admin"},
		{"owner", authz.ModeRestricted, "", "api-admin"},
		{"admin", authz.ModeRestricted, "viewer", "api-admin"}, // org admin beats an explicit row
		{"member", authz.ModeOpen, "", "api-deployer"},
		{"member", authz.ModeOpen, "viewer", "api-viewer"},
		{"member", authz.ModeOpen, "admin", "api-admin"},
		{"member", authz.ModeRestricted, "", ""},
		{"member", authz.ModeRestricted, "deployer", "api-deployer"},
		{"readonly", authz.ModeOpen, "", "api-viewer"},
		{"readonly", authz.ModeOpen, "admin", "api-viewer"}, // never more than viewer
		{"readonly", authz.ModeRestricted, "", ""},          // hidden: in no team
		{"readonly", authz.ModeRestricted, "viewer", "api-viewer"},
		{"bogus", authz.ModeOpen, "", ""},
	}
	for _, c := range cases {
		t.Run(c.org+"/"+c.mode+"/"+c.explicit, func(t *testing.T) {
			f := newFixture(t)
			id := f.add("ana", c.org, true)
			f.dir.mode = c.mode
			if c.explicit != "" {
				f.dir.explicit[id] = c.explicit
			}
			f.run(t, TriggerEvent)
			if c.team == "" {
				inTeams(t, f, "ana")
				if len(f.pend.pending[f.proj]) != 0 {
					t.Errorf("a user with no access must not be queued as pending: %v", f.pend.pending[f.proj])
				}
				return
			}
			inTeams(t, f, "ana", c.team)
		})
	}
}

func TestIdempotentAndNoMutationsOnSecondRun(t *testing.T) {
	f := newFixture(t)
	f.add("ana", "owner", true)
	f.add("bob", "member", true)
	f.add("cy", "readonly", true)
	r1 := f.run(t, TriggerEvent)
	if len(r1.Added) != 3 || len(r1.Removed) != 0 {
		t.Fatalf("first run: %+v", r1)
	}
	before := f.forge.mutations
	r2 := f.run(t, TriggerPeriodic)
	if len(r2.Added)+len(r2.Removed) != 0 || r2.Drift || f.forge.mutations != before {
		t.Fatalf("second run changed things: %+v (mutations %d -> %d)", r2, before, f.forge.mutations)
	}
	if len(f.states.audits) != 0 {
		t.Errorf("no drift expected, audits: %v", f.states.audits)
	}
	st, _ := f.states.ListTeamStates(context.Background(), f.proj)
	if len(st) != 3 {
		t.Fatalf("team state rows: %d", len(st))
	}
	for _, s := range st {
		if s.Members != 1 || s.DriftEvents != 0 {
			t.Errorf("state %s: %+v", s.Role, s)
		}
	}
}

func TestUserNotInForgejoYetIsPendingThenAdded(t *testing.T) {
	f := newFixture(t)
	id := f.add("newbie", "member", false)
	f.add("ana", "owner", true)
	rep := f.run(t, TriggerEvent)
	if len(rep.Pending) != 1 || rep.Pending[0] != id {
		t.Fatalf("pending: %v", rep.Pending)
	}
	inTeams(t, f, "ana", "api-admin")
	inTeams(t, f, "newbie")
	if got := f.pend.pending[f.proj]; len(got) != 1 || got[0] != id {
		t.Fatalf("queue: %v", got)
	}
	// first OIDC login happens
	f.forge.users["newbie"] = true
	rep = f.run(t, TriggerEvent)
	inTeams(t, f, "newbie", "api-deployer")
	if len(rep.Pending) != 0 || len(f.pend.pending[f.proj]) != 0 {
		t.Fatalf("pending not cleared: %v / %v", rep.Pending, f.pend.pending[f.proj])
	}
	if got, _ := f.ids.Get(context.Background(), id); got.LinkedAt == nil {
		t.Error("identity must be marked linked once the Forgejo user exists")
	}
}

func TestRoleRemovalDropsTeamAndPendingReviews(t *testing.T) {
	f := newFixture(t)
	f.add("ana", "owner", true)
	f.add("bob", "member", true)
	f.add("cy", "member", true)
	f.run(t, TriggerEvent)
	inTeams(t, f, "bob", "api-deployer")

	// bob leaves the org; cy is downgraded to a viewer row (can no longer review)
	f.remove("bob")
	f.dir.mode = authz.ModeRestricted
	f.dir.explicit[f.users["cy"]] = "viewer"
	rep := f.run(t, TriggerEvent)

	inTeams(t, f, "bob")
	inTeams(t, f, "cy", "api-viewer")
	sort.Strings(rep.Removed)
	if fmt.Sprint(rep.Removed) != "[bob cy]" {
		t.Fatalf("removed: %v", rep.Removed)
	}
	sort.Strings(f.jan.calls)
	if fmt.Sprint(f.jan.calls) != "[acme/api:bob acme/api:cy]" {
		t.Fatalf("janitor calls: %v", f.jan.calls)
	}
	if rep.ReviewsDropped != 4 {
		t.Errorf("reviews dropped %d", rep.ReviewsDropped)
	}
}

func TestJanitorSkippedWhenRoleStillReviews(t *testing.T) {
	f := newFixture(t)
	f.add("ana", "owner", true)
	f.add("bob", "member", true)
	f.run(t, TriggerEvent)
	f.dir.explicit[f.users["bob"]] = "admin" // deployer -> admin: moves team, keeps git.review
	f.dir.mode = authz.ModeRestricted
	f.run(t, TriggerEvent)
	inTeams(t, f, "bob", "api-admin")
	if len(f.jan.calls) != 0 {
		t.Fatalf("janitor called for a user who can still review: %v", f.jan.calls)
	}
}

func TestManualAddIsRemovedAndCountedAsDriftOnPeriodicPass(t *testing.T) {
	f := newFixture(t)
	f.add("ana", "owner", true)
	f.add("cy", "readonly", true)
	f.run(t, TriggerEvent)

	// somebody adds mallory by hand to the admin team and removes cy from viewer
	f.forge.users["mallory"] = true
	tid := f.forge.teams["acme/api-admin"].ID
	f.forge.members[tid]["mallory"] = true
	delete(f.forge.members[f.forge.teams["acme/api-viewer"].ID], "cy")

	rep := f.run(t, TriggerPeriodic)
	inTeams(t, f, "mallory")
	inTeams(t, f, "cy", "api-viewer")
	if !rep.Drift || fmt.Sprint(rep.Removed) != "[mallory]" || fmt.Sprint(rep.Added) != "[cy]" {
		t.Fatalf("report: %+v", rep)
	}
	if len(f.states.audits) != 1 || f.states.audits[0].action != "git.team_drift" {
		t.Fatalf("audits: %+v", f.states.audits)
	}
	st, _ := f.states.ListTeamStates(context.Background(), f.proj)
	for _, s := range st {
		switch s.Role {
		case authz.RoleAdmin:
			if s.DriftEvents != 1 || s.LastDriftRemoved != 1 || s.LastDriftAt == nil {
				t.Errorf("admin state: %+v", s)
			}
		case authz.RoleViewer:
			if s.DriftEvents != 1 || s.LastDriftAdded != 1 {
				t.Errorf("viewer state: %+v", s)
			}
		case authz.RoleDeployer:
			if s.DriftEvents != 0 {
				t.Errorf("deployer state: %+v", s)
			}
		}
	}

	// an event-driven pass corrects the same way but is not drift
	f.forge.members[tid]["mallory"] = true
	rep = f.run(t, TriggerEvent)
	inTeams(t, f, "mallory")
	if rep.Drift || len(f.states.audits) != 1 {
		t.Fatalf("event pass counted as drift: %+v", rep)
	}
}

type patchingForge struct {
	*memForge
	patched []gitcore.TeamSpec
}

func (p *patchingForge) PatchTeam(_ context.Context, _ string, _ int64, s gitcore.TeamSpec) error {
	p.patched = append(p.patched, s)
	return nil
}

func TestPermissionDriftReportedAndPatched(t *testing.T) {
	f := newFixture(t)
	f.add("ana", "owner", true)
	f.run(t, TriggerEvent)
	f.forge.permOf["api-admin"] = "admin" // legacy team created with admin permission
	rep := f.run(t, TriggerManual)
	if !rep.Drift || fmt.Sprint(rep.PermissionDrift) != "[api-admin]" {
		t.Fatalf("report: %+v", rep)
	}
	pf := &patchingForge{memForge: f.forge}
	f.rec.Forge = pf
	f.run(t, TriggerManual)
	if len(pf.patched) != 1 || pf.patched[0].Permission != "write" {
		t.Fatalf("patched: %+v", pf.patched)
	}
}

func TestKeepAndFailureIsolation(t *testing.T) {
	f := newFixture(t)
	f.add("ana", "owner", true)
	f.run(t, TriggerEvent)
	for _, l := range []string{"capsule-bot", "x1", "x2"} {
		f.forge.users[l] = true
		f.forge.members[f.forge.teams["acme/api-viewer"].ID][l] = true
	}
	f.rec.Keep = []string{"Capsule-Bot"}
	f.forge.failRm["x1"] = true
	rep, err := f.rec.Reconcile(context.Background(), f.proj, TriggerEvent)
	if err == nil || !strings.Contains(err.Error(), "x1") {
		t.Fatalf("expected an error about x1, got %v", err)
	}
	if fmt.Sprint(rep.Removed) != "[x2]" {
		t.Fatalf("x2 must still be removed: %v", rep.Removed)
	}
	inTeams(t, f, "capsule-bot", "api-viewer")
	inTeams(t, f, "x1", "api-viewer")
	st, _ := f.states.ListTeamStates(context.Background(), f.proj)
	hasErr := false
	for _, s := range st {
		hasErr = hasErr || s.LastError != ""
	}
	if !hasErr {
		t.Errorf("last_error not recorded: %+v", st)
	}
}

func TestExistenceCheckFailureFailsClosedAndQueues(t *testing.T) {
	f := newFixture(t)
	id := f.add("ana", "member", true)
	f.run(t, TriggerEvent)
	// the role changes while Forgejo cannot answer user lookups: stale access is still removed
	f.dir.mode = authz.ModeRestricted
	f.dir.explicit[id] = "viewer"
	f.forge.failExist = true
	rep, err := f.rec.Reconcile(context.Background(), f.proj, TriggerEvent)
	if err == nil {
		t.Fatal("expected an error")
	}
	inTeams(t, f, "ana")
	if len(rep.Pending) != 1 {
		t.Fatalf("pending: %v", rep.Pending)
	}
	f.forge.failExist = false
	f.run(t, TriggerEvent)
	inTeams(t, f, "ana", "api-viewer")
}

func TestStoredIdentityWinsOverEmailChange(t *testing.T) {
	f := newFixture(t)
	id := f.add("ana", "owner", true)
	f.forge.users["old-ana"] = true
	if _, err := f.ids.Ensure(context.Background(), id, "old-ana"); err != nil {
		t.Fatal(err)
	}
	f.run(t, TriggerEvent)
	inTeams(t, f, "old-ana", "api-admin")
	inTeams(t, f, "ana")
}

func TestLoginCollisionQueuesTheSecondUser(t *testing.T) {
	f := newFixture(t)
	f.add("ana", "owner", true)
	// another user whose e-mail sanitizes to the same login (no Taken probe wired here)
	other := uuid.New()
	f.dir.members = append(f.dir.members, Member{UserID: other, Email: "ana@y.io", OrgRole: "member"})
	rep, err := f.rec.Reconcile(context.Background(), f.proj, TriggerEvent)
	if err == nil || !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("want ErrUsernameTaken, got %v", err)
	}
	if len(rep.Pending) != 1 || rep.Pending[0] != other {
		t.Fatalf("pending: %v", rep.Pending)
	}
	inTeams(t, f, "ana", "api-admin")
}

func TestNoOpCases(t *testing.T) {
	f := newFixture(t)
	if rep, err := f.rec.Reconcile(context.Background(), uuid.New(), TriggerEvent); rep != nil || err != nil {
		t.Errorf("unknown / non-forgejo project: %v %v", rep, err)
	}
	f.forge.disabled = true
	f.add("ana", "owner", true)
	if rep, err := f.rec.Reconcile(context.Background(), f.proj, TriggerEvent); rep != nil || err != nil {
		t.Errorf("disabled forge: %v %v", rep, err)
	}
	if f.forge.mutations != 0 {
		t.Error("disabled forge was touched")
	}
	var nilRec *Reconciler
	if err := nilRec.SyncProject(context.Background(), f.proj); err != nil {
		t.Error(err)
	}
}

func TestReconcileAllWalksProjectsInPages(t *testing.T) {
	f := newFixture(t)
	f.add("ana", "owner", true)
	for i := 0; i < 130; i++ {
		f.states.projects = append(f.states.projects, uuid.New()) // not in the directory: no-ops
	}
	sum, err := f.rec.ReconcileAll(context.Background(), TriggerPeriodic)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Projects != 131 || sum.Added != 1 || sum.Failed != 0 {
		t.Fatalf("summary: %+v", sum)
	}
	if _, err := (&Reconciler{}).ReconcileAll(context.Background(), TriggerManual); err == nil {
		t.Error("a reconciler without a state store cannot enumerate")
	}
}

func TestIdentitiesDeriveAndOnLogin(t *testing.T) {
	st := newMemIDs()
	taken := map[string]bool{}
	ids := &Identities{Store: st, Taken: func(_ context.Context, _ uuid.UUID, b string) (bool, error) { return taken[b], nil }}
	u1, u2 := uuid.New(), uuid.New()
	l1, err := ids.DeriveLogin(context.Background(), u1, "Ana.Perez@x.io")
	if err != nil || l1 != "ana.perez" {
		t.Fatalf("derive: %q %v", l1, err)
	}
	if err := ids.OnLogin(context.Background(), u1, "Ana.Perez@x.io"); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(context.Background(), u1); got == nil || got.ForgejoUsername != "ana.perez" {
		t.Fatalf("stored: %+v", got)
	}
	taken["ana.perez"] = true
	l2, _ := ids.DeriveLogin(context.Background(), u2, "ana.perez@y.io")
	if !strings.HasPrefix(l2, "ana.perez-") || len(l2) != len("ana.perez-")+6 {
		t.Fatalf("collision suffix: %q", l2)
	}
	// a repeat login does not hit the store again (in-process memo)
	delete(st.rows, u1)
	if err := ids.OnLogin(context.Background(), u1, "Ana.Perez@x.io"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(context.Background(), u1); !errors.Is(err, ErrNoIdentity) {
		t.Error("OnLogin should be a no-op after the first success in this process")
	}
}
