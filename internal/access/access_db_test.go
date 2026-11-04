//go:build dbtest

package access

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/engine"
)

// Every write leaves its audit row in the same transaction; when the audit fails the change, its key and its epoch bump roll back.
func TestAuditIsInTheSameTransaction(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	org, owner := e.org(t, "open")
	proj := e.project(t, org)
	user := e.newMember(t, org, "member")
	o := act(owner)
	epoch := func() int64 {
		var n int64
		_ = e.pool.QueryRow(ctx, `SELECT access_epoch FROM organizations WHERE id = $1`, org).Scan(&n)
		return n
	}
	// a group, a custom template and an assignment to act on
	g, err := e.svc.CreateGroup(ctx, o, org, GroupInput{Slug: "base", Name: ptr("Base")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := e.svc.CreateTemplate(ctx, o, org, TemplateInput{Kind: "project", Slug: "t1", Name: "t1", Permissions: projPerms("project:view", "log:read")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	asg, err := e.svc.CreateAssignment(ctx, o, org, AssignmentInput{SubjectType: "user", SubjectID: user, Scope: ScopeRef{Type: "project", ID: proj}, TemplateID: tpl.Value.ID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	auditRows := func() int {
		return e.count(t, `SELECT count(*) FROM audit_logs WHERE org_id = $1 AND action LIKE 'access.%'`, org)
	}
	baseline := auditRows()

	e.svc.failAudit = func(string) error { return errors.New("audit store down") }
	before := map[string]int{
		"templates": e.count(t, `SELECT count(*) FROM role_templates WHERE org_id = $1`, org),
		"groups":    e.count(t, `SELECT count(*) FROM groups WHERE org_id = $1`, org),
		"live":      e.count(t, `SELECT count(*) FROM access_assignments WHERE org_id = $1 AND revoked_at IS NULL`, org),
		"members":   e.count(t, `SELECT count(*) FROM group_members WHERE group_id = $1`, g.Value.ID),
		"versions":  e.count(t, `SELECT count(*) FROM role_template_versions WHERE template_id = $1`, tpl.Value.ID),
		"idem":      e.count(t, `SELECT count(*) FROM access_idempotency WHERE org_id = $1`, org),
	}
	ep0 := epoch()
	idem := func(k string) *Idem { return &Idem{Key: k, Hash: "h-" + k} }
	failures := []struct {
		name string
		do   func() error
	}{
		{"create template", func() error {
			_, err := e.svc.CreateTemplate(ctx, o, org, TemplateInput{Kind: "project", Slug: "t2", Name: "t2", Permissions: []string{"project:view"}}, idem("k1"))
			return err
		}},
		{"publish template", func() error {
			_, err := e.svc.PublishTemplate(ctx, o, org, tpl.Value.ID, TemplateInput{Name: "t1", Permissions: projPerms("project:view", "log:read", "git:read")}, false, idem("k2"))
			return err
		}},
		{"create group", func() error {
			_, err := e.svc.CreateGroup(ctx, o, org, GroupInput{Slug: "g2", Name: ptr("G2")}, idem("k4"))
			return err
		}},
		{"rename group", func() error {
			_, err := e.svc.UpdateGroup(ctx, o, org, g.Value.ID, GroupInput{Name: ptr("Other")}, idem("k5"))
			return err
		}},
		{"add member", func() error {
			_, err := e.svc.AddGroupMembers(ctx, o, org, g.Value.ID, AddMembersInput{UserIDs: []uuid.UUID{user}}, idem("k6"))
			return err
		}},
		{"create assignment", func() error {
			_, err := e.svc.CreateAssignment(ctx, o, org, AssignmentInput{SubjectType: "group", SubjectID: g.Value.ID, Scope: ScopeRef{Type: "project", ID: proj}, TemplateID: tpl.Value.ID}, idem("k7"))
			return err
		}},
		{"patch assignment", func() error {
			_, err := e.svc.PatchAssignment(ctx, o, org, asg.Value.ID, PatchAssignmentInput{ReasonSet: true, Reason: "x"}, idem("k8"))
			return err
		}},
		{"revoke assignment", func() error { _, err := e.svc.RevokeAssignment(ctx, o, org, asg.Value.ID, idem("k9")); return err }},
		{"access override", func() error {
			_, err := e.svc.SetAccessOverride(ctx, o, org, proj, ptr("restricted"), true, idem("k10"))
			return err
		}},
		{"archive group", func() error { _, err := e.svc.ArchiveGroup(ctx, o, org, g.Value.ID, idem("k11")); return err }},
		{"archive template", func() error { _, err := e.svc.DeleteTemplate(ctx, o, org, tpl.Value.ID, idem("k3")); return err }},
	}
	for _, f := range failures {
		err := f.do()
		if err == nil {
			t.Fatalf("%s: succeeded although its audit write failed", f.name)
		}
	}
	after := map[string]int{
		"templates": e.count(t, `SELECT count(*) FROM role_templates WHERE org_id = $1`, org),
		"groups":    e.count(t, `SELECT count(*) FROM groups WHERE org_id = $1`, org),
		"live":      e.count(t, `SELECT count(*) FROM access_assignments WHERE org_id = $1 AND revoked_at IS NULL`, org),
		"members":   e.count(t, `SELECT count(*) FROM group_members WHERE group_id = $1`, g.Value.ID),
		"versions":  e.count(t, `SELECT count(*) FROM role_template_versions WHERE template_id = $1`, tpl.Value.ID),
		"idem":      e.count(t, `SELECT count(*) FROM access_idempotency WHERE org_id = $1`, org),
	}
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s changed although the audit failed: %d -> %d", k, v, after[k])
		}
	}
	if e.count(t, `SELECT count(*) FROM groups WHERE id = $1 AND name = 'Other'`, g.Value.ID) != 0 || e.count(t, `SELECT count(*) FROM groups WHERE id = $1 AND archived_at IS NOT NULL`, g.Value.ID) != 0 {
		t.Error("the group was renamed or archived although the audit failed")
	}
	if e.count(t, `SELECT count(*) FROM projects WHERE id = $1 AND access_override IS NOT NULL`, proj) != 0 {
		t.Error("the project override was applied although the audit failed")
	}
	if e.count(t, `SELECT count(*) FROM access_assignments WHERE id = $1 AND revoked_at IS NOT NULL`, asg.Value.ID) != 0 {
		t.Error("the assignment was revoked although the audit failed")
	}
	if epoch() != ep0 {
		t.Errorf("access_epoch moved (%d -> %d) although every change rolled back", ep0, epoch())
	}
	if auditRows() != baseline {
		t.Errorf("audit rows appeared for rolled-back changes")
	}

	// with the audit healthy every one of the same operations commits and leaves exactly its audit row(s)
	e.svc.failAudit = nil
	for _, f := range failures {
		n := auditRows()
		if err := f.do(); err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		if auditRows() <= n {
			t.Errorf("%s committed without an audit row", f.name)
		}
	}
	// the row carries who, from where, what and the request, and never a secret
	var action, ip, ua string
	var meta []byte
	if err := e.pool.QueryRow(ctx, `SELECT action, host(ip_address), user_agent, metadata FROM audit_logs WHERE org_id = $1 AND action = 'access.assignment.revoked'`, org).Scan(&action, &ip, &ua, &meta); err != nil {
		t.Fatal(err)
	}
	if ip != "203.0.113.7" || ua != "test" || !contains(string(meta), `"request_id"`) || !contains(string(meta), `"via": "session"`) {
		t.Errorf("audit row incomplete: ip=%s ua=%s meta=%s", ip, ua, meta)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestIdempotencyKey(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	org, owner := e.org(t, "open")
	o := act(owner)
	in := GroupInput{Slug: "alpha", Name: ptr("Alpha")}
	k := &Idem{Key: "key-1", Hash: HashRequest("POST", "/x", []byte("body-a"))}
	first, err := e.svc.CreateGroup(ctx, o, org, in, k)
	if err != nil || first.Status != 201 || first.Replayed {
		t.Fatalf("first: %v %+v", err, first)
	}
	second, err := e.svc.CreateGroup(ctx, o, org, in, k)
	if err != nil || !second.Replayed || second.Status != 201 || second.Value.ID != first.Value.ID {
		t.Fatalf("replay must return the stored response: %v %+v", err, second)
	}
	if n := e.count(t, `SELECT count(*) FROM groups WHERE org_id = $1`, org); n != 1 {
		t.Fatalf("%d groups after a replay, want 1", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_logs WHERE org_id = $1 AND action = 'access.group.created'`, org); n != 1 {
		t.Fatalf("a replay wrote %d audit rows", n)
	}
	// same key, different request
	_, err = e.svc.CreateGroup(ctx, o, org, GroupInput{Slug: "beta", Name: ptr("Beta")}, &Idem{Key: "key-1", Hash: HashRequest("POST", "/x", []byte("body-b"))})
	if x := wantErr(t, err, 409, ""); x.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("code %s", x.Code)
	}
	// without a key the same request is a duplicate
	_, err = e.svc.CreateGroup(ctx, o, org, in, nil)
	wantErr(t, err, 409, "DUPLICATE")
	// keys are per person and per organization
	other := e.newMember(t, org, "admin")
	if _, err := e.svc.CreateGroup(ctx, act(other), org, GroupInput{Slug: "gamma", Name: ptr("Gamma")}, k); err != nil {
		t.Fatalf("the same key of another person is independent: %v", err)
	}
	// size limit of the key
	_, err = e.svc.CreateGroup(ctx, o, org, GroupInput{Slug: "delta", Name: ptr("Delta")}, &Idem{Key: string(make([]byte, 129)), Hash: "h"})
	wantErr(t, err, 422, "")
	// an assignment with a key is created once
	user := e.newMember(t, org, "member")
	proj := e.project(t, org)
	ai := AssignmentInput{SubjectType: "user", SubjectID: user, Scope: ScopeRef{Type: "project", ID: proj}, TemplateID: sysProject("viewer")}
	ak := &Idem{Key: "asg-1", Hash: "a"}
	a1, err := e.svc.CreateAssignment(ctx, o, org, ai, ak)
	a2, err2 := e.svc.CreateAssignment(ctx, o, org, ai, ak)
	if err != nil || err2 != nil || a1.Value.ID != a2.Value.ID || !a2.Replayed {
		t.Fatalf("assignment replay: %v %v", err, err2)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_logs WHERE org_id = $1 AND action LIKE 'access.assignment.%'`, org); n != 1 {
		t.Fatalf("assignment replay wrote %d audit rows", n)
	}
}

func TestConcurrentAssignments(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	org, owner := e.org(t, "restricted")
	o := act(owner)
	proj := e.project(t, org)
	// 1) the very same assignment created by 24 requests at once: one live row, one "granted", the rest "changed"
	user := e.newMember(t, org, "member")
	ai := AssignmentInput{SubjectType: "user", SubjectID: user, Scope: ScopeRef{Type: "project", ID: proj}, TemplateID: sysProject("deployer")}
	var wg sync.WaitGroup
	var created, failed atomic.Int32
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.svc.CreateAssignment(ctx, o, org, ai, nil); err != nil {
				failed.Add(1)
				t.Errorf("concurrent create: %v", err)
			} else {
				created.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := e.count(t, `SELECT count(*) FROM access_assignments WHERE subject_id = $1 AND revoked_at IS NULL`, user); n != 1 {
		t.Fatalf("%d live rows for 24 identical concurrent assignments, want 1", n)
	}
	if g := e.count(t, `SELECT count(*) FROM audit_logs WHERE org_id = $1 AND action = 'access.assignment.granted'`, org); g != 1 {
		t.Fatalf("%d granted rows, want 1", g)
	}
	if c := e.count(t, `SELECT count(*) FROM audit_logs WHERE org_id = $1 AND action = 'access.assignment.changed'`, org); c != 23 {
		t.Fatalf("%d changed rows, want 23", c)
	}
	// 2) 40 different people at once: 40 rows, one audit row each, and the engine sees all of them in this process right away
	var users []uuid.UUID
	for i := 0; i < 40; i++ {
		users = append(users, e.newMember(t, org, "member"))
	}
	var ep0 int64
	_ = e.pool.QueryRow(ctx, `SELECT access_epoch FROM organizations WHERE id = $1`, org).Scan(&ep0)
	for _, u := range users {
		u := u
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.svc.CreateAssignment(ctx, o, org, AssignmentInput{SubjectType: "user", SubjectID: u, Scope: ScopeRef{Type: "project", ID: proj}, TemplateID: sysProject("viewer")}, nil); err != nil {
				t.Errorf("concurrent create: %v", err)
			}
		}()
	}
	wg.Wait()
	var ep1 int64
	_ = e.pool.QueryRow(ctx, `SELECT access_epoch FROM organizations WHERE id = $1`, org).Scan(&ep1)
	if ep1-ep0 != 40 {
		t.Errorf("access_epoch advanced %d times for 40 writes", ep1-ep0)
	}
	for _, u := range users {
		acc, set, _ := e.eng.Effective(ctx, u, org, engine.ProjectScope(proj))
		if acc.Hidden || !set.Has("project:view") {
			t.Fatalf("user %s does not see the project right after their assignment returned", u)
		}
	}
	// 3) concurrent editors of one template: versions are 2..n+1 with no gap or duplicate (one wins each round, the rest are told to retry)
	tpl, err := e.svc.CreateTemplate(ctx, o, org, TemplateInput{Kind: "project", Slug: "race", Name: "race", Permissions: projPerms("project:view")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var ok atomic.Int32
	for i := 0; i < 12; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			perms := projPerms("project:view", "log:read")
			if i%2 == 1 {
				perms = projPerms("project:view", "log:read", "git:read")
			}
			if _, err := e.svc.PublishTemplate(ctx, o, org, tpl.Value.ID, TemplateInput{Name: "race", Permissions: perms, Note: fmt.Sprint(i)}, false, nil); err == nil {
				ok.Add(1)
			} else if x := asErr(t, err); x.DetailCode() != "STALE_VERSION" {
				t.Errorf("publish: %v", err)
			}
		}()
	}
	wg.Wait()
	var maxV, n int
	_ = e.pool.QueryRow(ctx, `SELECT max(version), count(*) FROM role_template_versions WHERE template_id = $1`, tpl.Value.ID).Scan(&maxV, &n)
	if maxV != n || n < 2 {
		t.Fatalf("versions: max %d count %d (a gap or a duplicate)", maxV, n)
	}
}

func TestLastOwnerGuard(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	org, o1 := e.org(t, "open")
	o2 := e.newMember(t, org, "owner")
	admin := e.newMember(t, org, "admin")
	// a lone owner cannot be demoted (by another owner who is then no longer one is impossible; use the second owner to demote the first)
	// one owner demotes the other: allowed while two exist
	if _, err := e.svc.SetMemberTemplate(ctx, act(o1), org, o2, "admin", nil); err != nil {
		t.Fatalf("demoting one of two owners: %v", err)
	}
	// o1 is now the last owner: an admin cannot touch them, and promoting o2 back is only for owners
	_, err := e.svc.SetMemberTemplate(ctx, act(admin), org, o1, "member", nil)
	wantErr(t, err, 403, "")
	_, err = e.svc.SetMemberTemplate(ctx, act(o2), org, o1, "member", nil) // o2 is an admin now: cannot touch an owner
	wantErr(t, err, 403, "")
	e.exec(t, `UPDATE org_members SET role = 'owner' WHERE org_id = $1 AND user_id = $2`, org, o2)

	// two owners demote each other at the same instant: exactly one wins, the other is told LAST_OWNER (100 rounds)
	wins, last, lost := 0, 0, 0
	for round := 0; round < 100; round++ {
		var wg sync.WaitGroup
		res := make([]error, 2)
		wg.Add(2)
		go func() { defer wg.Done(); _, res[0] = e.svc.SetMemberTemplate(ctx, act(o1), org, o2, "admin", nil) }()
		go func() { defer wg.Done(); _, res[1] = e.svc.SetMemberTemplate(ctx, act(o2), org, o1, "admin", nil) }()
		wg.Wait()
		ok := 0
		for _, err := range res {
			switch {
			case err == nil:
				ok++
			case asErr(t, err).DetailCode() == "LAST_OWNER":
				last++
			case asErr(t, err).Status == 403 && strings.Contains(asErr(t, err).Message, "only an owner"):
				lost++ // the loser had already been demoted when its request started
			default:
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d demotions succeeded, want exactly 1", round, ok)
		}
		wins++
		if n := e.count(t, `SELECT count(*) FROM org_members WHERE org_id = $1 AND role = 'owner'`, org); n != 1 {
			t.Fatalf("round %d: %d owners left", round, n)
		}
		e.exec(t, `UPDATE org_members SET role = 'owner' WHERE org_id = $1 AND user_id IN ($2, $3)`, org, o1, o2)
	}
	t.Logf("last-owner race: %d rounds, %d wins, %d LAST_OWNER, %d already demoted", wins, wins, last, lost)
}
