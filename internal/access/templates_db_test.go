//go:build dbtest

package access

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
	"github.com/kynto/capsule/backend/internal/repository"
)

func projPerms(ids ...string) []string {
	set := catalog.NewSet(ids...)
	for _, id := range ids {
		for _, c := range closure(id) {
			set = set.Add(c)
		}
	}
	return set.IDs()
}

func TestTemplateValidationAndLifecycle(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	org, owner := e.org(t, "open")
	e.project(t, org)
	o := act(owner)

	in := func(kind, slug string, perms ...string) TemplateInput {
		return TemplateInput{Kind: kind, Slug: slug, Name: slug, Permissions: perms}
	}
	// wildcard, unknown, dependencies, scope, slug, name
	_, err := e.svc.CreateTemplate(ctx, o, org, in("project", "w1", "*"), nil)
	if x := wantErr(t, err, 422, ""); x.Details["fields"] == nil {
		t.Fatalf("wildcard: no field detail %v", x.Details)
	}
	_, err = e.svc.CreateTemplate(ctx, o, org, in("project", "w2", "deployment:*"), nil)
	wantErr(t, err, 422, "")
	_, err = e.svc.CreateTemplate(ctx, o, org, in("project", "u1", "project:view", "nope:nada"), nil)
	if x := wantErr(t, err, 422, ""); fmt.Sprint(x.Details["unknown_permissions"]) != "[nope:nada]" {
		t.Fatalf("unknown_permissions = %v", x.Details["unknown_permissions"])
	}
	_, err = e.svc.CreateTemplate(ctx, o, org, in("project", "d1", "deployment:create"), nil)
	if x := wantErr(t, err, 422, ""); x.Details["missing_dependencies"] == nil {
		t.Fatalf("no missing_dependencies: %v", x.Details)
	}
	_, err = e.svc.CreateTemplate(ctx, o, org, in("org", "o1", "org:read", "deployment:create", "deployment:read", "project:view"), nil)
	if x := wantErr(t, err, 422, ""); x.Details["out_of_scope"] == nil {
		t.Fatalf("no out_of_scope for a project permission in an org template: %v", x.Details)
	}
	_, err = e.svc.CreateTemplate(ctx, o, org, in("project", "pl1", "project:view", "platform-user:read"), nil)
	wantErr(t, err, 422, "")
	_, err = e.svc.CreateTemplate(ctx, o, org, in("project", "deployer", "project:view"), nil)
	if x := wantErr(t, err, 422, ""); x.Details["fields"].(map[string]string)["slug"] == "" {
		t.Fatalf("reserved slug must name the slug field: %v", x.Details)
	}
	_, err = e.svc.CreateTemplate(ctx, o, org, in("project", "Bad Slug", "project:view"), nil)
	wantErr(t, err, 422, "")
	long := in("project", "long", "project:view")
	long.Name = fmt.Sprintf("%081d", 0) // 81 characters
	_, err = e.svc.CreateTemplate(ctx, o, org, long, nil)
	wantErr(t, err, 422, "")
	many := in("project", "many")
	for i := 0; i < 201; i++ {
		many.Permissions = append(many.Permissions, "project:view")
	}
	_, err = e.svc.CreateTemplate(ctx, o, org, many, nil)
	wantErr(t, err, 422, "LIMIT_EXCEEDED")
	p := in("project", "c1", "project:view")
	ceil := []string{"project:view"}
	p.Ceiling = &ceil
	_, err = e.svc.CreateTemplate(ctx, o, org, p, nil)
	wantErr(t, err, 422, "")

	// create, duplicate, get, list
	rep, err := e.svc.CreateTemplate(ctx, o, org, TemplateInput{Kind: "project", Slug: "readers", Name: "Readers", Permissions: projPerms("project:view", "deployment:read", "log:read")}, nil)
	if err != nil || rep.Status != 201 || rep.Value.CurrentVersion != 1 || rep.Value.System {
		t.Fatalf("create: %v %+v", err, rep)
	}
	readers := rep.Value
	_, err = e.svc.CreateTemplate(ctx, o, org, TemplateInput{Kind: "project", Slug: "readers", Name: "Again", Permissions: []string{"project:view"}}, nil)
	wantErr(t, err, 409, "DUPLICATE")
	got, err := e.svc.GetTemplate(ctx, o, org, readers.ID)
	if err != nil || got.Slug != "readers" || len(got.Permissions) != len(readers.Permissions) {
		t.Fatalf("get: %v %+v", err, got)
	}

	// clone of a system template: same permissions, cloned_from set; clone kind must match
	sys, _ := loadHead(ctx, e.pool, org, sysProject("deployer"), false)
	sysVer, _ := loadVer(ctx, e.pool, sys.ID, 0)
	cl, err := e.svc.CreateTemplate(ctx, o, org, TemplateInput{Kind: "project", Slug: "deployer-nodb", Name: "Deployer sin base de datos", ClonedFrom: &sys.ID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sameStrings(cl.Value.Permissions, sysVer.Permissions) || cl.Value.ClonedFrom == nil || *cl.Value.ClonedFrom != sys.ID {
		t.Fatalf("clone differs from its source: %v vs %v", cl.Value.Permissions, sysVer.Permissions)
	}
	_, err = e.svc.CreateTemplate(ctx, o, org, TemplateInput{Kind: "repo", Slug: "wrongkind", Name: "x", ClonedFrom: &sys.ID}, nil)
	wantErr(t, err, 422, "")
	list, err := e.svc.ListTemplates(ctx, o, org, "project", false)
	if err != nil {
		t.Fatal(err)
	}
	sawSys, sawOwn := false, false
	for _, d := range list {
		sawSys = sawSys || (d.System && d.Slug == "deployer")
		sawOwn = sawOwn || (!d.System && d.Slug == "readers")
		if d.Kind != "project" {
			t.Fatalf("kind filter leaked %s", d.Kind)
		}
	}
	if !sawSys || !sawOwn {
		t.Fatalf("list misses system or own templates (sys=%v own=%v)", sawSys, sawOwn)
	}

	// system templates are immutable by API
	_, err = e.svc.PublishTemplate(ctx, o, org, sys.ID, TemplateInput{Name: "x", Permissions: []string{"project:view"}}, false, nil)
	wantErr(t, err, 409, "SYSTEM_TEMPLATE")
	_, err = e.svc.DeleteTemplate(ctx, o, org, sys.ID, nil)
	wantErr(t, err, 409, "SYSTEM_TEMPLATE")

	// publish v2: dry run does not save, real publish does, versions and diff
	next := TemplateInput{Name: "Readers", Permissions: projPerms("project:view", "deployment:read", "log:read", "git:read"), Note: "git"}
	dry, err := e.svc.PublishTemplate(ctx, o, org, readers.ID, next, true, nil)
	if err != nil || dry.Value.Published || fmt.Sprint(dry.Value.Impact.Gains) != "[git:read]" {
		t.Fatalf("dry run: %v %+v", err, dry.Value)
	}
	if v, _ := loadVer(ctx, e.pool, readers.ID, 0); v.Version != 1 {
		t.Fatalf("dry run saved a version")
	}
	pub, err := e.svc.PublishTemplate(ctx, o, org, readers.ID, next, false, nil)
	if err != nil || !pub.Value.Published || pub.Value.Template.CurrentVersion != 2 {
		t.Fatalf("publish: %v %+v", err, pub.Value)
	}
	vers, err := e.svc.ListTemplateVersions(ctx, o, org, readers.ID)
	if err != nil || len(vers) != 2 || vers[0].Version != 2 || vers[0].CreatedBy == nil || vers[0].CreatedBy.ID != owner {
		t.Fatalf("versions: %v %+v", err, vers)
	}
	d, err := e.svc.DiffTemplateVersions(ctx, o, org, readers.ID, 1, 2)
	if err != nil || fmt.Sprint(d.Added) != "[git:read]" || len(d.Removed) != 0 {
		t.Fatalf("diff: %v %+v", err, d)
	}
	_, err = e.svc.DiffTemplateVersions(ctx, o, org, readers.ID, 1, 9)
	wantErr(t, err, 404, "")
	// versions are immutable at the database level
	if _, err := e.pool.Exec(ctx, `UPDATE role_template_versions SET note = 'x' WHERE template_id = $1`, readers.ID); err == nil {
		t.Fatal("a template version was updatable")
	}
	// unchanged content: no new version
	again, err := e.svc.PublishTemplate(ctx, o, org, readers.ID, next, false, nil)
	if err != nil || again.Value.Published {
		t.Fatalf("identical content published a version: %v %+v", err, again.Value)
	}
	// slug and kind cannot change
	_, err = e.svc.PublishTemplate(ctx, o, org, readers.ID, TemplateInput{Slug: "other", Permissions: next.Permissions}, false, nil)
	wantErr(t, err, 422, "")

	// unused template is deleted; used one is archived and keeps working; archived is not assignable
	_, err = e.svc.DeleteTemplate(ctx, o, org, cl.Value.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM role_templates WHERE id = $1`, cl.Value.ID); n != 0 {
		t.Fatal("unused template was not deleted")
	}
	user := e.newMember(t, org, "member")
	proj := e.project(t, org)
	if _, err := e.svc.CreateAssignment(ctx, o, org, AssignmentInput{SubjectType: "user", SubjectID: user, Scope: ScopeRef{Type: "project", ID: proj}, TemplateID: readers.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DeleteTemplate(ctx, o, org, readers.ID, nil); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM role_templates WHERE id = $1 AND archived_at IS NOT NULL`, readers.ID); n != 1 {
		t.Fatal("used template was not archived")
	}
	_, err = e.svc.CreateAssignment(ctx, o, org, AssignmentInput{SubjectType: "user", SubjectID: e.newMember(t, org, "member"), Scope: ScopeRef{Type: "project", ID: proj}, TemplateID: readers.ID}, nil)
	wantErr(t, err, 409, "TEMPLATE_ARCHIVED")
	_, err = e.svc.PublishTemplate(ctx, o, org, readers.ID, next, false, nil)
	wantErr(t, err, 409, "TEMPLATE_ARCHIVED")
	if _, _, set, err := e.svc.requireAt(ctx, act(user), org, "project", proj); err != nil || !set.Has("project:view") {
		t.Fatalf("an assignment of an archived template stopped working: %v", err)
	}
	// audit rows exist for each write
	for _, a := range []string{"access.template.created", "access.template.cloned", "access.template.published", "access.template.archived", "access.template.deleted", "access.assignment.granted"} {
		if e.count(t, `SELECT count(*) FROM audit_logs WHERE org_id = $1 AND action = $2`, org, a) == 0 {
			t.Errorf("no audit row %s", a)
		}
	}
}

func TestTemplateLimitPerOrg(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	org, owner := e.org(t, "open")
	e.exec(t, `INSERT INTO role_templates (org_id, kind, slug, name) SELECT $1, 'project', 's' || g, 's' || g FROM generate_series(1, $2) g`, org, repository.MaxTemplatesPerOrg)
	_, err := e.svc.CreateTemplate(ctx, act(owner), org, TemplateInput{Kind: "project", Slug: "one-too-many", Name: "x", Permissions: []string{"project:view"}}, nil)
	wantErr(t, err, 422, "LIMIT_EXCEEDED")
}

// actors used by the escalation tests: a manager (custom organization role with the management permissions and the deployer role in
// every project), a project admin who is a plain member, and a viewer.
type escalationWorld struct {
	e                                                  *testEnv
	org, owner, mgr, padmin, viewer, target, otherUser uuid.UUID
	p1, p2                                             uuid.UUID
	group                                              uuid.UUID
}

func orgOnly(t testing.TB, ids ...string) []string {
	t.Helper()
	for _, id := range ids {
		c, ok := catalog.Get(id)
		if !ok || !c.HasScope(catalog.ScopeOrg) {
			t.Fatalf("%s is not an organization permission", id)
		}
	}
	return ids
}

func newEscalationWorld(t *testing.T) *escalationWorld {
	e := newTestEnv(t)
	ctx := context.Background()
	w := &escalationWorld{e: e}
	w.org, w.owner = e.org(t, "open")
	w.p1, w.p2 = e.project(t, w.org), e.project(t, w.org)
	w.mgr = e.newMember(t, w.org, "member")
	tpl := e.customOrgTemplate(t, w.org, "manager", orgOnly(t, "org:read", "member:read", "template:read", "template:manage", "group:read", "group:manage",
		"assignment:read", "assignment:grant", "audit:read"))
	e.setOrgTemplate(t, w.org, w.mgr, tpl, "member")
	// the manager holds the deployer permissions plus assignment:read/grant in every project (an organization-scope grant does not
	// reach projects: SPEC 5.3), so it can grant inside what it holds and nothing else
	dep, err := loadVer(context.Background(), e.pool, sysProject("deployer"), 0)
	if err != nil {
		t.Fatal(err)
	}
	var pm uuid.UUID
	if err := e.pool.QueryRow(context.Background(), `INSERT INTO role_templates (org_id, kind, slug, name) VALUES ($1,'project','pm-base','pm-base') RETURNING id`, w.org).Scan(&pm); err != nil {
		t.Fatal(err)
	}
	e.exec(t, `INSERT INTO role_template_versions (template_id, version, permissions) VALUES ($1,1,$2)`, pm, append(append([]string{}, dep.Permissions...), "assignment:read", "assignment:grant"))
	e.assign(t, w.org, "user", w.mgr, "org", w.org, pm, nil)
	w.padmin = e.newMember(t, w.org, "member")
	e.assign(t, w.org, "user", w.padmin, "project", w.p1, sysProject("admin"), nil)
	w.viewer = e.newMember(t, w.org, "readonly")
	w.target = e.newMember(t, w.org, "member")
	w.otherUser = e.newMember(t, w.org, "member")
	g, err := e.svc.CreateGroup(ctx, act(w.owner), w.org, GroupInput{Slug: "ops", Name: ptr("Ops")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.group = g.Value.ID
	return w
}

// heldBy returns the project permissions the person does NOT hold in every project.
func (w *escalationWorld) notHeld(t *testing.T, user uuid.UUID) []string {
	caps, err := w.e.svc.projectCaps(context.Background(), user, w.org)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, c := range catalog.All() {
		if c.HasScope(catalog.ScopeProject) && !c.HasScope(catalog.ScopePlatform) && !caps.Has(c.ID) && !c.Deprecated {
			out = append(out, c.ID)
		}
	}
	return out
}

// TestNoEscalationMatrix runs at least 40 negative cases: nobody grants, through a template, a group or an assignment, more than they hold.
func TestNoEscalationMatrix(t *testing.T) {
	w := newEscalationWorld(t)
	e, ctx := w.e, context.Background()
	m := act(w.mgr)
	lacking := w.notHeld(t, w.mgr)
	if len(lacking) < 20 {
		t.Fatalf("the manager lacks only %d permissions; the scenario is not useful", len(lacking))
	}
	cases := 0
	escalated := func(what string, err error) {
		t.Helper()
		cases++
		x := wantErr(t, err, 403, "ESCALATION")
		missing, _ := x.Details["missing"].([]string)
		if what != "" && len(missing) == 0 && x.Details["reason"] == nil {
			t.Errorf("%s: ESCALATION without missing or reason", what)
		}
	}

	// (1) creating a template with a permission the actor lacks (one case per lacking permission, closure included)
	for i, p := range lacking {
		_, err := e.svc.CreateTemplate(ctx, m, w.org, TemplateInput{Kind: "project", Slug: fmt.Sprintf("esc-%d", i), Name: p, Permissions: closure(p)}, nil)
		escalated("create "+p, err)
	}
	// (2) editing a template to add what the actor lacks
	ok, err := e.svc.CreateTemplate(ctx, m, w.org, TemplateInput{Kind: "project", Slug: "mine", Name: "Mine", Permissions: closure("deployment:read")}, nil)
	if err != nil {
		t.Fatalf("a manager can create a template inside what they hold: %v", err)
	}
	for _, p := range lacking[:10] {
		_, err := e.svc.PublishTemplate(ctx, m, w.org, ok.Value.ID, TemplateInput{Name: "Mine", Permissions: append(closure("deployment:read"), closure(p)...)}, false, nil)
		escalated("edit +"+p, err)
	}
	// ... but removing is free and adding held permissions is allowed
	if _, err := e.svc.PublishTemplate(ctx, m, w.org, ok.Value.ID, TemplateInput{Name: "Mine", Permissions: closure("project:view")}, false, nil); err != nil {
		t.Fatalf("removing permissions must be free: %v", err)
	}
	// (3) assigning a template that carries what the actor lacks: system templates and a custom one
	for _, slug := range []string{"admin"} {
		_, err := e.svc.CreateAssignment(ctx, m, w.org, AssignmentInput{SubjectType: "user", SubjectID: w.target, Scope: ScopeRef{Type: "project", ID: w.p1}, TemplateID: sysProject(slug)}, nil)
		escalated("assign "+slug, err)
		_, err = e.svc.CreateAssignment(ctx, m, w.org, AssignmentInput{SubjectType: "user", SubjectID: w.target, Scope: ScopeRef{Type: "org", ID: w.org}, TemplateID: sysProject(slug)}, nil)
		escalated("assign org-wide "+slug, err)
	}
	for i, p := range lacking[:12] {
		var tid uuid.UUID
		if err := e.pool.QueryRow(ctx, `INSERT INTO role_templates (org_id, kind, slug, name) VALUES ($1,'project',$2,$2) RETURNING id`, w.org, fmt.Sprintf("held-by-owner-%d", i)).Scan(&tid); err != nil {
			t.Fatal(err)
		}
		e.exec(t, `INSERT INTO role_template_versions (template_id, version, permissions) VALUES ($1,1,$2)`, tid, closure(p))
		_, err := e.svc.CreateAssignment(ctx, m, w.org, AssignmentInput{SubjectType: "user", SubjectID: w.target, Scope: ScopeRef{Type: "project", ID: w.p2}, TemplateID: tid}, nil)
		escalated("assign custom "+p, err)
		// through a group assignment created by the owner, adding members is a grant too
		e.assign(t, w.org, "group", w.group, "project", w.p2, tid, nil)
		_, err = e.svc.AddGroupMembers(ctx, m, w.org, w.group, AddMembersInput{UserIDs: []uuid.UUID{w.target}}, nil)
		escalated("group member +"+p, err)
		e.exec(t, `UPDATE access_assignments SET revoked_at = now() WHERE subject_id = $1 AND template_id = $2`, w.group, tid)
	}
	// (4) self grant: nobody widens their own access but an owner
	_, err = e.svc.CreateAssignment(ctx, m, w.org, AssignmentInput{SubjectType: "user", SubjectID: w.mgr, Scope: ScopeRef{Type: "project", ID: w.p1}, TemplateID: sysProject("viewer")}, nil)
	escalated("self grant held template", err)
	if x := asErr(t, err); x.Details["reason"] != "self_grant" {
		t.Errorf("self grant reason = %v", x.Details["reason"])
	}
	_, err = e.svc.CreateAssignment(ctx, act(w.padmin), w.org, AssignmentInput{SubjectType: "user", SubjectID: w.padmin, Scope: ScopeRef{Type: "project", ID: w.p1}, TemplateID: sysProject("admin")}, nil)
	escalated("project admin grants themselves admin", err)
	// a group the actor belongs to is the actor too
	e.exec(t, `INSERT INTO group_members (group_id, user_id) VALUES ($1,$2)`, w.group, w.padmin)
	_, err = e.svc.CreateAssignment(ctx, act(w.padmin), w.org, AssignmentInput{SubjectType: "group", SubjectID: w.group, Scope: ScopeRef{Type: "project", ID: w.p1}, TemplateID: sysProject("deployer")}, nil)
	escalated("project admin grants a group they belong to", err)
	e.exec(t, `DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, w.group, w.padmin)
	_, err = e.svc.AddGroupMembers(ctx, m, w.org, w.group, AddMembersInput{UserIDs: []uuid.UUID{w.mgr}}, nil) // group has no assignments now: allowed
	if err != nil {
		t.Fatalf("adding oneself to a group that grants nothing is harmless: %v", err)
	}
	e.exec(t, `DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, w.group, w.mgr)
	// (5) project admin: grants inside what they hold, never what they lack
	if _, err := e.svc.CreateAssignment(ctx, act(w.padmin), w.org, AssignmentInput{SubjectType: "user", SubjectID: w.target, Scope: ScopeRef{Type: "project", ID: w.p1}, TemplateID: sysProject("deployer")}, nil); err != nil {
		t.Fatalf("a project admin can grant deployer on their project: %v", err)
	}
	var prom uuid.UUID
	if err := e.pool.QueryRow(ctx, `INSERT INTO role_templates (org_id, kind, slug, name) VALUES ($1,'project','with-approve','x') RETURNING id`, w.org).Scan(&prom); err != nil {
		t.Fatal(err)
	}
	e.exec(t, `INSERT INTO role_template_versions (template_id, version, permissions) VALUES ($1,1,$2)`, prom, closure("promotion:approve"))
	_, err = e.svc.CreateAssignment(ctx, act(w.padmin), w.org, AssignmentInput{SubjectType: "user", SubjectID: w.otherUser, Scope: ScopeRef{Type: "project", ID: w.p1}, TemplateID: prom}, nil)
	escalated("project admin grants promotion:approve they lack", err)
	// (6) a project admin outside their project has no grant right at all (403 permission, not escalation) and cannot see another project (404)
	_, err = e.svc.CreateAssignment(ctx, act(w.padmin), w.org, AssignmentInput{SubjectType: "user", SubjectID: w.target, Scope: ScopeRef{Type: "project", ID: w.p2}, TemplateID: sysProject("viewer")}, nil)
	cases++
	wantErr(t, err, 403, "PERMISSION_DENIED")
	// (7) only owners assign or unassign owner; a manager cannot change their own role; template editing needs template:manage
	e.exec(t, `UPDATE organizations SET access_settings = access_settings || '{"custom_roles": true}'::jsonb WHERE id = $1`, w.org)
	adminMgr := e.newMember(t, w.org, "admin") // an org admin: holds member:update but is not an owner
	_, err = e.svc.SetMemberTemplate(ctx, act(adminMgr), w.org, w.target, "owner", nil)
	escalated("admin assigns owner", err)
	_, err = e.svc.SetMemberTemplate(ctx, act(adminMgr), w.org, w.owner, "member", nil)
	cases++
	wantErr(t, err, 403, "")
	_, err = e.svc.SetMemberTemplate(ctx, act(adminMgr), w.org, adminMgr, "owner", nil)
	cases++
	wantErr(t, err, 403, "")
	_, err = e.svc.CreateTemplate(ctx, act(w.padmin), w.org, TemplateInput{Kind: "project", Slug: "nope", Name: "x", Permissions: []string{"project:view"}}, nil)
	cases++
	wantErr(t, err, 403, "PERMISSION_DENIED")
	_, err = e.svc.CreateTemplate(ctx, act(w.viewer), w.org, TemplateInput{Kind: "project", Slug: "nope2", Name: "x", Permissions: []string{"project:view"}}, nil)
	cases++
	wantErr(t, err, 403, "PERMISSION_DENIED")
	// (8) org template: a manager cannot hand out an org template with permissions they do not hold
	hi := e.customOrgTemplate(t, w.org, "hi", orgOnly(t, "org:read", "member:read", "billing:read", "billing:manage"))
	_ = hi
	_, err = e.svc.SetMemberTemplate(ctx, act(adminMgr), w.org, w.otherUser, "hi", nil)
	escalated("admin hands out a template with billing:manage", err)

	if cases < 40 {
		t.Fatalf("only %d negative cases ran", cases)
	}
	t.Logf("no-escalation negative cases executed: %d (all denied)", cases)
	// nothing leaked in: the target holds only what the allowed grants gave
	var n int
	_ = e.pool.QueryRow(ctx, `SELECT count(*) FROM access_assignments WHERE subject_id = $1 AND revoked_at IS NULL`, w.target).Scan(&n)
	if n != 1 {
		t.Fatalf("target has %d live assignments, want 1 (the allowed deployer grant)", n)
	}
	// on the other project the target has exactly the member base (deployer): no denied path added anything
	dv, _ := loadVer(ctx, e.pool, sysProject("deployer"), 0)
	_, set, _ := e.eng.Effective(ctx, w.target, w.org, engine.ProjectScope(w.p2))
	if set != catalog.NewSet(dv.Permissions...) {
		t.Fatalf("target escalated through a denied path: %v", set.Minus(catalog.NewSet(dv.Permissions...)).IDs())
	}
}
