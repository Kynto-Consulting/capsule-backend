//go:build dbtest

package access

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
)

type world struct {
	e        *testEnv
	orgs     []uuid.UUID
	owners   map[uuid.UUID]uuid.UUID
	projects map[uuid.UUID][]uuid.UUID
	repos    map[uuid.UUID][]uuid.UUID // repo scope shares the project id; kept for readability
	users    map[uuid.UUID][]uuid.UUID
	groups   map[uuid.UUID][]uuid.UUID
}

// buildWorld creates orgs with projects, members of every kind (system roles, a custom role with a ceiling, suspended people), groups, random
// assignments at org, project, repo and env scope (some expired), and project policy overrides. Rows go in by SQL: this is setup, not the API.
func buildWorld(t testing.TB, e *testEnv, rng *rand.Rand, nOrgs, nProj, nUsers int) *world {
	t.Helper()
	ctx := context.Background()
	w := &world{e: e, owners: map[uuid.UUID]uuid.UUID{}, projects: map[uuid.UUID][]uuid.UUID{}, users: map[uuid.UUID][]uuid.UUID{}, groups: map[uuid.UUID][]uuid.UUID{}}
	tpls := []uuid.UUID{sysProject("viewer"), sysProject("deployer"), sysProject("admin")}
	repoTpls := []uuid.UUID{systemRepo("repo-read"), systemRepo("repo-write"), sysProject("viewer")}
	for o := 0; o < nOrgs; o++ {
		mode := []string{"open", "restricted"}[rng.Intn(2)]
		org, owner := e.org(t, mode)
		w.orgs = append(w.orgs, org)
		w.owners[org] = owner
		w.users[org] = append(w.users[org], owner)
		var envs []uuid.UUID
		for p := 0; p < nProj; p++ {
			id := e.project(t, org)
			w.projects[org] = append(w.projects[org], id)
			if p%8 == 0 {
				envs = append(envs, e.environment(t, id))
			}
			if rng.Intn(6) == 0 {
				e.exec(t, `UPDATE projects SET access_override = $2 WHERE id = $1`, id, []string{"open", "restricted"}[rng.Intn(2)])
			}
		}
		custom := e.customOrgTemplateCeil(t, org, "limited", orgOnly(t, "org:read", "member:read", "template:read"), []string{"org:read", "member:read", "template:read", "project:view", "deployment:read", "log:read"})
		for g := 0; g < 4; g++ {
			var gid uuid.UUID
			if err := e.pool.QueryRow(ctx, `INSERT INTO groups (org_id, slug, name) VALUES ($1,$2,$2) RETURNING id`, org, fmt.Sprintf("g%d", g)).Scan(&gid); err != nil {
				t.Fatal(err)
			}
			w.groups[org] = append(w.groups[org], gid)
		}
		roles := []string{"admin", "member", "member", "member", "readonly", "readonly", "limited"}
		for m := 0; m < nUsers; m++ {
			role := roles[rng.Intn(len(roles))]
			u := e.user(t)
			if role == "limited" {
				e.member(t, org, u, "readonly")
				e.setOrgTemplate(t, org, u, custom, "readonly")
			} else {
				e.member(t, org, u, role)
			}
			if rng.Intn(15) == 0 {
				e.exec(t, `UPDATE org_members SET status = 'suspended' WHERE org_id = $1 AND user_id = $2`, org, u)
			}
			w.users[org] = append(w.users[org], u)
			if rng.Intn(3) == 0 {
				e.exec(t, `INSERT INTO group_members (group_id, user_id, expires_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, w.groups[org][rng.Intn(4)], u, maybeExpiry(rng))
			}
		}
		subjects := func() (string, uuid.UUID) {
			if rng.Intn(10) < 3 {
				return "group", w.groups[org][rng.Intn(4)]
			}
			return "user", w.users[org][rng.Intn(len(w.users[org]))]
		}
		for i := 0; i < nUsers*2; i++ {
			st, sid := subjects()
			var scopeType string
			var scope, tpl uuid.UUID
			switch r := rng.Intn(20); {
			case r < 5:
				scopeType, scope, tpl = "org", org, tpls[rng.Intn(3)]
			case r < 15:
				scopeType, scope, tpl = "project", w.projects[org][rng.Intn(nProj)], tpls[rng.Intn(3)]
			case r < 18:
				scopeType, scope, tpl = "repo", w.projects[org][rng.Intn(nProj)], repoTpls[rng.Intn(3)]
			default:
				if len(envs) == 0 {
					continue
				}
				scopeType, scope, tpl = "env", envs[rng.Intn(len(envs))], tpls[rng.Intn(2)]
			}
			_, _ = e.pool.Exec(ctx, `INSERT INTO access_assignments (org_id, subject_type, subject_id, scope_type, scope_id, template_id, expires_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, org, st, sid, scopeType, scope, tpl, maybeExpiry(rng))
		}
	}
	return w
}

func maybeExpiry(rng *rand.Rand) *time.Time {
	switch rng.Intn(10) {
	case 0:
		t := time.Now().Add(-time.Hour)
		return &t
	case 1:
		t := time.Now().Add(48 * time.Hour)
		return &t
	}
	return nil
}

func ids(s catalog.Set) []string { return s.IDs() }

func TestMePermissionsMatchesEffective(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	rng := rand.New(rand.NewSource(20261104))
	w := buildWorld(t, e, rng, 3, 40, 30)
	ref := engine.New(e.store.EngineStore(), engine.Options{}) // independent evaluator: no shared cache with the service
	cases := 0
	type resp struct {
		Org struct {
			ID          uuid.UUID `json:"id"`
			Status      string    `json:"status"`
			Permissions []string  `json:"permissions"`
			Template    *struct {
				Slug string `json:"slug"`
			} `json:"template"`
		} `json:"org"`
		ProjectDefault []string               `json:"project_default"`
		Aggregate      []string               `json:"aggregate"`
		Permissions    *[]string              `json:"permissions"`
		ProjectSource  string                 `json:"project_source"`
		Projects       map[string]ProjectMask `json:"projects"`
		CatalogIndex   []string               `json:"catalog_index"`
		Epoch          int64                  `json:"epoch"`
	}
	for _, org := range w.orgs {
		for _, u := range w.users[org] {
			res, err := e.svc.MyPermissions(ctx, u, org.String(), "", "projects")
			if err != nil {
				t.Fatal(err)
			}
			var got resp
			if err := json.Unmarshal(res.Body, &got); err != nil {
				t.Fatal(err)
			}
			_, oset, _ := ref.Effective(ctx, u, org, engine.OrgScope())
			if fmt.Sprint(got.Org.Permissions) != fmt.Sprint(ids(oset)) {
				t.Fatalf("org permissions differ for %s", u)
			}
			cases++
			dacc, dset, _ := ref.Effective(ctx, u, org, engine.ProjectScope(probeProject))
			if dacc.Hidden {
				dset = catalog.Set{}
			}
			if fmt.Sprint(got.ProjectDefault) != fmt.Sprint(ids(dset)) {
				t.Fatalf("project_default differs for %s", u)
			}
			cases++
			var agg catalog.Set
			for _, p := range w.projects[org] {
				acc, set, _ := ref.Effective(ctx, u, org, engine.ProjectScope(p))
				if acc.Hidden {
					set = catalog.Set{}
				}
				agg = agg.Union(set)
				// sparse map: absent means project_default
				mask := dset.Hex()
				if m, ok := got.Projects[p.String()]; ok {
					mask = m.Mask
				}
				if mask != set.Hex() {
					t.Fatalf("mask of project %s for %s: got %s want %s", p, u, mask, set.Hex())
				}
				if hs, _ := catalog.SetFromHex(mask); hs.Has("project:view") == acc.Hidden {
					t.Fatalf("visibility of %s for %s disagrees with the engine (hidden=%v)", p, u, acc.Hidden)
				}
				cases += 2
				// ?project= answers in clear, or 404 when hidden
				one, err := e.svc.MyPermissions(ctx, u, org.String(), p.String(), "")
				if acc.Hidden {
					wantErr(t, err, 404, "")
				} else {
					if err != nil {
						t.Fatal(err)
					}
					var d resp
					_ = json.Unmarshal(one.Body, &d)
					if d.Permissions == nil || fmt.Sprint(*d.Permissions) != fmt.Sprint(ids(set)) || d.ProjectSource != string(acc.Source) {
						t.Fatalf("?project= for %s/%s differs from Effective", u, p)
					}
				}
				cases++
			}
			if fmt.Sprint(got.Aggregate) != fmt.Sprint(ids(agg)) {
				t.Fatalf("aggregate differs for %s", u)
			}
			cases++
		}
	}
	t.Logf("/me/permissions compared against Engine.Effective in %d cases (0 differences)", cases)
	if cases < 5000 {
		t.Fatalf("only %d cases", cases)
	}

	// ETag: stable while nothing changes (cached or recomputed), different after a write; a user outside the organization gets 404
	org := w.orgs[0]
	u := w.users[org][3]
	a, _ := e.svc.MyPermissions(ctx, u, org.String(), "", "projects")
	b, _ := e.svc.MyPermissions(ctx, u, org.String(), "", "projects")
	fresh, err := e.svc.permissionsOf(ctx, u, org, nil, true, false)
	if err != nil || a.ETag != b.ETag || a.ETag != fresh.ETag || string(a.Body) != string(fresh.Body) {
		t.Fatalf("ETag not stable: %s %s %s (%v)", a.ETag, b.ETag, fresh.ETag, err)
	}
	if &a.Body[0] != &b.Body[0] {
		t.Error("the second read did not come from the cache")
	}
	e.assign(t, org, "user", u, "project", w.projects[org][0], sysProject("admin"), nil)
	e.exec(t, `SELECT access_bump_org($1)`, org)
	c, _ := e.svc.MyPermissions(ctx, u, org.String(), "", "projects")
	if c.ETag == a.ETag || c.Epoch == a.Epoch {
		t.Error("ETag or epoch unchanged after a write")
	}
	stranger := e.user(t)
	_, err = e.svc.MyPermissions(ctx, stranger, org.String(), "", "")
	wantErr(t, err, 404, "")
	none, err := e.svc.MyPermissions(ctx, stranger, "", "", "")
	if err != nil || !contains(string(none.Body), `"catalog_version"`) {
		t.Fatalf("a user without organizations still gets an answer: %v", err)
	}
	// slug works as well as id
	var slug string
	_ = e.pool.QueryRow(ctx, `SELECT slug FROM organizations WHERE id = $1`, org).Scan(&slug)
	if r, err := e.svc.MyPermissions(ctx, u, slug, "", ""); err != nil || r.ETag == "" {
		t.Fatalf("slug: %v", err)
	}
}

func systemRepo(slug string) uuid.UUID { return repoID(slug) }

func TestSimulatorAgreesWithCan(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	rng := rand.New(rand.NewSource(7))
	w := buildWorld(t, e, rng, 2, 25, 25)
	ref := engine.New(e.store.EngineStore(), engine.Options{})
	all := catalog.All()
	cases, allowedN := 0, 0
	for cases < 1500 {
		org := w.orgs[rng.Intn(len(w.orgs))]
		u := w.users[org][rng.Intn(len(w.users[org]))]
		perm := all[rng.Intn(len(all))].ID
		var sc engine.Scope
		var ref2 ScopeRef
		switch rng.Intn(3) {
		case 0:
			sc, ref2 = engine.OrgScope(), ScopeRef{Type: "org", ID: org}
		case 1:
			p := w.projects[org][rng.Intn(len(w.projects[org]))]
			sc, ref2 = engine.ProjectScope(p), ScopeRef{Type: "project", ID: p}
		default:
			p := w.projects[org][rng.Intn(len(w.projects[org]))]
			sc, ref2 = engine.RepoScope(p, p), ScopeRef{Type: "repo", ID: p}
		}
		want, err := ref.Can(ctx, u, org, sc, perm)
		if err != nil {
			t.Fatal(err)
		}
		d, err := e.svc.Simulate(ctx, act(w.owners[org]), org, SimulateInput{UserID: u, Permission: perm, Scope: &ref2})
		if err != nil {
			t.Fatalf("simulate: %v", err)
		}
		if d.Allowed != want {
			t.Fatalf("simulator says %v, Can says %v (%s %s %v)", d.Allowed, want, u, perm, ref2)
		}
		if d.Allowed != (d.Reason == "granted") {
			t.Fatalf("allowed=%v with reason %s", d.Allowed, d.Reason)
		}
		if len(d.Trace) == 0 || d.Trace[len(d.Trace)-1].Step != "final" {
			t.Fatalf("trace does not end with final: %+v", d.Trace)
		}
		if d.Allowed {
			allowedN++
			grants := 0
			for _, s := range d.Trace {
				if s.Result == "grants" && s.Step != "final" {
					grants++
				}
			}
			if grants == 0 {
				t.Fatalf("allowed without a granting step: %+v", d.Trace)
			}
		}
		// the person asks about themselves
		if cases%10 == 0 {
			me, err := e.svc.ExplainSelf(ctx, u, org.String(), perm, ref2.Type, ref2.ID.String())
			if err != nil {
				// a hidden project is a 404 for the person; the simulator (run by an owner) still describes it
				if x, ok := err.(*Error); ok && x.Status == 404 && ref2.Type != "org" {
					cases++
					continue
				}
				t.Fatal(err)
			}
			if me.Allowed != want {
				t.Fatalf("explain says %v, Can says %v", me.Allowed, want)
			}
		}
		cases++
	}
	t.Logf("Simulate.allowed == Engine.Can in %d random cases (%d allowed)", cases, allowedN)
}

// TestImpactPreviewAgainstEngine: the dry run names exactly the people who follow the latest version, and publishing changes nobody else.
func TestImpactPreviewAgainstEngine(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	org, owner := e.org(t, "restricted")
	o := act(owner)
	var projs []uuid.UUID
	for i := 0; i < 4; i++ {
		projs = append(projs, e.project(t, org))
	}
	base := projPerms("project:view", "deployment:read", "log:read", "git:read")
	tpl, err := e.svc.CreateTemplate(ctx, o, org, TemplateInput{Kind: "project", Slug: "impact", Name: "impact", Permissions: base}, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := tpl.Value.ID
	direct := []uuid.UUID{e.newMember(t, org, "member"), e.newMember(t, org, "member")}
	pinned := e.newMember(t, org, "member")
	expired := e.newMember(t, org, "member")
	viaGroup := []uuid.UUID{e.newMember(t, org, "member"), e.newMember(t, org, "member"), e.newMember(t, org, "member")}
	suspended := e.newMember(t, org, "member")
	e.exec(t, `UPDATE org_members SET status = 'suspended' WHERE org_id = $1 AND user_id = $2`, org, suspended)
	bystander := e.newMember(t, org, "member")
	var gid uuid.UUID
	_ = e.pool.QueryRow(ctx, `INSERT INTO groups (org_id, slug, name) VALUES ($1,'imp','imp') RETURNING id`, org).Scan(&gid)
	for _, u := range viaGroup {
		e.exec(t, `INSERT INTO group_members (group_id, user_id) VALUES ($1,$2)`, gid, u)
	}
	e.exec(t, `INSERT INTO group_members (group_id, user_id) VALUES ($1,$2)`, gid, suspended)
	e.assign(t, org, "user", direct[0], "project", projs[0], id, nil)
	e.assign(t, org, "user", direct[1], "org", org, id, nil)
	pa := e.assign(t, org, "user", pinned, "project", projs[1], id, nil)
	e.exec(t, `UPDATE access_assignments SET pinned_version = 1 WHERE id = $1`, pa)
	past := time.Now().Add(-time.Hour)
	e.assign(t, org, "user", expired, "project", projs[2], id, &past)
	e.assign(t, org, "group", gid, "project", projs[3], id, nil)
	e.assign(t, org, "user", suspended, "project", projs[0], id, nil)
	e.assign(t, org, "user", bystander, "project", projs[0], sysProject("viewer"), nil)

	next := TemplateInput{Name: "impact", Permissions: projPerms("project:view", "deployment:read", "log:read", "envvar:read"), Note: "swap git for envvar"}
	dry, err := e.svc.PublishTemplate(ctx, o, org, id, next, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	imp := dry.Value.Impact
	followers, _ := e.svc.followerIDs(ctx, org, id)
	want := map[uuid.UUID]bool{direct[0]: true, direct[1]: true, viaGroup[0]: true, viaGroup[1]: true, viaGroup[2]: true}
	if len(followers) != len(want) {
		t.Fatalf("followers = %d, want %d (pinned, expired and suspended people excluded)", len(followers), len(want))
	}
	for _, f := range followers {
		if !want[f] {
			t.Fatalf("unexpected follower %s", f)
		}
	}
	if imp.Users != 5 || imp.Groups != 1 || imp.Projects != 4 { // org-wide assignment covers every project; group's project is one of them
		t.Fatalf("impact = %+v, want 5 users, 1 group, 4 projects", imp)
	}
	if fmt.Sprint(imp.Gains) != "[envvar:read]" || fmt.Sprint(imp.Loses) != "[git:read]" {
		t.Fatalf("gains %v loses %v", imp.Gains, imp.Loses)
	}
	if len(imp.AffectedUsers) != 5 {
		t.Fatalf("affected sample %d", len(imp.AffectedUsers))
	}
	// state before, from the evaluator
	all := append(append([]uuid.UUID{pinned, expired, suspended, bystander}, direct...), viaGroup...)
	snap := func() map[string][]string {
		m := map[string][]string{}
		for _, u := range all {
			e.eng.Invalidate(engine.Target{Org: org})
			for i, p := range projs {
				_, set, _ := e.eng.Effective(ctx, u, org, engine.ProjectScope(p))
				m[fmt.Sprintf("%s/%d", u, i)] = ids(set)
			}
		}
		return m
	}
	before := snap()
	if _, err := e.svc.PublishTemplate(ctx, o, org, id, next, false, nil); err != nil {
		t.Fatal(err)
	}
	after := snap()
	changed := map[uuid.UUID]bool{}
	for k, b := range before {
		if fmt.Sprint(b) != fmt.Sprint(after[k]) {
			var u uuid.UUID
			u, _ = uuid.Parse(k[:36])
			changed[u] = true
			bs, as := catalog.NewSet(b...), catalog.NewSet(after[k]...)
			if !catalog.NewSet(imp.Gains...).ContainsAll(as.Minus(bs)) || !catalog.NewSet(imp.Loses...).ContainsAll(bs.Minus(as)) {
				t.Errorf("%s changed by more than the announced gains/loses", k)
			}
		}
	}
	for u := range changed {
		if !want[u] {
			t.Errorf("person %s changed but the preview did not name them", u)
		}
	}
	for u := range want {
		if !changed[u] {
			t.Errorf("person %s was named by the preview but did not change", u)
		}
	}
	// the published result carries the same impact; the audit row records it
	var meta []byte
	if err := e.pool.QueryRow(ctx, `SELECT metadata FROM audit_logs WHERE org_id = $1 AND action = 'access.template.published' ORDER BY created_at DESC LIMIT 1`, org).Scan(&meta); err != nil {
		t.Fatal(err)
	}
	if !contains(string(meta), `"impact_users": 5`) {
		t.Errorf("audit metadata lacks the impact: %s", meta)
	}
}

func TestOverrideWouldHideAndProjectAccess(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	org, owner := e.org(t, "open")
	o := act(owner)
	proj := e.project(t, org)
	admin := e.newMember(t, org, "admin")
	m1 := e.newMember(t, org, "member")
	m2 := e.newMember(t, org, "readonly")
	m3 := e.newMember(t, org, "member")
	var gid uuid.UUID
	_ = e.pool.QueryRow(ctx, `INSERT INTO groups (org_id, slug, name) VALUES ($1,'qa','qa') RETURNING id`, org).Scan(&gid)
	m4 := e.newMember(t, org, "member")
	e.exec(t, `INSERT INTO group_members (group_id, user_id) VALUES ($1,$2)`, gid, m4)
	e.assign(t, org, "user", m3, "project", proj, sysProject("viewer"), nil)
	e.assign(t, org, "group", gid, "project", proj, sysProject("deployer"), nil)

	// who has access now (open): everyone
	pa, err := e.svc.ProjectAccess(ctx, o, org, proj, "", 100)
	if err != nil || pa.Mode != "open" || len(pa.Data) != 6 {
		t.Fatalf("access list: %v %+v", err, pa)
	}
	byUser := map[uuid.UUID]AccessRow{}
	for _, r := range pa.Data {
		byUser[r.User.ID] = r
	}
	if r := byUser[m4]; len(r.Via) == 0 || r.Via[0].Kind != "group" || r.Via[0].Label != "qa" || r.LegacyRole != "deployer" {
		t.Errorf("group member row: %+v", r)
	}
	if r := byUser[m3]; r.Source != "explicit" || r.LegacyRole != "viewer" {
		t.Errorf("explicit row: %+v", r)
	}
	if r := byUser[admin]; r.Source != "org" || r.LegacyRole != "admin" {
		t.Errorf("admin row: %+v", r)
	}
	if r := byUser[m1]; r.Source != "inherited" {
		t.Errorf("inherited row: %+v", r)
	}
	page1, err := e.svc.ProjectAccess(ctx, o, org, proj, "", 2)
	if err != nil || len(page1.Data) != 2 || page1.NextCursor == nil {
		t.Fatalf("pagination: %v %+v", err, page1)
	}
	page2, err := e.svc.ProjectAccess(ctx, o, org, proj, *page1.NextCursor, 100)
	if err != nil || len(page2.Data) != 4 {
		t.Fatalf("second page: %v %d", err, len(page2.Data))
	}

	// moving to restricted: m1 and m2 (only the open base lets them in) would lose the project
	_, err = e.svc.SetAccessOverride(ctx, o, org, proj, ptr("restricted"), false, nil)
	x := wantErr(t, err, 409, "WOULD_HIDE")
	list, _ := x.Details["would_hide"].([]UserRef)
	got := map[uuid.UUID]bool{}
	for _, u := range list {
		got[u.ID] = true
	}
	if len(got) != 2 || !got[m1] || !got[m2] {
		t.Fatalf("would_hide = %v, want m1 and m2", got)
	}
	if e.count(t, `SELECT count(*) FROM projects WHERE id = $1 AND access_override IS NOT NULL`, proj) != 0 {
		t.Fatal("applied without confirm")
	}
	res, err := e.svc.SetAccessOverride(ctx, o, org, proj, ptr("restricted"), true, nil)
	if err != nil || res.Value.EffectiveMode != "restricted" {
		t.Fatalf("confirmed: %v %+v", err, res)
	}
	for _, u := range []uuid.UUID{m1, m2} {
		if acc, _, _ := e.eng.Effective(ctx, u, org, engine.ProjectScope(proj)); !acc.Hidden {
			t.Errorf("%s still sees the project after the confirmed change", u)
		}
	}
	for _, u := range []uuid.UUID{m3, m4, admin, owner} {
		if acc, _, _ := e.eng.Effective(ctx, u, org, engine.ProjectScope(proj)); acc.Hidden {
			t.Errorf("%s lost the project although they have their own access", u)
		}
	}
	if e.count(t, `SELECT count(*) FROM audit_logs WHERE org_id = $1 AND action = 'access.mode.changed' AND project_id = $2`, org, proj) != 1 {
		t.Error("no audit row for the mode change")
	}
	pa, _ = e.svc.ProjectAccess(ctx, o, org, proj, "", 100)
	if pa.Mode != "restricted" || len(pa.Data) != 4 {
		t.Fatalf("restricted list: %+v", pa)
	}
	// back to inheriting the open organization: nobody loses anything, no warning
	if _, err := e.svc.SetAccessOverride(ctx, o, org, proj, nil, false, nil); err != nil {
		t.Fatalf("clearing the override: %v", err)
	}
	// invalid mode, unknown project, and a person without org:access-policy
	_, err = e.svc.SetAccessOverride(ctx, o, org, proj, ptr("closed"), false, nil)
	wantErr(t, err, 422, "")
	_, err = e.svc.SetAccessOverride(ctx, o, org, uuid.New(), ptr("open"), false, nil)
	wantErr(t, err, 404, "")
	_, err = e.svc.SetAccessOverride(ctx, act(m1), org, proj, ptr("open"), false, nil)
	wantErr(t, err, 403, "PERMISSION_DENIED")
}

// A project that does not exist, one of another organization and one the actor cannot see answer the same 404 with the same body.
func TestNotFoundDoesNotLeakExistence(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	org, owner := e.org(t, "restricted")
	other, _ := e.org(t, "open")
	hidden := e.project(t, org)
	foreign := e.project(t, other)
	nonexistent := uuid.New()
	// the actor manages access but sees no project: restricted organization and no assignments
	mgr := e.newMember(t, org, "member")
	tpl := e.customOrgTemplate(t, org, "mgr", orgOnly(t, "org:read", "member:read", "assignment:read", "assignment:grant", "audit:read"))
	e.setOrgTemplate(t, org, mgr, tpl, "member")
	target := e.newMember(t, org, "member")
	ownAsg := e.assign(t, org, "user", target, "project", hidden, sysProject("viewer"), nil)
	m := act(mgr)
	type probe struct {
		name string
		do   func(p uuid.UUID) error
	}
	probes := []probe{
		{"create assignment", func(p uuid.UUID) error {
			_, err := e.svc.CreateAssignment(ctx, m, org, AssignmentInput{SubjectType: "user", SubjectID: target, Scope: ScopeRef{Type: "project", ID: p}, TemplateID: sysProject("viewer")}, nil)
			return err
		}},
		{"create assignment (repo)", func(p uuid.UUID) error {
			_, err := e.svc.CreateAssignment(ctx, m, org, AssignmentInput{SubjectType: "user", SubjectID: target, Scope: ScopeRef{Type: "repo", ID: p}, TemplateID: systemRepo("repo-read")}, nil)
			return err
		}},
		{"project access", func(p uuid.UUID) error { _, err := e.svc.ProjectAccess(ctx, m, org, p, "", 10); return err }},
		{"simulate", func(p uuid.UUID) error {
			_, err := e.svc.Simulate(ctx, m, org, SimulateInput{UserID: target, Permission: "project:view", Scope: &ScopeRef{Type: "project", ID: p}})
			return err
		}},
		{"user permissions", func(p uuid.UUID) error {
			_, err := e.svc.UserPermissions(ctx, m, org, target, p.String(), "")
			return err
		}},
	}
	for _, pr := range probes {
		var bodies []string
		for _, p := range []uuid.UUID{hidden, foreign, nonexistent} {
			err := pr.do(p)
			x := wantErr(t, err, 404, "")
			b, _ := json.Marshal(map[string]any{"status": x.Status, "code": x.Code, "message": x.Message, "details": x.Details})
			bodies = append(bodies, string(b))
		}
		if bodies[0] != bodies[1] || bodies[1] != bodies[2] {
			t.Errorf("%s: hidden, foreign and nonexistent differ: %v", pr.name, bodies)
		}
	}
	// assignments: one in a hidden project, one of another organization and one that does not exist
	for _, id := range []uuid.UUID{ownAsg, uuid.New()} {
		_, err := e.svc.RevokeAssignment(ctx, m, org, id, nil)
		wantErr(t, err, 404, "")
		_, err = e.svc.PatchAssignment(ctx, m, org, id, PatchAssignmentInput{ReasonSet: true, Reason: "x"}, nil)
		wantErr(t, err, 404, "")
		_, err = e.svc.GetAssignment(ctx, m, org, id)
		wantErr(t, err, 404, "")
	}
	// templates and groups of another organization are 404 as well, indistinguishable from missing ones
	foreignGroup, _ := e.svc.CreateGroup(ctx, act(func() uuid.UUID {
		var o uuid.UUID
		_ = e.pool.QueryRow(ctx, `SELECT owner_id FROM organizations WHERE id = $1`, other).Scan(&o)
		return o
	}()), other, GroupInput{Slug: "x", Name: ptr("x")}, nil)
	ownerAct := act(owner)
	a1 := func() error { _, err := e.svc.GetGroup(ctx, ownerAct, org, foreignGroup.Value.ID); return err }()
	a2 := func() error { _, err := e.svc.GetGroup(ctx, ownerAct, org, uuid.New()); return err }()
	if asErr(t, a1).Message != asErr(t, a2).Message || asErr(t, a1).Status != 404 {
		t.Errorf("foreign vs missing group: %v / %v", a1, a2)
	}

	// timing: the three answers cost the same order of magnitude (they run the same code path)
	med := func(p uuid.UUID) time.Duration {
		var ds []time.Duration
		for i := 0; i < 200; i++ {
			t0 := time.Now()
			_ = probes[2].do(p)
			ds = append(ds, time.Since(t0))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[len(ds)/2]
	}
	mh, mf, mn := med(hidden), med(foreign), med(nonexistent)
	t.Logf("median time of the 404 path: hidden %v, other organization %v, nonexistent %v", mh, mf, mn)
	lo, hi := min3(mh, mf, mn), max3(mh, mf, mn)
	if hi > 4*lo+2*time.Millisecond {
		t.Errorf("404 paths differ in time by more than an order of magnitude: %v %v %v", mh, mf, mn)
	}
}

func min3(a, b, c time.Duration) time.Duration { return min(a, min(b, c)) }
func max3(a, b, c time.Duration) time.Duration { return max(a, max(b, c)) }

// GET /me/permissions with 5 000 projects: size, cold time and cached p99.
func TestMePermissionsPerformance(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	org, owner := e.org(t, "open")
	e.exec(t, `INSERT INTO projects (org_id, name, slug, repo_url, branch, runtime) SELECT $1, 'P', 'p-' || g || '-' || substr(md5(random()::text),1,8), 'https://example.com/r.git', 'main', 'node' FROM generate_series(1, 5000) g`, org)
	rows, _ := e.pool.Query(ctx, `SELECT id FROM projects WHERE org_id = $1`, org)
	var pids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		_ = rows.Scan(&id)
		pids = append(pids, id)
	}
	rows.Close()
	member := e.newMember(t, org, "member")
	for i := 0; i < 300; i++ {
		e.assign(t, org, "user", member, "project", pids[i], sysProject("viewer"), nil)
	}
	for _, who := range []struct {
		name string
		id   uuid.UUID
	}{{"owner (floor on everything)", owner}, {"member with 300 own assignments", member}} {
		e.eng.Invalidate(engine.Target{Org: org})
		e.svc.me.purgeOrg(org)
		t0 := time.Now()
		res, err := e.svc.MyPermissions(ctx, who.id, org.String(), "", "projects")
		cold := time.Since(t0)
		if err != nil {
			t.Fatal(err)
		}
		var ds []time.Duration
		for i := 0; i < 2000; i++ {
			t1 := time.Now()
			if _, err := e.svc.MyPermissions(ctx, who.id, org.String(), "", "projects"); err != nil {
				t.Fatal(err)
			}
			ds = append(ds, time.Since(t1))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		p50, p99 := ds[len(ds)/2], ds[len(ds)*99/100]
		t.Logf("%s: 5000 projects, body %d bytes, cold %v, cached p50 %v p99 %v", who.name, len(res.Body), cold, p50, p99)
		if len(res.Body) > 300*1024 {
			t.Errorf("%s: body %d bytes > 300 KB", who.name, len(res.Body))
		}
		if p99 > 20*time.Millisecond {
			t.Errorf("%s: cached p99 %v >= 20 ms", who.name, p99)
		}
		if cold > 25*time.Millisecond*4 {
			t.Logf("%s: cold computation %v (informational: the 25 ms goal of the work breakdown is for the server time with the snapshot cached)", who.name, cold)
		}
	}
}
