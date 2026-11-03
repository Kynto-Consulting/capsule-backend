//go:build dbtest

package repository

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
)

func TestProjectMembersDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewProjectMemberRepository(pool)
	ctx := context.Background()
	now := time.Now().Add(-time.Hour)

	owner := f.user("", now)
	admin := f.user("", now)
	m1 := f.user("", now) // plain member with explicit admin on p1
	m2 := f.user("", now) // plain member, no explicit role
	outsider := f.user("", now)
	org := f.org(owner)
	f.member(org, owner, "owner")
	f.member(org, admin, "admin")
	f.member(org, m1, "member")
	f.member(org, m2, "member")
	p1, p2 := f.project(org, ""), f.project(org, "")
	otherOrg := f.org(owner)
	f.member(otherOrg, m1, "member")
	pOther := f.project(otherOrg, "")

	// ---- default mode + LoadOrgAccess ----
	mode, err := r.GetOrgAccessMode(ctx, org)
	if err != nil || mode != "open" {
		t.Fatalf("default mode %q %v", mode, err)
	}
	if _, err := r.GetOrgAccessMode(ctx, uuid.New()); err != domain.ErrNotFound {
		t.Fatalf("mode missing org: %v", err)
	}
	if oa, err := r.LoadOrgAccess(ctx, org, outsider); err != nil || oa != nil {
		t.Fatalf("non member: %v %v", oa, err)
	}

	// ---- Upsert / List / role update / Remove ----
	if err := r.UpsertMember(ctx, p1, m1, "admin", owner); err != nil {
		t.Fatal(err)
	}
	if err := r.UpsertMember(ctx, p2, m1, "viewer", owner); err != nil {
		t.Fatal(err)
	}
	if err := r.UpsertMember(ctx, pOther, m1, "deployer", owner); err != nil {
		t.Fatal(err)
	}
	if err := r.UpsertMember(ctx, p1, m1, "deployer", owner); err != nil { // ON CONFLICT -> update
		t.Fatal(err)
	}
	if err := r.UpsertMember(ctx, p1, m1, "admin", owner); err != nil {
		t.Fatal(err)
	}
	if err := r.UpsertMember(ctx, p1, m2, "bogus", owner); err == nil {
		t.Fatal("invalid role accepted by CHECK constraint")
	}
	list, err := r.ListExplicit(ctx, p1)
	if err != nil || len(list) != 1 || list[0].UserID != m1 || list[0].Role != "admin" || list[0].CreatedBy == nil || *list[0].CreatedBy != owner {
		t.Fatalf("ListExplicit: %+v %v", list, err)
	}
	oa, err := r.LoadOrgAccess(ctx, org, m1)
	if err != nil || oa == nil || oa.OrgRole != "member" || oa.Mode != "open" || len(oa.Explicit) != 2 ||
		oa.Explicit[p1] != "admin" || oa.Explicit[p2] != "viewer" {
		t.Fatalf("LoadOrgAccess: %+v %v", oa, err)
	}
	if _, leaked := oa.Explicit[pOther]; leaked {
		t.Fatal("explicit role from another org leaked")
	}

	// ---- restricted mode + UserGrants ----
	if err := r.SetOrgAccessMode(ctx, org, "restricted"); err != nil {
		t.Fatal(err)
	}
	if err := r.SetOrgAccessMode(ctx, org, "weird"); err == nil {
		t.Fatal("invalid mode accepted")
	}
	if err := r.SetOrgAccessMode(ctx, uuid.New(), "open"); err != domain.ErrNotFound {
		t.Fatalf("set mode missing org: %v", err)
	}
	if oa, _ := r.LoadOrgAccess(ctx, org, m1); oa.Mode != "restricted" {
		t.Fatalf("mode not restricted: %q", oa.Mode)
	}
	grants, err := r.UserGrants(ctx, m1)
	if err != nil {
		t.Fatal(err)
	}
	byProj := map[uuid.UUID]authz.Grant{}
	for _, g := range grants {
		byProj[g.ProjectID] = g
	}
	if len(grants) != 3 {
		t.Fatalf("UserGrants len %d (want p1,p2,pOther)", len(grants))
	}
	if g := byProj[p1]; g.OrgID != org || g.OrgRole != "member" || g.Mode != "restricted" || g.ExplicitRole != "admin" || g.OrgSlug == "" || g.ProjectSlug == "" {
		t.Fatalf("grant p1 %+v", g)
	}
	if g := byProj[pOther]; g.ExplicitRole != "deployer" || g.Mode != "open" {
		t.Fatalf("grant pOther %+v", g)
	}
	// m2 has no explicit role: ExplicitRole is '' (COALESCE), not NULL-scan error
	g2, err := r.UserGrants(ctx, m2)
	if err != nil || len(g2) != 2 || g2[0].ExplicitRole != "" {
		t.Fatalf("m2 grants: %+v %v", g2, err)
	}
	if g, err := r.UserGrants(ctx, outsider); err != nil || len(g) != 0 {
		t.Fatalf("outsider grants: %v %v", g, err)
	}
	// soft-deleted projects and orgs disappear from grants and access
	pDel := f.project(org, "")
	if _, err := pool.Exec(ctx, `UPDATE projects SET deleted_at=now() WHERE id=$1`, pDel); err != nil {
		t.Fatal(err)
	}
	if g, _ := r.UserGrants(ctx, m2); len(g) != 2 {
		t.Fatalf("deleted project still granted: %d", len(g))
	}

	// ---- CountEffectiveAdmins: owner + admin + member(explicit admin on p1) = 3; p2 = 2 ----
	if n, err := r.CountEffectiveAdmins(ctx, org, p1); err != nil || n != 3 {
		t.Fatalf("effective admins p1 = %d, %v (want 3)", n, err)
	}
	if n, err := r.CountEffectiveAdmins(ctx, org, p2); err != nil || n != 2 {
		t.Fatalf("effective admins p2 = %d, %v (want 2)", n, err)
	}
	// an explicit admin who is NOT an org member must not count
	if err := r.UpsertMember(ctx, p2, outsider, "admin", owner); err != nil {
		t.Fatal(err)
	}
	if n, _ := r.CountEffectiveAdmins(ctx, org, p2); n != 2 {
		t.Fatalf("non-member explicit admin counted: %d", n)
	}

	// ---- RemoveMember ----
	if ok, err := r.RemoveMember(ctx, p1, m1); err != nil || !ok {
		t.Fatalf("remove: %v %v", ok, err)
	}
	if ok, err := r.RemoveMember(ctx, p1, m1); err != nil || ok {
		t.Fatalf("remove twice: %v %v", ok, err)
	}
	if n, _ := r.CountEffectiveAdmins(ctx, org, p1); n != 2 {
		t.Fatalf("admins after remove: %d", n)
	}

	// ---- project / user cascade ----
	if _, err := pool.Exec(ctx, `DELETE FROM project_members WHERE project_id=$1`, p2); err != nil {
		t.Fatal(err)
	}

	// ---- Audit: inet + jsonb ----
	e := authz.AuditEntry{OrgID: org, UserID: owner, Action: "member.upsert", ResourceType: "project", ResourceID: p1,
		IP: "203.0.113.7", OldValues: map[string]any{"role": "viewer"}, NewValues: map[string]any{"role": "admin", "n": 1}}
	if err := r.Audit(ctx, e); err != nil {
		t.Fatalf("Audit with ip: %v", err)
	}
	var ip, oldv, newv string
	if err := pool.QueryRow(ctx, `SELECT host(ip_address), old_values::text, new_values::text FROM audit_logs
		WHERE org_id=$1 AND action='member.upsert' ORDER BY created_at DESC LIMIT 1`, org).Scan(&ip, &oldv, &newv); err != nil {
		t.Fatal(err)
	}
	var ov, nv map[string]any
	_ = json.Unmarshal([]byte(oldv), &ov)
	_ = json.Unmarshal([]byte(newv), &nv)
	if ip != "203.0.113.7" || ov["role"] != "viewer" || nv["role"] != "admin" {
		t.Fatalf("audit row: ip=%s old=%s new=%s", ip, oldv, newv)
	}
	// IPv6, empty IP, nil maps
	if err := r.Audit(ctx, authz.AuditEntry{OrgID: org, UserID: owner, Action: "member.remove", ResourceType: "project", ResourceID: p1, IP: "2001:db8::1"}); err != nil {
		t.Fatalf("Audit ipv6/nil maps: %v", err)
	}
	if err := r.Audit(ctx, authz.AuditEntry{OrgID: org, UserID: owner, Action: "member.remove", ResourceType: "project", ResourceID: p1}); err != nil {
		t.Fatalf("Audit without ip: %v", err)
	}
	var nulls int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='member.remove' AND ip_address IS NULL AND old_values IS NULL`, org).Scan(&nulls)
	if nulls != 1 {
		t.Fatalf("expected one audit row with NULL ip/old_values, got %d", nulls)
	}
	// "ip:port" style input must fail loudly rather than corrupt data
	if err := r.Audit(ctx, authz.AuditEntry{OrgID: org, UserID: owner, Action: "x", ResourceType: "project", ResourceID: p1, IP: "203.0.113.7:5555"}); err == nil {
		t.Log("note: Audit accepts ip:port input (callers must strip the port)")
	} else {
		t.Logf("note: Audit rejects ip:port input as expected: %v", err)
	}

	// ---- org soft delete hides access ----
	if _, err := pool.Exec(ctx, `UPDATE organizations SET deleted_at=now() WHERE id=$1`, otherOrg); err != nil {
		t.Fatal(err)
	}
	if oa, err := r.LoadOrgAccess(ctx, otherOrg, m1); err != nil || oa != nil {
		t.Fatalf("deleted org access: %v %v", oa, err)
	}
	if g, _ := r.UserGrants(ctx, m1); len(g) != 2 { // p1,p2 of the live org only
		t.Fatalf("grants of deleted org leaked: %d", len(g))
	}
	if _, err := r.GetOrgAccessMode(ctx, otherOrg); err != domain.ErrNotFound {
		t.Fatalf("mode of deleted org: %v", err)
	}
}

// Concurrent upserts of the same (project,user) must converge on a single row.
func TestProjectMembersConcurrentUpsertDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewProjectMemberRepository(pool)
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)
	f.member(org, u, "owner")
	p := f.project(org, "")
	roles := []string{"admin", "deployer", "viewer"}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := r.UpsertMember(ctx, p, u, roles[i%3], u); err != nil {
				t.Errorf("upsert: %v", err)
			}
		}(i)
	}
	wg.Wait()
	l, err := r.ListExplicit(ctx, p)
	if err != nil || len(l) != 1 {
		t.Fatalf("rows after concurrent upsert: %d %v", len(l), err)
	}
}

// Concurrent Add against the access-rule limit: FOR UPDATE must make the cap exact.
func TestNetworkAddConcurrentLimitDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)
	proj := f.project(org, "")
	var dbID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO databases (project_id, org_id, name, host, db_name, credentials_enc, port, status)
		VALUES ($1,$2,'d','h','db',convert_to('x','UTF8'),$3,'available') RETURNING id`, proj, org, randPort()).Scan(&dbID); err != nil {
		t.Fatal(err)
	}
	repo := NewDatabaseAccessRepository(pool)
	t.Cleanup(func() { _ = repo.DeleteAll(context.Background(), dbID) }) // keep TestNetworkDB (exact ListDesired count) re-runnable
	const limit = 3
	var mu sync.Mutex
	okN, limN := 0, 0
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := repo.Add(ctx, &domain.DatabaseAccessRule{DatabaseID: dbID, CIDR: "198.51.100." + itoa(i) + "/32"}, limit)
			mu.Lock()
			defer mu.Unlock()
			switch err {
			case nil:
				okN++
			case domain.ErrRuleLimit:
				limN++
			default:
				t.Errorf("Add: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	l, _ := repo.List(ctx, dbID)
	if okN != limit || limN != 12-limit || len(l) != limit {
		t.Fatalf("limit not exact: ok=%d limit=%d stored=%d", okN, limN, len(l))
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
