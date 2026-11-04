//go:build dbtest

package repository

import (
	"context"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// planNodes walks an EXPLAIN (FORMAT JSON) document and returns "<node type> <relation>" for every node.
func planNodes(t *testing.T, raw []byte) []string {
	t.Helper()
	var doc []map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("explain json: %v", err)
	}
	var out []string
	var walk func(n map[string]any)
	walk = func(n map[string]any) {
		nt, _ := n["Node Type"].(string)
		rel, _ := n["Relation Name"].(string)
		idx, _ := n["Index Name"].(string)
		out = append(out, nt+" "+rel+" "+idx)
		if kids, ok := n["Plans"].([]any); ok {
			for _, k := range kids {
				walk(k.(map[string]any))
			}
		}
	}
	walk(doc[0]["Plan"].(map[string]any))
	return out
}

func explain(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) []string {
	t.Helper()
	var raw []byte
	if err := pool.QueryRow(context.Background(), "EXPLAIN (FORMAT JSON) "+sql, args...).Scan(&raw); err != nil {
		t.Fatalf("explain: %v", err)
	}
	return planNodes(t, raw)
}

func noSeqScan(t *testing.T, what string, nodes []string, rel string) {
	t.Helper()
	for _, n := range nodes {
		if len(n) > 8 && n[:8] == "Seq Scan" && n == "Seq Scan "+rel+" " {
			t.Errorf("%s: Seq Scan on %s in plan %v", what, rel, nodes)
		}
	}
	t.Logf("%s plan: %v", what, nodes)
}

// 100 000 assignments in the organization, one user with 10 000 of their own plus a group with 500: the snapshot query must use
// indexes (no Seq Scan on access_assignments) and load in <= 50 ms measured against real Postgres.
func TestAccessSnapshotQueryPlanAndLatency(t *testing.T) {
	x := newTfx(t)
	ctx := context.Background()
	s := NewAccessStore(x.pool)

	mustExec(t, x.pool, `INSERT INTO projects (org_id,name,slug,repo_url,branch,runtime) SELECT $1,'P','bulk-'||g,'https://example.com/r.git','main','node' FROM generate_series(1,10000) g`, x.org)
	mustExec(t, x.pool, `ALTER TABLE access_assignments DISABLE TRIGGER USER`)
	// 10 000 own assignments of the first user, one per project
	mustExec(t, x.pool, `INSERT INTO access_assignments (org_id,subject_type,subject_id,scope_type,scope_id,template_id,source)
		SELECT $1,'user',$2,'project',p.id,$3,'manual' FROM projects p WHERE p.org_id=$1 AND p.slug LIKE 'bulk-%'`, x.org, x.user, x.viewerTpl)
	// a second user with exactly 10 000 own assignments and no group (the case of the acceptance criterion)
	u2 := x.f.user("", timeNow())
	x.f.member(x.org, u2, "member")
	mustExec(t, x.pool, `INSERT INTO access_assignments (org_id,subject_type,subject_id,scope_type,scope_id,template_id,source)
		SELECT $1,'user',$2,'project',p.id,$3,'manual' FROM projects p WHERE p.org_id=$1 AND p.slug LIKE 'bulk-%'`, x.org, u2, x.depl)
	// a group the user belongs to with 500 assignments
	var grp uuid.UUID
	if err := x.pool.QueryRow(ctx, `INSERT INTO groups (org_id,slug,name) VALUES ($1,'big','Big') RETURNING id`, x.org).Scan(&grp); err != nil {
		t.Fatal(err)
	}
	mustExec(t, x.pool, `INSERT INTO group_members (group_id,user_id) VALUES ($1,$2)`, grp, x.user)
	mustExec(t, x.pool, `INSERT INTO access_assignments (org_id,subject_type,subject_id,scope_type,scope_id,template_id,source)
		SELECT $1,'group',$2,'project',p.id,$3,'manual' FROM projects p WHERE p.org_id=$1 AND p.slug LIKE 'bulk-%' LIMIT 500`, x.org, grp, x.depl)
	// filler up to 100 000 rows in the organization (other people) and another organization
	mustExec(t, x.pool, `INSERT INTO access_assignments (org_id,subject_type,subject_id,scope_type,scope_id,template_id,source)
		SELECT $1,'user',gen_random_uuid(),'org',$1,$2,'manual' FROM generate_series(1,79500)`, x.org, x.viewerTpl)
	other := x.f.org(x.owner)
	mustExec(t, x.pool, `INSERT INTO access_assignments (org_id,subject_type,subject_id,scope_type,scope_id,template_id,source)
		SELECT $1,'user',gen_random_uuid(),'org',$1,$2,'manual' FROM generate_series(1,5000)`, other, x.viewerTpl)
	mustExec(t, x.pool, `ALTER TABLE access_assignments ENABLE TRIGGER USER`)
	mustExec(t, x.pool, `ANALYZE access_assignments`)
	mustExec(t, x.pool, `ANALYZE group_members`)
	mustExec(t, x.pool, `ANALYZE groups`)
	total := qInt(t, x.pool, `SELECT count(*) FROM access_assignments WHERE org_id=$1`, x.org)
	t.Logf("assignments in the organization: %d (2 x 10 000 own + 500 via group + filler)", total)
	if total != 100000 {
		t.Fatalf("setup: %d rows", total)
	}

	noSeqScan(t, "snapshot query", explain(t, x.pool, loadUserAssignmentsSQL, x.org, x.user), "access_assignments")
	noSeqScan(t, "snapshot query (user without own rows)", explain(t, x.pool, loadUserAssignmentsSQL, x.org, uuid.New()), "access_assignments")
	noSeqScan(t, "who has access to X", explain(t, x.pool,
		`SELECT `+assignmentCols+` FROM access_assignments a WHERE a.scope_type = $1 AND a.scope_id = $2 AND a.org_id = $3 AND a.revoked_at IS NULL`, "project", x.p1, x.org), "access_assignments")
	noSeqScan(t, "expiry sweep", explain(t, x.pool,
		`SELECT id FROM access_assignments WHERE revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= $1`, time.Now()), "access_assignments")

	{
		rows, err := x.pool.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS) "+loadUserAssignmentsSQL, x.org, x.user)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var l string
			_ = rows.Scan(&l)
			t.Log("  ", l)
		}
		rows.Close()
	}
	measure := func(user uuid.UUID, want int) (time.Duration, time.Duration) {
		var durs []time.Duration
		for i := 0; i < 21; i++ {
			start := time.Now()
			got, err := s.LoadUserAssignments(ctx, x.org, user)
			d := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != want {
				t.Fatalf("loaded %d assignments, want %d", len(got), want)
			}
			if i > 0 { // first run warms the pool and the plan cache
				durs = append(durs, d)
			}
		}
		sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
		return durs[len(durs)/2], durs[len(durs)-1]
	}
	med, mx := measure(u2, 10000)
	t.Logf("LoadUserAssignments, user with 10 000 own assignments, 100 000 rows in the organization: median=%v max=%v", med, mx)
	if med > 50*time.Millisecond {
		t.Errorf("median %v > 50ms", med)
	}
	gmed, gmx := measure(x.user, 10500)
	t.Logf("LoadUserAssignments, user with 10 000 own + 500 via group: median=%v max=%v", gmed, gmx)
	// the other query of a snapshot: template versions for the distinct templates (tiny)
	start := time.Now()
	if _, err := s.LoadTemplateVersions(ctx, []TemplateRef{{x.viewerTpl, 0}, {x.depl, 0}, {SystemTemplateID("org", "member"), 0}}); err != nil {
		t.Fatal(err)
	}
	t.Logf("LoadTemplateVersions(3 refs): %v", time.Since(start))
}
