//go:build dbtest

package repository

import (
	"context"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/backup"
	"github.com/kynto/capsule/backend/internal/domain"
)

// randPort returns a port unlikely to collide with earlier runs on a shared test db.
func randPort() int { return 20000 + rand.Intn(40000) }

func TestProjectPortsDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewProjectPortRepository(pool)
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)
	p1, p2 := f.project(org, ""), f.project(org, "")
	h1, h2, h3, h4 := randPort(), randPort()+1, randPort()+2, randPort()+3
	if h1 == h2 || h2 == h3 {
		t.Skip("port collision")
	}

	if l, err := r.List(ctx, p1); err != nil || l == nil || len(l) != 0 {
		t.Fatalf("empty list: %v %v", l, err)
	}
	out, err := r.Replace(ctx, p1, []*domain.ProjectPort{
		{Name: "b", ContainerPort: 9090, HostPort: h2}, {Name: "a", ContainerPort: 8080, HostPort: h1}})
	if err != nil || len(out) != 2 || out[0].ContainerPort != 8080 || out[1].ContainerPort != 9090 ||
		out[0].HostPort != h1 || out[0].Protocol != "tcp" || out[0].Rules == nil || out[0].Name != "a" {
		t.Fatalf("Replace insert: %+v %v", out, err)
	}

	// ---- rules ----
	mk := func(c string) *domain.PortRule { return &domain.PortRule{CIDR: c, Description: "d", CreatedBy: &u} }
	r1, err := r.AddRule(ctx, p1, 8080, "tcp", mk("203.0.113.5/32"), 3)
	if err != nil || r1.PortID != out[0].ID || r1.CreatedBy == nil {
		t.Fatalf("AddRule: %+v %v", r1, err)
	}
	if _, err := r.AddRule(ctx, p1, 8080, "tcp", mk("203.0.113.5/32"), 3); err != domain.ErrConflict {
		t.Fatalf("dup rule: %v", err)
	}
	if _, err := r.AddRule(ctx, p1, 4444, "tcp", mk("203.0.113.6/32"), 3); err != domain.ErrNotFound {
		t.Fatalf("rule on unknown port: %v", err)
	}
	if _, err := r.AddRule(ctx, p2, 8080, "tcp", mk("203.0.113.6/32"), 3); err != domain.ErrNotFound {
		t.Fatalf("rule through wrong project: %v", err)
	}
	if _, err := r.AddRule(ctx, p1, 8080, "tcp", mk("255.255.255.255/32"), 3); err != nil { // longest cidr fits varchar(18)
		t.Fatalf("longest cidr: %v", err)
	}
	if _, err := r.AddRule(ctx, p1, 8080, "tcp", mk("198.51.100.0/24"), 3); err != nil {
		t.Fatal(err)
	}
	if _, err := r.AddRule(ctx, p1, 8080, "tcp", mk("192.0.2.0/24"), 3); err != domain.ErrRuleLimit {
		t.Fatalf("limit: %v", err)
	}
	rr9, err := r.AddRule(ctx, p1, 9090, "tcp", mk("203.0.113.9/32"), 3)
	if err != nil {
		t.Fatal(err)
	}
	// concurrent limit on a fresh port
	if _, err := r.Replace(ctx, p2, []*domain.ProjectPort{{ContainerPort: 80, HostPort: h3}}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	okN, limN := 0, 0
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := r.AddRule(ctx, p2, 80, "tcp", mk("198.51.100."+itoa(i)+"/32"), 3)
			mu.Lock()
			defer mu.Unlock()
			switch err {
			case nil:
				okN++
			case domain.ErrRuleLimit:
				limN++
			default:
				t.Errorf("AddRule concurrent: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if okN != 3 || limN != 9 {
		t.Fatalf("port rule limit not exact: ok=%d limit=%d", okN, limN)
	}

	// ---- Replace keeps rules + host_port of kept ports, drops removed ports and their rules ----
	out, err = r.Replace(ctx, p1, []*domain.ProjectPort{
		{Name: "renamed", ContainerPort: 8080, HostPort: h4}, // HostPort ignored for kept port
		{Name: "new", ContainerPort: 7000, HostPort: h2},     // h2 was just freed by removing 9090
	})
	if err != nil || len(out) != 2 {
		t.Fatalf("Replace 2: %+v %v", out, err)
	}
	by := map[int]*domain.ProjectPort{}
	for _, p := range out {
		by[p.ContainerPort] = p
	}
	if by[8080].Name != "renamed" || by[8080].HostPort != h1 || len(by[8080].Rules) != 3 || by[7000].HostPort != h2 {
		t.Fatalf("kept/new ports wrong: 8080=%+v 7000=%+v", by[8080], by[7000])
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM project_port_rules WHERE id=$1`, rr9.ID).Scan(&n)
	if n != 0 {
		t.Fatal("rule of removed port survived")
	}
	// host port already used by another project -> ErrConflict and nothing changes
	if _, err := r.Replace(ctx, p2, []*domain.ProjectPort{{ContainerPort: 80, HostPort: h3}, {ContainerPort: 81, HostPort: h1}}); err != domain.ErrConflict {
		t.Fatalf("host port conflict: %v", err)
	}
	if l, _ := r.List(ctx, p2); len(l) != 1 || len(l[0].Rules) != 3 {
		t.Fatalf("failed Replace was not rolled back: %+v", l)
	}

	// ---- UsedHostPorts across ports / databases / deployments ----
	lo := h1 - 5
	hi := h1 + 10
	dbPort, depPort := h1+6, h1+7
	var dbID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO databases (project_id, org_id, name, host, db_name, credentials_enc, port, status)
		VALUES ($1,$2,'d','h','db',convert_to('x','UTF8'),$3,'available') RETURNING id`, p1, org, dbPort).Scan(&dbID); err != nil {
		t.Fatalf("db fixture: %v", err)
	}
	dep := mkDeployment(t, f, p1, "success", "manual", time.Now())
	if _, err := pool.Exec(ctx, `UPDATE deployments SET host_port=$2 WHERE id=$1`, dep, depPort); err != nil {
		t.Fatal(err)
	}
	used, err := r.UsedHostPorts(ctx, "tcp", lo, hi)
	if err != nil {
		t.Fatalf("UsedHostPorts: %v", err)
	}
	for _, want := range []int{h1, dbPort, depPort} {
		if !used[want] {
			t.Errorf("UsedHostPorts missing %d (got %v)", want, used)
		}
	}
	if used[hi+100] {
		t.Error("out of range port reported")
	}
	if _, err := pool.Exec(ctx, `UPDATE databases SET deleted_at=now() WHERE id=$1`, dbID); err == nil {
		used, _ = r.UsedHostPorts(ctx, "tcp", lo, hi)
		if used[dbPort] {
			t.Error("deleted database still reserves its port")
		}
	}

	// ---- ListDesired / DeleteRule / DeleteAll / CHECKs ----
	des, err := r.ListDesired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cnt := 0
	for _, d := range des {
		if d.ProjectID == p1 && d.HostPort == h1 {
			cnt++
		}
	}
	if cnt != 3 {
		t.Fatalf("ListDesired rules for p1/8080: %d (want 3)", cnt)
	}
	rules, _ := r.List(ctx, p1)
	var ruleID uuid.UUID
	for _, p := range rules {
		if p.ContainerPort == 8080 {
			ruleID = p.Rules[0].ID
		}
	}
	if err := r.DeleteRule(ctx, p2, ruleID); err != domain.ErrNotFound {
		t.Fatalf("DeleteRule cross-project: %v", err)
	}
	if err := r.DeleteRule(ctx, p1, ruleID); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteRule(ctx, p1, ruleID); err != domain.ErrNotFound {
		t.Fatalf("DeleteRule twice: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_ports (project_id, container_port, protocol, host_port) VALUES ($1,1,'sctp',$2)`, p1, randPort()); err == nil {
		t.Error("sctp accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_ports (project_id, container_port, host_port) VALUES ($1,2,80)`, p1); err == nil {
		t.Error("host port < 1024 accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE projects SET deleted_at=now() WHERE id=$1`, p2); err != nil {
		t.Fatal(err)
	}
	des, _ = r.ListDesired(ctx)
	for _, d := range des {
		if d.ProjectID == p2 {
			t.Fatal("ListDesired includes deleted project")
		}
	}
	if _, err := r.Replace(ctx, p1, nil); err != nil {
		t.Fatalf("Replace(nil): %v", err)
	}
	if l, _ := r.List(ctx, p1); len(l) != 0 {
		t.Fatalf("Replace(nil) left %d ports", len(l))
	}
	if err := r.DeleteAll(ctx, p2); err != nil {
		t.Fatal(err)
	}
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM project_ports WHERE project_id=ANY($1)`, []uuid.UUID{p1, p2}).Scan(&n)
	if n != 0 {
		t.Fatalf("ports left: %d", n)
	}
}

func TestGitCoreDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewGitCoreRepository(pool)
	ctx := context.Background()
	u1, u2, u3 := f.user("", time.Now()), f.user("", time.Now()), f.user("", time.Now())
	org := f.org(u1)
	p, q := f.project(org, ""), f.project(org, "")
	now := time.Now().UTC().Truncate(time.Microsecond)

	if _, err := r.GetState(ctx, p); err != domain.ErrNotFound {
		t.Fatalf("GetState empty: %v", err)
	}
	if err := r.PutState(ctx, &domain.GitCoreState{ProjectID: p, Status: "pending", ImportURL: "https://x/y.git", NextAttemptAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := r.PutState(ctx, &domain.GitCoreState{ProjectID: q, Status: "pending", NextAttemptAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	s, err := r.GetState(ctx, p)
	if err != nil || s.Status != "pending" || s.ImportURL != "https://x/y.git" || s.Attempts != 0 || s.LastError != "" || !s.NextAttemptAt.Equal(now.Add(-time.Minute)) {
		t.Fatalf("GetState: %+v %v", s, err)
	}
	due, err := r.ListDueStates(ctx, now, 1000)
	if err != nil {
		t.Fatal(err)
	}
	foundP, foundQ := false, false
	for _, d := range due {
		foundP = foundP || d.ProjectID == p
		foundQ = foundQ || d.ProjectID == q
	}
	if !foundP || foundQ {
		t.Fatalf("due states: p=%v q=%v", foundP, foundQ)
	}
	if lim, err := r.ListDueStates(ctx, now.Add(2*time.Hour), 1); err != nil || len(lim) != 1 {
		t.Fatalf("limit: %d %v", len(lim), err)
	}
	// upsert -> ready is no longer due
	if err := r.PutState(ctx, &domain.GitCoreState{ProjectID: p, Status: "ready", Attempts: 2, LastError: "e", NextAttemptAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	s, _ = r.GetState(ctx, p)
	if s.Status != "ready" || s.Attempts != 2 || s.LastError != "e" || s.ImportURL != "" {
		t.Fatalf("upsert: %+v", s)
	}
	due, _ = r.ListDueStates(ctx, now, 1000)
	for _, d := range due {
		if d.ProjectID == p {
			t.Fatal("ready state listed as due")
		}
	}
	if err := r.PutState(ctx, &domain.GitCoreState{ProjectID: p, Status: "bogus"}); err == nil {
		t.Fatal("bad status accepted")
	}

	// team sync
	next := now.Add(-time.Second)
	if err := r.ReplaceTeamSync(ctx, p, []uuid.UUID{u1, u2}, "boom", next); err != nil {
		t.Fatalf("ReplaceTeamSync: %v", err)
	}
	if err := r.ReplaceTeamSync(ctx, p, []uuid.UUID{u1, u3}, "again", next); err != nil { // u2 dropped, u1 retried, u3 new
		t.Fatalf("ReplaceTeamSync 2: %v", err)
	}
	ts, err := r.ListDueTeamSync(ctx, now, 1000)
	if err != nil {
		t.Fatal(err)
	}
	got := map[uuid.UUID]*domain.GitTeamSync{}
	for _, x := range ts {
		if x.ProjectID == p {
			got[x.UserID] = x
		}
	}
	if len(got) != 2 || got[u2] != nil || got[u1] == nil || got[u1].Attempts != 2 || got[u1].LastError != "again" ||
		got[u3] == nil || got[u3].Attempts != 1 {
		t.Fatalf("team sync rows: %+v", got)
	}
	// other project untouched; nil pending empties this project only
	if err := r.ReplaceTeamSync(ctx, q, []uuid.UUID{u1}, "", next); err != nil {
		t.Fatal(err)
	}
	if err := r.ReplaceTeamSync(ctx, p, nil, "", next); err != nil {
		t.Fatalf("ReplaceTeamSync(nil): %v", err)
	}
	var np, nq int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM git_team_sync WHERE project_id=$1`, p).Scan(&np)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM git_team_sync WHERE project_id=$1`, q).Scan(&nq)
	if np != 0 || nq != 1 {
		t.Fatalf("after nil replace: p=%d q=%d", np, nq)
	}
	// future items are not due
	if err := r.ReplaceTeamSync(ctx, q, []uuid.UUID{u1}, "", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	ts, _ = r.ListDueTeamSync(ctx, now, 1000)
	for _, x := range ts {
		if x.ProjectID == q {
			t.Fatal("future team sync listed as due")
		}
	}
}

func TestDeployHealthDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	ctx := context.Background()
	pr := NewProjectRepository(pool)
	dr := NewDeploymentRepository(pool)
	u := f.user("", time.Now())
	org := f.org(u)
	p := f.project(org, "")

	// project defaults + update
	c, err := pr.GetHealthConfig(ctx, p)
	if err != nil || c != domain.DefaultProjectHealthConfig() {
		t.Fatalf("default config: %+v %v", c, err)
	}
	want := domain.ProjectHealthConfig{Path: "/healthz", TimeoutSeconds: 30, IntervalSeconds: 2, ExpectedStatus: "200"}
	if err := pr.SetHealthConfig(ctx, p, want); err != nil {
		t.Fatal(err)
	}
	if c, _ := pr.GetHealthConfig(ctx, p); c != want {
		t.Fatalf("config roundtrip: %+v", c)
	}
	if _, err := pr.GetHealthConfig(ctx, uuid.New()); err != domain.ErrNotFound {
		t.Fatalf("missing project config: %v", err)
	}
	if err := pr.SetHealthConfig(ctx, uuid.New(), want); err != domain.ErrNotFound {
		t.Fatalf("set missing project: %v", err)
	}
	_, _ = pool.Exec(ctx, `UPDATE projects SET deleted_at=now() WHERE id=$1`, p)
	if _, err := pr.GetHealthConfig(ctx, p); err != domain.ErrNotFound {
		t.Fatalf("deleted project config: %v", err)
	}
	_, _ = pool.Exec(ctx, `UPDATE projects SET deleted_at=NULL WHERE id=$1`, p)

	// deployments: health absent until a check ran; every deployment SELECT scans
	d, err := dr.Create(ctx, &domain.Deployment{ProjectID: p, Version: "v1", Trigger: "manual", BuildStrategy: "docker"})
	if err != nil {
		t.Fatalf("Create deployment: %v", err)
	}
	if d.Health != nil || d.ErrorMessage != "" {
		t.Fatalf("fresh deployment health %+v", d.Health)
	}
	chk := time.Now().UTC().Truncate(time.Microsecond)
	if err := dr.SetHealth(ctx, d.ID, domain.DeploymentHealth{Status: "healthy", Path: "/healthz", LastCheck: &chk, Detail: strings.Repeat("x", 3000)}); err != nil {
		t.Fatal(err)
	}
	if err := dr.SetErrorMessage(ctx, d.ID, strings.Repeat("e", 5000)); err != nil {
		t.Fatal(err)
	}
	g, err := dr.GetByID(ctx, d.ID)
	if err != nil || g.Health == nil || g.Health.Status != "healthy" || g.Health.Path != "/healthz" ||
		g.Health.LastCheck == nil || !g.Health.LastCheck.Equal(chk) || len(g.Health.Detail) != 2000 || len(g.ErrorMessage) != 4000 {
		t.Fatalf("GetByID health: %+v err=%v", g, err)
	}
	// nil LastCheck defaults to now
	if err := dr.SetHealth(ctx, d.ID, domain.DeploymentHealth{Status: "unhealthy"}); err != nil {
		t.Fatal(err)
	}
	g, _ = dr.GetByID(ctx, d.ID)
	if g.Health == nil || g.Health.Status != "unhealthy" || g.Health.LastCheck == nil || time.Since(*g.Health.LastCheck) > time.Minute || g.Health.Path != "" {
		t.Fatalf("default last check: %+v", g.Health)
	}
	if l, tot, err := dr.ListByProject(ctx, p, 1, 10); err != nil || len(l) != 1 || tot != 1 || l[0].Health == nil {
		t.Fatalf("ListByProject: %v %d %v", l, tot, err)
	}
	if err := dr.UpdateStatus(ctx, d.ID, "success"); err != nil {
		t.Fatal(err)
	}
	if l, err := dr.GetLatestSuccessfulByProject(ctx, p); err != nil || l.ID != d.ID {
		t.Fatalf("GetLatestSuccessful: %v", err)
	}
	d2, _ := dr.Create(ctx, &domain.Deployment{ProjectID: p, Version: "v2", Trigger: "manual", BuildStrategy: "docker"})
	if _, _, err := dr.ListQueued(ctx, 1, 500); err != nil {
		t.Fatalf("ListQueued: %v", err)
	}
	_ = d2
	// updating an unknown id is a silent no-op
	if err := dr.SetHealth(ctx, uuid.New(), domain.DeploymentHealth{Status: "healthy"}); err != nil {
		t.Fatalf("SetHealth unknown id: %v", err)
	}
}

func TestBackupsDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewBackupRepository(pool)
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)
	p, p2 := f.project(org, ""), f.project(org, "")
	now := time.Now().UTC().Truncate(time.Microsecond)

	// settings
	if s, err := r.GetSettings(ctx, p); err != nil || s != nil {
		t.Fatalf("GetSettings empty: %v %v", s, err)
	}
	if err := r.UpsertSettings(ctx, &backup.Settings{ProjectID: p, Enabled: true, Schedule: "6h", RetentionDays: 7, IncludeDatabases: true, IncludeVolumes: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.UpsertSettings(ctx, &backup.Settings{ProjectID: p, Enabled: false, Schedule: "weekly", RetentionDays: 30}); err != nil {
		t.Fatal(err)
	}
	s, err := r.GetSettings(ctx, p)
	if err != nil || s.Enabled || s.Schedule != "weekly" || s.RetentionDays != 30 || s.IncludeDatabases || s.IncludeVolumes || !s.Configured {
		t.Fatalf("settings: %+v %v", s, err)
	}
	if err := r.UpsertSettings(ctx, &backup.Settings{ProjectID: p, Schedule: "yearly", RetentionDays: 7}); err == nil {
		t.Fatal("bad schedule accepted")
	}
	if err := r.UpsertSettings(ctx, &backup.Settings{ProjectID: p, Schedule: "daily", RetentionDays: 0}); err == nil {
		t.Fatal("retention 0 accepted")
	}

	// runs: one running per project, platform included
	run := &backup.Run{ID: uuid.New(), ProjectID: &p, OrgID: &org, Kind: "backup", Trigger: "manual", StartedAt: now, UserID: &u}
	if err := r.CreateRun(ctx, run); err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if err := r.CreateRun(ctx, &backup.Run{ID: uuid.New(), ProjectID: &p, OrgID: &org, Kind: "restore", Trigger: "manual", StartedAt: now}); err != backup.ErrRunInProgress {
		t.Fatalf("second running run: %v", err)
	}
	if err := r.CreateRun(ctx, &backup.Run{ID: uuid.New(), ProjectID: &p2, OrgID: &org, Kind: "backup", Trigger: "manual", StartedAt: now}); err != nil {
		t.Fatalf("other project run: %v", err)
	}
	// platform runs (project NULL): the unique index uses COALESCE(project_id, zero uuid)
	plat := &backup.Run{ID: uuid.New(), Kind: "backup", Trigger: "schedule", StartedAt: now}
	n, err := r.FailOrphans(ctx, now) // clears every running run in the shared db
	if err != nil || n < 2 {
		t.Fatalf("FailOrphans: n=%d err=%v", n, err)
	}
	if err := r.CreateRun(ctx, plat); err != nil {
		t.Fatalf("platform run: %v", err)
	}
	if err := r.CreateRun(ctx, &backup.Run{ID: uuid.New(), Kind: "backup", Trigger: "schedule", StartedAt: now}); err != backup.ErrRunInProgress {
		t.Fatalf("second platform run: %v", err)
	}
	if err := r.FinishRun(ctx, plat.ID, "success", 1234, "", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateRun(ctx, &backup.Run{ID: uuid.New(), Kind: "backup", Trigger: "schedule", StartedAt: now}); err != nil {
		t.Fatalf("platform run after finish: %v", err)
	}
	if n, _ := r.FailOrphans(ctx, now); n < 1 {
		t.Fatalf("FailOrphans platform: %d", n)
	}
	if err := r.CreateRun(ctx, &backup.Run{ID: uuid.New(), ProjectID: &p, OrgID: &org, Kind: "bogus", Trigger: "manual", StartedAt: now}); err == nil {
		t.Fatal("bad kind accepted")
	}

	runs, err := r.ListRuns(ctx, &p, 10)
	if err != nil || len(runs) != 1 || runs[0].ID != run.ID || runs[0].Status != "failed" || runs[0].FinishedAt == nil ||
		runs[0].UserID == nil || *runs[0].UserID != u || runs[0].OrgID == nil || !strings.HasPrefix(runs[0].Error, "interrupted") {
		t.Fatalf("ListRuns: %+v %v", runs, err)
	}
	pr, err := r.ListRuns(ctx, nil, 10) // platform runs only
	if err != nil || len(pr) < 2 {
		t.Fatalf("platform ListRuns: %d %v", len(pr), err)
	}
	for _, x := range pr {
		if x.ProjectID != nil {
			t.Fatal("platform list contains project run")
		}
	}
	if lst, err := r.LastBackupStart(ctx, &p); err != nil || lst == nil || !lst.Equal(now) {
		t.Fatalf("LastBackupStart: %v %v", lst, err)
	}
	if lst, err := r.LastBackupStart(ctx, nil); err != nil || lst == nil {
		t.Fatalf("LastBackupStart platform: %v %v", lst, err)
	}
	pNone := f.project(org, "")
	if lst, err := r.LastBackupStart(ctx, &pNone); err != nil || lst != nil {
		t.Fatalf("LastBackupStart none: %v %v", lst, err)
	}

	// ClaimDue: opt-in via settings row; defaults cover projects with databases; platform candidate.
	// Fresh org/projects so assertions are not polluted by earlier runs.
	org2 := f.org(u)
	pa, pb, pc := f.project(org2, ""), f.project(org2, ""), f.project(org2, "")
	if err := r.UpsertSettings(ctx, &backup.Settings{ProjectID: pa, Enabled: true, Schedule: "daily", RetentionDays: 5}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO databases (project_id, org_id, name, host, db_name, credentials_enc, port, status)
		VALUES ($1,$2,'d','h','db',convert_to('x','UTF8'),$3,'available')`, pb, org2, randPort()); err != nil {
		t.Fatalf("db fixture: %v", err)
	}
	defaults := backup.Settings{Enabled: true, Schedule: "daily", RetentionDays: 14, IncludeDatabases: true}
	seen := map[uuid.UUID]backup.Candidate{}
	var platformSeen bool
	claimed, err := r.ClaimDue(ctx, true, defaults, func(c backup.Candidate) bool {
		if c.ProjectID == nil {
			platformSeen = true
			return false
		}
		seen[*c.ProjectID] = c
		return *c.ProjectID == pa || *c.ProjectID == pb
	})
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	if !platformSeen {
		t.Error("platform candidate missing")
	}
	if _, ok := seen[pc]; ok {
		t.Error("project without settings or databases offered")
	}
	ca, cb := seen[pa], seen[pb]
	if ca.Settings.RetentionDays != 5 || cb.Settings.RetentionDays != 14 || !cb.Settings.IncludeDatabases || ca.OrgID == nil || *ca.OrgID != org2 ||
		ca.Running || ca.LastStart != nil {
		t.Fatalf("candidates: a=%+v b=%+v", ca, cb)
	}
	got := map[uuid.UUID]bool{}
	for _, c := range claimed {
		if c.ProjectID != nil {
			got[*c.ProjectID] = true
		}
		if c.Status != "running" || c.Trigger != "schedule" {
			t.Fatalf("claimed run %+v", c)
		}
	}
	if !got[pa] || !got[pb] {
		t.Fatalf("claimed %v", got)
	}
	// second pass: both are now running -> Running flag, and inserting again conflicts
	_, err = r.ClaimDue(ctx, false, defaults, func(c backup.Candidate) bool {
		if c.ProjectID != nil && *c.ProjectID == pa && !c.Running {
			t.Error("running flag not set")
		}
		return false
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ClaimDue(ctx, false, defaults, func(c backup.Candidate) bool { return c.ProjectID != nil && *c.ProjectID == pa }); err != backup.ErrRunInProgress {
		t.Fatalf("ClaimDue over a running project: %v", err)
	}
	// advisory lock: a held lock makes ClaimDue a no-op
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, backupSchedulerLock); err != nil {
		t.Fatal(err)
	}
	called := false
	runsLocked, err := r.ClaimDue(ctx, true, defaults, func(backup.Candidate) bool { called = true; return true })
	_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, backupSchedulerLock)
	conn.Release()
	if err != nil || runsLocked != nil || called {
		t.Fatalf("ClaimDue under foreign lock: runs=%v called=%v err=%v", runsLocked, called, err)
	}
	// concurrent ClaimDue: advisory lock + unique index => each project claimed at most once
	_, _ = r.FailOrphans(ctx, now)
	var wg sync.WaitGroup
	var cmu sync.Mutex
	total := 0
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rs, err := r.ClaimDue(ctx, false, defaults, func(c backup.Candidate) bool { return c.ProjectID != nil && *c.ProjectID == pa })
			cmu.Lock()
			defer cmu.Unlock()
			if err != nil && err != backup.ErrRunInProgress {
				t.Errorf("concurrent ClaimDue: %v", err)
			}
			total += len(rs)
		}()
	}
	wg.Wait()
	if total != 1 {
		t.Fatalf("concurrent ClaimDue claimed pa %d times, want 1", total)
	}

	// snapshots
	runID := runs[0].ID
	sn := backup.Snapshot{ID: uuid.New(), ProjectID: &p, RunID: runID, Kind: "database", Source: "main", SourceID: uuid.NewString(), Engine: "postgres",
		ObjectKey: "k/" + uuid.NewString(), SizeBytes: 99, Checksum: strings.Repeat("a", 64), CreatedAt: now.Add(-48 * time.Hour)}
	if err := r.AddSnapshot(ctx, &sn); err != nil {
		t.Fatalf("AddSnapshot: %v", err)
	}
	sn2 := sn
	sn2.ID, sn2.CreatedAt, sn2.Kind = uuid.New(), now, "manifest"
	if err := r.AddSnapshot(ctx, &sn2); err != nil {
		t.Fatal(err)
	}
	psn := backup.Snapshot{ID: uuid.New(), RunID: plat.ID, Kind: "platform", Source: "server", ObjectKey: "p/" + uuid.NewString(), CreatedAt: now}
	if err := r.AddSnapshot(ctx, &psn); err != nil {
		t.Fatalf("AddSnapshot platform: %v", err)
	}
	bad := sn
	bad.ID, bad.Kind = uuid.New(), "weird"
	if err := r.AddSnapshot(ctx, &bad); err == nil {
		t.Fatal("bad snapshot kind accepted")
	}
	ls, err := r.ListSnapshots(ctx, &p)
	if err != nil || len(ls) != 2 || ls[0].ID != sn2.ID || ls[1].Checksum != sn.Checksum || ls[1].Engine != "postgres" {
		t.Fatalf("ListSnapshots: %+v %v", ls, err)
	}
	if pl, err := r.ListSnapshots(ctx, nil); err != nil || len(pl) < 1 || pl[0].ProjectID != nil {
		t.Fatalf("platform snapshots: %d %v", len(pl), err)
	}
	if g, err := r.GetSnapshot(ctx, &p, sn.ID); err != nil || g.ID != sn.ID || g.SizeBytes != 99 {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if _, err := r.GetSnapshot(ctx, &p2, sn.ID); err != backup.ErrNotFound {
		t.Fatalf("GetSnapshot wrong project: %v", err)
	}
	if _, err := r.GetSnapshot(ctx, nil, sn.ID); err != backup.ErrNotFound {
		t.Fatalf("GetSnapshot platform scope: %v", err)
	}
	if g, err := r.GetSnapshot(ctx, nil, psn.ID); err != nil || g.ProjectID != nil {
		t.Fatalf("GetSnapshot platform: %v", err)
	}
	exp, err := r.ExpiredSnapshots(ctx, &p, now.Add(-24*time.Hour))
	if err != nil || len(exp) != 1 || exp[0].ID != sn.ID {
		t.Fatalf("ExpiredSnapshots: %+v %v", exp, err)
	}
	if err := r.MarkSnapshotDeleted(ctx, sn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetSnapshot(ctx, &p, sn.ID); err != backup.ErrNotFound {
		t.Fatalf("deleted snapshot visible: %v", err)
	}
	if exp, _ := r.ExpiredSnapshots(ctx, &p, now.Add(time.Second)); len(exp) != 1 || exp[0].ID != sn2.ID {
		t.Fatalf("expired after delete: %+v", exp)
	}
	if ls, _ := r.ListSnapshots(ctx, &p); len(ls) != 1 {
		t.Fatalf("list after delete: %d", len(ls))
	}

	// LastDeployment: empty then with a successful deployment and env var names
	ld, err := r.LastDeployment(ctx, pNone)
	if err != nil || ld == nil || ld.DeploymentID != uuid.Nil || ld.EnvVarNames == nil || len(ld.EnvVarNames) != 0 {
		t.Fatalf("LastDeployment empty: %+v %v", ld, err)
	}
	dep := mkDeployment(t, f, pNone, "success", "manual", now)
	if _, err := pool.Exec(ctx, `UPDATE deployments SET git_sha='abc', image_tag='img:1', container_port=3000, host_port=31000, deploy_type='docker' WHERE id=$1`, dep); err != nil {
		t.Fatal(err)
	}
	mkDeployment(t, f, pNone, "failed", "manual", now.Add(time.Minute)) // newer but not successful
	for _, k := range []string{"B_KEY", "A_KEY"} {
		if _, err := pool.Exec(ctx, `INSERT INTO env_vars (project_id,key,value_enc) VALUES ($1,$2,convert_to('v','UTF8'))`, pNone, k); err != nil {
			t.Fatal(err)
		}
	}
	ld, err = r.LastDeployment(ctx, pNone)
	if err != nil || ld.DeploymentID != dep || ld.GitSHA != "abc" || ld.ImageTag != "img:1" || ld.ContainerPort != 3000 || ld.HostPort != 31000 ||
		ld.DeployType != "docker" || ld.SourceKey != "" || len(ld.EnvVarNames) != 2 || ld.EnvVarNames[0] != "A_KEY" {
		t.Fatalf("LastDeployment: %+v %v", ld, err)
	}

	// Audit (inet + jsonb)
	if err := r.Audit(ctx, backup.AuditEntry{OrgID: &org, UserID: &u, Action: "backup.run", ResourceType: "project", ResourceID: &p, IP: "198.51.100.4", NewValues: map[string]any{"a": 1}}); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if err := r.Audit(ctx, backup.AuditEntry{Action: "backup.platform", ResourceType: "platform"}); err != nil {
		t.Fatalf("Audit minimal: %v", err)
	}

	// cascade: deleting a run removes its snapshots
	if _, err := pool.Exec(ctx, `DELETE FROM backup_runs WHERE id=$1`, runID); err != nil {
		t.Fatal(err)
	}
	var left int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM backup_snapshots WHERE run_id=$1`, runID).Scan(&left)
	if left != 0 {
		t.Fatalf("snapshots survived run delete: %d", left)
	}
}
