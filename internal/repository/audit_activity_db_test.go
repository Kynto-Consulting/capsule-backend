//go:build dbtest

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitaudit"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/gitinsights"
)

func TestAuditLogDB100kStableCursor(t *testing.T) {
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	ctx := context.Background()
	owner := f.user("", time.Now().Add(-time.Hour))
	org, other := f.org(owner), f.org(owner)
	proj := f.project(org, "web")
	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)

	// 100 000 rows with many identical timestamps (10 rows per second) to stress the id tie-break.
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_logs (user_id, org_id, project_id, action, resource_type, created_at)
		SELECT CASE WHEN g % 2 = 0 THEN $1::uuid END, $2, CASE WHEN g % 5 = 0 THEN $3::uuid END,
		       CASE WHEN g % 3 = 0 THEN 'git.protection.change' ELSE 'member.role.change' END, 'project',
		       $4::timestamptz + (g / 10) * interval '1 second'
		FROM generate_series(1, 100000) g`, owner, org, proj, base); err != nil {
		t.Fatal(err)
	}
	// noise in another org must never leak
	if _, err := pool.Exec(ctx, `INSERT INTO audit_logs (org_id, action, resource_type) VALUES ($1, 'git.push', 'project')`, other); err != nil {
		t.Fatal(err)
	}
	r := NewAuditRepository(pool)
	svc := gitaudit.NewService(r)

	seen := make(map[uuid.UUID]bool, 100000)
	cursor, pages := "", 0
	var prev *gitaudit.Entry
	for {
		rows, next, err := svc.List(ctx, org, gitaudit.Filter{}, cursor, 200)
		if err != nil {
			t.Fatal(err)
		}
		for i := range rows {
			e := rows[i]
			if seen[e.ID] {
				t.Fatalf("row %s repeated on page %d", e.ID, pages)
			}
			seen[e.ID] = true
			if prev != nil && (e.CreatedAt.After(prev.CreatedAt) || (e.CreatedAt.Equal(prev.CreatedAt) && e.ID.String() >= prev.ID.String())) {
				t.Fatalf("order broken at page %d", pages)
			}
			prev = &rows[i]
		}
		pages++
		if pages == 3 { // new rows appended while paging must not shift the remaining pages
			if _, err := pool.Exec(ctx, `INSERT INTO audit_logs (org_id, action, resource_type) SELECT $1, 'git.push', 'project' FROM generate_series(1, 50)`, org); err != nil {
				t.Fatal(err)
			}
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 100000 {
		t.Fatalf("paged %d rows, want 100000", len(seen))
	}

	// filters
	count := func(fl gitaudit.Filter) int {
		n, cur := 0, ""
		for {
			rows, next, err := svc.List(ctx, org, fl, cur, 200)
			if err != nil {
				t.Fatal(err)
			}
			n += len(rows)
			if next == "" {
				return n
			}
			cur = next
		}
	}
	if n := count(gitaudit.Filter{Action: "git.protection.change"}); n != 33333 {
		t.Fatalf("exact action: %d", n)
	}
	if n := count(gitaudit.Filter{Action: "git.*"}); n < 33333 {
		t.Fatalf("prefix action: %d", n)
	}
	if n := count(gitaudit.Filter{Action: "git_*"}); n != 0 { // '_' is not a wildcard
		t.Fatalf("LIKE metacharacter leaked: %d", n)
	}
	if n := count(gitaudit.Filter{Actor: owner.String()}); n != 50000 {
		t.Fatalf("actor id: %d", n)
	}
	var email string
	_ = pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, owner).Scan(&email)
	if n := count(gitaudit.Filter{Actor: email}); n != 50000 {
		t.Fatalf("actor email: %d", n)
	}
	if n := count(gitaudit.Filter{ProjectID: &proj}); n != 20000 {
		t.Fatalf("project: %d", n)
	}
	since, until := base.Add(time.Hour), base.Add(2*time.Hour)
	if n := count(gitaudit.Filter{Since: &since, Until: &until}); n != 36010 { // 3601 seconds x 10 rows
		t.Fatalf("time window: %d", n)
	}
	if id, ok, err := r.ProjectID(ctx, org, "web"); err != nil || !ok || id != proj {
		t.Fatalf("project by slug: %v %v %v", id, ok, err)
	}
	if _, ok, _ := r.ProjectID(ctx, other, "web"); ok {
		t.Fatal("project of another org resolved")
	}

	// system actors (user_id NULL), a port-less IP and jsonb round trip
	rec := gitaudit.NewRecorder(r)
	if err := rec.Record(ctx, gitaudit.Input{OrgID: org, ProjectID: proj, ActorLabel: "system", Action: gitaudit.ActTeamDrift,
		ResourceType: gitaudit.ResProject, ResourceID: proj, IP: "203.0.113.9:4444", New: map[string]any{"team": "web-admin"}}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := svc.List(ctx, org, gitaudit.Filter{Action: gitaudit.ActTeamDrift, Actor: "system"}, "", 10)
	if err != nil || len(rows) != 1 || rows[0].UserID != nil || rows[0].IP != "203.0.113.9" || rows[0].NewValues["team"] != "web-admin" || rows[0].OldValues != nil {
		t.Fatalf("system entry: %+v %v", rows, err)
	}

	// retention removes only rows older than the cutoff
	n, err := r.PurgeBefore(ctx, base.Add(30*time.Minute))
	if err != nil || n != 17999 { // seconds 0..1799: second 0 holds 9 rows, the rest 10
		t.Fatalf("purge: %d %v", n, err)
	}
}

func TestGitActivityAndInsightsDB(t *testing.T) {
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	ctx := context.Background()
	owner := f.user("", time.Now().Add(-time.Hour))
	org := f.org(owner)
	proj, other := f.project(org, "api"), f.project(org, "other")
	r := NewGitActivityRepository(pool)
	rec := &gitinsights.ActivityRecorder{Store: r}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	ev := func(p uuid.UUID, name, actor string, h float64, data map[string]any) gitevents.Event {
		return gitevents.Event{ID: uuid.New(), OrgID: org, ProjectID: p, Name: name, Actor: actor,
			CreatedAt: t0.Add(time.Duration(h * float64(time.Hour))), Data: data}
	}
	pr := func(n int, author string) map[string]any { return map[string]any{"pr": n, "title": "t", "author": author} }
	events := []gitevents.Event{
		ev(proj, gitevents.PROpened, "ana", 2, pr(1, "ana")),
		ev(proj, gitevents.PRReviewSubmitted, "ana", 3, pr(1, "ana")), // own review ignored
		ev(proj, gitevents.PRReviewSubmitted, "bob", 5, pr(1, "ana")),
		ev(proj, gitevents.PRMerged, "ana", 10, pr(1, "ana")),
		ev(proj, gitevents.PROpened, "bob", 4, pr(2, "bob")),
		ev(proj, gitevents.PRReviewSubmitted, "ana", 14, pr(2, "bob")),
		ev(proj, gitevents.PRMerged, "bob", 24, pr(2, "bob")),
		ev(proj, gitevents.GitPush, "ana", 1, map[string]any{"sha": "abcdef123456", "commits": 4, "message": "m"}),
		ev(proj, gitevents.GitPush, "bob", 2, map[string]any{"sha": "1234567890ab"}),
		ev(proj, gitevents.DeploymentSucceeded, "bot", 6, map[string]any{"environment": "production"}),
		ev(proj, gitevents.DeploymentSucceeded, "bot", 7, map[string]any{"environment": "production"}),
		ev(proj, gitevents.DeploymentSucceeded, "bot", 8, map[string]any{"environment": "production"}),
		ev(proj, gitevents.DeploymentFailed, "bot", 9, map[string]any{"environment": "production"}),
		ev(other, gitevents.PROpened, "zed", 1, pr(1, "zed")), // other project: must not count
	}
	for _, e := range events {
		for i := 0; i < 2; i++ { // delivering twice must not duplicate (event_id is unique)
			if err := rec.Handle(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM git_activity WHERE project_id = $1`, proj).Scan(&n)
	if n != len(events)-1 {
		t.Fatalf("rows %d", n)
	}
	svc := &gitinsights.Service{Store: r}
	got, err := svc.Insights(ctx, proj, t0, t0.Add(10*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// first review: PR1 3h, PR2 10h -> median 23400 s; merge: PR1 8h, PR2 20h -> median 50400 s
	if got.Commits != 5 || got.PRsOpened != 2 || got.PRsMerged != 2 || got.MedianTimeToFirstReview != 23400 || got.MedianTimeToMerge != 50400 ||
		got.Deploys != 4 || got.ChangeFailureRate != 0.25 || len(got.Contributors) != 2 || got.Contributors[0].Person.Login != "ana" || got.Contributors[0].Commits != 4 {
		t.Fatalf("insights: %+v", got)
	}
	// activity list pages by cursor, newest first, only this project
	seen, cur := 0, ""
	for {
		rows, next, err := svc.ActivityPage(ctx, proj, cur, 4)
		if err != nil {
			t.Fatal(err)
		}
		seen += len(rows)
		if next == "" {
			break
		}
		cur = next
	}
	if seen != n {
		t.Fatalf("activity paged %d of %d", seen, n)
	}
	// retention
	if c, err := r.PurgeBefore(ctx, t0.Add(5*time.Hour)); err != nil || c == 0 {
		t.Fatalf("purge %d %v", c, err)
	}
}

func TestDigestStateDB(t *testing.T) {
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	ctx := context.Background()
	u := f.user("", time.Now().Add(-time.Hour))
	org := f.org(u)
	proj := f.project(org, "p")
	r := NewGitActivityRepository(pool)
	if _, err := pool.Exec(ctx, `INSERT INTO notification_settings (user_id, digest) VALUES ($1, 'daily')`, u); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	c, err := r.Candidates(ctx, "daily", now, 10)
	if err != nil || len(c) != 1 || c[0].LastSent != nil {
		t.Fatalf("candidates: %+v %v", c, err)
	}
	if ok, err := r.Claim(ctx, u, nil, now); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if ok, _ := r.Claim(ctx, u, nil, now.Add(time.Second)); ok { // a second instance loses the race
		t.Fatal("double claim")
	}
	if c, _ := r.Candidates(ctx, "daily", now, 10); len(c) != 0 {
		t.Fatal("claimed user is still a candidate")
	}
	if err := r.Release(ctx, u, now, nil); err != nil {
		t.Fatal(err)
	}
	if c, _ := r.Candidates(ctx, "daily", now, 10); len(c) != 1 {
		t.Fatal("released user must be a candidate again")
	}
	// pending: only unread, only newer than since
	_, _ = pool.Exec(ctx, `INSERT INTO notifications (user_id, org_id, project_id, event, title, created_at) VALUES
		($1,$2,$3,'pr.merged','a', now()), ($1,$2,$3,'pr.merged','b', now() - interval '3 days')`, u, org, proj)
	items, total, err := r.Pending(ctx, u, now.Add(-24*time.Hour), 10)
	if err != nil || total != 1 || len(items) != 1 || items[0].Title != "a" {
		t.Fatalf("pending: %+v %d %v", items, total, err)
	}
	// token notice organization lookup
	f.member(org, u, "member")
	tn := NewTokenNoticeRepository(pool)
	ref, ok, err := tn.UserOrg(ctx, u, []uuid.UUID{proj})
	if err != nil || !ok || ref.OrgID != org || ref.ProjectID == nil || *ref.ProjectID != proj {
		t.Fatalf("user org: %+v %v %v", ref, ok, err)
	}
}
