//go:build dbtest

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitevents"
)

func newNote(user, org uuid.UUID, project *uuid.UUID, event *uuid.UUID, at time.Time) *gitevents.Notification {
	return &gitevents.Notification{ID: uuid.New(), UserID: user, OrgID: org, ProjectID: project, EventID: event, Event: gitevents.PRMerged,
		Title: "PR #7 fusionado", URL: "https://app.example.com/git/a/b/pulls/7", Project: "a/b", CreatedAt: at.UTC().Truncate(time.Microsecond)}
}

func TestNotificationsInsertIsUniquePerUserAndEvent(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewNotificationRepository(pool)
	ev := NewGitEventRepository(pool, "k")
	ctx := context.Background()
	u1, u2 := f.user("", time.Now()), f.user("", time.Now())
	org := f.org(u1)
	p := f.project(org, "")
	e := a5Event(org, p, gitevents.PRMerged, "")
	e.Source = gitevents.SourceCapsule
	if _, err := ev.Insert(ctx, e); err != nil {
		t.Fatal(err)
	}
	if ins, err := r.InsertNotification(ctx, newNote(u1, org, &p, &e.ID, time.Now())); err != nil || !ins {
		t.Fatalf("%v %v", ins, err)
	}
	if ins, err := r.InsertNotification(ctx, newNote(u1, org, &p, &e.ID, time.Now())); err != nil || ins {
		t.Fatalf("a repeated fan-out must not notify twice: %v %v", ins, err)
	}
	if ins, err := r.InsertNotification(ctx, newNote(u2, org, &p, &e.ID, time.Now())); err != nil || !ins {
		t.Fatalf("another user is notified of the same event: %v %v", ins, err)
	}
	if ins, err := r.InsertNotification(ctx, newNote(u1, org, &p, nil, time.Now())); err != nil || !ins {
		t.Fatalf("notifications without an event id are never deduplicated: %v %v", ins, err)
	}
}

func TestNotificationsListPaginationReadAndIsolation(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewNotificationRepository(pool)
	ctx := context.Background()
	me, other := f.user("", time.Now()), f.user("", time.Now())
	org := f.org(me)
	base := time.Now().Add(-time.Hour)
	var mine []uuid.UUID
	for i := 0; i < 7; i++ {
		n := newNote(me, org, nil, nil, base.Add(time.Duration(i/2)*time.Second)) // ties on created_at
		if _, err := r.InsertNotification(ctx, n); err != nil {
			t.Fatal(err)
		}
		mine = append(mine, n.ID)
	}
	foreign := newNote(other, org, nil, nil, base)
	_, _ = r.InsertNotification(ctx, foreign)

	var seen []uuid.UUID
	var cur *gitevents.Cursor
	for page := 0; page < 10; page++ {
		rows, err := r.ListNotifications(ctx, me, false, cur, 4)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range rows {
			if n.UserID != me {
				t.Fatalf("another user's row leaked: %+v", n)
			}
			seen = append(seen, n.ID)
		}
		if len(rows) < 4 {
			break
		}
		last := rows[len(rows)-1]
		cur = &gitevents.Cursor{At: last.CreatedAt, ID: last.ID}
	}
	uniq := map[uuid.UUID]bool{}
	for _, id := range seen {
		uniq[id] = true
	}
	if len(seen) != 7 || len(uniq) != 7 {
		t.Fatalf("keyset pagination must visit each row once: %d rows, %d unique", len(seen), len(uniq))
	}

	if err := r.MarkRead(ctx, me, mine[:3]); err != nil {
		t.Fatal(err)
	}
	if err := r.MarkRead(ctx, me, []uuid.UUID{foreign.ID}); err != nil { // not mine: no-op
		t.Fatal(err)
	}
	unread, _ := r.ListNotifications(ctx, me, true, nil, 100)
	if len(unread) != 4 {
		t.Fatalf("unread after marking 3 of 7: %d", len(unread))
	}
	if fr, _ := r.ListNotifications(ctx, other, true, nil, 100); len(fr) != 1 {
		t.Fatal("marking someone else's id must not touch their row")
	}
	if err := r.MarkAllRead(ctx, me); err != nil {
		t.Fatal(err)
	}
	if unread, _ = r.ListNotifications(ctx, me, true, nil, 100); len(unread) != 0 {
		t.Fatalf("%d", len(unread))
	}
	all, _ := r.ListNotifications(ctx, me, false, nil, 100)
	for _, n := range all {
		if !n.Read {
			t.Fatal("read flag")
		}
	}
}

func TestNotificationSettingsRoundTrip(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewNotificationRepository(pool)
	ctx := context.Background()
	u := f.user("", time.Now())

	def, err := r.GetSettings(ctx, u)
	if err != nil || !def.Channels.InApp || def.Channels.Email || def.Channels.SlackDM || def.Digest != "off" || def.Events == nil {
		t.Fatalf("defaults: %+v %v", def, err)
	}
	in := gitevents.Settings{Channels: gitevents.ChannelFlags{InApp: true, Email: true},
		Events: map[string][]string{gitevents.PRMerged: {"email"}, gitevents.DeploymentFailed: {}}, Digest: "weekly"}
	if err := r.PutSettings(ctx, u, in); err != nil {
		t.Fatal(err)
	}
	got, _ := r.GetSettings(ctx, u)
	if !got.Channels.Email || got.Digest != "weekly" || len(got.Events[gitevents.PRMerged]) != 1 || got.Events[gitevents.DeploymentFailed] == nil || len(got.Events[gitevents.DeploymentFailed]) != 0 {
		t.Fatalf("%+v", got)
	}
	in.Digest = "daily"
	in.Channels.Email = false
	if err := r.PutSettings(ctx, u, in); err != nil { // upsert
		t.Fatal(err)
	}
	got, _ = r.GetSettings(ctx, u)
	if got.Digest != "daily" || got.Channels.Email {
		t.Fatalf("%+v", got)
	}
	u2 := f.user("", time.Now())
	m, err := r.SettingsFor(ctx, []uuid.UUID{u, u2})
	if err != nil || len(m) != 1 || m[u].Digest != "daily" {
		t.Fatalf("SettingsFor returns only stored rows: %+v %v", m, err)
	}
	// the database also enforces the digest values
	if _, err := pool.Exec(ctx, `UPDATE notification_settings SET digest='hourly' WHERE user_id=$1`, u); err == nil {
		t.Fatal("digest check constraint expected")
	}
}

func TestNotificationRecipientQueries(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewNotificationRepository(pool)
	ctx := context.Background()
	owner := f.user("", time.Now())
	orgAdmin, member, projAdmin, viewer := f.user("", time.Now()), f.user("", time.Now()), f.user("", time.Now()), f.user("", time.Now())
	org := f.org(owner)
	f.member(org, owner, "owner")
	f.member(org, orgAdmin, "admin")
	f.member(org, member, "member")
	f.member(org, projAdmin, "member")
	f.member(org, viewer, "member")
	p := f.project(org, "")
	if _, err := pool.Exec(ctx, `INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,'admin'), ($1,$3,'viewer')`, p, projAdmin, viewer); err != nil {
		t.Fatal(err)
	}
	ids, err := r.ProjectAdmins(ctx, org, p)
	if err != nil {
		t.Fatal(err)
	}
	got := map[uuid.UUID]bool{}
	for _, id := range ids {
		got[id] = true
	}
	if !got[owner] || !got[orgAdmin] || !got[projAdmin] || got[member] || got[viewer] || len(ids) != len(got) {
		t.Fatalf("admins = org owners/admins + explicit project admins, without duplicates: %v", ids)
	}

	emails, err := r.UserEmails(ctx, []uuid.UUID{owner, member})
	if err != nil || emails[owner] == "" || emails[member] == "" || len(emails) != 2 {
		t.Fatalf("%v %v", emails, err)
	}

	// git_identities belongs to package A2: while it is missing (or shaped differently) the answer is
	// empty, never an error and never a wrong user.
	m, err := r.UsersByLogin(ctx, []string{"ana", "ghost"})
	if err != nil {
		t.Fatalf("UsersByLogin must tolerate a missing git_identities table: %v", err)
	}
	if len(m) != 0 {
		var one int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM git_identities WHERE lower(forgejo_username) = 'ana'`).Scan(&one); err != nil || one == 0 {
			t.Fatalf("unexpected mapping without identities: %v", m)
		}
	}
}
