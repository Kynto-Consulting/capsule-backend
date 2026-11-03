//go:build dbtest

package repository

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

// Package A5, migrations 000038-000040. Run with TEST_DATABASE_URL pointing at a throwaway Postgres.

func a5Event(org, project uuid.UUID, name, delivery string) *gitevents.Event {
	return &gitevents.Event{
		ID: uuid.New(), OrgID: org, ProjectID: project, Source: gitevents.SourceForgejo, DeliveryID: delivery, RawEvent: "push",
		Name: name, Actor: "ana", Branch: "main", CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
		Data: map[string]any{"branch": "main", "pr": float64(7), "nested": map[string]any{"a": "b"}},
	}
}

func TestA5MigrationsDownAndUpAreIdempotent(t *testing.T) {
	pool := freshDB(t)
	ctx := context.Background()
	applyUpTo(t, pool, 40)
	applyUpTo(t, pool, 40) // twice: IF NOT EXISTS everywhere
	for _, m := range []string{"000040", "000039", "000038"} {
		for _, f := range migrationFiles(t, "down.sql") {
			if len(f.name) >= 6 && f.name[:6] == m {
				b, err := MigrationsFS.ReadFile("migrations/" + f.name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Exec(ctx, string(b)); err != nil {
					t.Fatalf("%s: %v", f.name, err)
				}
			}
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name IN
		('git_events','git_webhook_previous_secrets','outbound_webhooks','webhook_deliveries','notifications','notification_settings')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("down migrations must drop every A5 table: %d %v", n, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version IN (38, 39, 40)`); err != nil {
		t.Fatal(err)
	}
	applyUpTo(t, pool, 40) // and up again
}

func TestGitEventsInsertIsIdempotentByDelivery(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewGitEventRepository(pool, "test-secret-key")
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)
	p1, p2 := f.project(org, ""), f.project(org, "")

	e := a5Event(org, p1, gitevents.GitPush, "delivery-1")
	if ins, err := r.Insert(ctx, e); err != nil || !ins {
		t.Fatalf("first insert: %v %v", ins, err)
	}
	dup := a5Event(org, p1, gitevents.GitPush, "delivery-1")
	if ins, err := r.Insert(ctx, dup); err != nil || ins {
		t.Fatalf("the same (project, delivery) must not insert twice: %v %v", ins, err)
	}
	if ins, err := r.Insert(ctx, a5Event(org, p2, gitevents.GitPush, "delivery-1")); err != nil || !ins {
		t.Fatalf("the same delivery id on another project is independent: %v %v", ins, err)
	}
	for i := 0; i < 3; i++ { // Capsule events have no delivery id: never deduplicated
		c := a5Event(org, p1, gitevents.DeploymentFailed, "")
		c.Source = gitevents.SourceCapsule
		if ins, err := r.Insert(ctx, c); err != nil || !ins {
			t.Fatalf("capsule event %d: %v %v", i, ins, err)
		}
	}

	got, err := r.Get(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != e.Name || got.DeliveryID != "delivery-1" || got.Source != gitevents.SourceForgejo || got.Branch != "main" || got.Actor != "ana" ||
		got.Data["pr"] != float64(7) || got.Data["nested"].(map[string]any)["a"] != "b" || !got.CreatedAt.Equal(e.CreatedAt) {
		t.Fatalf("round trip: %+v", got)
	}
}

func TestGitEventsConcurrentDuplicateDeliveries(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewGitEventRepository(pool, "k")
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)
	p := f.project(org, "")
	var inserted int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ins, err := r.Insert(ctx, a5Event(org, p, gitevents.GitPush, "race")); err == nil && ins {
				atomic.AddInt32(&inserted, 1)
			}
		}()
	}
	wg.Wait()
	if inserted != 1 {
		t.Fatalf("exactly one concurrent insert of the same delivery may win, got %d", inserted)
	}
}

func TestGitEventsRecipientsActorAndDispatchLifecycle(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewGitEventRepository(pool, "k")
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)
	p := f.project(org, "")
	rcpt1, rcpt2 := f.user("", time.Now()), f.user("", time.Now())

	e := a5Event(org, p, gitevents.ApprovalRequested, "")
	e.Source = gitevents.SourceCapsule
	e.Recipients = []uuid.UUID{rcpt1, rcpt2}
	e.ActorUserID = u
	e.CreatedAt = time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	if _, err := r.Insert(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, e.ID)
	if err != nil || len(got.Recipients) != 2 || got.ActorUserID != u {
		t.Fatalf("%+v %v", got, err)
	}

	undisp, err := r.ListUndispatched(ctx, time.Now(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range undisp {
		if x.ID == e.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("a new event is undispatched")
	}
	if n, err := r.RecordDispatchFailure(ctx, e.ID); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	if n, _ := r.RecordDispatchFailure(ctx, e.ID); n != 2 {
		t.Fatalf("attempts: %d", n)
	}
	if err := r.MarkDispatched(ctx, e.ID); err != nil {
		t.Fatal(err)
	}
	undisp, _ = r.ListUndispatched(ctx, time.Now(), 1000)
	for _, x := range undisp {
		if x.ID == e.ID {
			t.Fatal("dispatched events are not listed")
		}
	}
	// the cutoff protects fresh events from the sweeper
	fresh := a5Event(org, p, gitevents.PRMerged, "")
	fresh.Source = gitevents.SourceCapsule
	fresh.CreatedAt = time.Now().UTC()
	_, _ = r.Insert(ctx, fresh)
	undisp, _ = r.ListUndispatched(ctx, time.Now().Add(-time.Minute), 1000)
	for _, x := range undisp {
		if x.ID == fresh.ID {
			t.Fatal("events younger than the cutoff must not be swept")
		}
	}
}

func TestGitEventsProjectInfo(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewGitEventRepository(pool, "k")
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)
	p := f.project(org, "shop-"+uuid.NewString()[:8])
	info, err := r.ProjectInfo(ctx, p)
	if err != nil || info.OrgID != org || info.ProjectSlug == "" || info.OrgSlug == "" {
		t.Fatalf("%+v %v", info, err)
	}
	if slug, err := r.OrgSlug(ctx, org); err != nil || slug != info.OrgSlug {
		t.Fatalf("%q %v", slug, err)
	}
	if _, err := r.ProjectInfo(ctx, uuid.New()); err != gitevents.ErrNoProject {
		t.Fatalf("unknown project: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE projects SET deleted_at = now() WHERE id = $1`, p); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ProjectInfo(ctx, p); err != gitevents.ErrNoProject {
		t.Fatalf("deleted project: %v", err)
	}
}

// The trigger of migration 000038 keeps the replaced inbound secret for 24 h.
func TestPreviousInboundWebhookSecretWindow(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	gitRepo := NewGitRepository(pool, "test-secret-key")
	r := NewGitEventRepository(pool, "test-secret-key")
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)
	p := f.project(org, "")

	if s, err := r.PreviousWebhookSecret(ctx, p); err != nil || s != "" {
		t.Fatalf("no previous secret yet: %q %v", s, err)
	}
	if _, err := gitRepo.Upsert(ctx, &domain.ProjectGit{ProjectID: p, Provider: "forgejo", RepoURL: "https://git.example.com/a/b.git", Branch: "main",
		AuthKind: "none", WebhookSecret: "first-secret", PreviewMax: 3, PreviewTTLHours: 24}); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.PreviousWebhookSecret(ctx, p); s != "" {
		t.Fatalf("the first secret has no predecessor: %q", s)
	}
	if err := gitRepo.RotateWebhookSecret(ctx, p, "second-secret"); err != nil {
		t.Fatal(err)
	}
	if s, err := r.PreviousWebhookSecret(ctx, p); err != nil || s != "first-secret" {
		t.Fatalf("after a rotation the old secret is still valid: %q %v", s, err)
	}
	var enc []byte
	if err := pool.QueryRow(ctx, `SELECT secret_enc FROM git_webhook_previous_secrets WHERE project_id=$1`, p).Scan(&enc); err != nil || len(enc) == 0 || string(enc) == "first-secret" {
		t.Fatalf("the previous secret is stored encrypted: %v", err)
	}
	if err := gitRepo.RotateWebhookSecret(ctx, p, "third-secret"); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.PreviousWebhookSecret(ctx, p); s != "second-secret" {
		t.Fatalf("only the latest predecessor is kept: %q", s)
	}
	if _, err := pool.Exec(ctx, `UPDATE git_webhook_previous_secrets SET expires_at = now() - interval '1 second' WHERE project_id=$1`, p); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.PreviousWebhookSecret(ctx, p); s != "" {
		t.Fatalf("after 24 h the old secret is rejected: %q", s)
	}
}
