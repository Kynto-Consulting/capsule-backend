//go:build dbtest

package repository

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/gitsource"
	"github.com/kynto/capsule/backend/internal/webhookout"
)

type whFixture struct {
	pool    *pgxpool.Pool
	repo    *OutboundWebhookRepository
	events  *GitEventRepository
	org     uuid.UUID
	project uuid.UUID
	user    uuid.UUID
}

// newWhFixture uses its own throwaway database: ClaimDue is global (it takes any due delivery), so
// sharing one database with other tests would let them steal each other's rows.
func newWhFixture(t *testing.T) *whFixture {
	t.Helper()
	pool := freshDB(t)
	if err := RunMigrations(context.Background(), pool); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	f := newFx(t, pool)
	u := f.user("", time.Now())
	org := f.org(u)
	return &whFixture{pool: pool, repo: NewOutboundWebhookRepository(pool, "test-secret-key"), events: NewGitEventRepository(pool, "test-secret-key"),
		org: org, project: f.project(org, ""), user: u}
}

func (w *whFixture) hook(kind string, project *uuid.UUID, events ...string) *webhookout.Webhook {
	if len(events) == 0 {
		events = []string{gitevents.PRMerged}
	}
	h := &webhookout.Webhook{ID: uuid.New(), OrgID: w.org, ProjectID: project, Kind: kind, Events: events, Active: true, BranchFilter: ""}
	switch kind {
	case webhookout.KindHTTP:
		h.URL, h.Secret = "https://hooks.example.com/in?token=URLTOKEN", "whsec_"+uuid.NewString()
	case webhookout.KindSlack:
		h.URL = "https://hooks.slack.com/services/T/B/SLACKSECRET"
	case webhookout.KindEmail:
		h.EmailTo = []string{"ops@example.com"}
	}
	if err := w.repo.CreateWebhook(context.Background(), h); err != nil {
		panic(err)
	}
	return h
}

func TestOutboundWebhookRoundTripAndEncryptionAtRest(t *testing.T) {
	w := newWhFixture(t)
	ctx := context.Background()
	h := w.hook(webhookout.KindHTTP, &w.project, gitevents.PRMerged, gitevents.GitPush)
	got, err := w.repo.GetWebhook(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != h.URL || got.Secret != h.Secret || got.Kind != "http" || !got.Active || len(got.Events) != 2 || got.ProjectID == nil || *got.ProjectID != w.project || got.PrevSecret != "" {
		t.Fatalf("round trip: %+v", got)
	}
	var urlEnc, secEnc []byte
	if err := w.pool.QueryRow(ctx, `SELECT url_enc, secret_enc FROM outbound_webhooks WHERE id=$1`, h.ID).Scan(&urlEnc, &secEnc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(urlEnc), "URLTOKEN") || strings.Contains(string(urlEnc), "hooks.example.com") || strings.Contains(string(secEnc), "whsec_") {
		t.Fatal("URL and secret must be encrypted at rest")
	}
	em := w.hook(webhookout.KindEmail, &w.project)
	if g, _ := w.repo.GetWebhook(ctx, em.ID); g.URL != "" || g.Secret != "" || len(g.EmailTo) != 1 {
		t.Fatalf("email webhook: %+v", g)
	}
	if _, err := w.repo.GetWebhook(ctx, uuid.New()); err != domain.ErrNotFound {
		t.Fatalf("%v", err)
	}
}

func TestOutboundWebhookScopesMatchingAndUpdates(t *testing.T) {
	w := newWhFixture(t)
	ctx := context.Background()
	f := newFx(t, w.pool)
	otherProject := f.project(w.org, "")
	otherOrg := f.org(w.user)

	proj := w.hook(webhookout.KindHTTP, &w.project, gitevents.GitPush)
	orgLevel := w.hook(webhookout.KindHTTP, nil, gitevents.GitPush)
	elsewhere := w.hook(webhookout.KindHTTP, &otherProject, gitevents.GitPush)
	off := w.hook(webhookout.KindHTTP, &w.project, gitevents.GitPush)
	off.Active = false
	if err := w.repo.UpdateWebhook(ctx, off); err != nil {
		t.Fatal(err)
	}
	unsub := w.hook(webhookout.KindHTTP, &w.project, gitevents.PRClosed)
	foreign := &webhookout.Webhook{ID: uuid.New(), OrgID: otherOrg, Kind: "http", URL: "https://x.example.com", Secret: "s", Events: []string{gitevents.GitPush}, Active: true}
	if err := w.repo.CreateWebhook(ctx, foreign); err != nil {
		t.Fatal(err)
	}

	ids := func(ws []webhookout.Webhook) map[uuid.UUID]bool {
		m := map[uuid.UUID]bool{}
		for _, x := range ws {
			m[x.ID] = true
		}
		return m
	}
	match, err := w.repo.MatchingWebhooks(ctx, w.org, w.project, gitevents.GitPush)
	if err != nil {
		t.Fatal(err)
	}
	m := ids(match)
	if !m[proj.ID] || !m[orgLevel.ID] || m[elsewhere.ID] || m[off.ID] || m[unsub.ID] || m[foreign.ID] {
		t.Fatalf("matching: %v", m)
	}
	list, _ := w.repo.ListWebhooks(ctx, webhookout.Scope{OrgID: w.org, ProjectID: &w.project})
	lm := ids(list)
	if !lm[proj.ID] || !lm[off.ID] || lm[orgLevel.ID] || lm[elsewhere.ID] {
		t.Fatalf("project scope: %v", lm)
	}
	ol, _ := w.repo.ListWebhooks(ctx, webhookout.Scope{OrgID: w.org})
	if om := ids(ol); !om[orgLevel.ID] || om[proj.ID] {
		t.Fatalf("org scope: %v", om)
	}

	proj.Events, proj.BranchFilter, proj.URL = []string{gitevents.PRMerged}, "main", "https://changed.example.com/x"
	if err := w.repo.UpdateWebhook(ctx, proj); err != nil {
		t.Fatal(err)
	}
	g, _ := w.repo.GetWebhook(ctx, proj.ID)
	if g.BranchFilter != "main" || g.URL != "https://changed.example.com/x" || g.Events[0] != gitevents.PRMerged || g.Secret != proj.Secret {
		t.Fatalf("%+v", g)
	}
	if err := w.repo.DisableWebhook(ctx, proj.ID, "gone"); err != nil {
		t.Fatal(err)
	}
	if g, _ = w.repo.GetWebhook(ctx, proj.ID); g.Active || g.DisabledReason != "gone" {
		t.Fatalf("%+v", g)
	}
	if err := w.repo.UpdateWebhook(ctx, &webhookout.Webhook{ID: uuid.New()}); err != domain.ErrNotFound {
		t.Fatalf("%v", err)
	}
	if err := w.repo.DeleteWebhook(ctx, elsewhere.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.repo.DeleteWebhook(ctx, elsewhere.ID); err != domain.ErrNotFound {
		t.Fatalf("%v", err)
	}
}

func TestOutboundWebhookRotateKeepsThePreviousSecret(t *testing.T) {
	w := newWhFixture(t)
	ctx := context.Background()
	h := w.hook(webhookout.KindHTTP, &w.project)
	exp := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Microsecond)
	if err := w.repo.RotateSecret(ctx, h.ID, "whsec_new", exp); err != nil {
		t.Fatal(err)
	}
	g, _ := w.repo.GetWebhook(ctx, h.ID)
	if g.Secret != "whsec_new" || g.PrevSecret != h.Secret || g.PrevSecretExpiresAt == nil || !g.PrevSecretExpiresAt.Equal(exp) {
		t.Fatalf("%+v", g)
	}
	if err := w.repo.RotateSecret(ctx, w.hook(webhookout.KindSlack, &w.project).ID, "x", exp); err != domain.ErrNotFound {
		t.Fatalf("only http webhooks rotate: %v", err)
	}
}

func (w *whFixture) event(t *testing.T) *gitevents.Event {
	t.Helper()
	e := &gitevents.Event{ID: uuid.New(), OrgID: w.org, ProjectID: w.project, Source: gitevents.SourceCapsule, Name: gitevents.PRMerged, CreatedAt: time.Now().UTC(),
		Data: map[string]any{}}
	if _, err := w.events.Insert(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	return e
}

func delivery(wh uuid.UUID, ev *uuid.UUID, next time.Time) *webhookout.Delivery {
	return &webhookout.Delivery{ID: uuid.New(), WebhookID: wh, EventID: ev, Event: "pr.merged", Payload: `{"id":"x"}`, Status: webhookout.StatusPending,
		NextAttemptAt: next.UTC(), CreatedAt: time.Now().UTC().Truncate(time.Microsecond)}
}

func TestWebhookDeliveriesUniquePerEventAndRedeliveryAllowed(t *testing.T) {
	w := newWhFixture(t)
	ctx := context.Background()
	h := w.hook(webhookout.KindHTTP, &w.project)
	ev := w.event(t)
	d1 := delivery(h.ID, &ev.ID, time.Now())
	if ins, err := w.repo.InsertDelivery(ctx, d1); err != nil || !ins {
		t.Fatalf("%v %v", ins, err)
	}
	if ins, err := w.repo.InsertDelivery(ctx, delivery(h.ID, &ev.ID, time.Now())); err != nil || ins {
		t.Fatalf("the fan-out may repeat: a webhook gets one delivery per event: %v %v", ins, err)
	}
	re := delivery(h.ID, &ev.ID, time.Now())
	re.RedeliveryOf = &d1.ID
	if ins, err := w.repo.InsertDelivery(ctx, re); err != nil || !ins {
		t.Fatalf("a redelivery of the same event is allowed: %v %v", ins, err)
	}
	other := w.hook(webhookout.KindHTTP, &w.project)
	if ins, _ := w.repo.InsertDelivery(ctx, delivery(other.ID, &ev.ID, time.Now())); !ins {
		t.Fatal("another webhook gets its own delivery of the same event")
	}
	g, err := w.repo.GetDelivery(ctx, d1.ID)
	if err != nil || g.Payload != `{"id":"x"}` || g.Status != "pending" || g.EventID == nil || *g.EventID != ev.ID {
		t.Fatalf("%+v %v", g, err)
	}
	if _, err := w.repo.GetDelivery(ctx, uuid.New()); err != domain.ErrNotFound {
		t.Fatalf("%v", err)
	}
	// deleting the webhook removes its deliveries
	if err := w.repo.DeleteWebhook(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.repo.GetDelivery(ctx, d1.ID); err != domain.ErrNotFound {
		t.Fatalf("cascade: %v", err)
	}
}

func TestClaimDueLeasesRowsAndNeverOverlaps(t *testing.T) {
	w := newWhFixture(t)
	ctx := context.Background()
	h := w.hook(webhookout.KindHTTP, &w.project)
	now := time.Now().UTC()
	var due []uuid.UUID
	for i := 0; i < 20; i++ {
		d := delivery(h.ID, nil, now.Add(-time.Minute))
		if _, err := w.repo.InsertDelivery(ctx, d); err != nil {
			t.Fatal(err)
		}
		due = append(due, d.ID)
	}
	future := delivery(h.ID, nil, now.Add(time.Hour))
	_, _ = w.repo.InsertDelivery(ctx, future)
	done := delivery(h.ID, nil, now.Add(-time.Minute))
	done.Status = webhookout.StatusDelivered
	_, _ = w.repo.InsertDelivery(ctx, done)

	mine := map[uuid.UUID]bool{}
	for _, id := range due {
		mine[id] = true
	}
	// several workers claim at once: SKIP LOCKED must hand each row to exactly one of them
	var mu sync.Mutex
	seen := map[uuid.UUID]int{}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ds, err := w.repo.ClaimDue(ctx, now, 2*time.Minute, 7)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			for _, d := range ds {
				seen[d.ID]++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("delivery %s claimed %d times", id, n)
		}
	}
	if seen[future.ID] != 0 || seen[done.ID] != 0 {
		t.Fatal("only pending rows that are due may be claimed")
	}
	// the rest is claimable; once everything is leased nothing is returned until the lease ends
	for {
		ds, err := w.repo.ClaimDue(ctx, now, 2*time.Minute, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(ds) == 0 {
			break
		}
		for _, d := range ds {
			seen[d.ID]++
		}
	}
	claimed := 0
	for id, n := range seen {
		if mine[id] {
			claimed++
			if n != 1 {
				t.Fatalf("%s claimed %d times", id, n)
			}
		}
	}
	if claimed != 20 {
		t.Fatalf("every due delivery of this test must be claimed once, got %d", claimed)
	}
	// a crashed worker never loses the delivery: after the lease it is claimable again
	ds, err := w.repo.ClaimDue(ctx, now.Add(3*time.Minute), 2*time.Minute, 100)
	if err != nil {
		t.Fatal(err)
	}
	re := 0
	for _, d := range ds {
		if mine[d.ID] {
			re++
		}
	}
	if re != 20 {
		t.Fatalf("leases must expire so a restarted process picks the deliveries up: %d", re)
	}
}

func TestRecordAttemptUpdatesDeliveryAndWebhookSummary(t *testing.T) {
	w := newWhFixture(t)
	ctx := context.Background()
	h := w.hook(webhookout.KindHTTP, &w.project)
	d := delivery(h.ID, nil, time.Now())
	_, _ = w.repo.InsertDelivery(ctx, d)

	// attempt that never left (webhook disabled): the webhook summary is untouched
	d.Attempt, d.Status, d.Error = 1, webhookout.StatusAbandoned, "webhook is disabled"
	if err := w.repo.RecordAttempt(ctx, d); err != nil {
		t.Fatal(err)
	}
	if g, _ := w.repo.GetWebhook(ctx, h.ID); g.LastDeliveryAt != nil {
		t.Fatal("no request was made, so there is no last delivery")
	}

	next := time.Now().Add(time.Minute).UTC().Truncate(time.Microsecond)
	d.Attempt, d.Status, d.StatusCode, d.DurationMS, d.Error, d.ResponseExcerpt = 2, webhookout.StatusPending, 503, 120, "receiver answered 503", "busy"
	d.NextAttemptAt, d.RequestHeaders = next, map[string]string{"X-Capsule-Event": "pr.merged"}
	if err := w.repo.RecordAttempt(ctx, d); err != nil {
		t.Fatal(err)
	}
	g, _ := w.repo.GetDelivery(ctx, d.ID)
	if g.Attempt != 2 || g.StatusCode != 503 || g.DurationMS != 120 || g.Error != "receiver answered 503" || g.ResponseExcerpt != "busy" ||
		!g.NextAttemptAt.Equal(next) || g.RequestHeaders["X-Capsule-Event"] != "pr.merged" || g.DeliveredAt != nil {
		t.Fatalf("%+v", g)
	}
	if wh, _ := w.repo.GetWebhook(ctx, h.ID); wh.LastDeliveryStatus != 503 || wh.LastDeliveryAt == nil {
		t.Fatalf("%+v", wh)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	d.Status, d.StatusCode, d.DeliveredAt = webhookout.StatusDelivered, 200, &now
	_ = w.repo.RecordAttempt(ctx, d)
	if g, _ = w.repo.GetDelivery(ctx, d.ID); g.Status != "delivered" || g.DeliveredAt == nil || !g.DeliveredAt.Equal(now) {
		t.Fatalf("%+v", g)
	}
}

func TestListDeliveriesCursorIsStable(t *testing.T) {
	w := newWhFixture(t)
	ctx := context.Background()
	h := w.hook(webhookout.KindHTTP, &w.project)
	base := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 7; i++ {
		d := delivery(h.ID, nil, base)
		d.CreatedAt = base.Add(-time.Duration(i/2) * time.Second) // ties on created_at on purpose
		if _, err := w.repo.InsertDelivery(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	svc := webhookout.New(webhookout.Config{Store: w.repo, Projects: w.events, Policy: gitsource.Policy{}})
	var ids []uuid.UUID
	cursor := ""
	for page := 0; page < 10; page++ {
		rows, next, err := svc.Deliveries(ctx, webhookout.Scope{OrgID: w.org, ProjectID: &w.project}, h.ID, cursor, 3)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			ids = append(ids, r.ID)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if len(ids) != 7 || len(seen) != 7 {
		t.Fatalf("every delivery exactly once across pages: %d rows, %d unique", len(ids), len(seen))
	}
}

// End to end against the real tables: events fan out to deliveries, a failing receiver is retried
// by a NEW service instance after a "restart", and it ends delivered.
func TestDeliveriesAndRetriesSurviveARestart(t *testing.T) {
	w := newWhFixture(t)
	ctx := context.Background()
	clock := &struct {
		mu sync.Mutex
		t  time.Time
	}{t: time.Now().UTC()}
	now := func() time.Time { clock.mu.Lock(); defer clock.mu.Unlock(); return clock.t }
	advance := func(d time.Duration) { clock.mu.Lock(); clock.t = clock.t.Add(d); clock.mu.Unlock() }

	answers := make(chan int, 10)
	var sent []string
	var smu sync.Mutex
	client := func() *http.Client {
		return &http.Client{Transport: dbRoundTrip(func(r *http.Request) (*http.Response, error) {
			code := <-answers
			smu.Lock()
			sent = append(sent, r.Header.Get("X-Capsule-Delivery"))
			smu.Unlock()
			return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("x"))}, nil
		})}
	}
	build := func() *webhookout.Service {
		return webhookout.New(webhookout.Config{Store: w.repo, Projects: w.events, OrgSlug: w.events.OrgSlug,
			Policy: gitsource.Policy{}, Client: client(), Now: now, BaseURL: "https://app.example.com"})
	}
	svc := build()
	h, err := svc.Create(ctx, webhookout.Scope{OrgID: w.org, ProjectID: &w.project}, webhookout.CreateInput{
		Kind: "http", URL: "https://1.1.1.1/hook", Events: []string{gitevents.PRMerged}}, w.user)
	if err != nil {
		t.Fatal(err)
	}

	bus := gitevents.NewBus(w.events, w.events, nil)
	bus.Subscribe(svc)
	if err := bus.Publish(ctx, gitevents.Event{ProjectID: w.project, Name: gitevents.PRMerged, Actor: "ana", Data: map[string]any{"pr": 7}}); err != nil {
		t.Fatal(err)
	}
	bus.Wait()

	answers <- 500
	if n := svc.ProcessDue(ctx); n != 1 {
		t.Fatalf("first attempt: %d", n)
	}
	rows, _, _ := svc.Deliveries(ctx, webhookout.Scope{OrgID: w.org, ProjectID: &w.project}, h.ID, "", 10)
	if len(rows) != 1 || rows[0].Status != webhookout.StatusPending || rows[0].Attempt != 1 || rows[0].StatusCode != 500 {
		t.Fatalf("%+v", rows)
	}

	// "restart": a new service instance on the same database; nothing is due yet
	svc2 := build()
	if n := svc2.ProcessDue(ctx); n != 0 {
		t.Fatalf("not due yet: %d", n)
	}
	advance(webhookout.Backoff[0] + time.Second)
	answers <- 200
	if n := svc2.ProcessDue(ctx); n != 1 {
		t.Fatalf("after the restart the pending delivery is attempted: %d", n)
	}
	rows, _, _ = svc2.Deliveries(ctx, webhookout.Scope{OrgID: w.org, ProjectID: &w.project}, h.ID, "", 10)
	if rows[0].Status != webhookout.StatusDelivered || rows[0].Attempt != 2 || rows[0].DeliveredAt == nil {
		t.Fatalf("%+v", rows[0])
	}
	smu.Lock()
	defer smu.Unlock()
	if len(sent) != 2 || sent[0] != sent[1] {
		t.Fatalf("the delivery id must be stable across the retry: %v", sent)
	}
	// the bus marked the event as fully dispatched
	undisp, _ := w.events.ListUndispatched(ctx, time.Now().Add(time.Hour), 1000)
	for _, e := range undisp {
		if e.ProjectID == w.project {
			t.Fatalf("event %s should be dispatched", e.ID)
		}
	}
}

type dbRoundTrip func(*http.Request) (*http.Response, error)

func (f dbRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
