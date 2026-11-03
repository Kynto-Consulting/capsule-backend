package gitevents

import (
	"context"
	"errors"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newBus(t *testing.T) (*Bus, *memStore, uuid.UUID) {
	t.Helper()
	pid := uuid.New()
	st := newMemStore()
	b := NewBus(st, memProjects{info: map[uuid.UUID]ProjectInfo{pid: {OrgID: uuid.New(), OrgSlug: "acme", ProjectSlug: "shop", ProjectName: "Shop"}}}, nil)
	return b, st, pid
}

func TestPublishPersistsCompletesAndDispatches(t *testing.T) {
	b, st, pid := newBus(t)
	sub := &recSub{name: "a"}
	b.Subscribe(sub)
	if err := b.Publish(context.Background(), Event{ProjectID: pid, Name: DeploymentFailed, Actor: "bot", Data: map[string]any{"environment": "prod"}}); err != nil {
		t.Fatal(err)
	}
	b.Wait()
	got := sub.events()
	if len(got) != 1 {
		t.Fatalf("subscriber got %d events", len(got))
	}
	e := got[0]
	if e.ID == uuid.Nil || e.OrgSlug != "acme" || e.ProjectSlug != "shop" || e.OrgID == uuid.Nil || e.Source != SourceCapsule || e.CreatedAt.IsZero() {
		t.Fatalf("event not completed: %+v", e)
	}
	if !st.isDispatched(e.ID) {
		t.Fatal("a fully fanned-out event must be marked dispatched")
	}
}

func TestPublishRejections(t *testing.T) {
	b, st, pid := newBus(t)
	ctx := context.Background()
	if err := b.Publish(ctx, Event{ProjectID: pid, Name: "nope.nothing"}); !errors.Is(err, ErrUnknownEvent) {
		t.Fatalf("unknown event: %v", err)
	}
	if err := b.Publish(ctx, Event{ProjectID: pid, Name: WebhookTest}); !errors.Is(err, ErrUnknownEvent) {
		t.Fatalf("webhook.test is not publishable: %v", err)
	}
	for _, key := range []string{"token", "client_secret", "Password", "api_key", "Authorization", "private_key"} {
		err := b.Publish(ctx, Event{ProjectID: pid, Name: PRMerged, Data: map[string]any{"nested": map[string]any{key: "x"}}})
		if !errors.Is(err, ErrSecretInEvent) {
			t.Fatalf("key %q must be rejected, got %v", key, err)
		}
	}
	if err := b.Publish(ctx, Event{ProjectID: uuid.New(), Name: PRMerged}); !errors.Is(err, ErrNoProject) {
		t.Fatalf("unknown project: %v", err)
	}
	if err := b.Publish(ctx, Event{ProjectID: pid, Name: PRMerged, Data: map[string]any{"x": make(chan int)}}); err == nil {
		t.Fatal("non-JSON data must be rejected")
	}
	if st.count() != 0 {
		t.Fatalf("rejected events must not be stored, have %d", st.count())
	}
}

func TestInsertErrorSurfaces(t *testing.T) {
	b, st, pid := newBus(t)
	st.insertErr = errors.New("db down")
	if err := b.Publish(context.Background(), Event{ProjectID: pid, Name: PRMerged}); err == nil {
		t.Fatal("storage failure must reach the publisher")
	}
}

func TestFailedSubscriberIsRetriedBySweepAndOthersStillRun(t *testing.T) {
	b, st, pid := newBus(t)
	flaky := &recSub{name: "flaky", failN: 1}
	steady := &recSub{name: "steady"}
	b.Subscribe(flaky)
	b.Subscribe(steady)
	b.SweepAge = 0
	if err := b.Publish(context.Background(), Event{ProjectID: pid, Name: PRMerged}); err != nil {
		t.Fatal(err)
	}
	b.Wait()
	if len(steady.events()) != 1 || len(flaky.events()) != 0 {
		t.Fatalf("steady=%d flaky=%d", len(steady.events()), len(flaky.events()))
	}
	id := steady.events()[0].ID
	if st.isDispatched(id) {
		t.Fatal("must stay undispatched while a subscriber fails")
	}
	time.Sleep(2 * time.Millisecond)
	if n := b.Sweep(context.Background()); n != 1 {
		t.Fatalf("sweep handled %d", n)
	}
	if len(flaky.events()) != 1 || !st.isDispatched(id) {
		t.Fatalf("sweep must redeliver and then mark dispatched (flaky=%d dispatched=%v)", len(flaky.events()), st.isDispatched(id))
	}
	if n := b.Sweep(context.Background()); n != 0 {
		t.Fatalf("nothing left to sweep, got %d", n)
	}
}

func TestSweepGivesUpAfterMaxAttempts(t *testing.T) {
	b, st, pid := newBus(t)
	b.Subscribe(&recSub{name: "dead", failN: 1000})
	b.SweepAge = 0
	b.maxAttempts = 3
	_ = b.Publish(context.Background(), Event{ProjectID: pid, Name: PRMerged})
	b.Wait()
	time.Sleep(2 * time.Millisecond)
	for i := 0; i < 5; i++ {
		b.Sweep(context.Background())
	}
	if len(st.events) != 1 {
		t.Fatal("event must be kept")
	}
	for id := range st.events {
		if !st.isDispatched(id) {
			t.Fatal("after max attempts the event is closed so it is not retried forever")
		}
		if st.failures[id] != 3 {
			t.Fatalf("attempts: %d", st.failures[id])
		}
	}
}

func TestSubscriberPanicDoesNotCrash(t *testing.T) {
	b, _, pid := newBus(t)
	b.Subscribe(&recSub{name: "bad", panics: true})
	if err := b.Publish(context.Background(), Event{ProjectID: pid, Name: PRMerged}); err != nil {
		t.Fatal(err)
	}
	b.Wait() // would crash the test binary if the panic escaped
}

func TestDuplicateDeliveryIsNotDispatchedTwice(t *testing.T) {
	b, _, pid := newBus(t)
	sub := &recSub{name: "a"}
	b.Subscribe(sub)
	e := Event{ProjectID: pid, Name: GitPush, Source: SourceForgejo, DeliveryID: "d-1"}
	dup, err := b.Record(context.Background(), e)
	if err != nil || dup {
		t.Fatalf("first: dup=%v err=%v", dup, err)
	}
	dup, err = b.Record(context.Background(), e)
	if err != nil || !dup {
		t.Fatalf("second must be a duplicate: dup=%v err=%v", dup, err)
	}
	b.Wait()
	if len(sub.events()) != 1 {
		t.Fatalf("dispatched %d times", len(sub.events()))
	}
}

func TestSharedPublisherIsNeverNil(t *testing.T) {
	SetShared(nil)
	if Shared() == nil {
		t.Fatal("Shared must never be nil")
	}
	if err := Shared().Publish(context.Background(), Event{Name: PRMerged}); err != nil {
		t.Fatal(err)
	}
	b, _, _ := newBus(t)
	SetShared(b)
	if Shared() != Publisher(b) {
		t.Fatal("SetShared not honoured")
	}
	SetShared(nil)
}

// The catalog must be exactly the x-webhook-events of the OpenAPI contract: a drift in either
// direction breaks webhook subscribers.
func TestCatalogMatchesOpenAPI(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/git-capsule/API.openapi.yaml")
	if err != nil {
		t.Skip("contract not available: " + err.Error())
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	i := strings.Index(text, "\nx-webhook-events:\n")
	if i < 0 {
		t.Fatal("x-webhook-events not found")
	}
	block := text[i+len("\nx-webhook-events:\n"):]
	re := regexp.MustCompile(`^  ([a-z_.]+):`)
	var names []string
	for _, line := range strings.Split(block, "\n") {
		if !strings.HasPrefix(line, "  ") {
			break
		}
		if m := re.FindStringSubmatch(line); m != nil {
			names = append(names, m[1])
		}
	}
	sort.Strings(names)
	want := Names()
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("catalog drift\ncontract: %v\ncode:     %v", names, want)
	}
}
