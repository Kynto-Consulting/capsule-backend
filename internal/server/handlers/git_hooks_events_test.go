package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

// fakeSink stands in for gitevents.Inbound: it dedupes by delivery id like the real one.
type fakeSink struct {
	mu     sync.Mutex
	seen   map[string]bool
	events []*gitsource.Event
	prev   string
	err    error
}

func (f *fakeSink) Accept(_ context.Context, _ uuid.UUID, ev *gitsource.Event, _ []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	if ev.DeliveryID != "" {
		if f.seen[ev.DeliveryID] {
			return true, nil
		}
		f.seen[ev.DeliveryID] = true
	}
	f.events = append(f.events, ev)
	return false, nil
}
func (f *fakeSink) PreviousSecret(context.Context, uuid.UUID) string { return f.prev }
func (f *fakeSink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

func withSink(t *testing.T, s InboundSink) {
	t.Helper()
	SetInboundSink(s)
	t.Cleanup(func() { SetInboundSink(nil) })
}

func hookRig(t *testing.T) *gitRig {
	g := newGitRig(t)
	g.store.link = &domain.ProjectGit{ProjectID: g.project.ID, Provider: "forgejo", RepoURL: "https://git.example.com/acme/shop.git",
		Branch: "main", WebhookSecret: "topsecret", AutoDeploy: true, PreviewEnabled: true}
	return g
}

func signedHeaders(event, delivery string, body []byte, secret string) map[string]string {
	h := map[string]string{"X-Forgejo-Event": event, "X-Forgejo-Signature": gitsource.Sign(body, secret)[len("sha256="):]}
	if delivery != "" {
		h["X-Forgejo-Delivery"] = delivery
	}
	return h
}

func status(t *testing.T, code int, rec interface{ Bytes() []byte }) string {
	t.Helper()
	var m map[string]string
	_ = json.Unmarshal(rec.Bytes(), &m)
	return m["status"]
}

func prBody(action string) []byte {
	b, _ := json.Marshal(map[string]any{"action": action, "number": 7,
		"pull_request": map[string]any{"number": 7, "title": "Add cart", "html_url": "https://git.example.com/acme/shop/pulls/7",
			"user": map[string]any{"login": "ana"},
			"head": map[string]any{"ref": "feat", "sha": "abc1234", "repo": map[string]any{"full_name": "acme/shop"}},
			"base": map[string]any{"ref": "main", "repo": map[string]any{"full_name": "acme/shop", "clone_url": "https://git.example.com/acme/shop.git"}}},
		"review": map[string]any{"type": "approved", "content": "lgtm"}})
	return b
}

func TestHookReviewEventIsRecordedAndNeverDeploys(t *testing.T) {
	g := hookRig(t)
	sink := &fakeSink{}
	withSink(t, sink)
	body := prBody("reviewed")
	rec := g.hook(g.project.ID, signedHeaders("pull_request_approved", "d-1", body, "topsecret"), body)
	if rec.Code != 202 || status(t, rec.Code, rec.Body) != "accepted" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if sink.count() != 1 || sink.events[0].Kind != gitsource.EventReview || sink.events[0].ReviewState != gitsource.ReviewApproved {
		t.Fatalf("the review must reach the sink: %+v", sink.events)
	}
	g.h.Service.Wait()
}

func TestHookReplayWithTheSameDeliveryIDIsADuplicate(t *testing.T) {
	g := hookRig(t)
	sink := &fakeSink{}
	withSink(t, sink)
	body, _ := json.Marshal(map[string]any{"ref": "refs/heads/main", "after": "0123456789abcdef0123456789abcdef01234567",
		"repository": map[string]any{"clone_url": "https://git.example.com/acme/shop.git"}})
	h := signedHeaders("push", "same-delivery", body, "topsecret")
	first := g.hook(g.project.ID, h, body)
	second := g.hook(g.project.ID, h, body)
	if first.Code != 202 || status(t, 0, first.Body) != "accepted" {
		t.Fatalf("first: %d %s", first.Code, first.Body)
	}
	if second.Code != 202 || status(t, 0, second.Body) != "duplicate" {
		t.Fatalf("replay must be acknowledged as a duplicate: %d %s", second.Code, second.Body)
	}
	if sink.count() != 1 {
		t.Fatalf("events recorded: %d", sink.count())
	}
	g.h.Service.Wait()
	// another delivery id is a new delivery
	h2 := signedHeaders("push", "other-delivery", body, "topsecret")
	if rec := g.hook(g.project.ID, h2, body); status(t, 0, rec.Body) != "accepted" {
		t.Fatalf("%s", rec.Body)
	}
	g.h.Service.Wait()
}

func TestHookAuthenticationHappensBeforeAnythingIsRecorded(t *testing.T) {
	g := hookRig(t)
	sink := &fakeSink{}
	withSink(t, sink)
	body := prBody("reviewed")
	for name, hdr := range map[string]map[string]string{
		"wrong secret": signedHeaders("pull_request_approved", "d", body, "nope"),
		"no signature": {"X-Forgejo-Event": "pull_request_approved", "X-Forgejo-Delivery": "d"},
	} {
		rec := g.hook(g.project.ID, hdr, body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if rec := g.hook(uuid.New(), signedHeaders("push", "d", body, "topsecret"), body); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown project: %d", rec.Code)
	}
	if sink.count() != 0 {
		t.Fatalf("unauthenticated deliveries must never be recorded: %d", sink.count())
	}
}

func TestHookAcceptsThePreviousSecretDuringTheRotationWindow(t *testing.T) {
	g := hookRig(t)
	sink := &fakeSink{prev: "oldsecret"}
	withSink(t, sink)
	body := prBody("reviewed")
	if rec := g.hook(g.project.ID, signedHeaders("pull_request_approved", "d1", body, "oldsecret"), body); rec.Code != 202 {
		t.Fatalf("previous secret must still work: %d %s", rec.Code, rec.Body)
	}
	if rec := g.hook(g.project.ID, signedHeaders("pull_request_approved", "d2", body, "topsecret"), body); rec.Code != 202 {
		t.Fatalf("current secret: %d", rec.Code)
	}
	if rec := g.hook(g.project.ID, signedHeaders("pull_request_approved", "d3", body, "thirdsecret"), body); rec.Code != 401 {
		t.Fatalf("an unrelated secret is rejected: %d", rec.Code)
	}
	sink.prev = "" // window over
	if rec := g.hook(g.project.ID, signedHeaders("pull_request_approved", "d4", body, "oldsecret"), body); rec.Code != 401 {
		t.Fatalf("after the window the old secret is rejected: %d", rec.Code)
	}
}

func TestHookStoreFailureAnswers503SoTheSenderCanRetry(t *testing.T) {
	g := hookRig(t)
	withSink(t, &fakeSink{err: errors.New("db down")})
	body := prBody("reviewed")
	rec := g.hook(g.project.ID, signedHeaders("pull_request_approved", "d", body, "topsecret"), body)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestHookProjectMissingFromTheEventStoreKeepsTheLegacyFlow(t *testing.T) {
	g := hookRig(t)
	withSink(t, &fakeSink{err: gitevents.ErrNoProject})
	body, _ := json.Marshal(map[string]any{"ref": "refs/heads/main", "after": "0123456789abcdef0123456789abcdef01234567",
		"repository": map[string]any{"clone_url": "https://git.example.com/acme/shop.git"}})
	rec := g.hook(g.project.ID, signedHeaders("push", "d", body, "topsecret"), body)
	if rec.Code != 202 || status(t, 0, rec.Body) != "accepted" {
		t.Fatalf("an unknown project in the event store must not break deploys or answer 5xx: %d %s", rec.Code, rec.Body)
	}
	g.h.Service.Wait()
}

func TestHookLegacyBehaviourWithoutASink(t *testing.T) {
	g := hookRig(t) // no sink installed
	// a review event: valid signature, nothing to do -> ignored (as before the product events existed)
	body := prBody("reviewed")
	rec := g.hook(g.project.ID, signedHeaders("pull_request_approved", "d", body, "topsecret"), body)
	if rec.Code != 202 || status(t, 0, rec.Body) != "ignored" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// PR "edited" with previews on must NOT reach the preview service
	body = prBody("edited")
	rec = g.hook(g.project.ID, signedHeaders("pull_request", "d", body, "topsecret"), body)
	if rec.Code != 202 || status(t, 0, rec.Body) != "ignored" {
		t.Fatalf("edited PR must not trigger previews: %d %s", rec.Code, rec.Body)
	}
	// opened PR with previews on still goes to the service
	body = prBody("opened")
	rec = g.hook(g.project.ID, signedHeaders("pull_request", "d", body, "topsecret"), body)
	if rec.Code != 202 || status(t, 0, rec.Body) != "accepted" {
		t.Fatalf("opened PR keeps working: %d %s", rec.Code, rec.Body)
	}
	g.h.Service.Wait()
}

func TestHookProductEventsAreRecordedEvenWhenNothingDeploys(t *testing.T) {
	g := hookRig(t)
	sink := &fakeSink{}
	withSink(t, sink)
	other, _ := json.Marshal(map[string]any{"ref": "refs/heads/feature", "after": "0123456789abcdef0123456789abcdef01234567",
		"repository": map[string]any{"clone_url": "https://git.example.com/acme/shop.git"}})
	rec := g.hook(g.project.ID, signedHeaders("push", "p1", other, "topsecret"), other)
	if rec.Code != 202 || status(t, 0, rec.Body) != "accepted" || sink.count() != 1 {
		t.Fatalf("a push to another branch is a product event but no deploy: %d %s events=%d", rec.Code, rec.Body, sink.count())
	}
	// events of a different repository under the same secret never reach the sink
	foreign, _ := json.Marshal(map[string]any{"ref": "refs/heads/main", "after": "0123456789abcdef0123456789abcdef01234567",
		"repository": map[string]any{"clone_url": "https://git.example.com/evil/other.git"}})
	rec = g.hook(g.project.ID, signedHeaders("push", "p2", foreign, "topsecret"), foreign)
	if status(t, 0, rec.Body) != "ignored" || sink.count() != 1 {
		t.Fatalf("foreign repo: %s events=%d", rec.Body, sink.count())
	}
	g.h.Service.Wait()
}
