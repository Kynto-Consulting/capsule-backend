package gitevents

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitsource"
)

func parse(t *testing.T, header map[string]string, body string) *gitsource.Event {
	t.Helper()
	h := http.Header{}
	for k, v := range header {
		h.Set(k, v)
	}
	ev, err := gitsource.ParseEvent(h, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

const prJSON = `"pull_request":{"number":7,"title":"Add cart","html_url":"https://git/x/pulls/7","merged":%MERGED%,"user":{"login":"ana"},
 "head":{"ref":"feat/cart","sha":"abc1234","repo":{"full_name":"acme/shop"}},
 "base":{"ref":"main","repo":{"full_name":"acme/shop","clone_url":"https://git/acme/shop.git"}}}`

func pr(merged string) string {
	out := ""
	for i := 0; i < len(prJSON); i++ {
		if i+8 <= len(prJSON) && prJSON[i:i+8] == "%MERGED%" {
			out += merged
			i += 7
			continue
		}
		out += string(prJSON[i])
	}
	return out
}

func TestProductEventMapping(t *testing.T) {
	fj := map[string]string{"X-Forgejo-Event": "pull_request"}
	cases := []struct {
		name   string
		hdr    map[string]string
		body   string
		event  string
		branch string
		key    string
		val    any
	}{
		{"push", map[string]string{"X-Forgejo-Event": "push"}, `{"ref":"refs/heads/main","before":"1","after":"2222222","head_commit":{"message":"fix","url":"u"}}`, GitPush, "main", "sha", "2222222"},
		{"pr opened", fj, `{"action":"opened","number":7,` + pr("false") + `}`, PROpened, "feat/cart", "title", "Add cart"},
		{"pr reopened", fj, `{"action":"reopened","number":7,` + pr("false") + `}`, PROpened, "feat/cart", "reopened", true},
		{"pr sync", fj, `{"action":"synchronize","number":7,` + pr("false") + `}`, PRUpdated, "feat/cart", "reason", "commits"},
		{"pr edited", fj, `{"action":"edited","number":7,` + pr("false") + `}`, PRUpdated, "feat/cart", "reason", "edited"},
		{"pr ready (WIP removed)", fj, `{"action":"edited","number":7,"changes":{"title":{"from":"WIP: Add cart"}},` + pr("false") + `}`, PRReadyForReview, "feat/cart", "pr", 7},
		{"pr merged", fj, `{"action":"closed","number":7,` + pr("true") + `}`, PRMerged, "feat/cart", "author", "ana"},
		{"pr closed", fj, `{"action":"closed","number":7,` + pr("false") + `}`, PRClosed, "feat/cart", "base", "main"},
		{"review requested", fj, `{"action":"review_requested","number":7,"requested_reviewer":{"login":"bruno"},` + pr("false") + `}`, PRReviewRequested, "feat/cart", "requested_reviewer", "bruno"},
		{"review", map[string]string{"X-Forgejo-Event": "pull_request_approved"}, `{"action":"reviewed","review":{"type":"approved","content":"lgtm"},"sender":{"login":"bruno"},` + pr("false") + `}`, PRReviewSubmitted, "feat/cart", "state", "approved"},
		{"status", map[string]string{"X-GitHub-Event": "status"}, `{"state":"failure","sha":"abc","context":"capsule/security"}`, CheckCompleted, "", "context", "capsule/security"},
		{"workflow", map[string]string{"X-GitHub-Event": "workflow_run"}, `{"action":"completed","workflow_run":{"id":5,"name":"CI","conclusion":"success","head_branch":"main"}}`, WorkflowRunCompleted, "main", "conclusion", "success"},
		{"branch created", map[string]string{"X-Forgejo-Event": "create"}, `{"ref":"x","ref_type":"branch"}`, GitBranchCreated, "x", "branch", "x"},
		{"branch deleted", map[string]string{"X-Forgejo-Event": "delete"}, `{"ref":"x","ref_type":"branch"}`, GitBranchDeleted, "x", "branch", "x"},
	}
	for _, c := range cases {
		ev := parse(t, c.hdr, c.body)
		name, branch, data, ok := ProductEvent(ev)
		if !ok || name != c.event || branch != c.branch {
			t.Errorf("%s: ok=%v name=%q branch=%q (%+v)", c.name, ok, name, branch, ev)
			continue
		}
		if !Valid(name) {
			t.Errorf("%s: %q is not in the catalog", c.name, name)
		}
		if data[c.key] != c.val {
			t.Errorf("%s: data[%s]=%v want %v (data=%v)", c.name, c.key, data[c.key], c.val, data)
		}
		if err := CheckNoSecrets(data); err != nil {
			t.Errorf("%s: data carries secret-looking keys: %v", c.name, err)
		}
	}
	// A deleted-branch push has no product meaning (the delete event carries it).
	ev := parse(t, map[string]string{"X-Forgejo-Event": "push"}, `{"ref":"refs/heads/x","after":"0000000000000000000000000000000000000000"}`)
	if _, _, _, ok := ProductEvent(ev); ok {
		t.Fatal("deleted push must not map")
	}
}

func newInbound(t *testing.T) (*Inbound, *recSub, *fakeInv, *memStore, uuid.UUID) {
	t.Helper()
	pid := uuid.New()
	st := newMemStore()
	res := memProjects{info: map[uuid.UUID]ProjectInfo{pid: {OrgID: uuid.New(), OrgSlug: "acme", ProjectSlug: "shop"}}}
	bus := NewBus(st, res, nil)
	sub := &recSub{name: "s"}
	bus.Subscribe(sub)
	inv := &fakeInv{}
	return NewInbound(bus, res, inv, nil), sub, inv, st, pid
}

func TestAcceptIsIdempotentByDeliveryID(t *testing.T) {
	in, sub, inv, _, pid := newInbound(t)
	ctx := context.Background()
	ev := parse(t, map[string]string{"X-Forgejo-Event": "push", "X-Forgejo-Delivery": "del-1"},
		`{"ref":"refs/heads/main","after":"2222222","head_commit":{"message":"m"}}`)
	dup, err := in.Accept(ctx, pid, ev, []byte("body"))
	if err != nil || dup {
		t.Fatalf("first: dup=%v err=%v", dup, err)
	}
	dup, err = in.Accept(ctx, pid, ev, []byte("body"))
	if err != nil || !dup {
		t.Fatalf("replay with the same delivery id must be a duplicate: dup=%v err=%v", dup, err)
	}
	// same delivery id, other project -> independent
	in.bus.projects.(memProjects).info[uuid.Nil] = ProjectInfo{OrgID: uuid.New(), OrgSlug: "o2", ProjectSlug: "p2"}
	if dup, err = in.Accept(ctx, uuid.Nil, ev, []byte("body")); err != nil || dup {
		t.Fatalf("other project: dup=%v err=%v", dup, err)
	}
	in.bus.Wait()
	if n := len(sub.events()); n != 2 {
		t.Fatalf("each distinct delivery is published once, got %d", n)
	}
	e := sub.events()[0]
	if e.Source != SourceForgejo || e.DeliveryID != "del-1" || e.Name != GitPush || e.Branch != "main" || e.Actor != "" {
		t.Fatalf("%+v", e)
	}
	// caches dropped once per accepted delivery, never for the duplicate
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if len(inv.calls) != 2 || inv.calls[0].Owner != "acme" || inv.calls[0].Repo != "shop" {
		t.Fatalf("InvalidateRepo calls: %+v", inv.calls)
	}
}

func TestAcceptFallsBackToBodyHash(t *testing.T) {
	in, sub, _, _, pid := newInbound(t)
	ctx := context.Background()
	ev := parse(t, map[string]string{"X-Forgejo-Event": "push"}, `{"ref":"refs/heads/main","after":"2222222"}`)
	if dup, _ := in.Accept(ctx, pid, ev, []byte("exact body")); dup {
		t.Fatal("first must not be a duplicate")
	}
	if dup, _ := in.Accept(ctx, pid, ev, []byte("exact body")); !dup {
		t.Fatal("an exact replay without delivery header must be detected by body hash")
	}
	if dup, _ := in.Accept(ctx, pid, ev, []byte("another body")); dup {
		t.Fatal("a different body is a different delivery")
	}
	in.bus.Wait()
	if len(sub.events()) != 2 {
		t.Fatalf("got %d", len(sub.events()))
	}
}

func TestAcceptUnmappedOnlyInvalidates(t *testing.T) {
	in, sub, inv, st, pid := newInbound(t)
	ev := parse(t, map[string]string{"X-Forgejo-Event": "push", "X-Forgejo-Delivery": "d"},
		`{"ref":"refs/heads/x","after":"0000000000000000000000000000000000000000"}`)
	dup, err := in.Accept(context.Background(), pid, ev, nil)
	if err != nil || dup {
		t.Fatalf("dup=%v err=%v", dup, err)
	}
	if st.count() != 0 || len(sub.events()) != 0 {
		t.Fatal("nothing must be recorded for a deleted-branch push")
	}
	if len(inv.calls) != 1 {
		t.Fatal("caches must still be invalidated")
	}
}

func TestAcceptErrors(t *testing.T) {
	in, _, _, st, pid := newInbound(t)
	ev := parse(t, map[string]string{"X-Forgejo-Event": "push", "X-Forgejo-Delivery": "d"}, `{"ref":"refs/heads/main","after":"2"}`)
	if _, err := in.Accept(context.Background(), uuid.New(), ev, nil); !errors.Is(err, ErrNoProject) {
		t.Fatalf("unknown project: %v", err)
	}
	st.insertErr = errors.New("db down")
	if _, err := in.Accept(context.Background(), pid, ev, nil); err == nil {
		t.Fatal("storage failure must be reported so the handler can answer 503")
	}
}

type fakePrev struct {
	secret string
	err    error
}

func (f fakePrev) PreviousWebhookSecret(context.Context, uuid.UUID) (string, error) {
	return f.secret, f.err
}

func TestPreviousSecret(t *testing.T) {
	in, _, _, _, pid := newInbound(t)
	if in.PreviousSecret(context.Background(), pid) != "" {
		t.Fatal("no store -> none")
	}
	in.SetPrevSecretStore(fakePrev{secret: "old"})
	if got := in.PreviousSecret(context.Background(), pid); got != "old" {
		t.Fatalf("%q", got)
	}
	in.SetPrevSecretStore(fakePrev{err: errors.New("boom")})
	if got := in.PreviousSecret(context.Background(), pid); got != "" {
		t.Fatal("a failing store must fail closed (no previous secret)")
	}
}
