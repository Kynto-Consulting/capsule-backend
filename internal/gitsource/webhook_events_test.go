package gitsource

import (
	"testing"
)

// Payload shapes for review, status and run events are NOT confirmed against Forgejo v15.0.11
// (see the notes in ParseEvent); these tests pin the shapes the parser is written for.

const repoBlock = `"repository":{"clone_url":"https://git.example.com/acme/shop.git","html_url":"https://git.example.com/acme/shop"}`

func prBlock(extra string) string {
	return `"pull_request":{"number":7,"title":"Add cart","html_url":"https://git.example.com/acme/shop/pulls/7","merged":false,
	 "user":{"login":"ana"},
	 "head":{"ref":"feat/cart","sha":"abc1234","repo":{"full_name":"acme/shop"}},
	 "base":{"ref":"main","repo":{"full_name":"acme/shop","clone_url":"https://git.example.com/acme/shop.git"}}` + extra + `}`
}

func TestDeliveryID(t *testing.T) {
	if got := DeliveryID(hdr("X-Forgejo-Delivery", " d-1 ")); got != "d-1" {
		t.Fatalf("forgejo: %q", got)
	}
	if got := DeliveryID(hdr("X-GitHub-Delivery", "g-9")); got != "g-9" {
		t.Fatalf("github: %q", got)
	}
	if got := DeliveryID(hdr()); got != "" {
		t.Fatalf("none: %q", got)
	}
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'a'
	}
	if got := DeliveryID(hdr("X-Forgejo-Delivery", string(long))); len(got) != 200 {
		t.Fatalf("must be capped, got %d", len(got))
	}
	ev, _ := ParseEvent(hdr("X-Forgejo-Event", "push", "X-Forgejo-Delivery", "d-2"), []byte(`{"ref":"refs/heads/main","after":"abc"}`))
	if ev.DeliveryID != "d-2" || ev.RawEvent != "push" {
		t.Fatalf("event must carry delivery id and raw event: %+v", ev)
	}
}

func TestParseEventPushKeepsBefore(t *testing.T) {
	ev, _ := ParseEvent(hdr("X-Forgejo-Event", "push"), []byte(`{"ref":"refs/heads/main","before":"1111111","after":"2222222"}`))
	if ev.Kind != EventPush || ev.Before != "1111111" {
		t.Fatalf("%+v", ev)
	}
}

func TestParseEventPullRequestNewActions(t *testing.T) {
	ev, _ := ParseEvent(hdr("X-Forgejo-Event", "pull_request"),
		[]byte(`{"action":"edited","number":7,"changes":{"title":{"from":"WIP: Add cart"}},`+prBlock("")+`,`+repoBlock+`}`))
	if ev.Kind != EventPullRequest || ev.Action != "edited" || ev.TitleFrom != "WIP: Add cart" || ev.Title != "Add cart" || ev.PRAuthor != "ana" {
		t.Fatalf("edited: %+v", ev)
	}
	ev, _ = ParseEvent(hdr("X-Forgejo-Event", "pull_request"),
		[]byte(`{"action":"review_requested","number":7,"requested_reviewer":{"login":"bruno"},`+prBlock("")+`,`+repoBlock+`}`))
	if ev.Kind != EventPullRequest || ev.Action != "review_requested" || ev.RequestedReviewer != "bruno" {
		t.Fatalf("review_requested: %+v", ev)
	}
	// still ignored
	ev, _ = ParseEvent(hdr("X-Forgejo-Event", "pull_request"), []byte(`{"action":"labeled","number":7,`+prBlock("")+`}`))
	if ev.Kind != EventIgnored {
		t.Fatalf("labeled must stay ignored: %+v", ev)
	}
}

func TestParseEventReview(t *testing.T) {
	cases := []struct {
		name, event, eventType, review, want string
	}{
		{"approved by name", "pull_request_approved", "", `{"type":"approved","content":"lgtm"}`, ReviewApproved},
		{"rejected by name", "pull_request_rejected", "", `{"type":"rejected","content":"no"}`, ReviewChangesRequested},
		{"comment review", "pull_request_comment", "", `{"type":"comment","content":"hm"}`, ReviewCommented},
		{"by event type header", "pull_request", "pull_request_review_approved", `{"type":"approved"}`, ReviewApproved},
		{"github shape", "pull_request_review", "", `{"state":"changes_requested","body":"fix","user":{"login":"bruno"}}`, ReviewChangesRequested},
	}
	for _, c := range cases {
		h := hdr("X-Forgejo-Event", c.event)
		if c.eventType != "" {
			h.Set("X-Forgejo-Event-Type", c.eventType)
		}
		action := "reviewed"
		if c.event == "pull_request" {
			action = "reviewed"
		}
		body := []byte(`{"action":"` + action + `","number":7,"review":` + c.review + `,"sender":{"login":"bruno"},` + prBlock("") + `,` + repoBlock + `}`)
		ev, err := ParseEvent(h, body)
		if err != nil || ev.Kind != EventReview || ev.ReviewState != c.want || ev.PR != 7 || ev.Reviewer != "bruno" || ev.PRAuthor != "ana" {
			t.Errorf("%s: %+v err=%v", c.name, ev, err)
		}
	}
	// A conversation comment on a PR (no review block) is not a review.
	ev, _ := ParseEvent(hdr("X-Forgejo-Event", "pull_request_comment"), []byte(`{"action":"created","comment":{"body":"x"},`+prBlock("")+`}`))
	if ev.Kind != EventIgnored {
		t.Fatalf("plain comment must be ignored: %+v", ev)
	}
	// Unknown review type is ignored rather than guessed.
	ev, _ = ParseEvent(hdr("X-Forgejo-Event", "pull_request_review"), []byte(`{"review":{"type":"weird"},`+prBlock("")+`}`))
	if ev.Kind != EventIgnored {
		t.Fatalf("unknown review type must be ignored: %+v", ev)
	}
}

func TestParseEventStatus(t *testing.T) {
	body := func(state string) []byte {
		return []byte(`{"state":"` + state + `","sha":"abc1234","context":"capsule/security","description":"done","target_url":"https://x/y",` + repoBlock + `,"sender":{"login":"bot"}}`)
	}
	for _, st := range []string{"success", "failure", "error"} {
		ev, _ := ParseEvent(hdr("X-GitHub-Event", "status"), body(st))
		if ev.Kind != EventStatus || ev.StatusState != st || ev.StatusContext != "capsule/security" || ev.SHA != "abc1234" || ev.StatusURL != "https://x/y" {
			t.Errorf("%s: %+v", st, ev)
		}
	}
	if ev, _ := ParseEvent(hdr("X-GitHub-Event", "status"), body("pending")); ev.Kind != EventIgnored {
		t.Fatalf("pending is not final: %+v", ev)
	}
}

func TestParseEventWorkflowRun(t *testing.T) {
	// GitHub shape
	gh := []byte(`{"action":"completed","workflow_run":{"id":99,"name":"CI","status":"completed","conclusion":"failure","head_sha":"abc","head_branch":"main","html_url":"https://x/runs/99"},` + repoBlock + `,"sender":{"login":"ana"}}`)
	ev, _ := ParseEvent(hdr("X-GitHub-Event", "workflow_run"), gh)
	if ev.Kind != EventWorkflowRun || ev.RunID != "99" || ev.RunConclusion != "failure" || ev.Branch != "main" || ev.SHA != "abc" || ev.Actor != "ana" || len(ev.RepoURLs) == 0 {
		t.Fatalf("github shape: %+v", ev)
	}
	// not completed -> ignored
	run := []byte(`{"action":"requested","workflow_run":{"id":1,"status":"queued"},` + repoBlock + `}`)
	if ev, _ := ParseEvent(hdr("X-GitHub-Event", "workflow_run"), run); ev.Kind != EventIgnored {
		t.Fatalf("queued run must be ignored: %+v", ev)
	}
	// Forgejo action_run_* shape (?)
	fj := []byte(`{"action":"failure","run":{"index":12,"title":"build","html_url":"https://git/x/actions/runs/12","commit_sha":"def","prettyref":"main"},` + repoBlock + `}`)
	ev, _ = ParseEvent(hdr("X-Forgejo-Event", "action_run_failure"), fj)
	if ev.Kind != EventWorkflowRun || ev.RunID != "12" || ev.RunConclusion != "failure" || ev.SHA != "def" || ev.Branch != "main" || ev.RunName != "build" {
		t.Fatalf("forgejo shape: %+v", ev)
	}
	ev, _ = ParseEvent(hdr("X-Forgejo-Event", "action_run_recover"), fj)
	if ev.Kind != EventWorkflowRun || ev.RunConclusion != "success" {
		t.Fatalf("recover means success: %+v", ev)
	}
	// no run object -> ignored
	if ev, _ := ParseEvent(hdr("X-Forgejo-Event", "action_run_success"), []byte(`{"action":"success"}`)); ev.Kind != EventIgnored {
		t.Fatalf("%+v", ev)
	}
}

func TestParseEventBranchCreateDelete(t *testing.T) {
	ev, _ := ParseEvent(hdr("X-Forgejo-Event", "create"), []byte(`{"ref":"feat/x","ref_type":"branch","sender":{"login":"ana"},`+repoBlock+`}`))
	if ev.Kind != EventBranchCreated || ev.Branch != "feat/x" || ev.Actor != "ana" {
		t.Fatalf("%+v", ev)
	}
	ev, _ = ParseEvent(hdr("X-Forgejo-Event", "delete"), []byte(`{"ref":"refs/heads/feat/x","ref_type":"branch",`+repoBlock+`}`))
	if ev.Kind != EventBranchDeleted || ev.Branch != "feat/x" {
		t.Fatalf("%+v", ev)
	}
	ev, _ = ParseEvent(hdr("X-Forgejo-Event", "create"), []byte(`{"ref":"v1","ref_type":"tag"}`))
	if ev.Kind != EventIgnored {
		t.Fatalf("tags are not branch events: %+v", ev)
	}
}
