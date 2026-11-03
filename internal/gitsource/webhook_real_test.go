package gitsource

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixtures in testdata/forgejo_v15.0.11 are REAL deliveries captured from a Forgejo 15.0.11
// instance (webhook secret "s3cret"; only the Forgejo, Content-Type and signature headers kept).
type realDelivery struct {
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

func loadReal(t *testing.T, name string) (http.Header, []byte) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "forgejo_v15.0.11", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var d realDelivery
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	for k, v := range d.Headers {
		h.Set(k, v)
	}
	return h, []byte(d.Body)
}

func TestRealForgejoSignatureIsBareHexHMACSHA256(t *testing.T) {
	h, body := loadReal(t, "push__push__main")
	sig := h.Get("X-Forgejo-Signature")
	m := hmac.New(sha256.New, []byte("s3cret"))
	m.Write(body)
	if want := hex.EncodeToString(m.Sum(nil)); sig != want {
		t.Fatalf("X-Forgejo-Signature is not bare hex HMAC-SHA256: %q vs %q", sig, want)
	}
	if h.Get("X-Hub-Signature-256") != "sha256="+sig {
		t.Fatalf("X-Hub-Signature-256 should carry the sha256= prefix: %q", h.Get("X-Hub-Signature-256"))
	}
	if !VerifySignature(h, body, "s3cret") || VerifySignature(h, body, "other") {
		t.Fatal("VerifySignature on the real headers")
	}
	// only the Forgejo header (no GitHub-style one): bare hex must verify as well
	only := http.Header{}
	only.Set("X-Forgejo-Signature", sig)
	if !VerifySignature(only, body, "s3cret") {
		t.Fatal("bare hex X-Forgejo-Signature rejected")
	}
	if DeliveryID(h) == "" {
		t.Fatal("delivery id")
	}
}

func TestRealForgejoPayloads(t *testing.T) {
	cases := []struct {
		file string
		kind string
		chk  func(t *testing.T, e *Event)
	}{
		{"push__push__main", EventPush, func(t *testing.T, e *Event) {
			if e.Branch != "main" || len(e.SHA) != 40 || e.Actor != "fjadmin" {
				t.Fatalf("%+v", e)
			}
		}},
		{"create__create", EventBranchCreated, func(t *testing.T, e *Event) {
			if e.Branch != "tmp1" {
				t.Fatalf("%+v", e)
			}
		}},
		{"delete__delete", EventBranchDeleted, func(t *testing.T, e *Event) {
			if e.Branch != "tmp1" {
				t.Fatalf("%+v", e)
			}
		}},
		{"pull_request__pull_request__opened", EventPullRequest, func(t *testing.T, e *Event) {
			if e.Action != "opened" || e.PR != 1 || e.Branch != "feat" || e.BaseRef != "main" || e.PRAuthor != "fjadmin" {
				t.Fatalf("%+v", e)
			}
		}},
		{"pull_request__pull_request_review_request__review_requested", EventPullRequest, func(t *testing.T, e *Event) {
			if e.Action != "review_requested" || e.RequestedReviewer != "alice" {
				t.Fatalf("%+v", e)
			}
		}},
		{"pull_request_approved__pull_request_review_approved__reviewed", EventReview, func(t *testing.T, e *Event) {
			if e.ReviewState != ReviewApproved || e.Reviewer != "alice" || e.PR != 1 || e.ReviewBody != "ok" {
				t.Fatalf("%+v", e)
			}
		}},
		{"pull_request_rejected__pull_request_review_rejected__reviewed", EventReview, func(t *testing.T, e *Event) {
			if e.ReviewState != ReviewChangesRequested || e.Reviewer != "alice" || e.ReviewBody != "fix" {
				t.Fatalf("%+v", e)
			}
		}},
		{"pull_request_comment__pull_request_review_comment__reviewed", EventReview, func(t *testing.T, e *Event) {
			if e.ReviewState != ReviewCommented || e.Reviewer != "alice" || e.ReviewBody != "looks ok" {
				t.Fatalf("%+v", e)
			}
		}},
		{"action_run_failure__action_run_failure", EventWorkflowRun, func(t *testing.T, e *Event) {
			if e.RunID != "5" || e.RunWorkflow != "ci.yml" || e.Branch != "feat" || len(e.SHA) != 40 || e.RunConclusion != "failure" || e.RunURL == "" {
				t.Fatalf("%+v", e)
			}
		}},
		{"pull_request__pull_request_sync", EventPullRequest, func(t *testing.T, e *Event) {
			if e.Action != "synchronize" || e.PR != 1 {
				t.Fatalf("%+v", e)
			}
		}},
		// a plain conversation comment on a PR arrives as X-Forgejo-Event: issue_comment
		{"issue_comment__pull_request_comment__created", EventIgnored, nil},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			h, body := loadReal(t, c.file)
			if !VerifySignature(h, body, "s3cret") {
				t.Fatal("signature")
			}
			e, err := ParseEvent(h, body)
			if err != nil {
				t.Fatal(err)
			}
			if e.Kind != c.kind {
				t.Fatalf("kind %q, want %q (%+v)", e.Kind, c.kind, e)
			}
			if c.chk != nil {
				c.chk(t, e)
			}
			if !strings.EqualFold(e.Provider, "forgejo") {
				t.Fatalf("provider %q", e.Provider)
			}
		})
	}
}
