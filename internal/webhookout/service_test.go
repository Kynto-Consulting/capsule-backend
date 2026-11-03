package webhookout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

type rig struct {
	t       *testing.T
	svc     *Service
	st      *memStore
	clock   *fakeClock
	mail    *fakeMailer
	org     uuid.UUID
	project uuid.UUID
	sc      Scope

	mu       sync.Mutex
	status   func(n int, r *http.Request) (int, http.Header, string) // answer for the nth request
	requests []*recorded
}

type recorded struct {
	Header http.Header
	Body   []byte
	URL    string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, st: newMemStore(), clock: &fakeClock{t: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}, mail: &fakeMailer{},
		org: uuid.New(), project: uuid.New()}
	r.sc = Scope{OrgID: r.org, ProjectID: &r.project}
	r.status = func(int, *http.Request) (int, http.Header, string) { return 200, nil, "ok" }
	client := &http.Client{Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
		var b []byte
		if req.Body != nil {
			b, _ = io.ReadAll(req.Body)
		}
		r.mu.Lock()
		r.requests = append(r.requests, &recorded{Header: req.Header.Clone(), Body: b, URL: req.URL.String()})
		n := len(r.requests)
		fn := r.status
		r.mu.Unlock()
		code, hdr, body := fn(n, req)
		if hdr == nil {
			hdr = http.Header{}
		}
		return &http.Response{StatusCode: code, Header: hdr, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse } // same as the production client
	r.svc = New(Config{
		Store: r.st, Projects: fakeProjects{info: gitevents.ProjectInfo{OrgID: r.org, OrgSlug: "acme", ProjectSlug: "shop"}},
		Policy: publicPolicy(), Client: client, Mailer: r.mail, BaseURL: "https://app.example.com", Now: r.clock.Now,
	})
	return r
}

func (r *rig) reqs() []*recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*recorded(nil), r.requests...)
}

func (r *rig) create(in CreateInput) *Webhook {
	r.t.Helper()
	if in.Kind == "" {
		in.Kind = KindHTTP
	}
	if in.URL == "" && in.Kind == KindHTTP {
		in.URL = "https://hooks.example.com/in"
	}
	if len(in.Events) == 0 {
		in.Events = []string{gitevents.PRMerged}
	}
	w, err := r.svc.Create(context.Background(), r.sc, in, uuid.New())
	if err != nil {
		r.t.Fatalf("create: %v", err)
	}
	return w
}

func (r *rig) event(name, branch string) gitevents.Event {
	return gitevents.Event{ID: uuid.New(), OrgID: r.org, ProjectID: r.project, OrgSlug: "acme", ProjectSlug: "shop", Name: name,
		Actor: "ana", Branch: branch, Data: map[string]any{"pr": 7, "title": "Add cart", "branch": branch}, CreatedAt: r.clock.Now()}
}

func (r *rig) deliver(e gitevents.Event) []Delivery {
	r.t.Helper()
	if err := r.svc.Handle(context.Background(), e); err != nil {
		r.t.Fatal(err)
	}
	return r.st.allDeliveries()
}

func TestCreateValidation(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	cases := []struct {
		name string
		in   CreateInput
		want string // substring of the validation error; "" = valid
	}{
		{"valid http", CreateInput{Kind: KindHTTP, URL: "https://hooks.example.com/x?t=1", Events: []string{"pr.merged"}}, ""},
		{"http not allowed", CreateInput{Kind: KindHTTP, URL: "http://hooks.example.com/x", Events: []string{"pr.merged"}}, "https"},
		{"credentials in url", CreateInput{Kind: KindHTTP, URL: "https://u:p@hooks.example.com/x", Events: []string{"pr.merged"}}, "credentials"},
		{"private host", CreateInput{Kind: KindHTTP, URL: "https://internal.example.com/x", Events: []string{"pr.merged"}}, "private"},
		{"loopback literal", CreateInput{Kind: KindHTTP, URL: "https://127.0.0.1/x", Events: []string{"pr.merged"}}, "private"},
		{"metadata literal", CreateInput{Kind: KindHTTP, URL: "https://169.254.169.254/latest", Events: []string{"pr.merged"}}, "private"},
		{"ipv6 loopback", CreateInput{Kind: KindHTTP, URL: "https://[::1]/x", Events: []string{"pr.merged"}}, "private"},
		{"fragment", CreateInput{Kind: KindHTTP, URL: "https://hooks.example.com/x#a", Events: []string{"pr.merged"}}, "fragment"},
		{"missing url", CreateInput{Kind: KindHTTP, Events: []string{"pr.merged"}}, "required"},
		{"bad kind", CreateInput{Kind: "sms", URL: "https://x.example.com", Events: []string{"pr.merged"}}, "kind"},
		{"no events", CreateInput{Kind: KindHTTP, URL: "https://hooks.example.com/x"}, "event"},
		{"unknown event", CreateInput{Kind: KindHTTP, URL: "https://hooks.example.com/x", Events: []string{"nope"}}, "unknown event"},
		{"branch filter chars", CreateInput{Kind: KindHTTP, URL: "https://hooks.example.com/x", Events: []string{"git.push"}, BranchFilter: "main; rm -rf"}, "branch"},
		{"slack ok", CreateInput{Kind: KindSlack, URL: "https://hooks.slack.com/services/T0/B0/xxx", Events: []string{"pr.merged"}}, ""},
		{"slack wrong host", CreateInput{Kind: KindSlack, URL: "https://evil.example.com/services/T0/B0/xxx", Events: []string{"pr.merged"}}, "Slack"},
		{"slack lookalike host", CreateInput{Kind: KindSlack, URL: "https://hooks.slack.com.evil.example.com/services/T0/B0/x", Events: []string{"pr.merged"}}, "Slack"},
		{"slack wrong path", CreateInput{Kind: KindSlack, URL: "https://hooks.slack.com/other", Events: []string{"pr.merged"}}, "Slack"},
		{"discord ok", CreateInput{Kind: KindDiscord, URL: "https://discord.com/api/webhooks/1/abc", Events: []string{"pr.merged"}}, ""},
		{"discord wrong host", CreateInput{Kind: KindDiscord, URL: "https://discord.example.com/api/webhooks/1/abc", Events: []string{"pr.merged"}}, "Discord"},
		{"email ok", CreateInput{Kind: KindEmail, EmailTo: []string{"a@x.io", "b@x.io"}, Events: []string{"pr.merged"}}, ""},
		{"email none", CreateInput{Kind: KindEmail, Events: []string{"pr.merged"}}, "recipients"},
		{"email bad", CreateInput{Kind: KindEmail, EmailTo: []string{"not-an-email"}, Events: []string{"pr.merged"}}, "valid email"},
		{"email with name", CreateInput{Kind: KindEmail, EmailTo: []string{"Eve <e@x.io>"}, Events: []string{"pr.merged"}}, "valid email"},
		{"email header injection", CreateInput{Kind: KindEmail, EmailTo: []string{"a@x.io\r\nBcc: e@x.io"}, Events: []string{"pr.merged"}}, "valid email"},
	}
	for _, c := range cases {
		w, err := r.svc.Create(ctx, r.sc, c.in, uuid.Nil)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", c.name, err)
			}
			if err == nil && c.in.Kind == KindHTTP && !strings.HasPrefix(w.Secret, "whsec_") {
				t.Errorf("%s: http webhooks get a signing secret", c.name)
			}
			if err == nil && c.in.Kind != KindHTTP && w.Secret != "" {
				t.Errorf("%s: only http webhooks get a secret", c.name)
			}
			continue
		}
		var ve *ValidationError
		if !errors.As(err, &ve) || !strings.Contains(ve.Error(), c.want) {
			t.Errorf("%s: want validation error containing %q, got %v", c.name, c.want, err)
		}
	}
}

func TestWebhookLimitPerScope(t *testing.T) {
	r := newRig(t)
	for i := 0; i < MaxWebhooksPerScope; i++ {
		r.create(CreateInput{})
	}
	if _, err := r.svc.Create(context.Background(), r.sc, CreateInput{Kind: KindHTTP, URL: "https://hooks.example.com/x", Events: []string{"pr.merged"}}, uuid.Nil); err == nil {
		t.Fatal("limit per scope must be enforced")
	}
	// another scope is unaffected
	if _, err := r.svc.Create(context.Background(), Scope{OrgID: r.org}, CreateInput{Kind: KindHTTP, URL: "https://hooks.example.com/x", Events: []string{"pr.merged"}}, uuid.Nil); err != nil {
		t.Fatalf("org scope: %v", err)
	}
}

func TestSignedDeliveryCanBeVerifiedByTheReceiver(t *testing.T) {
	r := newRig(t)
	w := r.create(CreateInput{Events: []string{gitevents.PRMerged}})
	secret := w.Secret
	ds := r.deliver(r.event(gitevents.PRMerged, "feat/cart"))
	if len(ds) != 1 || ds[0].Status != StatusPending {
		t.Fatalf("one pending delivery expected: %+v", ds)
	}
	if n := r.svc.ProcessDue(context.Background()); n != 1 {
		t.Fatalf("processed %d", n)
	}
	reqs := r.reqs()
	if len(reqs) != 1 {
		t.Fatalf("requests: %d", len(reqs))
	}
	h := reqs[0].Header
	if h.Get("X-Capsule-Event") != "pr.merged" || h.Get("X-Capsule-Delivery") != ds[0].ID.String() || h.Get("Content-Type") != "application/json" {
		t.Fatalf("headers: %v", h)
	}
	ts, _ := strconv.ParseInt(h.Get("X-Capsule-Timestamp"), 10, 64)
	if ts != r.clock.Now().Unix() {
		t.Fatalf("timestamp %d", ts)
	}
	if !Verify([]string{secret}, h.Get("X-Capsule-Timestamp"), []string{h.Get("X-Capsule-Signature")}, reqs[0].Body, r.clock.Now()) {
		t.Fatal("receiver must be able to verify the signature")
	}
	if Verify([]string{secret}, h.Get("X-Capsule-Timestamp"), []string{h.Get("X-Capsule-Signature")}, append([]byte(nil), append(reqs[0].Body, ' ')...), r.clock.Now()) {
		t.Fatal("a modified body must not verify")
	}
	if Verify([]string{"whsec_wrong"}, h.Get("X-Capsule-Timestamp"), []string{h.Get("X-Capsule-Signature")}, reqs[0].Body, r.clock.Now()) {
		t.Fatal("wrong secret must not verify")
	}
	if Verify([]string{secret}, h.Get("X-Capsule-Timestamp"), []string{h.Get("X-Capsule-Signature")}, reqs[0].Body, r.clock.Now().Add(Tolerance+time.Second)) {
		t.Fatal("a stale timestamp (replay) must be rejected")
	}
	var env Envelope
	if err := json.Unmarshal(reqs[0].Body, &env); err != nil {
		t.Fatal(err)
	}
	if env.ID != ds[0].ID.String() || env.Event != "pr.merged" || env.APIVersion != APIVersion || env.Org.Slug != "acme" || env.Project.Slug != "shop" ||
		env.Actor == nil || env.Actor.Login != "ana" || env.Data["title"] != "Add cart" || env.CreatedAt.IsZero() {
		t.Fatalf("envelope: %s", reqs[0].Body)
	}
	got := r.st.delivery(ds[0].ID)
	if got.Status != StatusDelivered || got.StatusCode != 200 || got.Attempt != 1 || got.DeliveredAt == nil {
		t.Fatalf("delivery: %+v", got)
	}
	for k, v := range got.RequestHeaders {
		if strings.Contains(strings.ToLower(k), "signature") || strings.Contains(v, "sha256=") || strings.Contains(v, secret) {
			t.Fatalf("stored request headers must not carry signatures: %v", got.RequestHeaders)
		}
	}
	if wh, _ := r.st.GetWebhook(context.Background(), w.ID); wh.LastDeliveryStatus != 200 {
		t.Fatalf("last delivery status: %d", wh.LastDeliveryStatus)
	}
}

func TestBackoffScheduleWithFakeClock(t *testing.T) {
	r := newRig(t)
	r.status = func(int, *http.Request) (int, http.Header, string) { return 500, nil, "nope" }
	r.create(CreateInput{})
	ds := r.deliver(r.event(gitevents.PRMerged, ""))
	id := ds[0].ID
	ctx := context.Background()

	var first *recorded
	var stamps []string
	for attempt := 1; attempt <= MaxAttempts(); attempt++ {
		if n := r.svc.ProcessDue(ctx); n != 1 {
			t.Fatalf("attempt %d: processed %d", attempt, n)
		}
		d := r.st.delivery(id)
		if d.Attempt != attempt || d.StatusCode != 500 || d.Error != "receiver answered 500" {
			t.Fatalf("attempt %d: %+v", attempt, d)
		}
		reqs := r.reqs()
		last := reqs[len(reqs)-1]
		if first == nil {
			first = last
		}
		stamps = append(stamps, last.Header.Get("X-Capsule-Timestamp"))
		if last.Header.Get("X-Capsule-Delivery") != id.String() || !bytes.Equal(last.Body, first.Body) {
			t.Fatalf("attempt %d: delivery id and body must be stable across retries", attempt)
		}
		if attempt == MaxAttempts() {
			if d.Status != StatusFailed {
				t.Fatalf("after %d attempts the delivery fails for good: %+v", attempt, d)
			}
			break
		}
		want := r.clock.Now().Add(Backoff[attempt-1])
		if d.Status != StatusPending || !d.NextAttemptAt.Equal(want) {
			t.Fatalf("attempt %d: status=%s next=%v want %v", attempt, d.Status, d.NextAttemptAt, want)
		}
		// not due yet: nothing is sent
		before := len(r.reqs())
		r.clock.Advance(Backoff[attempt-1] - time.Second)
		if n := r.svc.ProcessDue(ctx); n != 0 || len(r.reqs()) != before {
			t.Fatalf("attempt %d: must wait for the backoff", attempt)
		}
		r.clock.Advance(time.Second)
	}
	seen := map[string]bool{}
	for _, s := range stamps {
		seen[s] = true
	}
	if len(seen) != len(stamps) {
		t.Fatalf("each attempt must carry a fresh timestamp: %v", stamps)
	}
	if want := []time.Duration{10 * time.Second, time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour}; fmt.Sprint(Backoff) != fmt.Sprint(want) {
		t.Fatalf("backoff must match the contract: %v", Backoff)
	}
	// nothing more is ever attempted
	r.clock.Advance(24 * time.Hour)
	if n := r.svc.ProcessDue(ctx); n != 0 {
		t.Fatalf("failed deliveries are not retried: %d", n)
	}
}

func TestPendingDeliveriesSurviveARestart(t *testing.T) {
	r := newRig(t)
	r.status = func(n int, _ *http.Request) (int, http.Header, string) {
		if n == 1 {
			return 503, nil, ""
		}
		return 200, nil, "ok"
	}
	r.create(CreateInput{})
	ds := r.deliver(r.event(gitevents.PRMerged, ""))
	r.svc.ProcessDue(context.Background()) // first attempt fails
	// "restart": a brand new Service on the same store picks the delivery up when it is due
	svc2 := New(Config{Store: r.st, Projects: fakeProjects{}, Policy: publicPolicy(), Now: r.clock.Now,
		Client: &http.Client{Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
			b, _ := io.ReadAll(req.Body)
			r.mu.Lock()
			r.requests = append(r.requests, &recorded{Header: req.Header.Clone(), Body: b})
			r.mu.Unlock()
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}}, nil
		})}})
	if n := svc2.ProcessDue(context.Background()); n != 0 {
		t.Fatal("not due yet")
	}
	r.clock.Advance(Backoff[0])
	if n := svc2.ProcessDue(context.Background()); n != 1 {
		t.Fatalf("after restart: %d", n)
	}
	if d := r.st.delivery(ds[0].ID); d.Status != StatusDelivered || d.Attempt != 2 {
		t.Fatalf("%+v", d)
	}
}

func TestGone410DisablesTheWebhook(t *testing.T) {
	r := newRig(t)
	r.status = func(int, *http.Request) (int, http.Header, string) { return 410, nil, "gone" }
	w := r.create(CreateInput{})
	ds := r.deliver(r.event(gitevents.PRMerged, ""))
	r.svc.ProcessDue(context.Background())
	d := r.st.delivery(ds[0].ID)
	if d.Status != StatusAbandoned || d.StatusCode != 410 || !strings.Contains(d.Error, "410") {
		t.Fatalf("%+v", d)
	}
	got, _ := r.st.GetWebhook(context.Background(), w.ID)
	if got.Active || !strings.Contains(got.DisabledReason, "410") {
		t.Fatalf("webhook must be disabled: %+v", got)
	}
	// no further events are queued for it, and no retries happen
	if n := len(r.deliver(r.event(gitevents.PRMerged, ""))); n != 1 {
		t.Fatalf("disabled webhook must not receive new deliveries, have %d", n)
	}
	r.clock.Advance(time.Hour)
	if r.svc.ProcessDue(context.Background()) != 0 {
		t.Fatal("no retry after 410")
	}
	// re-enabling clears the reason
	on := true
	up, err := r.svc.Update(context.Background(), r.sc, w.ID, PatchInput{Active: &on})
	if err != nil || !up.Active || up.DisabledReason != "" {
		t.Fatalf("%+v %v", up, err)
	}
}

func TestRetryAfterIsHonouredAndCapped(t *testing.T) {
	r := newRig(t)
	r.status = func(int, *http.Request) (int, http.Header, string) {
		return 429, http.Header{"Retry-After": {"3600"}}, "slow down"
	}
	r.create(CreateInput{})
	ds := r.deliver(r.event(gitevents.PRMerged, ""))
	r.svc.ProcessDue(context.Background())
	if d := r.st.delivery(ds[0].ID); !d.NextAttemptAt.Equal(r.clock.Now().Add(time.Hour)) {
		t.Fatalf("Retry-After beats the short backoff: %v", d.NextAttemptAt)
	}
	r.status = func(int, *http.Request) (int, http.Header, string) {
		return 503, http.Header{"Retry-After": {"99999999"}}, ""
	}
	r.clock.Advance(time.Hour)
	r.svc.ProcessDue(context.Background())
	if d := r.st.delivery(ds[0].ID); d.NextAttemptAt.Sub(r.clock.Now()) > maxRetryAfter {
		t.Fatalf("Retry-After is capped at %v: %v", maxRetryAfter, d.NextAttemptAt.Sub(r.clock.Now()))
	}
}

func TestTransportErrorsNeverLeakTheURLOrSecrets(t *testing.T) {
	r := newRig(t)
	w := r.create(CreateInput{URL: "https://hooks.example.com/in?token=SUPERSECRETTOKEN"})
	r.svc.client = &http.Client{Transport: rtFunc(func(req *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Post", URL: req.URL.String(), Err: errors.New("dial tcp: connection refused")}
	})}
	ds := r.deliver(r.event(gitevents.PRMerged, ""))
	r.svc.ProcessDue(context.Background())
	d := r.st.delivery(ds[0].ID)
	if d.Error == "" || strings.Contains(d.Error, "SUPERSECRETTOKEN") || strings.Contains(d.Error, "hooks.example.com") {
		t.Fatalf("error leaks the URL: %q", d.Error)
	}
	if d.Status != StatusPending || d.StatusCode != 0 {
		t.Fatalf("network failure is retried: %+v", d)
	}
	_ = w
}

func TestResponseExcerptIsBoundedAndRedacted(t *testing.T) {
	r := newRig(t)
	w := r.create(CreateInput{})
	r.status = func(int, *http.Request) (int, http.Header, string) {
		return 500, nil, "echo " + w.Secret + "\n\x00\x01" + strings.Repeat("A", 5000)
	}
	ds := r.deliver(r.event(gitevents.PRMerged, ""))
	r.svc.ProcessDue(context.Background())
	d := r.st.delivery(ds[0].ID)
	if strings.Contains(d.ResponseExcerpt, w.Secret) || !strings.Contains(d.ResponseExcerpt, "[redacted]") {
		t.Fatalf("secret echoed by the receiver must be redacted: %q", d.ResponseExcerpt)
	}
	if len(d.ResponseExcerpt) > 520 || strings.ContainsAny(d.ResponseExcerpt, "\n\x00\x01") {
		t.Fatalf("excerpt must be short and printable: %d", len(d.ResponseExcerpt))
	}
}

func TestDefaultClientBlocksPrivateDestinationsAtDialTime(t *testing.T) {
	// A webhook already stored (validation passed when it resolved to a public address) must still
	// not be able to reach a private address later (DNS rebinding): the real client re-checks.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	st := newMemStore()
	svc := New(Config{Store: st, Projects: fakeProjects{}, Policy: publicPolicy()}) // default client
	w := &Webhook{ID: uuid.New(), OrgID: uuid.New(), Kind: KindHTTP, URL: srv.URL, Secret: "whsec_x", Events: []string{"pr.merged"}, Active: true}
	_ = st.CreateWebhook(context.Background(), w)
	d := &Delivery{ID: uuid.New(), WebhookID: w.ID, Event: "pr.merged", Payload: `{}`, Status: StatusPending, NextAttemptAt: time.Now()}
	_, _ = st.InsertDelivery(context.Background(), d)
	svc.attempt(context.Background(), d, w, true)
	if d.Status == StatusDelivered || d.StatusCode != 0 || !strings.Contains(d.Error, "not allowed") {
		t.Fatalf("loopback destination must be refused: %+v", d)
	}
}

func TestDefaultClientNeverFollowsRedirects(t *testing.T) {
	svc := New(Config{Store: newMemStore(), Policy: publicPolicy()})
	req, _ := http.NewRequest("POST", "https://internal.example.com/", nil)
	if err := svc.client.CheckRedirect(req, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirects must not be followed: %v", err)
	}
	// and a 3xx answer counts as a failed attempt, not as delivered
	r := newRig(t)
	r.status = func(int, *http.Request) (int, http.Header, string) {
		return 302, http.Header{"Location": {"http://169.254.169.254/latest/meta-data"}}, ""
	}
	r.create(CreateInput{})
	ds := r.deliver(r.event(gitevents.PRMerged, ""))
	r.svc.ProcessDue(context.Background())
	if d := r.st.delivery(ds[0].ID); d.Status == StatusDelivered {
		t.Fatalf("a redirect is not a delivery: %+v", d)
	}
	if len(r.reqs()) != 1 {
		t.Fatalf("the Location target must never be requested")
	}
}

func TestSecretRotationKeepsThePreviousSecretFor24Hours(t *testing.T) {
	r := newRig(t)
	w := r.create(CreateInput{})
	oldSecret := w.Secret
	rot, err := r.svc.RotateSecret(context.Background(), r.sc, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rot.Secret == oldSecret || !strings.HasPrefix(rot.Secret, "whsec_") {
		t.Fatalf("rotation must issue a new secret")
	}
	if rot.PrevSecret != oldSecret || rot.PrevSecretExpiresAt == nil || !rot.PrevSecretExpiresAt.Equal(r.clock.Now().Add(24*time.Hour)) {
		t.Fatalf("previous secret window: %+v", rot)
	}
	send := func() *recorded {
		r.deliver(r.event(gitevents.PRMerged, ""))
		r.svc.ProcessDue(context.Background())
		reqs := r.reqs()
		return reqs[len(reqs)-1]
	}
	q := send()
	ts := q.Header.Get("X-Capsule-Timestamp")
	if !Verify([]string{rot.Secret}, ts, []string{q.Header.Get("X-Capsule-Signature")}, q.Body, r.clock.Now()) {
		t.Fatal("main signature uses the new secret")
	}
	if !Verify([]string{oldSecret}, ts, []string{q.Header.Get("X-Capsule-Signature-Previous")}, q.Body, r.clock.Now()) {
		t.Fatal("during the window the previous signature uses the old secret")
	}
	// a receiver still holding only the old secret keeps working through the header list
	if !Verify([]string{oldSecret}, ts, []string{q.Header.Get("X-Capsule-Signature"), q.Header.Get("X-Capsule-Signature-Previous")}, q.Body, r.clock.Now()) {
		t.Fatal("old receiver must still verify")
	}
	r.clock.Advance(24*time.Hour + time.Second)
	q = send()
	if q.Header.Get("X-Capsule-Signature-Previous") != "" {
		t.Fatal("after 24 h the previous secret stops signing")
	}
	// rotating twice keeps only the latest previous
	rot2, _ := r.svc.RotateSecret(context.Background(), r.sc, w.ID)
	if rot2.PrevSecret != rot.Secret {
		t.Fatal("second rotation: previous must be the one just replaced")
	}
	// non-http cannot rotate
	sl := r.create(CreateInput{Kind: KindSlack, URL: "https://hooks.slack.com/services/T/B/x"})
	if _, err := r.svc.RotateSecret(context.Background(), r.sc, sl.ID); !errors.Is(err, ErrNotRotatable) {
		t.Fatalf("%v", err)
	}
}

func TestFanOutFiltersAndIsIdempotent(t *testing.T) {
	r := newRig(t)
	push := r.create(CreateInput{Events: []string{gitevents.GitPush}, BranchFilter: "release/**"})
	all := r.create(CreateInput{Events: []string{gitevents.GitPush, gitevents.PRMerged}})
	off := r.create(CreateInput{Events: []string{gitevents.GitPush}, Active: boolPtr(false)})
	other := r.create(CreateInput{Events: []string{gitevents.PRClosed}})
	orgHook, err := r.svc.Create(context.Background(), Scope{OrgID: r.org}, CreateInput{Kind: KindHTTP, URL: "https://org.example.com/h", Events: []string{gitevents.GitPush}}, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	otherOrg, _ := r.svc.Create(context.Background(), Scope{OrgID: uuid.New()}, CreateInput{Kind: KindHTTP, URL: "https://x.example.com/h", Events: []string{gitevents.GitPush}}, uuid.Nil)

	e := r.event(gitevents.GitPush, "main")
	for i := 0; i < 3; i++ { // the bus may redeliver the same event
		if err := r.svc.Handle(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	got := map[uuid.UUID]int{}
	for _, d := range r.st.allDeliveries() {
		got[d.WebhookID]++
	}
	if got[all.ID] != 1 || got[orgHook.ID] != 1 {
		t.Fatalf("subscribers get exactly one delivery per event: %v", got)
	}
	if got[push.ID] != 0 {
		t.Fatal("branch filter release/** must not match main")
	}
	if got[off.ID] != 0 || got[other.ID] != 0 || got[otherOrg.ID] != 0 {
		t.Fatalf("inactive, unsubscribed and foreign-org webhooks get nothing: %v", got)
	}
	if err := r.svc.Handle(context.Background(), r.event(gitevents.GitPush, "release/1.2")); err != nil {
		t.Fatal(err)
	}
	if n := countFor(r.st, push.ID); n != 1 {
		t.Fatalf("release/1.2 matches the filter: %d", n)
	}
	// events not tied to a branch pass the filter
	pf := r.create(CreateInput{Events: []string{gitevents.SecurityAlertCreated}, BranchFilter: "main"})
	if err := r.svc.Handle(context.Background(), r.event(gitevents.SecurityAlertCreated, "")); err != nil {
		t.Fatal(err)
	}
	if n := countFor(r.st, pf.ID); n != 1 {
		t.Fatalf("branchless event: %d", n)
	}
}

func countFor(st *memStore, id uuid.UUID) int {
	n := 0
	for _, d := range st.allDeliveries() {
		if d.WebhookID == id {
			n++
		}
	}
	return n
}

func boolPtr(b bool) *bool { return &b }

func TestBranchMatches(t *testing.T) {
	cases := []struct {
		filter, branch string
		want           bool
	}{
		{"", "anything", true},
		{"main", "", true},
		{"main", "main", true},
		{"main", "main2", false},
		{"release/*", "release/1", true},
		{"release/*", "release/1/hotfix", false},
		{"release/**", "release/1/hotfix", true},
		{"feat-?", "feat-a", true},
		{"feat-?", "feat-ab", false},
		{"a.b", "axb", false},
		{"*", "a/b", false},
		{"**", "a/b", true},
	}
	for _, c := range cases {
		if got := BranchMatches(c.filter, c.branch); got != c.want {
			t.Errorf("BranchMatches(%q,%q)=%v want %v", c.filter, c.branch, got, c.want)
		}
	}
}

func TestSlackAndDiscordGetFormattedMessagesNotTheEnvelope(t *testing.T) {
	r := newRig(t)
	sl := r.create(CreateInput{Kind: KindSlack, URL: "https://hooks.slack.com/services/T0/B0/SECRETSLACK", Events: []string{gitevents.PRMerged}})
	dc := r.create(CreateInput{Kind: KindDiscord, URL: "https://discord.com/api/webhooks/1/SECRETDISCORD", Events: []string{gitevents.PRMerged}})
	e := r.event(gitevents.PRMerged, "feat")
	e.Data["title"] = "Fix <!channel> & <@U123> `x`"
	r.deliver(e)
	r.svc.ProcessDue(context.Background())
	var slackReq, discordReq *recorded
	for _, q := range r.reqs() {
		switch {
		case strings.Contains(q.URL, "hooks.slack.com"):
			slackReq = q
		case strings.Contains(q.URL, "discord.com"):
			discordReq = q
		}
	}
	if slackReq == nil || discordReq == nil {
		t.Fatalf("both destinations must be called: %v", r.reqs())
	}
	for _, q := range []*recorded{slackReq, discordReq} {
		for k := range q.Header {
			if strings.HasPrefix(k, "X-Capsule") {
				t.Fatalf("Slack/Discord get a formatted message, not the signed envelope (header %s)", k)
			}
		}
		if strings.Contains(string(q.Body), `"api_version"`) {
			t.Fatalf("envelope leaked to chat: %s", q.Body)
		}
	}
	var sm map[string]any
	_ = json.Unmarshal(slackReq.Body, &sm)
	text, _ := sm["text"].(string)
	if !strings.Contains(text, "&lt;!channel&gt;") || strings.Contains(text, "<!channel>") || strings.Contains(text, "<@U123>") || !strings.Contains(text, "&amp;") {
		t.Fatalf("Slack mention injection must be neutralised: %q", text)
	}
	if !strings.Contains(text, "Ver en Git Capsule") || !strings.Contains(text, "https://app.example.com/git/acme/shop/pulls/7") {
		t.Fatalf("slack text: %q", text)
	}
	var dm map[string]any
	_ = json.Unmarshal(discordReq.Body, &dm)
	am, _ := dm["allowed_mentions"].(map[string]any)
	if parse, ok := am["parse"].([]any); !ok || len(parse) != 0 {
		t.Fatalf("Discord must not allow any mention: %s", discordReq.Body)
	}
	if embeds, _ := dm["embeds"].([]any); len(embeds) != 1 {
		t.Fatalf("discord embed: %s", discordReq.Body)
	}
	// the stored delivery (visible in the API) never contains the URL
	for _, d := range r.st.allDeliveries() {
		if strings.Contains(d.Error+d.ResponseExcerpt, "SECRETSLACK") || strings.Contains(d.Error+d.ResponseExcerpt, "SECRETDISCORD") {
			t.Fatal("URL leaked into a delivery row")
		}
	}
	_, _ = sl, dc
}

func TestEmailWebhook(t *testing.T) {
	r := newRig(t)
	r.create(CreateInput{Kind: KindEmail, EmailTo: []string{"ops@example.com"}, Events: []string{gitevents.PRMerged}})
	e := r.event(gitevents.PRMerged, "feat")
	e.Data["title"] = "<b>bold</b>"
	r.deliver(e)
	r.svc.ProcessDue(context.Background())
	if len(r.mail.sent) != 1 {
		t.Fatalf("sent: %d", len(r.mail.sent))
	}
	m := r.mail.sent[0]
	if m.To[0] != "ops@example.com" || !strings.HasPrefix(m.Subject, "[Git Capsule] ") || strings.Contains(m.HTML, "<b>bold</b>") || len(r.reqs()) != 0 {
		t.Fatalf("%+v", m)
	}
	if d := r.st.allDeliveries()[0]; d.Status != StatusDelivered {
		t.Fatalf("%+v", d)
	}

	// SES failure: generic error, retried
	r.mail.err = errors.New("ses: AccessDenied arn:aws:iam::123456789012:user/x")
	r.deliver(r.event(gitevents.PRMerged, ""))
	r.svc.ProcessDue(context.Background())
	for _, d := range r.st.allDeliveries() {
		if d.Status == StatusPending && strings.Contains(d.Error, "arn:aws") {
			t.Fatalf("mailer detail leaked: %q", d.Error)
		}
	}

	// no mailer configured: clear, retried error
	r2 := newRig(t)
	r2.svc.mailer = nil
	r2.create(CreateInput{Kind: KindEmail, EmailTo: []string{"ops@example.com"}, Events: []string{gitevents.PRMerged}})
	r2.deliver(r2.event(gitevents.PRMerged, ""))
	r2.svc.ProcessDue(context.Background())
	if d := r2.st.allDeliveries()[0]; d.Status != StatusPending || !strings.Contains(d.Error, "not configured") {
		t.Fatalf("%+v", d)
	}
}

func TestSendTestIsSynchronousAndNotRetried(t *testing.T) {
	r := newRig(t)
	w := r.create(CreateInput{})
	d, err := r.svc.SendTest(context.Background(), r.sc, w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != StatusDelivered || d.Event != gitevents.WebhookTest || d.StatusCode != 200 {
		t.Fatalf("%+v", d)
	}
	var env Envelope
	_ = json.Unmarshal(r.reqs()[0].Body, &env)
	if env.Event != "webhook.test" || env.Project.Slug != "shop" || env.ID != d.ID.String() {
		t.Fatalf("%s", r.reqs()[0].Body)
	}
	r.status = func(int, *http.Request) (int, http.Header, string) { return 500, nil, "" }
	d, _ = r.svc.SendTest(context.Background(), r.sc, w.ID)
	if d.Status != StatusFailed || d.Attempt != 1 {
		t.Fatalf("a failed test is final: %+v", d)
	}
	r.clock.Advance(time.Hour)
	if r.svc.ProcessDue(context.Background()) != 0 {
		t.Fatal("tests are never retried")
	}
	// org-level webhooks can be tested too
	oh, _ := r.svc.Create(context.Background(), Scope{OrgID: r.org}, CreateInput{Kind: KindHTTP, URL: "https://org.example.com/h", Events: []string{"git.push"}}, uuid.Nil)
	r.status = func(int, *http.Request) (int, http.Header, string) { return 200, nil, "" }
	if d, err := r.svc.SendTest(context.Background(), Scope{OrgID: r.org}, oh.ID); err != nil || d.Status != StatusDelivered {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestRedeliverCreatesANewSignedDelivery(t *testing.T) {
	r := newRig(t)
	w := r.create(CreateInput{})
	ds := r.deliver(r.event(gitevents.PRMerged, ""))
	r.svc.ProcessDue(context.Background())
	orig := r.st.delivery(ds[0].ID)

	nd, err := r.svc.Redeliver(context.Background(), r.sc, w.ID, orig.ID)
	if err != nil {
		t.Fatal(err)
	}
	if nd.ID == orig.ID || nd.Status != StatusPending || nd.RedeliveryOf == nil || *nd.RedeliveryOf != orig.ID || nd.Event != orig.Event {
		t.Fatalf("%+v", nd)
	}
	var a, b Envelope
	_ = json.Unmarshal([]byte(orig.Payload), &a)
	_ = json.Unmarshal([]byte(nd.Payload), &b)
	if b.ID != nd.ID.String() || a.ID == b.ID || a.Event != b.Event || fmt.Sprint(a.Data) != fmt.Sprint(b.Data) {
		t.Fatalf("redelivery must carry the same event under a new delivery id:\n%s\n%s", orig.Payload, nd.Payload)
	}
	if n := r.svc.ProcessDue(context.Background()); n != 1 {
		t.Fatalf("processed %d", n)
	}
	last := r.reqs()[len(r.reqs())-1]
	if last.Header.Get("X-Capsule-Delivery") != nd.ID.String() || !Verify([]string{w.Secret}, last.Header.Get("X-Capsule-Timestamp"), []string{last.Header.Get("X-Capsule-Signature")}, last.Body, r.clock.Now()) {
		t.Fatal("the redelivery must be signed over its own body")
	}
	// a delivery of another webhook is not found; a disabled webhook refuses
	w2 := r.create(CreateInput{})
	if _, err := r.svc.Redeliver(context.Background(), r.sc, w2.ID, orig.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-webhook redelivery: %v", err)
	}
	_ = r.st.DisableWebhook(context.Background(), w.ID, "x")
	if _, err := r.svc.Redeliver(context.Background(), r.sc, w.ID, orig.ID); !errors.Is(err, ErrDisabled) {
		t.Fatalf("%v", err)
	}
}

func TestScopeIsolation(t *testing.T) {
	r := newRig(t)
	w := r.create(CreateInput{})
	ctx := context.Background()
	otherProject := uuid.New()
	for name, sc := range map[string]Scope{
		"other project": {OrgID: r.org, ProjectID: &otherProject},
		"other org":     {OrgID: uuid.New(), ProjectID: r.sc.ProjectID},
		"org level":     {OrgID: r.org},
	} {
		if _, err := r.svc.Get(ctx, sc, w.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("%s: Get %v", name, err)
		}
		if err := r.svc.Delete(ctx, sc, w.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("%s: Delete %v", name, err)
		}
		if _, err := r.svc.RotateSecret(ctx, sc, w.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("%s: Rotate %v", name, err)
		}
		if _, err := r.svc.SendTest(ctx, sc, w.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("%s: Test %v", name, err)
		}
		if _, _, err := r.svc.Deliveries(ctx, sc, w.ID, "", 10); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("%s: Deliveries %v", name, err)
		}
		if _, err := r.svc.Update(ctx, sc, w.ID, PatchInput{}); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("%s: Update %v", name, err)
		}
	}
	if err := r.svc.Delete(ctx, r.sc, w.ID); err != nil {
		t.Fatal(err)
	}
}

func TestUpdate(t *testing.T) {
	r := newRig(t)
	w := r.create(CreateInput{})
	ctx := context.Background()
	slack := "slack"
	if _, err := r.svc.Update(ctx, r.sc, w.ID, PatchInput{Kind: &slack}); err == nil {
		t.Fatal("kind cannot change")
	}
	bad := "http://insecure.example.com"
	if _, err := r.svc.Update(ctx, r.sc, w.ID, PatchInput{URL: &bad}); err == nil {
		t.Fatal("update must validate the url like create")
	}
	priv := "https://internal.example.com/x"
	if _, err := r.svc.Update(ctx, r.sc, w.ID, PatchInput{URL: &priv}); err == nil {
		t.Fatal("update must apply the SSRF policy")
	}
	mails := []string{"a@x.io"}
	if _, err := r.svc.Update(ctx, r.sc, w.ID, PatchInput{EmailTo: &mails}); err == nil {
		t.Fatal("recipients only on email webhooks")
	}
	good := "https://other.example.com/in"
	evs := []string{gitevents.GitPush}
	bf := "main"
	up, err := r.svc.Update(ctx, r.sc, w.ID, PatchInput{URL: &good, Events: &evs, BranchFilter: &bf})
	if err != nil || up.URL != good || len(up.Events) != 1 || up.BranchFilter != "main" || up.Secret != w.Secret {
		t.Fatalf("%+v %v", up, err)
	}
	empty := []string{}
	if _, err := r.svc.Update(ctx, r.sc, w.ID, PatchInput{Events: &empty}); err == nil {
		t.Fatal("events cannot become empty")
	}
}

func TestDeliveriesPagination(t *testing.T) {
	r := newRig(t)
	w := r.create(CreateInput{})
	base := r.clock.Now()
	for i := 0; i < 5; i++ {
		_, _ = r.st.InsertDelivery(context.Background(), &Delivery{ID: uuid.New(), WebhookID: w.ID, Event: "pr.merged", Payload: "{}", Status: StatusDelivered,
			CreatedAt: base.Add(time.Duration(i) * time.Second)})
	}
	var ids []uuid.UUID
	cursor := ""
	for page := 0; page < 10; page++ {
		rows, next, err := r.svc.Deliveries(context.Background(), r.sc, w.ID, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range rows {
			ids = append(ids, d.ID)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	uniq := map[uuid.UUID]bool{}
	for _, id := range ids {
		uniq[id] = true
	}
	if len(ids) != 5 || len(uniq) != 5 {
		t.Fatalf("each delivery exactly once, got %d (%d unique)", len(ids), len(uniq))
	}
	if _, _, err := r.svc.Deliveries(context.Background(), r.sc, w.ID, "garbage", 2); err == nil {
		t.Fatal("invalid cursor")
	}
}

func TestSecretsNeverAppearInDeliveriesOrErrors(t *testing.T) {
	r := newRig(t)
	w := r.create(CreateInput{})
	r.status = func(int, *http.Request) (int, http.Header, string) { return 500, nil, "x" }
	r.deliver(r.event(gitevents.PRMerged, ""))
	r.svc.ProcessDue(context.Background())
	for _, d := range r.st.allDeliveries() {
		blob, _ := json.Marshal(d)
		if strings.Contains(string(blob), w.Secret) {
			t.Fatalf("secret stored in a delivery row: %s", blob)
		}
		// the payload is the body; it must not contain the secret either
		if strings.Contains(d.Payload, w.Secret) {
			t.Fatal("secret in payload")
		}
	}
}
