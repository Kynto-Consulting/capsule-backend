package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/internal/webhookout"
)

// ---- in-memory webhookout.Store ------------------------------------------------------------------

type whStore struct {
	mu    sync.Mutex
	hooks map[uuid.UUID]*webhookout.Webhook
	deliv map[uuid.UUID]*webhookout.Delivery
}

func newWhStore() *whStore {
	return &whStore{hooks: map[uuid.UUID]*webhookout.Webhook{}, deliv: map[uuid.UUID]*webhookout.Delivery{}}
}

func sameProj(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (s *whStore) CreateWebhook(_ context.Context, w *webhookout.Webhook) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *w
	c.CreatedAt = time.Now()
	s.hooks[w.ID] = &c
	return nil
}
func (s *whStore) GetWebhook(_ context.Context, id uuid.UUID) (*webhookout.Webhook, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w, ok := s.hooks[id]; ok {
		c := *w
		return &c, nil
	}
	return nil, domain.ErrNotFound
}
func (s *whStore) ListWebhooks(_ context.Context, sc webhookout.Scope) ([]webhookout.Webhook, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []webhookout.Webhook
	for _, w := range s.hooks {
		if w.OrgID == sc.OrgID && sameProj(w.ProjectID, sc.ProjectID) {
			out = append(out, *w)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (s *whStore) UpdateWebhook(_ context.Context, w *webhookout.Webhook) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.hooks[w.ID]
	o.URL, o.EmailTo, o.Events, o.BranchFilter, o.Active, o.DisabledReason = w.URL, w.EmailTo, w.Events, w.BranchFilter, w.Active, w.DisabledReason
	return nil
}
func (s *whStore) DeleteWebhook(_ context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.hooks, id)
	return nil
}
func (s *whStore) RotateSecret(_ context.Context, id uuid.UUID, sec string, exp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.hooks[id]
	w.PrevSecret, w.PrevSecretExpiresAt, w.Secret = w.Secret, &exp, sec
	return nil
}
func (s *whStore) DisableWebhook(_ context.Context, id uuid.UUID, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hooks[id].Active, s.hooks[id].DisabledReason = false, reason
	return nil
}
func (s *whStore) MatchingWebhooks(context.Context, uuid.UUID, uuid.UUID, string) ([]webhookout.Webhook, error) {
	return nil, nil
}
func (s *whStore) InsertDelivery(_ context.Context, d *webhookout.Delivery) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *d
	s.deliv[d.ID] = &c
	return true, nil
}
func (s *whStore) GetDelivery(_ context.Context, id uuid.UUID) (*webhookout.Delivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.deliv[id]; ok {
		c := *d
		return &c, nil
	}
	return nil, domain.ErrNotFound
}
func (s *whStore) ListDeliveries(_ context.Context, id uuid.UUID, after *gitevents.Cursor, limit int) ([]webhookout.Delivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []webhookout.Delivery
	for _, d := range s.deliv {
		if d.WebhookID == id {
			out = append(out, *d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (s *whStore) ClaimDue(context.Context, time.Time, time.Duration, int) ([]webhookout.Delivery, error) {
	return nil, nil
}
func (s *whStore) RecordAttempt(_ context.Context, d *webhookout.Delivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *d
	s.deliv[d.ID] = &c
	return nil
}

type auditRec struct {
	mu      sync.Mutex
	entries []authz.AuditEntry
}

func (a *auditRec) Audit(_ context.Context, e authz.AuditEntry) error {
	a.mu.Lock()
	a.entries = append(a.entries, e)
	a.mu.Unlock()
	return nil
}

type whRig struct {
	t       *testing.T
	router  chi.Router
	store   *whStore
	audit   *auditRec
	org     uuid.UUID
	project uuid.UUID
	sent    []*http.Request
	status  int
}

type whProjects struct{}

func (whProjects) ProjectInfo(context.Context, uuid.UUID) (gitevents.ProjectInfo, error) {
	return gitevents.ProjectInfo{OrgSlug: "acme", ProjectSlug: "shop"}, nil
}

func newWhRig(t *testing.T, role string) *whRig {
	t.Helper()
	g := &whRig{t: t, store: newWhStore(), audit: &auditRec{}, org: uuid.New(), project: uuid.New(), status: 200}
	svc := webhookout.New(webhookout.Config{
		Store: g.store, Projects: whProjects{},
		Policy: publicPolicy(),
		Client: &http.Client{Transport: whRoundTrip(func(r *http.Request) (*http.Response, error) {
			g.sent = append(g.sent, r)
			return &http.Response{StatusCode: g.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
		})},
	})
	h := NewWebhooksHandler(fakeOrgRepo{role: role}, svc, g.audit, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.SetAuthz(authz.New(authz.OrgOnlyStore{Orgs: fakeOrgRepo{role: role}}))
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: uuid.New()})))
		})
	})
	h.Mount(r)
	g.router = r
	return g
}

type whRoundTrip func(*http.Request) (*http.Response, error)

func (f whRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (g *whRig) call(method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	g.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	rec := httptest.NewRecorder()
	g.router.ServeHTTP(rec, httptest.NewRequest(method, path, rd))
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec, m
}

func (g *whRig) proj() string {
	return "/orgs/" + g.org.String() + "/projects/" + g.project.String() + "/webhooks"
}
func (g *whRig) orgPath() string { return "/orgs/" + g.org.String() + "/webhooks" }

func TestWebhookAPILifecycleAndSecretVisibility(t *testing.T) {
	g := newWhRig(t, "owner")
	rec, created := g.call("POST", g.proj(), map[string]any{"kind": "http", "url": "https://hooks.example.com/in", "events": []string{"pr.merged", "git.push"}, "branch_filter": "main"})
	if rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	secret, _ := created["secret"].(string)
	id, _ := created["id"].(string)
	if !strings.HasPrefix(secret, "whsec_") || id == "" || created["kind"] != "http" || created["active"] != true || created["has_secret"] != true {
		t.Fatalf("create response: %v", created)
	}
	// the secret is shown at creation only
	for _, c := range []struct{ method, path string }{{"GET", g.proj()}, {"GET", g.proj() + "/" + id + "/deliveries"}} {
		rec, _ := g.call(c.method, c.path, nil)
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("%s %s leaks the secret: %s", c.method, c.path, rec.Body)
		}
	}
	rec, listed := g.call("GET", g.proj(), nil)
	items, _ := listed["items"].([]any)
	if rec.Code != 200 || len(items) != 1 || items[0].(map[string]any)["url"] != "https://hooks.example.com/in" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	rec, upd := g.call("PATCH", g.proj()+"/"+id, map[string]any{"active": false, "events": []string{"pr.closed"}})
	if rec.Code != 200 || upd["active"] != false || strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	g.call("PATCH", g.proj()+"/"+id, map[string]any{"active": true})

	rec, rot := g.call("POST", g.proj()+"/"+id+"/rotate-secret", nil)
	newSecret, _ := rot["secret"].(string)
	if rec.Code != 200 || !strings.HasPrefix(newSecret, "whsec_") || newSecret == secret || rot["previous_secret_expires_at"] == nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("the previous secret is never returned")
	}

	rec, del := g.call("POST", g.proj()+"/"+id+"/test", nil)
	if rec.Code != 200 || del["status"] != "delivered" || del["event"] != "webhook.test" || del["status_code"] != float64(200) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(g.sent) != 1 || g.sent[0].Header.Get("X-Capsule-Signature") == "" {
		t.Fatal("test send must be signed")
	}
	if strings.Contains(rec.Body.String(), "sha256=") {
		t.Fatalf("delivery view must not expose signatures: %s", rec.Body)
	}
	deliveryID, _ := del["id"].(string)

	rec, dl := g.call("GET", g.proj()+"/"+id+"/deliveries", nil)
	if rec.Code != 200 || len(dl["items"].([]any)) != 1 || dl["next_cursor"] != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	rec, re := g.call("POST", g.proj()+"/"+id+"/deliveries/"+deliveryID+"/redeliver", nil)
	if rec.Code != 202 || re["status"] != "pending" || re["id"] == deliveryID || re["redelivery_of"] != deliveryID {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	if rec, _ := g.call("DELETE", g.proj()+"/"+id, nil); rec.Code != 204 {
		t.Fatalf("%d", rec.Code)
	}
	if rec, _ := g.call("DELETE", g.proj()+"/"+id, nil); rec.Code != 404 {
		t.Fatalf("second delete: %d", rec.Code)
	}

	actions := map[string]bool{}
	g.audit.mu.Lock()
	for _, e := range g.audit.entries {
		actions[e.Action] = true
		blob, _ := json.Marshal(e)
		if strings.Contains(string(blob), "hooks.example.com") || strings.Contains(string(blob), secret) || strings.Contains(string(blob), newSecret) {
			t.Fatalf("audit entry leaks the URL or a secret: %s", blob)
		}
	}
	g.audit.mu.Unlock()
	for _, a := range []string{"webhook.create", "webhook.update", "webhook.rotate", "webhook.test", "webhook.redeliver", "webhook.delete"} {
		if !actions[a] {
			t.Errorf("missing audit action %s (have %v)", a, actions)
		}
	}
}

func TestWebhookAPIValidationAnswers422(t *testing.T) {
	g := newWhRig(t, "owner")
	for name, body := range map[string]map[string]any{
		"http url":     {"kind": "http", "url": "http://x.example.com", "events": []string{"pr.merged"}},
		"private host": {"kind": "http", "url": "https://127.0.0.1/x", "events": []string{"pr.merged"}},
		"events":       {"kind": "http", "url": "https://x.example.com", "events": []string{"bogus"}},
		"slack host":   {"kind": "slack", "url": "https://x.example.com/services/a/b/c", "events": []string{"pr.merged"}},
		"email":        {"kind": "email", "email_to": []string{"bad"}, "events": []string{"pr.merged"}},
	} {
		rec, m := g.call("POST", g.proj(), body)
		errObj, _ := m["error"].(map[string]any)
		if rec.Code != 422 || errObj["code"] != "VALIDATION_ERROR" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	rec := httptest.NewRecorder()
	g.router.ServeHTTP(rec, httptest.NewRequest("POST", g.proj(), strings.NewReader("{not json")))
	if rec.Code != 400 {
		t.Fatalf("malformed body: %d", rec.Code)
	}
	if rec, _ := g.call("POST", g.proj()+"/not-a-uuid/test", nil); rec.Code != 404 {
		t.Fatalf("bad id: %d", rec.Code)
	}
	if rec, _ := g.call("POST", g.proj()+"/"+uuid.NewString()+"/rotate-secret", nil); rec.Code != 404 {
		t.Fatalf("unknown webhook: %d", rec.Code)
	}
}

func TestWebhookAPIPermissions(t *testing.T) {
	// project routes need webhooks.manage (project admin); org routes need an org owner/admin
	for _, c := range []struct {
		role        string
		project     int
		org         int
		description string
	}{
		{"owner", 200, 200, "org owner"},
		{"admin", 200, 200, "org admin"},
		{"member", 403, 403, "plain member is only a deployer"},
		{"readonly", 403, 403, "readonly"},
		{"", 403, 403, "not a member"},
	} {
		g := newWhRig(t, c.role)
		if rec, _ := g.call("GET", g.proj(), nil); rec.Code != c.project {
			t.Errorf("%s: project list %d", c.description, rec.Code)
		}
		if rec, _ := g.call("GET", g.orgPath(), nil); rec.Code != c.org {
			t.Errorf("%s: org list %d", c.description, rec.Code)
		}
		if c.project == 403 {
			if rec, _ := g.call("POST", g.proj(), map[string]any{"kind": "http", "url": "https://x.example.com", "events": []string{"pr.merged"}}); rec.Code != 403 {
				t.Errorf("%s: create %d", c.description, rec.Code)
			}
			if len(g.store.hooks) != 0 {
				t.Errorf("%s: nothing may be created", c.description)
			}
		}
	}
}

func TestOrgLevelWebhooksAndIsolation(t *testing.T) {
	g := newWhRig(t, "owner")
	rec, created := g.call("POST", g.orgPath(), map[string]any{"kind": "http", "url": "https://org.example.com/in", "events": []string{"git.push"}})
	if rec.Code != 201 || created["project_id"] != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	id := created["id"].(string)
	// org-level webhooks do not appear in the project list and cannot be reached through it
	_, pl := g.call("GET", g.proj(), nil)
	if len(pl["items"].([]any)) != 0 {
		t.Fatal("project list must not include org-level webhooks")
	}
	if rec, _ := g.call("DELETE", g.proj()+"/"+id, nil); rec.Code != 404 {
		t.Fatalf("org-level webhook through the project route: %d", rec.Code)
	}
	// and a project webhook is not reachable through the org route
	_, pc := g.call("POST", g.proj(), map[string]any{"kind": "http", "url": "https://p.example.com/in", "events": []string{"git.push"}})
	if rec, _ := g.call("PATCH", g.orgPath()+"/"+pc["id"].(string), map[string]any{"active": false}); rec.Code != 404 {
		t.Fatalf("project webhook through the org route: %d", rec.Code)
	}
	if rec, _ := g.call("POST", g.orgPath()+"/"+id+"/test", nil); rec.Code != 200 {
		t.Fatalf("org test send: %d", rec.Code)
	}
	if rec, _ := g.call("DELETE", g.orgPath()+"/"+id, nil); rec.Code != 204 {
		t.Fatalf("org delete: %d", rec.Code)
	}
}

func TestSlackURLIsMaskedInResponses(t *testing.T) {
	g := newWhRig(t, "owner")
	rec, created := g.call("POST", g.proj(), map[string]any{"kind": "slack", "url": "https://hooks.slack.com/services/T000/B000/XXXXSECRET", "events": []string{"pr.merged"}})
	if rec.Code != 201 || strings.Contains(rec.Body.String(), "XXXXSECRET") || created["url"] != "https://hooks.slack.com/services/T000/..." || created["secret"] != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec, _ = g.call("GET", g.proj(), nil)
	if strings.Contains(rec.Body.String(), "XXXXSECRET") {
		t.Fatalf("list leaks the Slack URL: %s", rec.Body)
	}
	if rec, _ := g.call("POST", g.proj()+"/"+created["id"].(string)+"/rotate-secret", nil); rec.Code != 422 {
		t.Fatalf("slack webhooks have no secret to rotate: %d", rec.Code)
	}
}

func TestRedeliverToDisabledWebhookIs409(t *testing.T) {
	g := newWhRig(t, "owner")
	_, c := g.call("POST", g.proj(), map[string]any{"kind": "http", "url": "https://h.example.com/in", "events": []string{"pr.merged"}})
	id := c["id"].(string)
	_, d := g.call("POST", g.proj()+"/"+id+"/test", nil)
	g.call("PATCH", g.proj()+"/"+id, map[string]any{"active": false})
	rec, _ := g.call("POST", g.proj()+"/"+id+"/deliveries/"+d["id"].(string)+"/redeliver", nil)
	if rec.Code != 409 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestMaskURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://hooks.slack.com/services/T1/B2/SECRET": "https://hooks.slack.com/services/T1/...",
		"https://discord.com/api/webhooks/123/TOKEN":    "https://discord.com/api/webhooks/...",
		"https://x.example.com/":                        "https://x.example.com/...",
		"::::":                                          "",
	} {
		if got := maskURL(in); got != want {
			t.Errorf("maskURL(%q)=%q want %q", in, got, want)
		}
	}
}
