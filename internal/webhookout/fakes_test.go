package webhookout

import (
	"context"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

type memStore struct {
	mu         sync.Mutex
	hooks      map[uuid.UUID]*Webhook
	deliveries map[uuid.UUID]*Delivery
	events     map[string]bool // webhook|event unique
	disabled   map[uuid.UUID]string
}

func newMemStore() *memStore {
	return &memStore{hooks: map[uuid.UUID]*Webhook{}, deliveries: map[uuid.UUID]*Delivery{}, events: map[string]bool{}, disabled: map[uuid.UUID]string{}}
}

func cp(w *Webhook) *Webhook { c := *w; return &c }

func (m *memStore) CreateWebhook(_ context.Context, w *Webhook) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.CreatedAt, w.UpdatedAt = time.Now(), time.Now()
	m.hooks[w.ID] = cp(w)
	return nil
}
func (m *memStore) GetWebhook(_ context.Context, id uuid.UUID) (*Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if w, ok := m.hooks[id]; ok {
		return cp(w), nil
	}
	return nil, domain.ErrNotFound
}
func (m *memStore) ListWebhooks(_ context.Context, sc Scope) ([]Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Webhook
	for _, w := range m.hooks {
		if w.OrgID == sc.OrgID && sameProject(w.ProjectID, sc.ProjectID) {
			out = append(out, *w)
		}
	}
	return out, nil
}
func (m *memStore) UpdateWebhook(_ context.Context, w *Webhook) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.hooks[w.ID]
	if !ok {
		return domain.ErrNotFound
	}
	old.URL, old.EmailTo, old.Events, old.BranchFilter, old.Active, old.DisabledReason = w.URL, w.EmailTo, w.Events, w.BranchFilter, w.Active, w.DisabledReason
	return nil
}
func (m *memStore) DeleteWebhook(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hooks[id]; !ok {
		return domain.ErrNotFound
	}
	delete(m.hooks, id)
	return nil
}
func (m *memStore) RotateSecret(_ context.Context, id uuid.UUID, newSecret string, prevExpires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.hooks[id]
	if !ok {
		return domain.ErrNotFound
	}
	w.PrevSecret, w.PrevSecretExpiresAt, w.Secret = w.Secret, &prevExpires, newSecret
	return nil
}
func (m *memStore) DisableWebhook(_ context.Context, id uuid.UUID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if w, ok := m.hooks[id]; ok {
		w.Active, w.DisabledReason = false, reason
	}
	m.disabled[id] = reason
	return nil
}
func (m *memStore) MatchingWebhooks(_ context.Context, orgID, projectID uuid.UUID, event string) ([]Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Webhook
	for _, w := range m.hooks {
		if !w.Active || w.OrgID != orgID || (w.ProjectID != nil && *w.ProjectID != projectID) {
			continue
		}
		for _, e := range w.Events {
			if e == event {
				out = append(out, *w)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out, nil
}
func (m *memStore) InsertDelivery(_ context.Context, d *Delivery) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d.EventID != nil && d.RedeliveryOf == nil {
		k := d.WebhookID.String() + "|" + d.EventID.String()
		if m.events[k] {
			return false, nil
		}
		m.events[k] = true
	}
	c := *d
	m.deliveries[d.ID] = &c
	return true, nil
}
func (m *memStore) GetDelivery(_ context.Context, id uuid.UUID) (*Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d, ok := m.deliveries[id]; ok {
		c := *d
		return &c, nil
	}
	return nil, domain.ErrNotFound
}
func (m *memStore) ListDeliveries(_ context.Context, webhookID uuid.UUID, after *gitevents.Cursor, limit int) ([]Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Delivery
	for _, d := range m.deliveries {
		if d.WebhookID == webhookID {
			out = append(out, *d)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID.String() > out[j].ID.String()
	})
	if after != nil {
		var f []Delivery
		for _, d := range out {
			if d.CreatedAt.Before(after.At) || (d.CreatedAt.Equal(after.At) && d.ID.String() < after.ID.String()) {
				f = append(f, d)
			}
		}
		out = f
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (m *memStore) ClaimDue(_ context.Context, now time.Time, lease time.Duration, limit int) ([]Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Delivery
	for _, d := range m.deliveries {
		if d.Status == StatusPending && !d.NextAttemptAt.After(now) {
			out = append(out, *d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NextAttemptAt.Before(out[j].NextAttemptAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	for _, d := range out {
		m.deliveries[d.ID].NextAttemptAt = now.Add(lease)
	}
	return out, nil
}
func (m *memStore) RecordAttempt(_ context.Context, d *Delivery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *d
	m.deliveries[d.ID] = &c
	if d.RequestHeaders != nil {
		if w, ok := m.hooks[d.WebhookID]; ok {
			w.LastDeliveryStatus = d.StatusCode
			now := time.Now()
			w.LastDeliveryAt = &now
		}
	}
	return nil
}
func (m *memStore) delivery(id uuid.UUID) Delivery {
	m.mu.Lock()
	defer m.mu.Unlock()
	return *m.deliveries[id]
}
func (m *memStore) allDeliveries() []Delivery {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Delivery
	for _, d := range m.deliveries {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

type fakeProjects struct{ info gitevents.ProjectInfo }

func (f fakeProjects) ProjectInfo(context.Context, uuid.UUID) (gitevents.ProjectInfo, error) {
	return f.info, nil
}

// publicLookup resolves every host to a public address (no network in tests).
func publicPolicy() gitsource.Policy {
	return gitsource.Policy{Lookup: func(_ context.Context, host string) ([]net.IP, error) {
		if host == "internal.example.com" {
			return []net.IP{net.ParseIP("10.0.0.5")}, nil
		}
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}}
}

// rtFunc turns a function into an http.RoundTripper (no sockets).
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type sentMail struct {
	To                  []string
	Subject, Text, HTML string
}
type fakeMailer struct {
	mu   sync.Mutex
	sent []sentMail
	err  error
}

func (f *fakeMailer) Send(_ context.Context, to []string, s, t, h string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, sentMail{to, s, t, h})
	return nil
}
