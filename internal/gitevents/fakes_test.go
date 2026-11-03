package gitevents

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

type memStore struct {
	mu         sync.Mutex
	events     map[uuid.UUID]*Event
	deliveries map[string]uuid.UUID // project|delivery -> event id
	dispatched map[uuid.UUID]bool
	failures   map[uuid.UUID]int
	insertErr  error
}

func newMemStore() *memStore {
	return &memStore{events: map[uuid.UUID]*Event{}, deliveries: map[string]uuid.UUID{}, dispatched: map[uuid.UUID]bool{}, failures: map[uuid.UUID]int{}}
}

func (m *memStore) Insert(_ context.Context, e *Event) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.insertErr != nil {
		return false, m.insertErr
	}
	if e.DeliveryID != "" {
		k := e.ProjectID.String() + "|" + e.DeliveryID
		if _, dup := m.deliveries[k]; dup {
			return false, nil
		}
		m.deliveries[k] = e.ID
	}
	c := *e
	m.events[e.ID] = &c
	return true, nil
}
func (m *memStore) MarkDispatched(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	m.dispatched[id] = true
	m.mu.Unlock()
	return nil
}
func (m *memStore) RecordDispatchFailure(_ context.Context, id uuid.UUID) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failures[id]++
	return m.failures[id], nil
}
func (m *memStore) ListUndispatched(_ context.Context, cutoff time.Time, limit int) ([]Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Event
	for id, e := range m.events {
		if !m.dispatched[id] && e.CreatedAt.Before(cutoff) {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (m *memStore) isDispatched(id uuid.UUID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dispatched[id]
}
func (m *memStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

type memProjects struct {
	info map[uuid.UUID]ProjectInfo
}

func (p memProjects) ProjectInfo(_ context.Context, id uuid.UUID) (ProjectInfo, error) {
	if i, ok := p.info[id]; ok {
		return i, nil
	}
	return ProjectInfo{}, ErrNoProject
}

type recSub struct {
	mu     sync.Mutex
	name   string
	got    []Event
	failN  int // fail this many calls first
	panics bool
}

func (s *recSub) Name() string { return s.name }
func (s *recSub) Handle(_ context.Context, e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.panics {
		panic("boom")
	}
	if s.failN > 0 {
		s.failN--
		return errors.New("temporary")
	}
	s.got = append(s.got, e)
	return nil
}
func (s *recSub) events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.got...)
}

type fakeInv struct {
	mu    sync.Mutex
	calls []gitcore.RepoRef
}

func (f *fakeInv) InvalidateRepo(_ context.Context, r gitcore.RepoRef) error {
	f.mu.Lock()
	f.calls = append(f.calls, r)
	f.mu.Unlock()
	return nil
}

// ---- notify store ------------------------------------------------------------------------------

type memNotify struct {
	mu       sync.Mutex
	rows     []Notification
	read     map[uuid.UUID]bool
	settings map[uuid.UUID]Settings
	admins   []uuid.UUID
	logins   map[string]uuid.UUID
	emails   map[uuid.UUID]string
	failIns  bool
}

func newMemNotify() *memNotify {
	return &memNotify{read: map[uuid.UUID]bool{}, settings: map[uuid.UUID]Settings{}, logins: map[string]uuid.UUID{}, emails: map[uuid.UUID]string{}}
}

func (m *memNotify) InsertNotification(_ context.Context, n *Notification) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failIns {
		return false, errors.New("db down")
	}
	for _, r := range m.rows {
		if r.UserID == n.UserID && n.EventID != nil && r.EventID != nil && *r.EventID == *n.EventID {
			return false, nil
		}
	}
	m.rows = append(m.rows, *n)
	return true, nil
}
func (m *memNotify) ListNotifications(_ context.Context, userID uuid.UUID, unreadOnly bool, after *Cursor, limit int) ([]Notification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Notification
	for _, r := range m.rows {
		if r.UserID != userID || (unreadOnly && m.read[r.ID]) {
			continue
		}
		r.Read = m.read[r.ID]
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID.String() > out[j].ID.String()
	})
	if after != nil {
		var f []Notification
		for _, r := range out {
			if r.CreatedAt.Before(after.At) || (r.CreatedAt.Equal(after.At) && r.ID.String() < after.ID.String()) {
				f = append(f, r)
			}
		}
		out = f
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (m *memNotify) MarkRead(_ context.Context, userID uuid.UUID, ids []uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		for _, r := range m.rows {
			if r.ID == id && r.UserID == userID {
				m.read[id] = true
			}
		}
	}
	return nil
}
func (m *memNotify) MarkAllRead(_ context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.UserID == userID {
			m.read[r.ID] = true
		}
	}
	return nil
}
func (m *memNotify) GetSettings(_ context.Context, userID uuid.UUID) (Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.settings[userID]; ok {
		return s, nil
	}
	return DefaultSettings(), nil
}
func (m *memNotify) PutSettings(_ context.Context, userID uuid.UUID, s Settings) error {
	m.mu.Lock()
	m.settings[userID] = s
	m.mu.Unlock()
	return nil
}
func (m *memNotify) SettingsFor(_ context.Context, ids []uuid.UUID) (map[uuid.UUID]Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[uuid.UUID]Settings{}
	for _, id := range ids {
		if s, ok := m.settings[id]; ok {
			out[id] = s
		}
	}
	return out, nil
}
func (m *memNotify) ProjectAdmins(context.Context, uuid.UUID, uuid.UUID) ([]uuid.UUID, error) {
	return m.admins, nil
}
func (m *memNotify) UsersByLogin(_ context.Context, logins []string) (map[string]uuid.UUID, error) {
	out := map[string]uuid.UUID{}
	for _, l := range logins {
		if id, ok := m.logins[l]; ok {
			out[l] = id
		}
	}
	return out, nil
}
func (m *memNotify) UserEmails(_ context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	out := map[uuid.UUID]string{}
	for _, id := range ids {
		out[id] = m.emails[id]
	}
	return out, nil
}

type fakeMailer struct {
	mu    sync.Mutex
	sent  []mailMsg
	fails bool
}
type mailMsg struct {
	To                  []string
	Subject, Text, HTML string
}

func (f *fakeMailer) Send(_ context.Context, to []string, subject, text, html string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails {
		return errors.New("ses down")
	}
	f.sent = append(f.sent, mailMsg{to, subject, text, html})
	return nil
}
