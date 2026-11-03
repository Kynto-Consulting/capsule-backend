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
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type inboxStore struct {
	mu       sync.Mutex
	rows     []gitevents.Notification
	read     map[uuid.UUID]bool
	settings map[uuid.UUID]gitevents.Settings
}

func (s *inboxStore) InsertNotification(context.Context, *gitevents.Notification) (bool, error) {
	return true, nil
}
func (s *inboxStore) ListNotifications(_ context.Context, uid uuid.UUID, unread bool, after *gitevents.Cursor, limit int) ([]gitevents.Notification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []gitevents.Notification
	for _, r := range s.rows {
		if r.UserID != uid || (unread && s.read[r.ID]) {
			continue
		}
		r.Read = s.read[r.ID]
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if after != nil {
		var f []gitevents.Notification
		for _, r := range out {
			if r.CreatedAt.Before(after.At) {
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
func (s *inboxStore) MarkRead(_ context.Context, uid uuid.UUID, ids []uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		for _, r := range s.rows {
			if r.ID == id && r.UserID == uid {
				s.read[id] = true
			}
		}
	}
	return nil
}
func (s *inboxStore) MarkAllRead(_ context.Context, uid uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.UserID == uid {
			s.read[r.ID] = true
		}
	}
	return nil
}
func (s *inboxStore) GetSettings(_ context.Context, uid uuid.UUID) (gitevents.Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.settings[uid]; ok {
		return st, nil
	}
	return gitevents.DefaultSettings(), nil
}
func (s *inboxStore) PutSettings(_ context.Context, uid uuid.UUID, st gitevents.Settings) error {
	s.mu.Lock()
	s.settings[uid] = st
	s.mu.Unlock()
	return nil
}
func (s *inboxStore) SettingsFor(context.Context, []uuid.UUID) (map[uuid.UUID]gitevents.Settings, error) {
	return nil, nil
}
func (s *inboxStore) ProjectAdmins(context.Context, uuid.UUID, uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}
func (s *inboxStore) UsersByLogin(context.Context, []string) (map[string]uuid.UUID, error) {
	return nil, nil
}
func (s *inboxStore) UserEmails(context.Context, []uuid.UUID) (map[uuid.UUID]string, error) {
	return nil, nil
}

func newInboxRig(t *testing.T, user uuid.UUID, st *inboxStore) chi.Router {
	t.Helper()
	h := NewNotificationsHandler(gitevents.NewNotifier(st, nil, "", nil), slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if user != uuid.Nil {
				req = req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: user}))
			}
			next.ServeHTTP(w, req)
		})
	})
	h.Mount(r)
	return r
}

func notifJSON(r http.Handler, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, path, rd))
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec, m
}

func TestNotificationsAPI(t *testing.T) {
	me, other := uuid.New(), uuid.New()
	st := &inboxStore{read: map[uuid.UUID]bool{}, settings: map[uuid.UUID]gitevents.Settings{}}
	base := time.Now().UTC().Truncate(time.Microsecond)
	var mine []uuid.UUID
	for i := 0; i < 3; i++ {
		id := uuid.New()
		mine = append(mine, id)
		st.rows = append(st.rows, gitevents.Notification{ID: id, UserID: me, Event: "pr.merged", Title: "t", URL: "https://app/x", Project: "acme/shop", CreatedAt: base.Add(time.Duration(i) * time.Second)})
	}
	foreign := uuid.New()
	st.rows = append(st.rows, gitevents.Notification{ID: foreign, UserID: other, Event: "pr.merged", Title: "secret of someone else", CreatedAt: base})
	r := newInboxRig(t, me, st)

	rec, page := notifJSON(r, "GET", "/user/notifications?limit=2", nil)
	items, _ := page["items"].([]any)
	if rec.Code != 200 || len(items) != 2 || page["next_cursor"] == nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if first := items[0].(map[string]any); first["event"] != "pr.merged" || first["project"] != "acme/shop" || first["read"] != false || first["url"] != "https://app/x" {
		t.Fatalf("item shape: %v", first)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("someone else")) || bytes.Contains(rec.Body.Bytes(), []byte(other.String())) {
		t.Fatal("a user must only see their own notifications")
	}
	rec, page2 := notifJSON(r, "GET", "/user/notifications?limit=2&cursor="+page["next_cursor"].(string), nil)
	if rec.Code != 200 || len(page2["items"].([]any)) != 1 || page2["next_cursor"] != nil {
		t.Fatalf("second page: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := notifJSON(r, "GET", "/user/notifications?cursor=%25%25", nil); rec.Code != 400 {
		t.Fatalf("bad cursor: %d", rec.Code)
	}

	// mark some, then unread filter
	if rec, _ := notifJSON(r, "PATCH", "/user/notifications", map[string]any{"ids": []string{mine[0].String(), foreign.String()}}); rec.Code != 204 {
		t.Fatalf("%d", rec.Code)
	}
	if st.read[foreign] {
		t.Fatal("marking someone else's notification must be a no-op")
	}
	_, unread := notifJSON(r, "GET", "/user/notifications?unread=true", nil)
	if len(unread["items"].([]any)) != 2 {
		t.Fatalf("unread: %v", unread)
	}
	if rec, _ := notifJSON(r, "PATCH", "/user/notifications", map[string]any{"all": true}); rec.Code != 204 {
		t.Fatalf("%d", rec.Code)
	}
	_, unread = notifJSON(r, "GET", "/user/notifications?unread=true", nil)
	if len(unread["items"].([]any)) != 0 {
		t.Fatalf("all read: %v", unread)
	}
	if rec, _ := notifJSON(r, "PATCH", "/user/notifications", map[string]any{}); rec.Code != 422 {
		t.Fatalf("empty mark: %d", rec.Code)
	}
}

func TestNotificationSettingsAPI(t *testing.T) {
	me := uuid.New()
	st := &inboxStore{read: map[uuid.UUID]bool{}, settings: map[uuid.UUID]gitevents.Settings{}}
	r := newInboxRig(t, me, st)

	rec, def := notifJSON(r, "GET", "/user/notification-settings", nil)
	ch, _ := def["channels"].(map[string]any)
	if rec.Code != 200 || ch["in_app"] != true || ch["email"] != false || ch["slack_dm"] != false || def["digest"] != "off" {
		t.Fatalf("defaults: %d %s", rec.Code, rec.Body)
	}
	rec, saved := notifJSON(r, "PUT", "/user/notification-settings", map[string]any{
		"channels": map[string]any{"in_app": true, "email": true, "slack_dm": false},
		"events":   map[string]any{"pr.merged": []string{"email"}},
		"digest":   "daily",
	})
	if rec.Code != 200 || saved["digest"] != "daily" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	_, again := notifJSON(r, "GET", "/user/notification-settings", nil)
	ev, _ := again["events"].(map[string]any)
	if again["digest"] != "daily" || ev["pr.merged"] == nil {
		t.Fatalf("not persisted: %v", again)
	}
	for name, body := range map[string]map[string]any{
		"digest":  {"digest": "hourly"},
		"event":   {"events": map[string]any{"nope": []string{"in_app"}}},
		"channel": {"events": map[string]any{"pr.merged": []string{"sms"}}},
	} {
		if rec, _ := notifJSON(r, "PUT", "/user/notification-settings", body); rec.Code != 422 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
}

func TestNotificationsRequireAuthentication(t *testing.T) {
	st := &inboxStore{read: map[uuid.UUID]bool{}, settings: map[uuid.UUID]gitevents.Settings{}}
	r := newInboxRig(t, uuid.Nil, st)
	for _, c := range [][2]string{{"GET", "/user/notifications"}, {"PATCH", "/user/notifications"}, {"GET", "/user/notification-settings"}, {"PUT", "/user/notification-settings"}} {
		if rec, _ := notifJSON(r, c[0], c[1], map[string]any{"all": true}); rec.Code != 401 {
			t.Errorf("%s %s: %d", c[0], c[1], rec.Code)
		}
	}
}
