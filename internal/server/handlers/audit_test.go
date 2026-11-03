package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitaudit"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type c2Reader struct{ rows []gitaudit.Entry }

func (c *c2Reader) List(_ context.Context, _ uuid.UUID, _ gitaudit.Filter, _ *gitaudit.Cursor, limit int) ([]gitaudit.Entry, error) {
	if limit > len(c.rows) {
		limit = len(c.rows)
	}
	return c.rows[:limit], nil
}
func (c *c2Reader) ProjectID(context.Context, uuid.UUID, string) (uuid.UUID, bool, error) {
	return uuid.Nil, false, nil
}

type c2Writer struct{ n int }

func (w *c2Writer) Append(context.Context, gitaudit.Entry) error { w.n++; return nil }

func c2Router(t *testing.T, role string, rows []gitaudit.Entry) (http.Handler, *c2Writer) {
	t.Helper()
	w := &c2Writer{}
	WireC2(gitaudit.NewService(&c2Reader{rows: rows}), gitaudit.NewRecorder(w), nil)
	t.Cleanup(func() { WireC2(nil, nil, nil) })
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(rw, req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: uuid.New()})))
		})
	})
	MountC2(r, C2Deps{Orgs: fakeOrgRepo{role: role}})
	return r, w
}

func TestAuditLogRequiresOrgAdmin(t *testing.T) {
	org := uuid.New()
	for role, want := range map[string]int{"owner": 200, "admin": 200, "member": 403, "readonly": 403, "": 403} {
		h, _ := c2Router(t, role, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/orgs/"+org.String()+"/audit-log", nil))
		if rec.Code != want {
			t.Errorf("role %q: %d, want %d", role, rec.Code, want)
		}
	}
}

func TestAuditLogCSVIsNeutralizedAndAudited(t *testing.T) {
	org := uuid.New()
	rows := []gitaudit.Entry{{ID: uuid.New(), OrgID: org, Action: "git.push", ResourceType: "project", ActorName: "=HYPERLINK(\"http://x\")", CreatedAt: time.Now()}}
	h, w := c2Router(t, "admin", rows)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/orgs/"+org.String()+"/audit-log?format=csv", nil))
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("%d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	if !strings.Contains(body, "'=HYPERLINK") || strings.Contains(body, ",=HYPERLINK") {
		t.Fatalf("formula not neutralized: %s", body)
	}
	if w.n != 1 {
		t.Fatalf("the export must be audited exactly once, got %d", w.n)
	}
}

func TestAuditLogBadInputs(t *testing.T) {
	org := uuid.New()
	h, _ := c2Router(t, "owner", nil)
	for _, q := range []string{"cursor=zzz", "since=yesterday", "action=DROP%20TABLE", "since=2026-02-01&until=2026-01-01"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/orgs/"+org.String()+"/audit-log?"+q, nil))
		if rec.Code != 400 {
			t.Errorf("%s: %d", q, rec.Code)
		}
	}
}

// Immutability over HTTP: nothing but GET is registered.
func TestC2RoutesAreReadOnly(t *testing.T) {
	h, _ := c2Router(t, "owner", nil)
	n := 0
	err := chi.Walk(h.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		n++
		if method != http.MethodGet {
			t.Errorf("%s %s is not read-only", method, route)
		}
		return nil
	})
	if err != nil || n == 0 {
		t.Fatalf("walk: %v routes=%d", err, n)
	}
	for _, m := range []string{"DELETE", "PUT", "PATCH", "POST"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/orgs/"+uuid.NewString()+"/audit-log", nil))
		if rec.Code != 405 && rec.Code != 404 {
			t.Errorf("%s answered %d", m, rec.Code)
		}
	}
}
