package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/connaudit"
	"github.com/kynto/capsule/backend/internal/domain"
)

type memConnStore struct {
	mu   sync.Mutex
	mode connaudit.Mode
	sups map[string]connaudit.Suppression
	fs   map[uuid.UUID][]connaudit.Finding
}

func newMemConn() *memConnStore {
	return &memConnStore{mode: connaudit.ModeWarn, sups: map[string]connaudit.Suppression{}, fs: map[uuid.UUID][]connaudit.Finding{}}
}
func (m *memConnStore) Mode(context.Context, uuid.UUID) (connaudit.Mode, error) { return m.mode, nil }
func (m *memConnStore) SetMode(_ context.Context, _ uuid.UUID, x connaudit.Mode) error {
	m.mode = x
	return nil
}
func (m *memConnStore) Suppressions(context.Context, uuid.UUID) ([]connaudit.Suppression, error) {
	var out []connaudit.Suppression
	for _, s := range m.sups {
		out = append(out, s)
	}
	return out, nil
}
func (m *memConnStore) PutSuppression(_ context.Context, _ uuid.UUID, s connaudit.Suppression) error {
	m.sups[s.FindingID] = s
	return nil
}
func (m *memConnStore) DeleteSuppression(_ context.Context, _ uuid.UUID, id string) error {
	delete(m.sups, id)
	return nil
}
func (m *memConnStore) SaveFindings(_ context.Context, id uuid.UUID, f []connaudit.Finding) error {
	m.fs[id] = f
	return nil
}
func (m *memConnStore) FindingsFor(_ context.Context, ids []uuid.UUID) (map[uuid.UUID][]connaudit.Finding, error) {
	out := map[uuid.UUID][]connaudit.Finding{}
	for _, id := range ids {
		out[id] = m.fs[id]
	}
	return out, nil
}

func connRouter(role string, st connaudit.Store) http.Handler {
	h := NewConnAuditHandler(fakeOrgRepo{role: role}, fixedOrgProjects{}, st)
	r := chi.NewRouter()
	r.Use(withTestUser)
	r.Get("/orgs/{orgID}/projects/{projectID}/connection-audit", h.Get)
	r.Put("/orgs/{orgID}/projects/{projectID}/connection-audit/mode", h.SetMode)
	r.Put("/orgs/{orgID}/projects/{projectID}/connection-audit/suppressions", h.PutSuppression)
	r.Delete("/orgs/{orgID}/projects/{projectID}/connection-audit/suppressions", h.DeleteSuppression)
	return r
}

func connDo(h http.Handler, method, suffix, body string) *httptest.ResponseRecorder {
	u := "/orgs/" + connTestOrg.String() + "/projects/" + uuid.NewString() + "/connection-audit" + suffix
	req := httptest.NewRequest(method, u, bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestConnAuditEndpoints(t *testing.T) {
	st := newMemConn()
	h := NewConnAuditHandler(fakeOrgRepo{role: "admin"}, fixedOrgProjects{}, st)
	r := chi.NewRouter()
	r.Use(withTestUser)
	r.Get("/orgs/{orgID}/projects/{projectID}/connection-audit", h.Get)
	r.Put("/orgs/{orgID}/projects/{projectID}/connection-audit/mode", h.SetMode)
	r.Put("/orgs/{orgID}/projects/{projectID}/connection-audit/suppressions", h.PutSuppression)
	r.Delete("/orgs/{orgID}/projects/{projectID}/connection-audit/suppressions", h.DeleteSuppression)

	if rec := connDo(r, "PUT", "/mode", `{"connection_audit_mode":"loud"}`); rec.Code != 422 {
		t.Fatalf("bad mode: %d", rec.Code)
	}
	if rec := connDo(r, "PUT", "/mode", `{"connection_audit_mode":"strict"}`); rec.Code != 200 || st.mode != connaudit.ModeStrict {
		t.Fatalf("set mode: %d %s", rec.Code, rec.Body)
	}
	if rec := connDo(r, "PUT", "/suppressions", `{"finding_id":"aaaaaaaaaaaa","reason":"x"}`); rec.Code != 422 {
		t.Fatalf("short reason: %d", rec.Code)
	}
	exp := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	if rec := connDo(r, "PUT", "/suppressions", `{"finding_id":"aaaaaaaaaaaa","reason":"sidecar propio del contenedor","expires_at":"`+exp+`"}`); rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	rec := connDo(r, "GET", "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "aaaaaaaaaaaa") || !strings.Contains(rec.Body.String(), `"strict"`) {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	if rec := connDo(r, "DELETE", "/suppressions?finding_id=aaaaaaaaaaaa", ""); rec.Code != 204 || len(st.sups) != 0 {
		t.Fatalf("delete: %d", rec.Code)
	}
}

func TestConnAuditPermissionsAndUnconfigured(t *testing.T) {
	st := newMemConn()
	viewer := connRouter("viewer", st)
	if rec := connDo(viewer, "PUT", "/mode", `{"connection_audit_mode":"off"}`); rec.Code != 403 && rec.Code != 404 {
		t.Fatalf("viewer must not change policy: %d", rec.Code)
	}
	if st.mode != connaudit.ModeWarn {
		t.Fatal("mode changed")
	}
	if rec := connDo(connRouter("admin", nil), "GET", "", ""); rec.Code != 501 {
		t.Fatalf("no store: %d", rec.Code)
	}
}

func TestAttachConnAppliesSuppressions(t *testing.T) {
	st := newMemConn()
	pid, did := uuid.New(), uuid.New()
	st.fs[did] = []connaudit.Finding{{ID: "aaaaaaaaaaaa", Severity: connaudit.SevCritical}, {ID: "bbbbbbbbbbbb", Severity: connaudit.SevWarning}}
	st.sups["aaaaaaaaaaaa"] = connaudit.Suppression{FindingID: "aaaaaaaaaaaa", Reason: "motivo valido"}
	var c connAttach
	c.SetConnAudit(st)
	d := &domain.Deployment{ID: did}
	c.attachConn(context.Background(), pid, d, &domain.Deployment{ID: uuid.New()})
	if len(d.ConnectionWarnings) != 2 || !d.ConnectionWarnings[0].Suppressed || d.ConnectionWarnings[1].Suppressed {
		t.Fatalf("%+v", d.ConnectionWarnings)
	}
}

var connTestOrg = uuid.New()

// fixedOrgProjects returns a project that belongs to connTestOrg.
type fixedOrgProjects struct{ domain.ProjectRepository }

func (fixedOrgProjects) GetByID(context.Context, uuid.UUID) (*domain.Project, error) {
	return &domain.Project{OrgID: connTestOrg}, nil
}
