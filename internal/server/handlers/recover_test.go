package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/recovery"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type fakeRecoverSvc struct {
	enabled bool
	err     error
	reqs    []recovery.Request
	idem    []string
}

func (f *fakeRecoverSvc) Enabled() bool { return f.enabled }
func (f *fakeRecoverSvc) Plan(_ context.Context, r recovery.Request) (recovery.Plan, error) {
	f.reqs = append(f.reqs, r)
	if f.err != nil {
		return recovery.Plan{}, f.err
	}
	return recovery.Plan{PlanID: "abc", Ready: true, EstimateSecond: 60,
		Steps: []recovery.Step{{ID: "f0-preflight", Phase: "F0", Name: "F0 preflight"}},
		Risks: []recovery.Risk{{Code: "STALE_BACKUP", Severity: "warning", Subject: "x", Message: "old"}}}, nil
}
func (f *fakeRecoverSvc) Start(_ context.Context, r recovery.Request, _ *uuid.UUID, idem string) (*recovery.Run, error) {
	f.reqs = append(f.reqs, r)
	f.idem = append(f.idem, idem)
	if f.err != nil {
		return nil, f.err
	}
	return &recovery.Run{ID: uuid.New(), Mode: r.Mode, Status: recovery.RunRunning, Steps: []recovery.StepState{{ID: "f0", Name: "F0", Phase: "F0", Status: recovery.StepPending}}}, nil
}
func (f *fakeRecoverSvc) Get(_ context.Context, id uuid.UUID) (*recovery.Run, error) {
	return &recovery.Run{ID: id, Mode: recovery.ModeApply, Status: recovery.RunSuccess}, f.err
}

func rcCall(t *testing.T, svc *fakeRecoverSvc, orgRole, userRole, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	orgID := uuid.New()
	h := NewRecoverHandler(fakeOrgRepo{role: orgRole}, bkProjects{orgID: orgID}, svc)
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: uuid.New(), Role: userRole})))
		})
	})
	h.Mount(r)
	full := strings.ReplaceAll(strings.ReplaceAll(path, "{o}", orgID.String()), "{p}", uuid.New().String())
	req := httptest.NewRequest(method, full, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestRecoverPlatformRequiresPlatformAdmin(t *testing.T) {
	rec := rcCall(t, &fakeRecoverSvc{enabled: true}, "admin", "user", "POST", "/git/admin/recover", `{"mode":"plan"}`, nil)
	if rec.Code != 403 {
		t.Fatalf("org admin is not platform admin: %d %s", rec.Code, rec.Body)
	}
}

func TestRecoverPlanContract(t *testing.T) {
	svc := &fakeRecoverSvc{enabled: true}
	rec := rcCall(t, svc, "admin", "admin", "POST", "/git/admin/recover", `{"mode":"plan","target":"ephemeral","scope":["git","databases"]}`, nil)
	if rec.Code != 202 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	for _, k := range []string{"id", "mode", "status", "steps", "plan_id", "risks", "ready"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing %q in %s", k, rec.Body)
		}
	}
	if m["status"] != "planned" {
		t.Errorf("plan status %v", m["status"])
	}
	r := svc.reqs[0]
	if !r.All || r.Target != recovery.TargetEphemeral || len(r.Scopes) != 2 {
		t.Errorf("request not mapped: %+v", r)
	}
}

func TestRecoverApplyPassesIdempotencyKey(t *testing.T) {
	svc := &fakeRecoverSvc{enabled: true}
	rec := rcCall(t, svc, "admin", "admin", "POST", "/git/admin/recover", `{"mode":"apply","force_overwrite":true}`, map[string]string{"Idempotency-Key": "k-1"})
	if rec.Code != 202 || svc.idem[0] != "k-1" || !svc.reqs[0].ForceOverwrite {
		t.Fatalf("%d %s idem=%v req=%+v", rec.Code, rec.Body, svc.idem, svc.reqs)
	}
	if svc.reqs[0].ApplyInfra {
		t.Fatal("infrastructure changes are never accepted through the API")
	}
}

func TestRecoverProjectNeedsProjectDelete(t *testing.T) {
	for role, want := range map[string]int{"readonly": 403, "admin": 202} {
		rec := rcCall(t, &fakeRecoverSvc{enabled: true}, role, "user", "POST", "/orgs/{o}/projects/{p}/recover", `{"mode":"verify"}`, nil)
		if rec.Code != want && !(want == 403 && rec.Code == 404) {
			t.Errorf("role %s: %d (want %d) %s", role, rec.Code, want, rec.Body)
		}
	}
}

func TestRecoverErrorsAndDisabled(t *testing.T) {
	for _, c := range []struct {
		err  error
		code int
	}{{recovery.ErrActive, 409}, {recovery.ErrBlocked, 422}, {recovery.ErrInvalid, 400}, {recovery.ErrNotFound, 404}} {
		rec := rcCall(t, &fakeRecoverSvc{enabled: true, err: c.err}, "admin", "admin", "POST", "/git/admin/recover", `{"mode":"apply"}`, nil)
		if rec.Code != c.code {
			t.Errorf("%v -> %d, want %d", c.err, rec.Code, c.code)
		}
	}
	rec := rcCall(t, &fakeRecoverSvc{}, "admin", "admin", "POST", "/git/admin/recover", `{"mode":"plan"}`, nil)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "RECOVERY_DISABLED") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = rcCall(t, &fakeRecoverSvc{enabled: true}, "admin", "admin", "GET", "/git/admin/recover/"+uuid.New().String(), "", nil)
	if rec.Code != 200 {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	if rec = rcCall(t, &fakeRecoverSvc{enabled: true}, "admin", "admin", "GET", "/git/admin/recover/not-a-uuid", "", nil); rec.Code != 400 {
		t.Fatalf("bad id: %d", rec.Code)
	}
}
