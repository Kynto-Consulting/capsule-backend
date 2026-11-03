package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/backup"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type fakeBackupSvc struct {
	enabled bool
	err     error
	calls   []string
	patch   backup.Patch
	audits  []backup.AuditEntry
}

func (f *fakeBackupSvc) Enabled() bool { return f.enabled }
func (f *fakeBackupSvc) Get(context.Context, uuid.UUID) (*backup.View, error) {
	next := time.Date(2026, 11, 3, 3, 0, 0, 0, time.UTC)
	return &backup.View{Enabled: true, Schedule: "daily", RetentionDays: 14, Include: backup.IncludeView{Databases: true},
		LastRuns: []backup.RunView{{ID: uuid.New(), Kind: "backup", Status: "success", StartedAt: next, SizeBytes: 12}}, NextRun: &next}, f.err
}
func (f *fakeBackupSvc) Update(_ context.Context, _ uuid.UUID, p backup.Patch) (*backup.View, error) {
	f.calls = append(f.calls, "update")
	f.patch = p
	if f.err != nil {
		return nil, f.err
	}
	return &backup.View{Enabled: true, Schedule: "daily", RetentionDays: 14, LastRuns: []backup.RunView{}}, nil
}
func (f *fakeBackupSvc) StartBackup(context.Context, uuid.UUID, *uuid.UUID) (uuid.UUID, error) {
	f.calls = append(f.calls, "run")
	return uuid.New(), f.err
}
func (f *fakeBackupSvc) StartVerify(context.Context, uuid.UUID, *uuid.UUID) (uuid.UUID, error) {
	f.calls = append(f.calls, "verify")
	return uuid.New(), f.err
}
func (f *fakeBackupSvc) StartRestore(_ context.Context, _, _ uuid.UUID, target string, _ *uuid.UUID) (uuid.UUID, error) {
	f.calls = append(f.calls, "restore:"+target)
	return uuid.New(), f.err
}
func (f *fakeBackupSvc) Snapshots(context.Context, uuid.UUID) ([]backup.SnapshotView, error) {
	return []backup.SnapshotView{{ID: uuid.New(), CreatedAt: time.Now(), SizeBytes: 5, Kind: "database", Source: "main"}}, f.err
}
func (f *fakeBackupSvc) StartPlatformBackup(context.Context, *uuid.UUID) (uuid.UUID, error) {
	f.calls = append(f.calls, "platform-run")
	return uuid.New(), f.err
}
func (f *fakeBackupSvc) StartPlatformVerify(context.Context, *uuid.UUID) (uuid.UUID, error) {
	f.calls = append(f.calls, "platform-verify")
	return uuid.New(), f.err
}
func (f *fakeBackupSvc) PlatformView(context.Context) (map[string]any, error) {
	return map[string]any{"enabled": f.enabled}, f.err
}
func (f *fakeBackupSvc) Audit(_ context.Context, e backup.AuditEntry) { f.audits = append(f.audits, e) }

type bkProjects struct {
	domain.ProjectRepository
	orgID uuid.UUID
}

func (p bkProjects) GetByID(_ context.Context, id uuid.UUID) (*domain.Project, error) {
	return &domain.Project{ID: id, OrgID: p.orgID}, nil
}

// bkCall performs one request as a user with the given org role against the real handler.
func bkCall(t *testing.T, svc *fakeBackupSvc, orgRole, userRole, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	orgID := uuid.New()
	h := NewBackupHandler(fakeOrgRepo{role: orgRole}, bkProjects{orgID: orgID}, svc)
	r := chi.NewRouter()
	wrap := func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			f(w, req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: uuid.New(), Role: userRole})))
		}
	}
	base := "/orgs/{orgID}/projects/{projectID}/backups"
	r.Get(base, wrap(h.Get))
	r.Put(base, wrap(h.Put))
	r.Post(base+"/run", wrap(h.Run))
	r.Post(base+"/verify", wrap(h.Verify))
	r.Get(base+"/snapshots", wrap(h.Snapshots))
	r.Post(base+"/restore", wrap(h.Restore))
	r.Get("/platform/backups", wrap(h.PlatformGet))
	r.Post("/platform/backups/run", wrap(h.PlatformRun))
	r.Post("/platform/backups/verify", wrap(h.PlatformVerify))
	full := strings.ReplaceAll(strings.ReplaceAll(path, "{o}", orgID.String()), "{p}", uuid.New().String())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, full, strings.NewReader(body)))
	return rec
}

const bkBase = "/orgs/{o}/projects/{p}/backups"

func TestBackupGetContract(t *testing.T) {
	rec := bkCall(t, &fakeBackupSvc{enabled: true}, "readonly", "user", "GET", bkBase, "")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	for _, k := range []string{"enabled", "schedule", "retention_days", "include", "last_runs", "next_run"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing %q in %s", k, rec.Body)
		}
	}
	inc := m["include"].(map[string]any)
	if _, ok := inc["databases"]; !ok {
		t.Error("include.databases missing")
	}
	run := m["last_runs"].([]any)[0].(map[string]any)
	for _, k := range []string{"id", "status", "started_at", "finished_at", "size_bytes", "error"} {
		if _, ok := run[k]; !ok {
			t.Errorf("last_runs[0].%s missing: %v", k, run)
		}
	}
}

func TestBackupSnapshotsContract(t *testing.T) {
	rec := bkCall(t, &fakeBackupSvc{enabled: true}, "readonly", "user", "GET", bkBase+"/snapshots", "")
	var m struct {
		Data []map[string]any `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	if rec.Code != 200 || len(m.Data) != 1 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	for _, k := range []string{"id", "created_at", "size_bytes", "kind", "source"} {
		if _, ok := m.Data[0][k]; !ok {
			t.Errorf("snapshot.%s missing", k)
		}
	}
}

func TestBackupWritesAnswer409WhenDisabled(t *testing.T) {
	svc := &fakeBackupSvc{enabled: false}
	id := uuid.New().String()
	for _, c := range []struct{ method, path, body string }{
		{"PUT", bkBase, `{"enabled":true}`},
		{"POST", bkBase + "/run", ``},
		{"POST", bkBase + "/verify", ``},
		{"POST", bkBase + "/restore", `{"snapshot_id":"` + id + `"}`},
		{"POST", "/platform/backups/run", ``},
		{"POST", "/platform/backups/verify", ``},
	} {
		rec := bkCall(t, svc, "owner", "admin", c.method, c.path, c.body)
		if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"BACKUPS_DISABLED"`) {
			t.Errorf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body)
		}
	}
	if len(svc.calls) != 0 {
		t.Fatalf("service reached while disabled: %v", svc.calls)
	}
	if rec := bkCall(t, svc, "readonly", "user", "GET", bkBase, ""); rec.Code != 200 {
		t.Fatalf("GET must still work when disabled: %d", rec.Code)
	}
}

func TestBackupPermissions(t *testing.T) {
	id := uuid.New().String()
	restore := `{"snapshot_id":"` + id + `"}`
	cases := []struct {
		name, org, method, path, body string
		want                          int
	}{
		{"viewer reads", "readonly", "GET", bkBase, "", 200},
		{"viewer lists snapshots", "readonly", "GET", bkBase + "/snapshots", "", 200},
		{"viewer cannot configure", "readonly", "PUT", bkBase, `{"enabled":true}`, 403},
		{"viewer cannot run", "readonly", "POST", bkBase + "/run", "", 403},
		{"viewer cannot verify", "readonly", "POST", bkBase + "/verify", "", 403},
		{"viewer cannot restore", "readonly", "POST", bkBase + "/restore", restore, 403},
		{"member (deployer) configures", "member", "PUT", bkBase, `{"enabled":true}`, 200},
		{"member runs", "member", "POST", bkBase + "/run", "", 202},
		{"member verifies", "member", "POST", bkBase + "/verify", "", 202},
		{"member cannot restore (needs databases permission)", "member", "POST", bkBase + "/restore", restore, 403},
		{"admin restores", "admin", "POST", bkBase + "/restore", restore, 202},
		{"owner restores", "owner", "POST", bkBase + "/restore", restore, 202},
		{"non member", "", "GET", bkBase, "", 403},
	}
	for _, c := range cases {
		svc := &fakeBackupSvc{enabled: true}
		rec := bkCall(t, svc, c.org, "user", c.method, c.path, c.body)
		if rec.Code != c.want {
			t.Errorf("%s: got %d want %d (%s)", c.name, rec.Code, c.want, rec.Body)
		}
		if c.want >= 400 && len(svc.calls) != 0 {
			t.Errorf("%s: service was called despite %d", c.name, rec.Code)
		}
	}
}

func TestBackupPlatformRoutesNeedPlatformAdmin(t *testing.T) {
	for _, p := range []string{"/platform/backups/run", "/platform/backups/verify"} {
		if rec := bkCall(t, &fakeBackupSvc{enabled: true}, "owner", "user", "POST", p, ""); rec.Code != 403 {
			t.Errorf("%s as org owner without platform role: %d", p, rec.Code)
		}
		svc := &fakeBackupSvc{enabled: true}
		rec := bkCall(t, svc, "", "admin", "POST", p, "")
		if rec.Code != 202 || !strings.Contains(rec.Body.String(), `"run_id"`) || len(svc.audits) != 1 {
			t.Errorf("%s as platform admin: %d %s audits=%d", p, rec.Code, rec.Body, len(svc.audits))
		}
	}
	if rec := bkCall(t, &fakeBackupSvc{enabled: true}, "", "user", "GET", "/platform/backups", ""); rec.Code != 403 {
		t.Errorf("platform view: %d", rec.Code)
	}
}

func TestBackupPutParsesPartialBodyAndMapsErrors(t *testing.T) {
	svc := &fakeBackupSvc{enabled: true}
	rec := bkCall(t, svc, "owner", "user", "PUT", bkBase, `{"retention_days":7,"include":{"volumes":true}}`)
	if rec.Code != 200 || svc.patch.RetentionDays == nil || *svc.patch.RetentionDays != 7 || svc.patch.IncludeVolumes == nil ||
		!*svc.patch.IncludeVolumes || svc.patch.IncludeDatabases != nil || svc.patch.Enabled != nil || svc.patch.Schedule != nil {
		t.Fatalf("partial body: %d patch=%+v", rec.Code, svc.patch)
	}
	if len(svc.audits) != 1 || svc.audits[0].Action != "backup.config_update" {
		t.Fatalf("audit: %+v", svc.audits)
	}
	if rec := bkCall(t, svc, "owner", "user", "PUT", bkBase, `{not json`); rec.Code != 400 {
		t.Fatalf("bad json: %d", rec.Code)
	}
	bad := &fakeBackupSvc{enabled: true, err: &backup.InvalidError{Msg: "retention_days must be between 1 and 30"}}
	if rec := bkCall(t, bad, "owner", "user", "PUT", bkBase, `{"retention_days":99}`); rec.Code != 400 || !strings.Contains(rec.Body.String(), "between 1 and 30") {
		t.Fatalf("validation: %d %s", rec.Code, rec.Body)
	}
	busy := &fakeBackupSvc{enabled: true, err: backup.ErrRunInProgress}
	if rec := bkCall(t, busy, "owner", "user", "POST", bkBase+"/run", ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "BACKUP_IN_PROGRESS") {
		t.Fatalf("busy: %d %s", rec.Code, rec.Body)
	}
}

func TestBackupRestoreBodyValidation(t *testing.T) {
	svc := &fakeBackupSvc{enabled: true}
	if rec := bkCall(t, svc, "owner", "user", "POST", bkBase+"/restore", `{"snapshot_id":"nope"}`); rec.Code != 400 {
		t.Fatalf("bad id: %d", rec.Code)
	}
	id := uuid.New().String()
	rec := bkCall(t, svc, "owner", "user", "POST", bkBase+"/restore", `{"snapshot_id":"`+id+`","target":"copy_1"}`)
	if rec.Code != 202 || len(svc.calls) != 1 || svc.calls[0] != "restore:copy_1" {
		t.Fatalf("%d %s %v", rec.Code, rec.Body, svc.calls)
	}
	if len(svc.audits) != 1 || svc.audits[0].Action != "backup.restore" {
		t.Fatalf("restore must be audited: %+v", svc.audits)
	}
	unsupported := &fakeBackupSvc{enabled: true, err: &backup.InvalidError{Msg: "restoring redis snapshots is not supported"}}
	if rec := bkCall(t, unsupported, "owner", "user", "POST", bkBase+"/restore", `{"snapshot_id":"`+id+`"}`); rec.Code != 400 {
		t.Fatalf("unsupported: %d", rec.Code)
	}
	missing := &fakeBackupSvc{enabled: true, err: backup.ErrNotFound}
	if rec := bkCall(t, missing, "owner", "user", "POST", bkBase+"/restore", `{"snapshot_id":"`+id+`"}`); rec.Code != 404 {
		t.Fatalf("missing: %d", rec.Code)
	}
}
