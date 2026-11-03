package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/security"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// ---- rig -------------------------------------------------------------------------------------

type secRoles struct{ byUser map[uuid.UUID]string }

func (s secRoles) LoadOrgAccess(_ context.Context, _, user uuid.UUID) (*authz.OrgAccess, error) {
	role, ok := s.byUser[user]
	if !ok {
		return nil, nil
	}
	return &authz.OrgAccess{OrgRole: role, Mode: authz.ModeOpen}, nil
}
func (s secRoles) UserGrants(context.Context, uuid.UUID) ([]authz.Grant, error) { return nil, nil }

type secOrgs struct {
	domain.OrganizationRepository
	org *domain.Organization
}

func (o secOrgs) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	if id != o.org.ID {
		return nil, domain.ErrNotFound
	}
	return o.org, nil
}

type secProjects struct {
	domain.ProjectRepository
	p *domain.Project
}

func (p secProjects) GetByID(_ context.Context, id uuid.UUID) (*domain.Project, error) {
	if id != p.p.ID {
		return nil, domain.ErrNotFound
	}
	return p.p, nil
}

type secRig struct {
	t       *testing.T
	router  chi.Router
	svc     *security.Service
	store   *security.MemStore
	org     uuid.UUID
	project uuid.UUID
	users   map[string]*domain.User
	clock   time.Time
}

func newSecRig(t *testing.T) *secRig {
	t.Helper()
	org := &domain.Organization{ID: uuid.New(), Slug: "acme"}
	proj := &domain.Project{ID: uuid.New(), OrgID: org.ID, Slug: "app"}
	viewer := &domain.User{ID: uuid.New(), Name: "Vera Viewer", Email: "vera@x.io"}
	deployer := &domain.User{ID: uuid.New(), Name: "Dan Deployer", Email: "dan@x.io"}
	admin := &domain.User{ID: uuid.New(), Name: "Ada Admin", Email: "ada@x.io"}
	outsider := &domain.User{ID: uuid.New(), Name: "Olga Outsider", Email: "olga@x.io"}
	users := map[string]*domain.User{"viewer": viewer, "deployer": deployer, "admin": admin, "outsider": outsider}
	az := authz.New(secRoles{byUser: map[uuid.UUID]string{viewer.ID: "readonly", deployer.ID: "member", admin.ID: "admin"}})

	store := security.NewMemStore()
	store.AddProject(security.Target{ProjectID: proj.ID, OrgID: org.ID, OrgSlug: org.Slug, ProjectSlug: proj.Slug})
	svc := security.New(store, nil, security.Config{FingerprintKey: "handler-test-key", UploadsPerMinute: 1000}, nil)
	rig := &secRig{t: t, svc: svc, store: store, org: org.ID, project: proj.ID, users: users, clock: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}
	svc.SetClock(func() time.Time { return rig.clock })

	h := NewSecurityHandler(svc, az, secOrgs{org: org}, secProjects{p: proj})
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if u := users[req.Header.Get("X-Test-User")]; u != nil {
				req = req.WithContext(middleware.WithUser(req.Context(), u))
			}
			next.ServeHTTP(w, req)
		})
	})
	mountSecurityOn(r, h)
	rig.router = r
	return rig
}

// mountSecurityOn registers the same routes MountSecurity does, on a handler built for tests.
func mountSecurityOn(r chi.Router, h *SecurityHandler) {
	r.Get(securityBase+"/overview", h.Overview)
	r.Get(securityBase+"/alerts", h.AlertsList)
	r.Get(securityBase+"/alerts/{alertID}", h.AlertGet)
	r.Post(securityBase+"/alerts/{alertID}/dismiss", h.AlertDismiss)
	r.Post(securityBase+"/alerts/{alertID}/reopen", h.AlertReopen)
	r.Post(securityBase+"/sarif", h.SarifUpload)
	r.Get(securityBase+"/sarif/{uploadID}", h.SarifStatus)
	r.Get(securityBase+"/policy", h.PolicyGet)
	r.Put(securityBase+"/policy", h.PolicyPut)
	r.Get(securityBase+"/suppressions", h.SuppressionsList)
	r.Post(securityBase+"/suppressions", h.SuppressionCreate)
	r.Delete(securityBase+"/suppressions/{suppressionID}", h.SuppressionDelete)
	r.Post(securityBase+"/scans", h.ScanTrigger)
	r.Get(securityBase+"/renovate", h.RenovateGet)
	r.Put(securityBase+"/renovate", h.RenovatePut)
	r.Post(securityBase+"/renovate/run", h.RenovateRun)
}

func (g *secRig) path(suffix string) string {
	return "/orgs/" + g.org.String() + "/projects/" + g.project.String() + "/security" + suffix
}

type secResp struct {
	code int
	body map[string]any
	raw  string
	hdr  http.Header
}

func (g *secRig) do(user, method, suffix string, body any, hdr ...string) secResp {
	g.t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case string:
		rd = bytes.NewReader([]byte(b))
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req := httptest.NewRequest(method, g.path(suffix), rd)
	req.Header.Set("Content-Type", "application/json")
	if user != "" {
		req.Header.Set("X-Test-User", user)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	g.router.ServeHTTP(rec, req)
	out := secResp{code: rec.Code, raw: rec.Body.String(), hdr: rec.Header()}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	return out
}

func (r secResp) errCode() string {
	e, _ := r.body["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func (r secResp) errFields() []string {
	e, _ := r.body["error"].(map[string]any)
	fs, _ := e["fields"].([]any)
	var out []string
	for _, f := range fs {
		out = append(out, f.(map[string]any)["field"].(string))
	}
	return out
}

func secSarif(tool string, rules ...[3]string) string { // rule, level, snippet
	var results []any
	for _, ru := range rules {
		results = append(results, map[string]any{
			"ruleId": ru[0], "level": ru[1], "message": map[string]any{"text": "msg " + ru[0]},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": "src/" + ru[0] + ".go"},
				"region":           map[string]any{"startLine": 5, "snippet": map[string]any{"text": ru[2]}},
			}}},
		})
	}
	b, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": tool}}, "results": results}}})
	return string(b)
}

const secSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func (g *secRig) uploadSarif(user, sarif string) secResp {
	g.t.Helper()
	res := g.do(user, http.MethodPost, "/sarif", map[string]any{"commit_sha": secSHA, "ref": "refs/heads/main", "sarif": sarif})
	if res.code == http.StatusAccepted {
		g.clock = g.clock.Add(time.Second)
		if _, err := g.svc.ProcessPending(context.Background(), 10); err != nil {
			g.t.Fatal(err)
		}
	}
	return res
}

func (g *secRig) alertIDs(user, query string) []string {
	g.t.Helper()
	res := g.do(user, http.MethodGet, "/alerts"+query, nil)
	if res.code != 200 {
		g.t.Fatalf("list alerts: %d %s", res.code, res.raw)
	}
	var ids []string
	for _, it := range res.body["items"].([]any) {
		ids = append(ids, it.(map[string]any)["id"].(string))
	}
	return ids
}

// ---- tests -----------------------------------------------------------------------------------

func TestSecurityPermissionMatrix(t *testing.T) {
	g := newSecRig(t)
	g.uploadSarif("admin", secSarif("semgrep", [3]string{"r.med", "warning", "x := 1"}))
	alert := g.alertIDs("admin", "")[0]
	exp := g.clock.Add(24 * time.Hour).Format(time.RFC3339)
	dismiss := map[string]any{"reason": "wont_fix", "justification": "accepted for the sprint", "expires_at": exp}
	policy := security.DefaultPolicy()
	sup := map[string]any{"match": map[string]any{"rule_id": "zz"}, "reason": "used_in_tests", "justification": "only used in tests", "expires_at": exp}
	renov := map[string]any{"enabled": true}

	type call struct {
		name           string
		method, suffix string
		body           any
		perm           string // minimum role: viewer|deployer|admin
		okStatus       int
	}
	calls := []call{
		{"overview", "GET", "/overview", nil, "viewer", 200},
		{"alerts list", "GET", "/alerts", nil, "viewer", 200},
		{"alert get", "GET", "/alerts/" + alert, nil, "viewer", 200},
		{"policy get", "GET", "/policy", nil, "viewer", 200},
		{"suppressions list", "GET", "/suppressions", nil, "viewer", 200},
		{"renovate get", "GET", "/renovate", nil, "viewer", 200},
		{"alert dismiss", "POST", "/alerts/" + alert + "/dismiss", dismiss, "deployer", 200},
		{"suppression create", "POST", "/suppressions", sup, "deployer", 201},
		{"sarif upload", "POST", "/sarif", map[string]any{"commit_sha": secSHA, "ref": "main", "sarif": secSarif("semgrep")}, "deployer", 202},
		{"policy put", "PUT", "/policy", policy, "admin", 200},
		{"renovate put", "PUT", "/renovate", renov, "admin", 200},
	}
	rank := map[string]int{"": -1, "outsider": -1, "viewer": 0, "deployer": 1, "admin": 2}
	for _, c := range calls {
		for _, user := range []string{"", "outsider", "viewer", "deployer", "admin"} {
			// every call below mutates state: re-open the alert before each dismiss attempt
			if c.name == "alert dismiss" {
				g.reset(alert)
			}
			res := g.do(user, c.method, c.suffix, c.body)
			want := c.okStatus
			switch {
			case user == "":
				want = http.StatusUnauthorized
			case user == "outsider":
				want = http.StatusForbidden
			case rank[user] < rank[c.perm]:
				want = http.StatusForbidden
			}
			if res.code != want {
				t.Errorf("%s as %q: status %d, want %d (%s)", c.name, user, res.code, want, res.raw)
			}
		}
	}
}

// reset puts a dismissed alert back to open in the store (the matrix test dismisses it repeatedly).
func (g *secRig) reset(id string) {
	g.store.Reset(uuid.MustParse(id))
}

func TestSecretAlertsAreCountersOnlyForViewers(t *testing.T) {
	g := newSecRig(t)
	// secret alert with the raw value in the SARIF
	val := "sk_" + "live_" + "FixtureValue0123456789ab"
	raw, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool": map[string]any{"driver": map[string]any{"name": "gitleaks"}},
		"results": []any{map[string]any{"ruleId": "stripe-access-token", "message": map[string]any{"text": "stripe-access-token has detected secret for file app.js."},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": "app.js"},
				"region": map[string]any{"startLine": 1, "snippet": map[string]any{"text": val}}}}}}},
	}}})
	g.uploadSarif("admin", string(raw))
	g.uploadSarif("admin", secSarif("semgrep", [3]string{"code.rule", "error", "y"}))

	viewerList := g.do("viewer", "GET", "/alerts", nil)
	if n := len(viewerList.body["items"].([]any)); n != 1 {
		t.Fatalf("viewer sees %d alerts, want only the code one", n)
	}
	devList := g.do("deployer", "GET", "/alerts", nil)
	if n := len(devList.body["items"].([]any)); n != 2 {
		t.Fatalf("deployer sees %d alerts, want 2", n)
	}
	// counters include the secret for everyone
	ov := g.do("viewer", "GET", "/overview", nil)
	if ov.body["open"].(float64) != 2 || ov.body["by_kind"].(map[string]any)["secret"].(float64) != 1 {
		t.Fatalf("overview: %s", ov.raw)
	}
	var secretID string
	for _, id := range g.alertIDs("deployer", "?kind=secret") {
		secretID = id
	}
	if res := g.do("viewer", "GET", "/alerts/"+secretID, nil); res.code != 403 {
		t.Fatalf("viewer reading a secret alert: %d", res.code)
	}
	res := g.do("deployer", "GET", "/alerts/"+secretID, nil)
	if res.code != 200 {
		t.Fatalf("deployer: %d", res.code)
	}
	loc := res.body["location"].(map[string]any)
	if loc["path"] != "app.js" || loc["start_line"].(float64) != 1 || res.body["rule_id"] != "stripe-access-token" {
		t.Fatalf("a deployer sees rule and path: %s", res.raw)
	}
	// the value is nowhere in any response
	for _, r := range []secResp{viewerList, devList, ov, res, g.do("admin", "GET", "/alerts/"+secretID, nil), g.do("admin", "GET", "/alerts?kind=secret", nil)} {
		if strings.Contains(r.raw, val) {
			t.Fatalf("the value of the secret is in a response: %s", r.raw)
		}
	}
}

func TestSecurityAlertJSONShape(t *testing.T) {
	g := newSecRig(t)
	g.uploadSarif("admin", secSarif("semgrep", [3]string{"r.high", "error", "dangerous()"}))
	res := g.do("viewer", "GET", "/alerts", nil)
	if res.code != 200 || res.body["next_cursor"] != nil {
		t.Fatalf("list: %d %s", res.code, res.raw)
	}
	a := res.body["items"].([]any)[0].(map[string]any)
	for _, k := range []string{"id", "kind", "tool", "rule_id", "severity", "state", "title", "description", "fingerprint", "location", "first_seen_sha", "branch", "dismissal", "created_at", "updated_at", "trace"} {
		if _, ok := a[k]; !ok {
			t.Errorf("alert lacks %q: %v", k, a)
		}
	}
	if a["severity"] != "high" || a["state"] != "open" || a["tool"] != "semgrep" || a["kind"] != "code" || a["dismissal"] != nil {
		t.Errorf("alert: %v", a)
	}
	if res := g.do("viewer", "GET", "/alerts?limit=500", nil); res.code != 422 {
		t.Errorf("limit 500: %d", res.code)
	}
	if res := g.do("viewer", "GET", "/alerts?severity=urgent", nil); res.code != 422 || res.errCode() != "VALIDATION_ERROR" {
		t.Errorf("bad severity: %d %s", res.code, res.raw)
	}
	if res := g.do("viewer", "GET", "/alerts/"+uuid.NewString(), nil); res.code != 404 {
		t.Errorf("unknown alert: %d", res.code)
	}
	if res := g.do("viewer", "GET", "/alerts/not-a-uuid", nil); res.code != 400 {
		t.Errorf("bad id: %d", res.code)
	}
	ov := g.do("viewer", "GET", "/overview", nil)
	for _, k := range []string{"by_severity", "by_kind", "open", "dismissed", "last_scan_at", "policy_blocking"} {
		if _, ok := ov.body[k]; !ok {
			t.Errorf("overview lacks %q: %s", k, ov.raw)
		}
	}
}

func TestSecurityDismissEndpoint(t *testing.T) {
	g := newSecRig(t)
	g.uploadSarif("admin", secSarif("semgrep", [3]string{"r.high", "error", "a"}, [3]string{"r.med", "warning", "b"}))
	var hi, med string
	for _, it := range g.do("admin", "GET", "/alerts", nil).body["items"].([]any) {
		m := it.(map[string]any)
		if m["severity"] == "high" {
			hi = m["id"].(string)
		} else {
			med = m["id"].(string)
		}
	}
	exp := g.clock.Add(24 * time.Hour).Format(time.RFC3339)

	// validation: 422 with the field names
	res := g.do("deployer", "POST", "/alerts/"+med+"/dismiss", map[string]any{"reason": "nope", "justification": "short"})
	if res.code != 422 || res.errCode() != "VALIDATION_ERROR" {
		t.Fatalf("validation: %d %s", res.code, res.raw)
	}
	fs := strings.Join(res.errFields(), ",")
	for _, want := range []string{"reason", "justification", "expires_at"} {
		if !strings.Contains(fs, want) {
			t.Errorf("fields %q lack %s", fs, want)
		}
	}
	// unknown JSON fields are refused instead of ignored
	if res := g.do("deployer", "POST", "/alerts/"+med+"/dismiss", `{"reason":"wont_fix","justification":"a long justification","expires_at":"`+exp+`","force":true}`); res.code != 400 {
		t.Errorf("unknown field: %d", res.code)
	}
	// a deployer cannot dismiss a high alert
	if res := g.do("deployer", "POST", "/alerts/"+hi+"/dismiss", map[string]any{"reason": "wont_fix", "justification": "a long justification", "expires_at": exp}); res.code != 403 || res.errCode() != "ADMIN_REQUIRED" {
		t.Fatalf("deployer on high: %d %s", res.code, res.raw)
	}
	// admin can
	res = g.do("admin", "POST", "/alerts/"+hi+"/dismiss", map[string]any{"reason": "risk_accepted", "justification": "vendor patch scheduled", "expires_at": exp})
	if res.code != 200 || res.body["state"] != "dismissed" {
		t.Fatalf("admin on high: %d %s", res.code, res.raw)
	}
	d := res.body["dismissal"].(map[string]any)
	if d["reason"] != "risk_accepted" || d["expires_at"] == nil || d["by"].(map[string]any)["name"] != "Ada Admin" {
		t.Fatalf("dismissal: %v", d)
	}
	// dismissing again: 409
	if res := g.do("admin", "POST", "/alerts/"+hi+"/dismiss", map[string]any{"reason": "wont_fix", "justification": "a long justification", "expires_at": exp}); res.code != 409 {
		t.Fatalf("second dismiss: %d", res.code)
	}
	// a viewer cannot reopen; a deployer can
	if res := g.do("viewer", "POST", "/alerts/"+hi+"/reopen", nil); res.code != 403 {
		t.Fatalf("viewer reopen: %d", res.code)
	}
	if res := g.do("deployer", "POST", "/alerts/"+hi+"/reopen", nil); res.code != 200 || res.body["state"] != "open" {
		t.Fatalf("reopen: %d %s", res.code, res.raw)
	}
	if res := g.do("deployer", "POST", "/alerts/"+hi+"/reopen", nil); res.code != 409 {
		t.Fatalf("reopen an open alert: %d", res.code)
	}
}

func TestSecuritySarifEndpoint(t *testing.T) {
	g := newSecRig(t)
	ok := map[string]any{"commit_sha": secSHA, "ref": "refs/heads/main", "sarif": secSarif("semgrep", [3]string{"r", "error", "a"})}
	res := g.do("deployer", "POST", "/sarif", ok, "Idempotency-Key", "abc-1")
	if res.code != 202 || res.body["id"] == nil || res.body["status"] != "pending" {
		t.Fatalf("upload: %d %s", res.code, res.raw)
	}
	id := res.body["id"].(string)
	again := g.do("deployer", "POST", "/sarif", ok, "Idempotency-Key", "abc-1")
	if again.code != 202 || again.body["id"] != id {
		t.Fatalf("idempotent replay: %d %s", again.code, again.raw)
	}
	g.clock = g.clock.Add(time.Second)
	if _, err := g.svc.ProcessPending(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	st := g.do("viewer", "GET", "/sarif/"+id, nil)
	if st.code != 200 || st.body["status"] != "complete" || st.body["alerts_created"].(float64) != 1 {
		t.Fatalf("status: %d %s", st.code, st.raw)
	}
	if res := g.do("viewer", "GET", "/sarif/"+uuid.NewString(), nil); res.code != 404 {
		t.Fatalf("unknown upload: %d", res.code)
	}

	bad := map[string]map[string]any{
		"commit_sha": {"commit_sha": "zz", "ref": "main", "sarif": "{}"},
		"ref":        {"commit_sha": secSHA, "ref": "refs/remotes/x", "sarif": "{}"},
	}
	for name, b := range bad {
		if r := g.do("deployer", "POST", "/sarif", b); r.code != 422 || r.errCode() != "VALIDATION_ERROR" {
			t.Errorf("%s: %d %s", name, r.code, r.raw)
		}
	}
	if r := g.do("deployer", "POST", "/sarif", map[string]any{"commit_sha": secSHA, "ref": "main", "sarif": "{}"}); r.code != 422 || r.errCode() != "SARIF_INVALID" {
		t.Errorf("invalid sarif: %d %s", r.code, r.raw)
	}
	if r := g.do("deployer", "POST", "/sarif", map[string]any{"commit_sha": secSHA, "ref": "main", "sarif": `{"version":"2.0.0","runs":[]}`}); r.code != 422 || r.errCode() != "SARIF_UNSUPPORTED" {
		t.Errorf("old sarif: %d %s", r.code, r.raw)
	}
	if r := g.do("deployer", "POST", "/sarif", `{"commit_sha":"`+secSHA+`","ref":"main","sarif":"{}","extra":1}`); r.code != 400 {
		t.Errorf("unknown field: %d", r.code)
	}
	// results over the limit: 422 with a clear code
	var b strings.Builder
	b.WriteString(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[`)
	for i := 0; i <= security.MaxResults; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"ruleId":"r","message":{"text":"m"}}`)
	}
	b.WriteString(`]}]}`)
	if r := g.do("deployer", "POST", "/sarif", map[string]any{"commit_sha": secSHA, "ref": "main", "sarif": b.String()}); r.code != 422 || r.errCode() != "SARIF_TOO_MANY_RESULTS" {
		t.Errorf("too many results: %d %s", r.code, r.errCode())
	}
	// a body far over the limit is refused with 413 before it is parsed
	huge := `{"commit_sha":"` + secSHA + `","ref":"main","sarif":"` + strings.Repeat("A", 15<<20) + `"}`
	if r := g.do("deployer", "POST", "/sarif", huge); r.code != 413 || r.errCode() != "SARIF_TOO_LARGE" {
		t.Errorf("huge body: %d %s", r.code, r.errCode())
	}
	// hostile nesting
	deep := `{"version":"2.1.0","runs":[],"properties":` + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + `}`
	if r := g.do("deployer", "POST", "/sarif", map[string]any{"commit_sha": secSHA, "ref": "main", "sarif": deep}); r.code != 422 || r.errCode() != "SARIF_TOO_DEEP" {
		t.Errorf("deep: %d %s", r.code, r.errCode())
	}
}

func TestSecuritySarifRateLimit(t *testing.T) {
	g := newSecRig(t)
	g.svc = security.New(g.store, nil, security.Config{FingerprintKey: "k", UploadsPerMinute: 2}, nil)
	g.svc.SetClock(func() time.Time { return g.clock })
	org := &domain.Organization{ID: g.org, Slug: "acme"}
	proj := &domain.Project{ID: g.project, OrgID: g.org, Slug: "app"}
	az := authz.New(secRoles{byUser: map[uuid.UUID]string{g.users["deployer"].ID: "member"}})
	h := NewSecurityHandler(g.svc, az, secOrgs{org: org}, secProjects{p: proj})
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), g.users["deployer"])))
		})
	})
	mountSecurityOn(r, h)
	g.router = r
	body := map[string]any{"commit_sha": secSHA, "ref": "main", "sarif": secSarif("semgrep")}
	codes := []int{}
	var retry string
	for i := 0; i < 4; i++ {
		res := g.do("deployer", "POST", "/sarif", body)
		codes = append(codes, res.code)
		if res.code == 429 {
			retry = res.hdr.Get("Retry-After")
			if res.errCode() != "RATE_LIMITED" {
				t.Errorf("code = %s", res.errCode())
			}
		}
	}
	if codes[0] != 202 || codes[1] != 202 || codes[2] != 429 || retry == "" {
		t.Fatalf("codes = %v retry=%q", codes, retry)
	}
}

func TestSecurityPolicyEndpoints(t *testing.T) {
	g := newSecRig(t)
	res := g.do("viewer", "GET", "/policy", nil)
	if res.code != 200 {
		t.Fatalf("get: %d", res.code)
	}
	bm := res.body["block_merge_on"].(map[string]any)
	if bm["dependency"] != "high" || bm["secret"] != "any" || res.body["block_deploy_on"] != "critical" || res.body["max_suppression_days"].(float64) != 180 {
		t.Fatalf("default policy: %s", res.raw)
	}
	if res.body["required_tools"] == nil || res.body["applies_to_branches"] == nil {
		t.Fatalf("empty lists must be [] not null: %s", res.raw)
	}
	put := map[string]any{
		"block_merge_on": map[string]any{"dependency": "critical", "code": "medium", "secret": "any"}, "block_deploy_on": "high",
		"required_tools": []string{"semgrep", "gitleaks"}, "max_suppression_days": 120, "applies_to_branches": []string{"main", "release/*"},
	}
	if r := g.do("admin", "PUT", "/policy", put); r.code != 200 || r.body["max_suppression_days"].(float64) != 120 {
		t.Fatalf("put: %d %s", r.code, r.raw)
	}
	if r := g.do("viewer", "GET", "/policy", nil); len(r.body["required_tools"].([]any)) != 2 {
		t.Fatalf("stored policy: %s", r.raw)
	}
	put["block_deploy_on"] = "medium"
	put["max_suppression_days"] = 500
	put["block_merge_on"] = map[string]any{"dependency": "x", "code": "medium", "secret": "all"}
	r := g.do("admin", "PUT", "/policy", put)
	if r.code != 422 {
		t.Fatalf("invalid policy: %d", r.code)
	}
	fs := strings.Join(r.errFields(), ",")
	for _, w := range []string{"block_deploy_on", "max_suppression_days", "block_merge_on.dependency", "block_merge_on.secret"} {
		if !strings.Contains(fs, w) {
			t.Errorf("fields %q lack %s", fs, w)
		}
	}
	if r := g.do("admin", "PUT", "/policy", `{"nope":1}`); r.code != 400 {
		t.Errorf("unknown field: %d", r.code)
	}
}

func TestSecuritySuppressionEndpoints(t *testing.T) {
	g := newSecRig(t)
	exp := g.clock.Add(48 * time.Hour).Format(time.RFC3339)
	body := func(m map[string]any) map[string]any {
		b := map[string]any{"match": map[string]any{"path_glob": "vendor/**"}, "reason": "used_in_tests", "justification": "vendored code we do not own", "expires_at": exp}
		for k, v := range m {
			b[k] = v
		}
		return b
	}
	for name, b := range map[string]map[string]any{
		"glob **":     body(map[string]any{"match": map[string]any{"path_glob": "**"}}),
		"no justif":   body(map[string]any{"justification": ""}),
		"no expiry":   body(map[string]any{"expires_at": nil}),
		"bad reason":  body(map[string]any{"reason": "meh"}),
		"empty match": body(map[string]any{"match": map[string]any{}}),
		"too far":     body(map[string]any{"expires_at": g.clock.Add(400 * 24 * time.Hour).Format(time.RFC3339)}),
		"fingerprint": body(map[string]any{"match": map[string]any{"fingerprint": "xyz"}}),
	} {
		if r := g.do("deployer", "POST", "/suppressions", b); r.code != 422 {
			t.Errorf("%s: status %d %s", name, r.code, r.raw)
		}
	}
	r := g.do("deployer", "POST", "/suppressions", body(nil))
	if r.code != 201 || r.body["state"] != "active" || r.body["match"].(map[string]any)["path_glob"] != "vendor/**" {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	id := r.body["id"].(string)
	l := g.do("viewer", "GET", "/suppressions", nil)
	items := l.body["items"].([]any)
	if l.code != 200 || len(items) != 1 || items[0].(map[string]any)["justification"] == nil {
		t.Fatalf("list: %d %s", l.code, l.raw)
	}
	if d := g.do("viewer", "DELETE", "/suppressions/"+id, nil); d.code != 403 {
		t.Fatalf("viewer delete: %d", d.code)
	}
	if d := g.do("deployer", "DELETE", "/suppressions/"+id, nil); d.code != 204 {
		t.Fatalf("delete: %d %s", d.code, d.raw)
	}
	if d := g.do("deployer", "DELETE", "/suppressions/"+id, nil); d.code != 404 {
		t.Fatalf("delete twice: %d", d.code)
	}
	l = g.do("viewer", "GET", "/suppressions", nil)
	if st := l.body["items"].([]any)[0].(map[string]any)["state"]; st != "revoked" {
		t.Fatalf("state after delete = %v", st)
	}
}

func TestSecurityScanAndRenovateEndpointsWithoutGit(t *testing.T) {
	g := newSecRig(t)
	if r := g.do("deployer", "POST", "/scans", map[string]any{"tools": []string{"semgrep"}}); r.code != 503 {
		t.Fatalf("scan without Git: %d %s", r.code, r.raw)
	}
	if r := g.do("viewer", "POST", "/scans", nil); r.code != 403 {
		t.Fatalf("viewer scan: %d", r.code)
	}
	r := g.do("viewer", "GET", "/renovate", nil)
	if r.code != 200 || r.body["enabled"] != false || r.body["onboarding"] != "none" {
		t.Fatalf("renovate get: %d %s", r.code, r.raw)
	}
	if r := g.do("deployer", "POST", "/renovate/run", nil); r.code != 422 || r.errCode() != "RENOVATE_DISABLED" {
		t.Fatalf("run while disabled: %d %s", r.code, r.raw)
	}
	if r := g.do("deployer", "PUT", "/renovate", map[string]any{"enabled": true}); r.code != 403 {
		t.Fatalf("deployer put: %d", r.code)
	}
	r = g.do("admin", "PUT", "/renovate", map[string]any{"enabled": true, "schedule": "before 6am on monday"})
	if r.code != 200 || r.body["enabled"] != true || r.body["topic_synced"] != false || r.body["sync_error"] == nil || r.body["schedule"] != "before 6am on monday" {
		t.Fatalf("renovate put: %d %s", r.code, r.raw)
	}
	if r := g.do("admin", "PUT", "/renovate", map[string]any{"preset": "bad preset $(x)"}); r.code != 422 {
		t.Fatalf("bad preset: %d", r.code)
	}
	if r := g.do("deployer", "POST", "/renovate/run", nil); r.code != 503 { // enabled but no runner configured
		t.Fatalf("run without runner: %d %s", r.code, r.raw)
	}
}

func TestSecurityUnknownProjectAndMissingService(t *testing.T) {
	g := newSecRig(t)
	req := httptest.NewRequest("GET", "/orgs/"+g.org.String()+"/projects/"+uuid.NewString()+"/security/overview", nil)
	req.Header.Set("X-Test-User", "admin")
	rec := httptest.NewRecorder()
	g.router.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Errorf("unknown project: %d", rec.Code)
	}
	// without a Service (security.WireSecurity not called) every route answers 501
	h := &SecurityHandler{}
	r := chi.NewRouter()
	mountSecurityOn(r, h)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", g.path("/overview"), nil))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("no service: %d", rec.Code)
	}
}

// The route table must be exactly the B7 part of the OpenAPI contract.
func TestSecurityRoutesMatchTheContract(t *testing.T) {
	spec, err := os.ReadFile("../../../../docs/git-capsule/API.openapi.yaml")
	if err != nil {
		t.Skipf("contract not readable from here: %v", err)
	}
	text := strings.ReplaceAll(string(spec), "\r\n", "\n")
	// path lines of the spec under .../security/ and their methods
	reHeader := regexp.MustCompile(`(?m)^  (/orgs/\{orgID\}/projects/\{projectID\}/security[^:\n]*):$`)
	want := map[string]bool{}
	idx := reHeader.FindAllStringSubmatchIndex(text, -1)
	for i, m := range idx {
		path := text[m[2]:m[3]]
		end := len(text)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		block := text[m[1]:end]
		// stop at the next top-level path (a line starting with two spaces and a slash)
		if n := regexp.MustCompile(`(?m)^  /`).FindStringIndex(block); n != nil {
			block = block[:n[0]]
		}
		for _, mm := range regexp.MustCompile(`(?m)^    (get|post|put|delete|patch):$`).FindAllStringSubmatch(block, -1) {
			want[strings.ToUpper(mm[1])+" "+path] = true
		}
	}
	got := map[string]bool{}
	g := newSecRig(t)
	_ = g
	err = chi.Walk(g.router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		got[method+" "+strings.TrimSuffix(route, "/")] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var missing, extra []string
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	for k := range got {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(want) != 16 {
		t.Fatalf("expected 16 security operations in the contract, parsed %d", len(want))
	}
	if len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("route table differs from the contract.\nmissing: %v\nextra: %v", missing, extra)
	}
}
