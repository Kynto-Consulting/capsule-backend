package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/netaccess"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/internal/service"
)

type memPortRepo struct {
	mu    sync.Mutex
	ports []*domain.ProjectPort
}

func (f *memPortRepo) List(context.Context, uuid.UUID) ([]*domain.ProjectPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*domain.ProjectPort{}, f.ports...), nil
}
func (f *memPortRepo) UsedHostPorts(_ context.Context, proto string, _, _ int) (map[int]bool, error) {
	out := map[int]bool{}
	for _, p := range f.ports {
		if pp, _ := domain.NormalizeProtocol(p.Protocol); pp == proto {
			out[p.HostPort] = true
		}
	}
	return out, nil
}
func (f *memPortRepo) Replace(_ context.Context, pid uuid.UUID, ports []*domain.ProjectPort) ([]*domain.ProjectPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ports = nil
	for _, p := range ports {
		c := *p
		if c.ID == uuid.Nil {
			c.ID = uuid.New()
		}
		if c.Rules == nil {
			c.Rules = []*domain.PortRule{}
		}
		f.ports = append(f.ports, &c)
	}
	return append([]*domain.ProjectPort{}, f.ports...), nil
}
func (f *memPortRepo) AddRule(_ context.Context, _ uuid.UUID, cp int, proto string, rule *domain.PortRule, max int) (*domain.PortRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.ports {
		if pp, _ := domain.NormalizeProtocol(p.Protocol); p.ContainerPort == cp && pp == proto {
			c := *rule
			c.ID = uuid.New()
			p.Rules = append(p.Rules, &c)
			return &c, nil
		}
	}
	return nil, domain.ErrNotFound
}
func (f *memPortRepo) DeleteRule(_ context.Context, _, ruleID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.ports {
		for i, r := range p.Rules {
			if r.ID == ruleID {
				p.Rules = append(p.Rules[:i], p.Rules[i+1:]...)
				return nil
			}
		}
	}
	return domain.ErrNotFound
}
func (f *memPortRepo) ListDesired(context.Context) ([]domain.DesiredPortRule, error) { return nil, nil }
func (f *memPortRepo) DeleteAll(context.Context, uuid.UUID) error                    { f.ports = nil; return nil }

type nopPortsFirewall struct{ calls int }

func (f *nopPortsFirewall) ReconcileProjectPorts(context.Context, uuid.UUID, []netaccess.PortDesired) error {
	f.calls++
	return nil
}
func (f *nopPortsFirewall) SyncAllPorts(context.Context, []netaccess.PortDesired) error { return nil }

type fakePortDeploys struct {
	domain.DeploymentRepository
	dep *domain.Deployment
}

func (f fakePortDeploys) GetLatestSuccessfulByProject(context.Context, uuid.UUID) (*domain.Deployment, error) {
	if f.dep == nil {
		return nil, domain.ErrNotFound
	}
	return f.dep, nil
}

type portsEnv struct {
	router  http.Handler
	org     uuid.UUID
	project uuid.UUID
	repo    *memPortRepo
}

func newPortsEnv(t *testing.T, role string, enabled bool, strategy string, dep *domain.Deployment, fargate bool) *portsEnv {
	t.Helper()
	org, proj := uuid.New(), uuid.New()
	repo := &memPortRepo{}
	var fw service.PortsFirewall
	if enabled {
		fw = &nopPortsFirewall{}
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.NewPortsService(repo, fw, nil, service.PortsConfig{From: 41000, To: 41999, Host: "tcp.example.test"}, logger)
	h := NewProjectPortsHandler(fakeOrgRepo{role: role},
		fakeAccessProjects{p: &domain.Project{ID: proj, OrgID: org, BuildStrategy: strategy}},
		fakePortDeploys{dep: dep}, svc, fargate, logger)
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: uuid.New()})))
		})
	})
	base := "/orgs/{orgID}/projects/{projectID}/ports"
	r.Get(base, h.List)
	r.Put(base, h.Replace)
	r.Post(base+"/{containerPort}/access", h.AddAccess)
	r.Delete(base+"/{containerPort}/access/{ruleID}", h.RemoveAccess)
	return &portsEnv{router: r, org: org, project: proj, repo: repo}
}

func (e *portsEnv) do(method, suffix string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, fmt.Sprintf("/orgs/%s/projects/%s/ports%s", e.org, e.project, suffix), &buf)
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func dockerDep() *domain.Deployment {
	hp := 20100
	return &domain.Deployment{HostPort: &hp, ContainerPort: 3000}
}

func TestPorts501WhenNotConfigured(t *testing.T) {
	e := newPortsEnv(t, "owner", false, "docker", dockerDep(), false)
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		rec := e.do(m, "", map[string]any{"ports": []any{}})
		if rec.Code != http.StatusNotImplemented || errCode(t, rec) != "NOT_CONFIGURED" {
			t.Fatalf("%s: %d %s", m, rec.Code, rec.Body)
		}
	}
	if rec := e.do(http.MethodPost, "/5432/access", map[string]any{"cidr": "10.0.0.0/8"}); rec.Code != http.StatusNotImplemented {
		t.Fatalf("post: %d", rec.Code)
	}
	if rec := e.do(http.MethodDelete, "/5432/access/"+uuid.NewString(), nil); rec.Code != http.StatusNotImplemented {
		t.Fatalf("delete: %d", rec.Code)
	}
}

func TestPortsUnsupportedForOtherDeployTypes(t *testing.T) {
	zero := 0
	cases := []struct {
		name     string
		strategy string
		dep      *domain.Deployment
		fargate  bool
	}{
		{"lambda", "lambda", nil, false},
		{"static", "static", nil, false},
		{"fargate deployed", "fargate", &domain.Deployment{HostPort: &zero}, true},
		{"fargate default no deploy", "", nil, true},
	}
	for _, c := range cases {
		e := newPortsEnv(t, "owner", true, c.strategy, c.dep, c.fargate)
		rec := e.do(http.MethodPut, "", map[string]any{"ports": []map[string]any{{"name": "pg", "container_port": 5432, "protocol": "tcp"}}})
		if rec.Code != http.StatusBadRequest || errCode(t, rec) != "UNSUPPORTED" {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body)
		}
	}
}

func TestPortsPutGetExactJSONAndAccess(t *testing.T) {
	e := newPortsEnv(t, "owner", true, "docker", dockerDep(), false)

	rec := e.do(http.MethodPut, "", map[string]any{"ports": []map[string]any{
		{"name": "postgres", "container_port": 5432, "protocol": "tcp"},
		{"name": "redis", "container_port": 6379},
	}})
	if rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	var got struct {
		AddressHost string `json:"address_host"`
		Ports       []struct {
			Name          string            `json:"name"`
			ContainerPort int               `json:"container_port"`
			Protocol      string            `json:"protocol"`
			HostPort      int               `json:"host_port"`
			Access        string            `json:"access"`
			CIDRs         []json.RawMessage `json:"cidrs"`
		} `json:"ports"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.AddressHost != "tcp.example.test" || len(got.Ports) != 2 {
		t.Fatalf("body = %s", rec.Body)
	}
	pg := got.Ports[0]
	if pg.Name != "postgres" || pg.ContainerPort != 5432 || pg.Protocol != "tcp" || pg.HostPort != 41000 || pg.Access != "private" || pg.CIDRs == nil || len(pg.CIDRs) != 0 {
		t.Fatalf("port = %+v", pg)
	}
	if got.Ports[1].HostPort != 41001 {
		t.Fatalf("second host port = %d", got.Ports[1].HostPort)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"cidrs":[]`)) {
		t.Fatalf("cidrs must serialise as [] not null: %s", rec.Body)
	}

	// allowlist
	rec = e.do(http.MethodPost, "/5432/access", map[string]any{"cidr": "203.0.113.5", "description": "office"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("post: %d %s", rec.Code, rec.Body)
	}
	var rule map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &rule)
	if rule["cidr"] != "203.0.113.5/32" || rule["description"] != "office" || rule["id"] == "" {
		t.Fatalf("rule = %v", rule)
	}
	rec = e.do(http.MethodGet, "", nil)
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"access":"allowlist"`)) {
		t.Fatalf("get: %s", rec.Body)
	}
	// delete
	if rec = e.do(http.MethodDelete, "/5432/access/"+rule["id"].(string), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if rec = e.do(http.MethodGet, "", nil); bytes.Contains(rec.Body.Bytes(), []byte(`"allowlist"`)) {
		t.Fatalf("rule still there: %s", rec.Body)
	}
}

func TestPortsAllowPublicGate(t *testing.T) {
	e := newPortsEnv(t, "admin", true, "docker", dockerDep(), false)
	e.do(http.MethodPut, "", map[string]any{"ports": []map[string]any{{"container_port": 5432}}})

	rec := e.do(http.MethodPost, "/5432/access", map[string]any{"cidr": "0.0.0.0/0"})
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "PUBLIC_NOT_ALLOWED" {
		t.Fatalf("without allow_public: %d %s", rec.Code, rec.Body)
	}
	rec = e.do(http.MethodPost, "/5432/access", map[string]any{"cidr": "0.0.0.0/0", "allow_public": true})
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin with allow_public: %d %s", rec.Code, rec.Body)
	}
	if rec = e.do(http.MethodGet, "", nil); !bytes.Contains(rec.Body.Bytes(), []byte(`"access":"public"`)) {
		t.Fatalf("access must be public: %s", rec.Body)
	}
	// A /7 is never accepted, even with allow_public.
	rec = e.do(http.MethodPost, "/5432/access", map[string]any{"cidr": "10.0.0.0/7", "allow_public": true})
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "INVALID_CIDR" {
		t.Fatalf("/7: %d %s", rec.Code, rec.Body)
	}
}

func TestPortsPublicRequiresOwnerOrAdmin(t *testing.T) {
	// checkPortCIDR is the gate; a plain member must be refused even with allow_public.
	rec := httptest.NewRecorder()
	if _, ok := checkPortCIDR(rec, "0.0.0.0/0", true, "member"); ok || rec.Code != http.StatusForbidden {
		t.Fatalf("member: ok=%v code=%d", ok, rec.Code)
	}
	for _, role := range []string{"owner", "admin"} {
		rec := httptest.NewRecorder()
		if c, ok := checkPortCIDR(rec, "0.0.0.0/0", true, role); !ok || c != netaccess.PublicCIDR {
			t.Fatalf("%s must be allowed", role)
		}
	}
}

func TestPortsValidationErrors(t *testing.T) {
	e := newPortsEnv(t, "owner", true, "docker", dockerDep(), false)
	for _, p := range []int{22, 2375, 2376, 0, 70000} {
		rec := e.do(http.MethodPut, "", map[string]any{"ports": []map[string]any{{"container_port": p}}})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("port %d: %d %s", p, rec.Code, rec.Body)
		}
	}
	var many []map[string]any
	for i := 0; i < 11; i++ {
		many = append(many, map[string]any{"container_port": 3000 + i})
	}
	rec := e.do(http.MethodPut, "", map[string]any{"ports": many})
	if rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "LIMIT_EXCEEDED" {
		t.Fatalf("11 ports: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do(http.MethodPost, "/9999/access", map[string]any{"cidr": "10.0.0.0/8"}); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown port: %d %s", rec.Code, rec.Body)
	}
}

func TestPortsUDPCreateListAccess(t *testing.T) {
	e := newPortsEnv(t, "owner", true, "docker", dockerDep(), false)
	rec := e.do(http.MethodPut, "", map[string]any{"ports": []map[string]any{
		{"name": "game", "container_port": 7777, "protocol": "tcp"},
		{"name": "game-udp", "container_port": 7777, "protocol": "UDP"},
	}})
	if rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	var got struct {
		Ports []struct {
			Name     string `json:"name"`
			Protocol string `json:"protocol"`
			HostPort int    `json:"host_port"`
		} `json:"ports"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Ports) != 2 {
		t.Fatalf("body = %s", rec.Body)
	}
	if got.Ports[0].Protocol != "tcp" || got.Ports[1].Protocol != "udp" || got.Ports[0].HostPort != 41000 || got.Ports[1].HostPort != 41000 {
		t.Fatalf("tcp and udp must each take the lowest free number of their own protocol: %s", rec.Body)
	}

	// access on the udp port, selected by ?protocol=udp
	rec = e.do(http.MethodPost, "/7777/access?protocol=udp", map[string]any{"cidr": "203.0.113.5", "description": "jugadores"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("post udp: %d %s", rec.Code, rec.Body)
	}
	var rule map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &rule)
	// the same CIDR on tcp is a separate rule; the body can carry the protocol too
	if rec = e.do(http.MethodPost, "/7777/access", map[string]any{"cidr": "203.0.113.5", "protocol": "tcp"}); rec.Code != http.StatusCreated {
		t.Fatalf("post tcp: %d %s", rec.Code, rec.Body)
	}
	// deleting with the wrong protocol does not find it; the right one does
	if rec = e.do(http.MethodDelete, "/7777/access/"+rule["id"].(string), nil); rec.Code != http.StatusNotFound {
		t.Fatalf("delete default tcp: %d %s", rec.Code, rec.Body)
	}
	if rec = e.do(http.MethodDelete, "/7777/access/"+rule["id"].(string)+"?protocol=udp", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete udp: %d %s", rec.Code, rec.Body)
	}

	// errors in Spanish
	rec = e.do(http.MethodPost, "/7777/access?protocol=sctp", map[string]any{"cidr": "10.0.0.0/8"})
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "INVALID_PROTOCOL" || !bytes.Contains(rec.Body.Bytes(), []byte("tcp o udp")) {
		t.Fatalf("sctp: %d %s", rec.Code, rec.Body)
	}
	rec = e.do(http.MethodPut, "", map[string]any{"ports": []map[string]any{{"container_port": 7777, "protocol": "icmp"}}})
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "INVALID_PROTOCOL" {
		t.Fatalf("put icmp: %d %s", rec.Code, rec.Body)
	}
	rec = e.do(http.MethodPost, "/9999/access?protocol=udp", map[string]any{"cidr": "10.0.0.0/8"})
	if rec.Code != http.StatusNotFound || !bytes.Contains(rec.Body.Bytes(), []byte("9999/udp")) {
		t.Fatalf("missing udp port: %d %s", rec.Code, rec.Body)
	}
	rec = e.do(http.MethodPut, "", map[string]any{"ports": []map[string]any{
		{"container_port": 7777, "protocol": "udp"}, {"container_port": 7777, "protocol": "udp"},
	}})
	if rec.Code != http.StatusBadRequest || errCode(t, rec) != "DUPLICATE_PORT" {
		t.Fatalf("duplicate udp: %d %s", rec.Code, rec.Body)
	}
}
