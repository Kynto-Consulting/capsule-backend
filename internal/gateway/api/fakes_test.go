package api

import (
	"bytes"
	"context"
	"log/slog"
	"math/rand"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gateway/store"
	"github.com/kynto/capsule/backend/internal/gitaudit"
)

// ---- in-memory RouteStore ----------------------------------------------------------------------

type fakeStore struct {
	mu       sync.Mutex
	rev      int64
	services map[uuid.UUID]*store.Service
	routes   map[uuid.UUID]*store.Route
	pool     map[int]string // port -> free|leased|quarantine
	leases   map[uuid.UUID]*store.Lease
	quotas   map[uuid.UUID]store.Quotas
	policy   map[uuid.UUID]string
	calls    map[string]int
	sweepErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{services: map[uuid.UUID]*store.Service{}, routes: map[uuid.UUID]*store.Route{}, pool: map[int]string{},
		leases: map[uuid.UUID]*store.Lease{}, quotas: map[uuid.UUID]store.Quotas{}, policy: map[uuid.UUID]string{}, calls: map[string]int{}}
}

func (f *fakeStore) bump()              { f.rev++ }
func (f *fakeStore) count(n string) int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls[n] }

func (f *fakeStore) view(r *store.Route) *store.RouteView {
	sv := f.services[r.ServiceID]
	return &store.RouteView{Route: *r, OrgID: sv.OrgID, ProjectID: sv.ProjectID, ServiceName: sv.Name}
}

func (f *fakeStore) gwEnabled(sv *store.Service) bool {
	for _, a := range sv.Accesses {
		if a.Kind == store.AccessGateway && a.Enabled {
			return true
		}
	}
	return false
}

func (f *fakeStore) ResolveRoute(_ context.Context, transport, host string) (*store.RouteView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.routes {
		if r.Transport == transport && r.Host == host && r.Enabled && f.gwEnabled(f.services[r.ServiceID]) {
			return f.view(r), nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) ResolveService(_ context.Context, projectID uuid.UUID, name, transport string) (*store.RouteView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.routes {
		sv := f.services[r.ServiceID]
		if sv.ProjectID == projectID && sv.Name == name && r.Transport == transport && r.Enabled && f.gwEnabled(sv) {
			return f.view(r), nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) Revision(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["Revision"]++
	return f.rev, nil
}

func (f *fakeStore) Snapshot(_ context.Context, since int64) (*store.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["Snapshot"]++
	s := &store.Snapshot{Rev: f.rev, Routes: []store.RouteView{}, Leases: []store.LeaseView{}}
	if since == f.rev {
		s.Unchanged = true
		return s, nil
	}
	var ids []string
	byID := map[string]*store.Route{}
	for _, r := range f.routes {
		if r.Enabled && f.gwEnabled(f.services[r.ServiceID]) {
			ids = append(ids, r.Host)
			byID[r.Host] = r
		}
	}
	sort.Strings(ids)
	for _, h := range ids {
		s.Routes = append(s.Routes, *f.view(byID[h]))
	}
	for _, l := range f.leases {
		if l.State == "active" {
			s.Leases = append(s.Leases, store.LeaseView{Port: l.Port, ServiceID: l.ServiceID, ProjectID: l.ProjectID, OrgID: l.OrgID})
		}
	}
	return s, nil
}

func cloneService(sv *store.Service) *store.Service {
	c := *sv
	c.Accesses = append([]store.Access(nil), sv.Accesses...)
	return &c
}

func (f *fakeStore) CreateService(_ context.Context, in store.NewService) (*store.Service, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !store.ValidServiceName(in.Name) {
		return nil, store.ErrInvalid
	}
	if in.Protocol == "" {
		in.Protocol = "tcp"
	}
	if in.DefaultAccess == "" {
		in.DefaultAccess = store.AccessGateway
	}
	if in.DefaultAccess == store.AccessDirectPort && in.DirectPort == nil {
		return nil, store.ErrInvalid
	}
	for _, s := range f.services {
		if s.OrgID == in.OrgID && s.ProjectID == in.ProjectID && s.Name == in.Name {
			return nil, store.ErrConflict
		}
	}
	sv := &store.Service{ID: uuid.New(), OrgID: in.OrgID, ProjectID: in.ProjectID, Name: in.Name, Protocol: in.Protocol, ContainerPort: in.ContainerPort,
		DefaultAccess: in.DefaultAccess, ProjectPortID: in.ProjectPortID, DatabaseID: in.DatabaseID, CreatedAt: time.Now()}
	sv.Accesses = []store.Access{{ID: uuid.New(), ServiceID: sv.ID, Kind: store.AccessGateway, Enabled: true}}
	if in.DirectPort != nil {
		p := *in.DirectPort
		sv.Accesses = append(sv.Accesses, store.Access{ID: uuid.New(), ServiceID: sv.ID, Kind: store.AccessDirectPort, Enabled: true, Port: &p})
	}
	f.services[sv.ID] = sv
	f.bump()
	return cloneService(sv), nil
}

func (f *fakeStore) GetService(_ context.Context, id uuid.UUID) (*store.Service, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sv := f.services[id]; sv != nil {
		return cloneService(sv), nil
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) ListServices(_ context.Context, projectID uuid.UUID) ([]*store.Service, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*store.Service
	for _, sv := range f.services {
		if sv.ProjectID == projectID {
			out = append(out, cloneService(sv))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *fakeStore) releaseLocked(serviceID uuid.UUID) error {
	l := f.leases[serviceID]
	if l == nil || l.State != "active" {
		return store.ErrNotFound
	}
	l.State = "released"
	f.pool[l.Port] = "quarantine"
	f.bump()
	return nil
}

func (f *fakeStore) DeleteService(_ context.Context, id uuid.UUID, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.services[id] == nil {
		return store.ErrNotFound
	}
	_ = f.releaseLocked(id)
	for rid, r := range f.routes {
		if r.ServiceID == id {
			delete(f.routes, rid)
		}
	}
	delete(f.services, id)
	f.bump()
	return nil
}

func (f *fakeStore) SetAccess(_ context.Context, serviceID uuid.UUID, kind string, enabled bool, port *int) (*store.Access, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sv := f.services[serviceID]
	if sv == nil {
		return nil, store.ErrNotFound
	}
	for i := range sv.Accesses {
		if sv.Accesses[i].Kind == kind {
			sv.Accesses[i].Enabled = enabled
			if port != nil {
				p := *port
				sv.Accesses[i].Port = &p
			}
			f.bump()
			a := sv.Accesses[i]
			return &a, nil
		}
	}
	a := store.Access{ID: uuid.New(), ServiceID: serviceID, Kind: kind, Enabled: enabled, Port: port}
	sv.Accesses = append(sv.Accesses, a)
	f.bump()
	return &a, nil
}

func (f *fakeStore) SetDefaultAccess(_ context.Context, serviceID uuid.UUID, kind string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	sv := f.services[serviceID]
	if sv == nil {
		return store.ErrNotFound
	}
	sv.DefaultAccess = kind
	f.bump()
	return nil
}

func (f *fakeStore) UpsertRoute(_ context.Context, in store.NewRoute) (*store.Route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.services[in.ServiceID] == nil {
		return nil, store.ErrNotFound
	}
	if in.Transport == "" {
		in.Transport = "tcp"
	}
	if in.Mode == "" {
		in.Mode = store.ModePassthrough
	}
	if in.Protocol == "" {
		in.Protocol = f.services[in.ServiceID].Protocol
	}
	f.bump()
	for _, r := range f.routes {
		if r.Transport == in.Transport && r.Host == in.Host {
			if r.ServiceID != in.ServiceID {
				return nil, store.ErrConflict
			}
			r.Protocol, r.DestHost, r.DestPort, r.Mode, r.Enabled, r.Rev = in.Protocol, in.DestHost, in.DestPort, in.Mode, in.Enabled, f.rev
			c := *r
			return &c, nil
		}
	}
	r := &store.Route{ID: uuid.New(), ServiceID: in.ServiceID, Host: in.Host, Transport: in.Transport, Protocol: in.Protocol, DestHost: in.DestHost,
		DestPort: in.DestPort, Mode: in.Mode, Enabled: in.Enabled, Rev: f.rev}
	f.routes[r.ID] = r
	c := *r
	return &c, nil
}

func (f *fakeStore) DeleteRoute(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.routes, id)
	f.bump()
	return nil
}

func (f *fakeStore) SeedPortPool(_ context.Context, lo, hi int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["SeedPortPool"]++
	f.calls["seed_lo"], f.calls["seed_hi"] = lo, hi
	n := 0
	for p := lo; p <= hi; p++ {
		if _, ok := f.pool[p]; !ok {
			f.pool[p] = "free"
			n++
		}
	}
	return n, nil
}

func (f *fakeStore) activeCount(org uuid.UUID, project *uuid.UUID) int {
	n := 0
	for _, l := range f.leases {
		if l.State == "active" && l.OrgID == org && (project == nil || l.ProjectID == *project) {
			n++
		}
	}
	return n
}

func (f *fakeStore) LeasePort(_ context.Context, serviceID uuid.UUID) (*store.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sv := f.services[serviceID]
	if sv == nil {
		return nil, store.ErrNotFound
	}
	if l := f.leases[serviceID]; l != nil && l.State == "active" {
		c := *l
		return &c, nil
	}
	q, ok := f.quotas[sv.OrgID]
	if !ok {
		q = store.Quotas{MaxRandomPorts: store.DefaultMaxRandomPortsOrg, MaxRandomPortsPerProject: store.DefaultMaxRandomPortsProject}
	}
	if f.activeCount(sv.OrgID, nil) >= q.MaxRandomPorts {
		return nil, &store.QuotaError{Scope: "org", Limit: q.MaxRandomPorts}
	}
	if f.activeCount(sv.OrgID, &sv.ProjectID) >= q.MaxRandomPortsPerProject {
		return nil, &store.QuotaError{Scope: "project", Limit: q.MaxRandomPortsPerProject}
	}
	var free []int
	for p, st := range f.pool {
		if st == "free" {
			free = append(free, p)
		}
	}
	if len(free) == 0 {
		return nil, store.ErrPortPoolExhausted
	}
	sort.Ints(free)
	port := free[rand.Intn(len(free))]
	f.pool[port] = "leased"
	l := &store.Lease{ID: uuid.New(), Port: port, ServiceID: serviceID, ProjectID: sv.ProjectID, OrgID: sv.OrgID, State: "active", LeasedAt: time.Now()}
	f.leases[serviceID] = l
	f.bump()
	c := *l
	return &c, nil
}

func (f *fakeStore) ReleaseLease(_ context.Context, serviceID uuid.UUID, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.releaseLocked(serviceID)
}

func (f *fakeStore) TouchLease(_ context.Context, port int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["TouchLease"]++
	return nil
}

func (f *fakeStore) ReleaseIdle(_ context.Context, _ time.Time, _ time.Duration) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["ReleaseIdle"]++
	return 0, nil
}

func (f *fakeStore) SweepPool(context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["SweepPool"]++
	return 0, f.sweepErr
}

func (f *fakeStore) PoolStats(context.Context) (store.PoolStats, error) {
	return store.PoolStats{}, nil
}

func (f *fakeStore) GetQuotas(_ context.Context, org uuid.UUID) (store.Quotas, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if q, ok := f.quotas[org]; ok {
		return q, nil
	}
	return store.Quotas{MaxRandomPorts: store.DefaultMaxRandomPortsOrg, MaxRandomPortsPerProject: store.DefaultMaxRandomPortsProject}, nil
}

func (f *fakeStore) SetQuotas(_ context.Context, org uuid.UUID, q store.Quotas) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.quotas[org] = q
	return nil
}

func (f *fakeStore) GetOrgPolicy(_ context.Context, org uuid.UUID) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.policy[org]; ok {
		return p, nil
	}
	return store.PolicyWarn, nil
}

func (f *fakeStore) SetOrgPolicy(_ context.Context, org uuid.UUID, p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policy[org] = p
	return nil
}

// ---- other fakes -------------------------------------------------------------------------------

type fakeProjects struct{ m map[uuid.UUID]*domain.Project }

func (f fakeProjects) GetByID(_ context.Context, id uuid.UUID) (*domain.Project, error) {
	if p := f.m[id]; p != nil {
		return p, nil
	}
	return nil, domain.ErrNotFound
}

type fakeAuthz struct {
	m   map[uuid.UUID]authz.Access // by user id
	org uuid.UUID
}

func (f fakeAuthz) Access(_ context.Context, u, org, _ uuid.UUID) (authz.Access, error) {
	if f.org != uuid.Nil && org != f.org {
		return authz.Access{}, nil
	}
	return f.m[u], nil
}

type fakeUsers struct{ gone map[uuid.UUID]bool }

func (f fakeUsers) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if f.gone[id] {
		return nil, domain.ErrNotFound
	}
	return &domain.User{ID: id}, nil
}

type fakeOrgs struct{ roles map[uuid.UUID]string }

func (f fakeOrgs) GetMemberRole(_ context.Context, _, u uuid.UUID) (string, error) {
	if r, ok := f.roles[u]; ok {
		return r, nil
	}
	return "", domain.ErrNotFound
}

type fakeAPITokens struct{ m map[string]*domain.APIToken }

func (f fakeAPITokens) GetByHash(_ context.Context, h string) (*domain.APIToken, error) {
	if t := f.m[h]; t != nil {
		return t, nil
	}
	return nil, domain.ErrNotFound
}

type fakeIPLists struct {
	cidrs      []string
	restricted bool
	err        error
}

func (f *fakeIPLists) AllowedCIDRs(context.Context, *store.Service) ([]string, bool, error) {
	return f.cidrs, f.restricted, f.err
}

type fakeSources struct {
	ports []*domain.ProjectPort
	dbs   []*domain.Database
}

func (f *fakeSources) Ports(context.Context, uuid.UUID) ([]*domain.ProjectPort, error) {
	return f.ports, nil
}
func (f *fakeSources) Databases(context.Context, uuid.UUID) ([]*domain.Database, error) {
	return f.dbs, nil
}

type fakeSvcTokens struct {
	mu sync.Mutex
	m  map[uuid.UUID]*ServiceToken
}

func (f *fakeSvcTokens) Create(_ context.Context, t *ServiceToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[uuid.UUID]*ServiceToken{}
	}
	c := *t
	f.m[t.ID] = &c
	return nil
}
func (f *fakeSvcTokens) GetByHash(_ context.Context, h string) (*ServiceToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.m {
		if t.Hash == h {
			c := *t
			return &c, nil
		}
	}
	return nil, domain.ErrNotFound
}
func (f *fakeSvcTokens) List(_ context.Context, p uuid.UUID) ([]*ServiceToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*ServiceToken
	for _, t := range f.m {
		if t.ProjectID == p {
			c := *t
			out = append(out, &c)
		}
	}
	return out, nil
}
func (f *fakeSvcTokens) CountActive(_ context.Context, p uuid.UUID, now time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, t := range f.m {
		if t.ProjectID == p && t.Active(now) {
			n++
		}
	}
	return n, nil
}
func (f *fakeSvcTokens) Revoke(_ context.Context, p, id uuid.UUID) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t := f.m[id]; t != nil && t.ProjectID == p && t.RevokedAt == nil {
		now := time.Now()
		t.RevokedAt = &now
		return true, nil
	}
	return false, nil
}
func (f *fakeSvcTokens) TouchUsed(context.Context, uuid.UUID) error { return nil }

type fakeAudit struct {
	mu      sync.Mutex
	entries []gitaudit.Entry
}

func (f *fakeAudit) Append(_ context.Context, e gitaudit.Entry) error {
	f.mu.Lock()
	f.entries = append(f.entries, e)
	f.mu.Unlock()
	return nil
}
func (f *fakeAudit) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.entries {
		out = append(out, e.Action)
	}
	return out
}

// ---- test environment --------------------------------------------------------------------------

type env struct {
	t        *testing.T
	svc      *Service
	st       *fakeStore
	audit    *fakeAudit
	logs     *bytes.Buffer
	now      *time.Time
	ips      *fakeIPLists
	src      *fakeSources
	svcTok   *fakeSvcTokens
	apiTok   fakeAPITokens
	az       fakeAuthz
	users    fakeUsers
	orgs     fakeOrgs
	org      uuid.UUID
	project  *domain.Project
	admin    uuid.UUID
	deployer uuid.UUID
	viewer   uuid.UUID
	outsider uuid.UUID
	hidden   uuid.UUID
}

const testSecret = "s3cr3t-shared-value-0123456789abcdef"

func newEnv(t *testing.T, mod ...func(*Config)) *env {
	t.Helper()
	e := &env{t: t, st: newFakeStore(), audit: &fakeAudit{}, logs: &bytes.Buffer{}, ips: &fakeIPLists{}, src: &fakeSources{}, svcTok: &fakeSvcTokens{},
		apiTok: fakeAPITokens{m: map[string]*domain.APIToken{}}, users: fakeUsers{gone: map[uuid.UUID]bool{}}}
	e.org = uuid.New()
	e.project = &domain.Project{ID: uuid.New(), OrgID: e.org, Slug: "shop", Name: "Shop"}
	e.admin, e.deployer, e.viewer, e.outsider, e.hidden = uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	e.az = fakeAuthz{org: e.org, m: map[uuid.UUID]authz.Access{
		e.admin:    {Role: authz.RoleAdmin, Member: true},
		e.deployer: {Role: authz.RoleDeployer, Member: true},
		e.viewer:   {Role: authz.RoleViewer, Member: true},
		e.hidden:   {Member: true, Hidden: true},
	}}
	e.orgs = fakeOrgs{roles: map[uuid.UUID]string{e.admin: "owner", e.deployer: "member", e.viewer: "readonly"}}
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	e.now = &now
	cfg := Config{Secret: testSecret, Zone: "example.test", DestHost: "127.0.0.1", TCPHost: "tcp.example.test", PollInterval: 10 * time.Millisecond,
		SigningKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", DefaultWait: 200 * time.Millisecond, MaxWait: 400 * time.Millisecond}
	for _, m := range mod {
		m(&cfg)
	}
	logger := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc, err := New(Deps{Store: e.st, Projects: fakeProjects{m: map[uuid.UUID]*domain.Project{e.project.ID: e.project}}, Orgs: e.orgs, Users: e.users,
		Authz: e.az, APITokens: e.apiTok, SvcTokens: e.svcTok, IPLists: e.ips, Sources: e.src, Audit: e.audit, Logger: logger, Config: cfg,
		Now: func() time.Time { return *e.now }})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

// expose creates an API-style service (gateway on, route enabled).
func (e *env) expose(name, protocol string, port int) *ServiceView {
	e.t.Helper()
	v, err := e.svc.CreateService(context.Background(), e.project, Actor{UserID: e.admin}, CreateInput{Name: name, Protocol: protocol, ContainerPort: port})
	if err != nil {
		e.t.Fatalf("expose %s: %v", name, err)
	}
	return v
}

// capToken registers a cap_ token for the user and returns its plaintext.
func (e *env) capToken(user uuid.UUID, mod func(*domain.APIToken)) string {
	plain := "cap_" + uuid.NewString() + uuid.NewString()
	t := &domain.APIToken{ID: uuid.New(), UserID: user, Name: "t", TokenHash: sha256Hex(plain)}
	if mod != nil {
		mod(t)
	}
	e.apiTok.m[sha256Hex(plain)] = t
	return plain
}

func (e *env) routeID(name string) uuid.UUID {
	e.t.Helper()
	rv, err := e.st.ResolveService(context.Background(), e.project.ID, name, "tcp")
	if err != nil {
		e.t.Fatalf("route of %s: %v", name, err)
	}
	return rv.ID
}

func (e *env) routeServiceID(name string) uuid.UUID {
	e.t.Helper()
	for _, sv := range e.st.services {
		if sv.Name == name {
			return sv.ID
		}
	}
	e.t.Fatalf("no service %s", name)
	return uuid.Nil
}
