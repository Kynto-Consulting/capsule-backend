package forgejo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

const testToken = "svc-token-SECRET"

// ---- fake Forgejo ------------------------------------------------------------

type fakeHook struct {
	ID     int64
	URL    string
	Secret string
	Events []string
}

type fakeTeam struct {
	ID         int64
	Name       string
	Permission string
	Repos      map[string]bool
	Members    map[string]bool
}

type fakeForgejo struct {
	mu       sync.Mutex
	srv      *httptest.Server
	fail     bool // every request answers 500
	orgs     map[string]bool
	repos    map[string]string // "org/repo" -> default branch
	users    map[string]bool
	hooks    map[string][]*fakeHook
	teams    map[string]*fakeTeam // by "org/name"
	nextID   int64
	calls    []string
	migrated []map[string]any
	badToken int
}

func newFakeForgejo(t *testing.T) *fakeForgejo {
	f := &fakeForgejo{orgs: map[string]bool{}, repos: map[string]string{}, users: map[string]bool{},
		hooks: map[string][]*fakeHook{}, teams: map[string]*fakeTeam{}, nextID: 100}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeForgejo) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (f *fakeForgejo) teamByID(id int64) *fakeTeam {
	for _, t := range f.teams {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func (f *fakeForgejo) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "token "+testToken {
		f.badToken++
		writeJSON(w, 401, map[string]string{"message": "bad token"})
		return
	}
	if f.fail {
		writeJSON(w, 500, map[string]string{"message": "boom " + testToken})
		return
	}
	var body map[string]any
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		if len(b) > 0 {
			_ = json.Unmarshal(b, &body)
		}
	}
	p := strings.TrimPrefix(r.URL.Path, "/api/v1")
	seg := strings.Split(strings.Trim(p, "/"), "/")
	notFound := func() { writeJSON(w, 404, map[string]string{"message": "not found"}) }
	switch {
	case r.Method == "GET" && len(seg) == 2 && seg[0] == "orgs":
		if f.orgs[seg[1]] {
			writeJSON(w, 200, map[string]string{"username": seg[1]})
		} else {
			notFound()
		}
	case r.Method == "POST" && p == "/orgs":
		f.orgs[body["username"].(string)] = true
		writeJSON(w, 201, body)
	case r.Method == "GET" && len(seg) == 3 && seg[0] == "repos":
		if br, ok := f.repos[seg[1]+"/"+seg[2]]; ok {
			writeJSON(w, 200, map[string]any{"name": seg[2], "default_branch": br, "html_url": "x"})
		} else {
			notFound()
		}
	case r.Method == "POST" && len(seg) == 3 && seg[0] == "orgs" && seg[2] == "repos":
		key := seg[1] + "/" + body["name"].(string)
		if _, ok := f.repos[key]; ok {
			writeJSON(w, 409, map[string]string{"message": "exists"})
			return
		}
		f.repos[key] = body["default_branch"].(string)
		writeJSON(w, 201, map[string]any{"name": body["name"], "default_branch": f.repos[key]})
	case r.Method == "POST" && p == "/repos/migrate":
		f.migrated = append(f.migrated, body)
		f.repos[body["repo_owner"].(string)+"/"+body["repo_name"].(string)] = "trunk"
		writeJSON(w, 201, map[string]any{"name": body["repo_name"], "default_branch": "trunk"})
	case len(seg) == 4 && seg[0] == "repos" && seg[3] == "hooks" && r.Method == "GET":
		out := []map[string]any{}
		for _, h := range f.hooks[seg[1]+"/"+seg[2]] {
			out = append(out, map[string]any{"id": h.ID, "config": map[string]string{"url": h.URL}})
		}
		writeJSON(w, 200, out)
	case len(seg) == 4 && seg[0] == "repos" && seg[3] == "hooks" && r.Method == "POST":
		cfg := body["config"].(map[string]any)
		f.nextID++
		f.hooks[seg[1]+"/"+seg[2]] = append(f.hooks[seg[1]+"/"+seg[2]], &fakeHook{ID: f.nextID, URL: cfg["url"].(string), Secret: cfg["secret"].(string), Events: toStrings(body["events"])})
		writeJSON(w, 201, map[string]any{"id": f.nextID})
	case len(seg) == 5 && seg[0] == "repos" && seg[3] == "hooks" && r.Method == "PATCH":
		id, _ := strconv.ParseInt(seg[4], 10, 64)
		for _, h := range f.hooks[seg[1]+"/"+seg[2]] {
			if h.ID == id {
				cfg := body["config"].(map[string]any)
				h.URL, h.Secret, h.Events = cfg["url"].(string), cfg["secret"].(string), toStrings(body["events"])
			}
		}
		writeJSON(w, 200, nil)
	case r.Method == "GET" && len(seg) == 4 && seg[0] == "orgs" && seg[2] == "teams" && seg[3] == "search":
		q := r.URL.Query().Get("q")
		out := []map[string]any{}
		for key, t := range f.teams {
			if strings.HasPrefix(key, seg[1]+"/") && strings.Contains(t.Name, q) {
				out = append(out, map[string]any{"id": t.ID, "name": t.Name})
			}
		}
		writeJSON(w, 200, map[string]any{"ok": true, "data": out})
	case r.Method == "POST" && len(seg) == 3 && seg[0] == "orgs" && seg[2] == "teams":
		f.nextID++
		name := body["name"].(string)
		f.teams[seg[1]+"/"+name] = &fakeTeam{ID: f.nextID, Name: name, Permission: body["permission"].(string), Repos: map[string]bool{}, Members: map[string]bool{}}
		writeJSON(w, 201, map[string]any{"id": f.nextID, "name": name})
	case r.Method == "PUT" && len(seg) == 5 && seg[0] == "teams" && seg[2] == "repos":
		id, _ := strconv.ParseInt(seg[1], 10, 64)
		f.teamByID(id).Repos[seg[3]+"/"+seg[4]] = true
		writeJSON(w, 204, nil)
	case r.Method == "GET" && len(seg) == 3 && seg[0] == "teams" && seg[2] == "members":
		id, _ := strconv.ParseInt(seg[1], 10, 64)
		out := []map[string]string{}
		for m := range f.teamByID(id).Members {
			out = append(out, map[string]string{"login": m})
		}
		writeJSON(w, 200, out)
	case len(seg) == 4 && seg[0] == "teams" && seg[2] == "members" && r.Method == "PUT":
		id, _ := strconv.ParseInt(seg[1], 10, 64)
		f.teamByID(id).Members[seg[3]] = true
		writeJSON(w, 204, nil)
	case len(seg) == 4 && seg[0] == "teams" && seg[2] == "members" && r.Method == "DELETE":
		id, _ := strconv.ParseInt(seg[1], 10, 64)
		delete(f.teamByID(id).Members, seg[3])
		writeJSON(w, 204, nil)
	case r.Method == "GET" && len(seg) == 2 && seg[0] == "users":
		if f.users[seg[1]] {
			writeJSON(w, 200, map[string]string{"login": seg[1]})
		} else {
			notFound()
		}
	default:
		writeJSON(w, 400, map[string]string{"message": "unexpected " + r.Method + " " + r.URL.Path})
	}
}

func toStrings(v any) []string {
	var out []string
	if a, ok := v.([]any); ok {
		for _, x := range a {
			out = append(out, fmt.Sprint(x))
		}
	}
	return out
}

func (f *fakeForgejo) members(org, team string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.teams[org+"/"+team]
	if t == nil {
		return nil
	}
	var out []string
	for m := range t.Members {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// ---- fake Capsule stores --------------------------------------------------------

type memGit struct {
	domain.GitRepository
	mu   sync.Mutex
	link *domain.ProjectGit
}

func (m *memGit) Get(_ context.Context, id uuid.UUID) (*domain.ProjectGit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.link != nil && m.link.ProjectID == id {
		c := *m.link
		return &c, nil
	}
	return nil, domain.ErrNotFound
}

func (m *memGit) Upsert(_ context.Context, g *domain.ProjectGit) (*domain.ProjectGit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *g
	m.link = &c
	return &c, nil
}

type memProjects struct {
	domain.ProjectRepository
	p *domain.Project
}

func (m memProjects) GetByID(_ context.Context, id uuid.UUID) (*domain.Project, error) {
	if m.p.ID == id {
		return m.p, nil
	}
	return nil, domain.ErrNotFound
}

func (m memProjects) ListByOrg(context.Context, uuid.UUID, int, int) ([]*domain.Project, int, error) {
	return []*domain.Project{m.p}, 1, nil
}

type memOrgs struct {
	domain.OrganizationRepository
	org     *domain.Organization
	mu      sync.Mutex
	members []*domain.OrgMember
}

func (m *memOrgs) GetByID(context.Context, uuid.UUID) (*domain.Organization, error) {
	return m.org, nil
}
func (m *memOrgs) GetMembers(context.Context, uuid.UUID) ([]*domain.OrgMember, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*domain.OrgMember(nil), m.members...), nil
}

type memMembers struct {
	authz.MemberStore
	mu       sync.Mutex
	mode     string
	explicit map[uuid.UUID]string
}

func (m *memMembers) GetOrgAccessMode(context.Context, uuid.UUID) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode, nil
}

func (m *memMembers) ListExplicit(context.Context, uuid.UUID) ([]authz.Member, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []authz.Member
	for u, r := range m.explicit {
		out = append(out, authz.Member{UserID: u, Role: r})
	}
	return out, nil
}

type memStore struct {
	mu      sync.Mutex
	state   map[uuid.UUID]*domain.GitCoreState
	pending map[uuid.UUID]map[uuid.UUID]bool
	next    map[uuid.UUID]time.Time
}

func newMemStore() *memStore {
	return &memStore{state: map[uuid.UUID]*domain.GitCoreState{}, pending: map[uuid.UUID]map[uuid.UUID]bool{}, next: map[uuid.UUID]time.Time{}}
}

func (s *memStore) GetState(_ context.Context, id uuid.UUID) (*domain.GitCoreState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.state[id]; ok {
		c := *st
		return &c, nil
	}
	return nil, domain.ErrNotFound
}

func (s *memStore) PutState(_ context.Context, st *domain.GitCoreState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *st
	s.state[st.ProjectID] = &c
	return nil
}

func (s *memStore) ListDueStates(_ context.Context, now time.Time, _ int) ([]*domain.GitCoreState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*domain.GitCoreState
	for _, st := range s.state {
		if st.Status == domain.GitCorePending && !st.NextAttemptAt.After(now) {
			c := *st
			out = append(out, &c)
		}
	}
	return out, nil
}

func (s *memStore) ReplaceTeamSync(_ context.Context, id uuid.UUID, pending []uuid.UUID, _ string, next time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := map[uuid.UUID]bool{}
	for _, u := range pending {
		set[u] = true
	}
	s.pending[id] = set
	s.next[id] = next
	return nil
}

func (s *memStore) ListDueTeamSync(_ context.Context, now time.Time, _ int) ([]*domain.GitTeamSync, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*domain.GitTeamSync
	for id, set := range s.pending {
		if len(set) == 0 || s.next[id].After(now) {
			continue
		}
		for u := range set {
			out = append(out, &domain.GitTeamSync{ProjectID: id, UserID: u})
		}
	}
	return out, nil
}

func (s *memStore) pendingFor(id uuid.UUID) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending[id])
}

// ---- rig --------------------------------------------------------------------------

type rig struct {
	f       *fakeForgejo
	core    *Core
	git     *memGit
	store   *memStore
	orgs    *memOrgs
	mem     *memMembers
	project *domain.Project
	now     time.Time
	mu      sync.Mutex
}

func publicPolicy() gitsource.Policy {
	return gitsource.Policy{Lookup: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil }}
}

func newRig(t *testing.T) *rig {
	t.Helper()
	f := newFakeForgejo(t)
	org := &domain.Organization{ID: uuid.New(), Slug: "acme"}
	p := &domain.Project{ID: uuid.New(), OrgID: org.ID, Slug: "shop"}
	r := &rig{f: f, git: &memGit{}, store: newMemStore(), orgs: &memOrgs{org: org}, mem: &memMembers{mode: authz.ModeOpen, explicit: map[uuid.UUID]string{}},
		project: p, now: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}
	r.core = &Core{
		Client:    NewClient(Config{URL: f.srv.URL, Token: testToken, SSHHost: "git.example.com"}),
		PublicURL: "https://api.example.com",
		Git:       r.git, Projects: memProjects{p: p}, Orgs: r.orgs, Members: r.mem, Store: r.store,
		Username: func(_ context.Context, _ uuid.UUID, email string) (string, error) {
			return strings.Split(email, "@")[0], nil
		},
		Policy: publicPolicy(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:    func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now },
	}
	return r
}

func (r *rig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func (r *rig) addMember(role, name string) uuid.UUID {
	id := uuid.New()
	r.orgs.mu.Lock()
	r.orgs.members = append(r.orgs.members, &domain.OrgMember{UserID: id, Email: name + "@example.com", Role: role})
	r.orgs.mu.Unlock()
	return id
}

// ---- tests ------------------------------------------------------------------------

func TestProvisionCreatesOrgRepoWebhookAndLinkIdempotently(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	res, err := r.core.Provision(ctx, r.project.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.WebURL != r.f.srv.URL+"/acme/shop" || res.CloneHTTPS != r.f.srv.URL+"/acme/shop.git" || res.CloneSSH != "git@git.example.com:acme/shop.git" {
		t.Fatalf("urls %+v", res)
	}
	link := r.git.link
	if link == nil || link.Provider != "forgejo" || !link.AutoDeploy || link.Branch != "main" || link.AuthKind != "token" || link.Credential != testToken || link.RepoURL != res.CloneHTTPS {
		t.Fatalf("link %+v", link)
	}
	if len(link.WebhookSecret) < 32 {
		t.Fatal("random webhook secret expected")
	}
	hooks := r.f.hooks["acme/shop"]
	if len(hooks) != 1 || hooks[0].URL != "https://api.example.com/hooks/git/"+r.project.ID.String() || hooks[0].Secret != link.WebhookSecret {
		t.Fatalf("hooks %+v", hooks)
	}
	if strings.Join(hooks[0].Events, ",") != strings.Join(HookEvents, ",") || len(hooks[0].Events) < 11 {
		t.Fatalf("events %v", hooks[0].Events)
	}
	st, _ := r.store.GetState(ctx, r.project.ID)
	if st == nil || st.Status != domain.GitCoreReady {
		t.Fatalf("state %+v", st)
	}

	secret := link.WebhookSecret
	if _, err := r.core.Provision(ctx, r.project.ID, ""); err != nil {
		t.Fatal(err)
	}
	if r.f.countExact("POST /api/v1/orgs") != 1 || r.f.countExact("POST /api/v1/orgs/acme/repos") != 1 {
		t.Fatalf("org/repo must be created once: %v", r.f.calls)
	}
	if len(r.f.hooks["acme/shop"]) != 1 || r.git.link.WebhookSecret != secret || r.f.hooks["acme/shop"][0].Secret != secret {
		t.Fatal("webhook must be updated in place keeping the secret")
	}
	if r.f.badToken != 0 {
		t.Fatal("every call must carry the service token")
	}
}

func TestProvisionAdoptsExistingRepo(t *testing.T) {
	r := newRig(t)
	r.f.orgs["acme"] = true
	r.f.repos["acme/shop"] = "master"
	if _, err := r.core.Provision(context.Background(), r.project.ID, ""); err != nil {
		t.Fatal(err)
	}
	if r.f.countExact("POST /api/v1/orgs") != 0 || r.f.countExact("POST /api/v1/orgs/acme/repos") != 0 {
		t.Fatalf("nothing should be created: %v", r.f.calls)
	}
	if r.git.link.Branch != "master" {
		t.Fatalf("branch should follow the repo default, got %s", r.git.link.Branch)
	}
}

func TestProvisionImportUsesMigrationAndValidatesURL(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.core.Provision(ctx, r.project.ID, "http://example.com/x.git"); err == nil || !strings.Contains(err.Error(), "invalid import URL") {
		t.Fatalf("http import must be rejected: %v", err)
	}
	r.core.Policy = gitsource.Policy{Lookup: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.5")}, nil }}
	if _, err := r.core.Provision(ctx, r.project.ID, "https://internal.example.com/x.git"); err == nil || !strings.Contains(err.Error(), "invalid import URL") {
		t.Fatalf("private import must be rejected (SSRF): %v", err)
	}
	if len(r.f.migrated) != 0 || r.git.link != nil {
		t.Fatal("rejected imports must not reach Forgejo")
	}
	r.core.Policy = publicPolicy()
	if _, err := r.core.Provision(ctx, r.project.ID, "https://github.com/acme/old.git"); err != nil {
		t.Fatal(err)
	}
	if len(r.f.migrated) != 1 || r.f.migrated[0]["clone_addr"] != "https://github.com/acme/old.git" || r.f.migrated[0]["repo_owner"] != "acme" ||
		r.f.migrated[0]["repo_name"] != "shop" || r.f.migrated[0]["private"] != true || r.f.migrated[0]["mirror"] != false {
		t.Fatalf("migrate body %v", r.f.migrated)
	}
	if r.git.link.Branch != "trunk" {
		t.Fatalf("imported default branch expected, got %s", r.git.link.Branch)
	}
}

func TestProvisionRefusesProjectLinkedToAnotherProvider(t *testing.T) {
	r := newRig(t)
	r.git.link = &domain.ProjectGit{ProjectID: r.project.ID, Provider: "github", RepoURL: "https://github.com/a/b.git"}
	if _, err := r.core.Provision(context.Background(), r.project.ID, ""); err != ErrAlreadyLinked {
		t.Fatalf("got %v", err)
	}
	if len(r.f.calls) != 0 {
		t.Fatal("must not touch Forgejo")
	}
}

func TestForgejoFailureNeverBlocksAndIsRetried(t *testing.T) {
	r := newRig(t)
	r.f.fail = true
	start := time.Now()
	r.core.OnProjectCreated(r.project) // returns immediately
	if time.Since(start) > time.Second {
		t.Fatal("OnProjectCreated must not block")
	}
	r.core.Wait()
	st, err := r.store.GetState(context.Background(), r.project.ID)
	if err != nil || st.Status != domain.GitCorePending || st.Attempts != 1 || st.LastError == "" {
		t.Fatalf("state %+v err %v", st, err)
	}
	if strings.Contains(st.LastError, testToken) {
		t.Fatalf("token leaked in visible state: %s", st.LastError)
	}
	if r.git.link != nil {
		t.Fatal("no link while provisioning fails")
	}

	// Not due yet: no retry. After the backoff it succeeds once Forgejo is back.
	r.f.fail = false
	r.core.RetryOnce(context.Background())
	if r.git.link != nil {
		t.Fatal("retry must wait for next_attempt_at")
	}
	r.advance(2 * time.Minute)
	r.core.RetryOnce(context.Background())
	st, _ = r.store.GetState(context.Background(), r.project.ID)
	if r.git.link == nil || st.Status != domain.GitCoreReady || st.LastError != "" {
		t.Fatalf("retry should have provisioned: state %+v link %+v", st, r.git.link)
	}
}

func TestProvisionGivesUpAfterMaxAttempts(t *testing.T) {
	r := newRig(t)
	r.f.fail = true
	for i := 0; i < maxProvisionAttempts; i++ {
		_, _ = r.core.Provision(context.Background(), r.project.ID, "")
	}
	st, _ := r.store.GetState(context.Background(), r.project.ID)
	if st.Status != domain.GitCoreFailed {
		t.Fatalf("expected failed, got %+v", st)
	}
	r.advance(24 * time.Hour)
	before := len(r.f.calls)
	r.core.RetryOnce(context.Background())
	if len(r.f.calls) != before {
		t.Fatal("failed projects are not retried automatically")
	}
}

func TestDisabledCoreDoesNothing(t *testing.T) {
	r := newRig(t)
	r.core.Client = NewClient(Config{})
	r.core.OnProjectCreated(r.project)
	r.core.OnMembersChanged(r.project.OrgID, r.project.ID)
	r.core.OnOrgChanged(r.project.OrgID)
	r.core.Wait()
	if _, err := r.core.Provision(context.Background(), r.project.ID, ""); err != ErrDisabled {
		t.Fatalf("got %v", err)
	}
	if len(r.f.calls) != 0 || len(r.store.state) != 0 {
		t.Fatal("disabled integration must be inert")
	}
	if w, h, s := r.core.Links(&domain.ProjectGit{Provider: "forgejo", RepoURL: "https://x.test/a/b.git"}); w != "" || h != "" || s != "" {
		t.Fatal("no links when disabled")
	}
}

func TestTeamSyncPendingUntilForgejoUserExists(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.core.Provision(ctx, r.project.ID, ""); err != nil {
		t.Fatal(err)
	}
	alice := r.addMember("owner", "alice")
	bob := r.addMember("member", "bob")
	carol := r.addMember("member", "carol")
	_ = carol
	r.mem.explicit[bob] = "viewer"
	r.f.users["alice"] = true

	if err := r.core.SyncProject(ctx, r.project.ID); err != nil {
		t.Fatal(err)
	}
	if got := r.f.members("acme", "shop-admin"); strings.Join(got, ",") != "alice" {
		t.Fatalf("admin team %v calls=%v", got, r.f.calls)
	}
	if r.store.pendingFor(r.project.ID) != 2 {
		t.Fatalf("bob and carol must be pending, got %d", r.store.pendingFor(r.project.ID))
	}
	// team shape: permissions and repo assignment
	for name, perm := range map[string]string{"shop-admin": "admin", "shop-deployer": "write", "shop-viewer": "read"} {
		tm := r.f.teams["acme/"+name]
		if tm == nil || tm.Permission != perm || !tm.Repos["acme/shop"] {
			t.Fatalf("team %s: %+v", name, tm)
		}
	}

	// Their first OIDC login creates the Forgejo users; the periodic retry applies it.
	r.f.users["bob"], r.f.users["carol"] = true, true
	r.core.RetryOnce(ctx) // not due yet
	if r.store.pendingFor(r.project.ID) != 2 {
		t.Fatal("retry must respect next_attempt_at")
	}
	r.advance(3 * time.Minute)
	r.core.RetryOnce(ctx)
	if r.store.pendingFor(r.project.ID) != 0 {
		t.Fatalf("pending must be applied, got %d", r.store.pendingFor(r.project.ID))
	}
	if strings.Join(r.f.members("acme", "shop-viewer"), ",") != "bob" || strings.Join(r.f.members("acme", "shop-deployer"), ",") != "carol" {
		t.Fatalf("viewer %v deployer %v", r.f.members("acme", "shop-viewer"), r.f.members("acme", "shop-deployer"))
	}

	// Role change: bob viewer -> deployer moves him between teams.
	r.mem.explicit[bob] = "deployer"
	r.core.OnMembersChanged(r.project.OrgID, r.project.ID)
	r.core.Wait()
	if len(r.f.members("acme", "shop-viewer")) != 0 || strings.Join(r.f.members("acme", "shop-deployer"), ",") != "bob,carol" {
		t.Fatalf("after role change: viewer %v deployer %v", r.f.members("acme", "shop-viewer"), r.f.members("acme", "shop-deployer"))
	}

	// Restricted mode: members without an explicit role lose access (carol), explicit ones keep it.
	r.mem.mode = authz.ModeRestricted
	r.core.OnOrgChanged(r.project.OrgID)
	r.core.Wait()
	if strings.Join(r.f.members("acme", "shop-deployer"), ",") != "bob" {
		t.Fatalf("restricted mode: %v", r.f.members("acme", "shop-deployer"))
	}

	// Leaving the organization revokes everything.
	r.orgs.mu.Lock()
	r.orgs.members = r.orgs.members[:0]
	r.orgs.mu.Unlock()
	r.core.OnOrgChanged(r.project.OrgID)
	r.core.Wait()
	for _, team := range []string{"shop-admin", "shop-deployer", "shop-viewer"} {
		if m := r.f.members("acme", team); len(m) != 0 {
			t.Fatalf("%s still has %v", team, m)
		}
	}
	_ = alice
}

func TestTeamSyncFailureDoesNotPanicOrBlockAndSkipsUnlinkedProjects(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	// No link yet: nothing to do, no Forgejo calls.
	if err := r.core.SyncProject(ctx, r.project.ID); err != nil || len(r.f.calls) != 0 {
		t.Fatalf("unlinked project: err=%v calls=%v", err, r.f.calls)
	}
	if _, err := r.core.Provision(ctx, r.project.ID, ""); err != nil {
		t.Fatal(err)
	}
	r.f.fail = true
	r.core.OnMembersChanged(r.project.OrgID, r.project.ID)
	r.core.Wait() // the failure is only logged
}

func TestLinksAndSSHFormats(t *testing.T) {
	cfg := Config{URL: "https://git.tumi-ai.com", Token: "t", SSHHost: "git.tumi-ai.com"}
	if cfg.CloneSSH("a", "b") != "git@git.tumi-ai.com:a/b.git" {
		t.Fatal(cfg.CloneSSH("a", "b"))
	}
	cfg.SSHHost = "git.tumi-ai.com:2222"
	if cfg.CloneSSH("a", "b") != "ssh://git@git.tumi-ai.com:2222/a/b.git" {
		t.Fatal(cfg.CloneSSH("a", "b"))
	}
	cfg.SSHHost = ""
	if cfg.CloneSSH("a", "b") != "git@git.tumi-ai.com:a/b.git" {
		t.Fatal("ssh host falls back to the web host")
	}
	c := &Core{Client: NewClient(cfg)}
	w, h, s := c.Links(&domain.ProjectGit{Provider: "forgejo", RepoURL: "https://git.tumi-ai.com/acme/shop.git"})
	if w != "https://git.tumi-ai.com/acme/shop" || h != "https://git.tumi-ai.com/acme/shop.git" || s != "git@git.tumi-ai.com:acme/shop.git" {
		t.Fatalf("%s %s %s", w, h, s)
	}
	if w, _, _ := c.Links(&domain.ProjectGit{Provider: "github", RepoURL: "https://github.com/a/b.git"}); w != "" {
		t.Fatal("only forgejo links get URLs")
	}
}

func (f *fakeForgejo) countExact(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == call {
			n++
		}
	}
	return n
}
