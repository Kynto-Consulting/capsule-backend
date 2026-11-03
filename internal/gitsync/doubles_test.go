package gitsync

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

// ---- in-memory doubles ----------------------------------------------------------------------

type memIDs struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*Identity
}

func newMemIDs() *memIDs { return &memIDs{rows: map[uuid.UUID]*Identity{}} }

func (m *memIDs) Get(_ context.Context, id uuid.UUID) (*Identity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.rows[id]; r != nil {
		c := *r
		return &c, nil
	}
	return nil, ErrNoIdentity
}

func (m *memIDs) Ensure(_ context.Context, id uuid.UUID, login string) (*Identity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.rows[id]; r != nil {
		c := *r
		return &c, nil
	}
	for _, r := range m.rows {
		if strings.EqualFold(r.ForgejoUsername, login) {
			return nil, ErrUsernameTaken
		}
	}
	m.rows[id] = &Identity{UserID: id, ForgejoUsername: login}
	c := *m.rows[id]
	return &c, nil
}

func (m *memIDs) MarkLinked(_ context.Context, id uuid.UUID, fid int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.rows[id]; r != nil {
		now := time.Now()
		r.LinkedAt = &now
		if fid > 0 {
			r.ForgejoUserID = &fid
		}
	}
	return nil
}

type audit struct {
	action string
	values map[string]any
}

type memStates struct {
	mu       sync.Mutex
	states   map[string]TeamState
	projects []uuid.UUID
	audits   []audit
}

func newMemStates() *memStates { return &memStates{states: map[string]TeamState{}} }

func (m *memStates) PutTeamState(_ context.Context, st TeamState, drift bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := st.ProjectID.String() + "/" + string(st.Role)
	old := m.states[k]
	st.DriftEvents = old.DriftEvents
	st.LastDriftAt = old.LastDriftAt
	if drift {
		st.DriftEvents++
		t := st.LastSyncedAt
		st.LastDriftAt = &t
	} else {
		st.LastDriftAdded, st.LastDriftRemoved = old.LastDriftAdded, old.LastDriftRemoved
	}
	m.states[k] = st
	return nil
}

func (m *memStates) ListTeamStates(_ context.Context, p uuid.UUID) ([]TeamState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []TeamState
	for _, r := range Roles {
		if s, ok := m.states[p.String()+"/"+string(r)]; ok {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *memStates) ListForgejoProjects(_ context.Context, after uuid.UUID, limit int) ([]uuid.UUID, error) {
	var out []uuid.UUID
	for _, p := range m.projects {
		if strings.Compare(p.String(), after.String()) > 0 {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *memStates) AuditDrift(_ context.Context, _, _ uuid.UUID, action string, v map[string]any) error {
	m.mu.Lock()
	m.audits = append(m.audits, audit{action, v})
	m.mu.Unlock()
	return nil
}

type memPending struct {
	mu      sync.Mutex
	pending map[uuid.UUID][]uuid.UUID
}

func (m *memPending) ReplaceTeamSync(_ context.Context, p uuid.UUID, pend []uuid.UUID, _ string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		m.pending = map[uuid.UUID][]uuid.UUID{}
	}
	m.pending[p] = append([]uuid.UUID(nil), pend...)
	return nil
}

type memForge struct {
	mu        sync.Mutex
	disabled  bool
	users     map[string]bool
	teams     map[string]*gitcore.Team // "org/name"
	members   map[int64]map[string]bool
	nextID    int64
	mutations int
	failRm    map[string]bool // login whose removal fails
	failExist bool
	permOf    map[string]string // forced permission of an existing team name
}

func newForge() *memForge {
	return &memForge{users: map[string]bool{}, teams: map[string]*gitcore.Team{}, members: map[int64]map[string]bool{},
		failRm: map[string]bool{}, permOf: map[string]string{}}
}

func (f *memForge) Enabled() bool                           { return !f.disabled }
func (f *memForge) EnsureOrg(context.Context, string) error { return nil }
func (f *memForge) UserExists(_ context.Context, l string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failExist {
		return false, errors.New("forgejo down")
	}
	return f.users[l], nil
}
func (f *memForge) EnsureTeam(_ context.Context, org string, s gitcore.TeamSpec) (*gitcore.Team, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := org + "/" + s.Name
	if t := f.teams[k]; t != nil {
		c := *t
		if p, ok := f.permOf[s.Name]; ok {
			c.Permission = p
		}
		return &c, nil
	}
	f.nextID++
	f.mutations++
	t := &gitcore.Team{ID: f.nextID, Name: s.Name, Permission: s.Permission}
	f.teams[k], f.members[t.ID] = t, map[string]bool{}
	c := *t
	return &c, nil
}
func (f *memForge) AddTeamRepo(context.Context, int64, gitcore.RepoRef) error { return nil }
func (f *memForge) TeamMembers(_ context.Context, id int64) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for l := range f.members[id] {
		out = append(out, strings.ToUpper(l[:1])+l[1:]) // Forgejo may return any case: the reconciler lowercases
	}
	return out, nil
}
func (f *memForge) AddTeamMember(_ context.Context, id int64, l string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mutations++
	f.members[id][l] = true
	return nil
}
func (f *memForge) RemoveTeamMember(_ context.Context, id int64, l string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRm[l] {
		return errors.New("boom")
	}
	f.mutations++
	delete(f.members[id], l)
	return nil
}

// everywhere returns every team name a login is in.
func (f *memForge) everywhere(login string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, t := range f.teams {
		if f.members[t.ID][login] {
			out = append(out, t.Name)
		}
	}
	sort.Strings(out)
	return out
}

type memDir struct {
	info     *ProjectInfo
	members  []Member
	mode     string
	explicit map[uuid.UUID]string
}

func (d *memDir) Project(_ context.Context, id uuid.UUID) (*ProjectInfo, error) {
	if d.info == nil || d.info.ID != id {
		return nil, nil
	}
	return d.info, nil
}
func (d *memDir) Members(context.Context, uuid.UUID) ([]Member, error) { return d.members, nil }
func (d *memDir) Access(context.Context, uuid.UUID, uuid.UUID) (string, map[uuid.UUID]string, error) {
	return d.mode, d.explicit, nil
}

type janitor struct {
	calls []string
	n     int
}

func (j *janitor) DropPendingReviews(_ context.Context, r gitcore.RepoRef, login string) (int, error) {
	j.calls = append(j.calls, r.String()+":"+login)
	return j.n, nil
}

// ---- fixture --------------------------------------------------------------------------------

type fixture struct {
	rec    *Reconciler
	forge  *memForge
	dir    *memDir
	ids    *memIDs
	states *memStates
	pend   *memPending
	jan    *janitor
	proj   uuid.UUID
	org    uuid.UUID
	users  map[string]uuid.UUID // login -> id
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{forge: newForge(), ids: newMemIDs(), states: newMemStates(), pend: &memPending{}, jan: &janitor{n: 2},
		proj: uuid.New(), org: uuid.New(), users: map[string]uuid.UUID{}}
	f.dir = &memDir{
		info: &ProjectInfo{ID: f.proj, OrgID: f.org, Slug: "api", Repo: gitcore.RepoRef{Owner: "acme", Repo: "api"}},
		mode: authz.ModeOpen, explicit: map[uuid.UUID]string{},
	}
	f.rec = &Reconciler{Forge: f.forge, Dir: f.dir, IDs: &Identities{Store: f.ids}, States: f.states, Pending: f.pend, Janitor: f.jan}
	f.states.projects = []uuid.UUID{f.proj}
	return f
}

// add registers an org member whose e-mail local part is the login.
func (f *fixture) add(login, orgRole string, inForgejo bool) uuid.UUID {
	id := uuid.New()
	f.users[login] = id
	f.dir.members = append(f.dir.members, Member{UserID: id, Email: login + "@x.io", OrgRole: orgRole})
	if inForgejo {
		f.forge.users[login] = true
	}
	return id
}

func (f *fixture) remove(login string) {
	var keep []Member
	for _, m := range f.dir.members {
		if m.UserID != f.users[login] {
			keep = append(keep, m)
		}
	}
	f.dir.members = keep
}

func (f *fixture) run(t *testing.T, trig Trigger) *Report {
	t.Helper()
	rep, err := f.rec.Reconcile(context.Background(), f.proj, trig)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if rep == nil {
		t.Fatal("nil report")
	}
	return rep
}

func inTeams(t *testing.T, f *fixture, login string, want ...string) {
	t.Helper()
	got := f.forge.everywhere(login)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s is in teams %v, want %v", login, got, want)
	}
}
