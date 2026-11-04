package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/systemtemplates"
)

// memStore is the in-memory Store of the tests. It behaves like the repository will: every write bumps
// the epoch of the organization (and of the user when the account changes), group assignments reach the
// users that are members of the group, and revoked rows, archived groups and expired group memberships
// never come out of LoadAccess.
type memStore struct {
	mu         sync.Mutex
	orgEpoch   map[uuid.UUID]int64
	userEpoch  map[uuid.UUID]int64
	userActive map[uuid.UUID]bool
	policy     map[uuid.UUID]string
	overrides  map[uuid.UUID]map[uuid.UUID]string
	members    map[memKey]*memMember
	groups     map[uuid.UUID]*memGroup
	assigns    []*memAssign

	loads, epochCalls int
	loadErr, epochErr error
	// afterRead runs after LoadAccess copied its data and before it returns (to interleave a write).
	afterRead func()
}

type memKey struct{ org, user uuid.UUID }

type memMember struct {
	active bool
	tpl    *OrgTemplate
}

type memGroup struct {
	org      uuid.UUID
	archived bool
	members  map[uuid.UUID]time.Time // user -> membership expiry (zero: none)
}

type memAssign struct {
	Assignment
	org     uuid.UUID
	revoked bool
}

func newMemStore() *memStore {
	return &memStore{
		orgEpoch: map[uuid.UUID]int64{}, userEpoch: map[uuid.UUID]int64{}, userActive: map[uuid.UUID]bool{},
		policy: map[uuid.UUID]string{}, overrides: map[uuid.UUID]map[uuid.UUID]string{},
		members: map[memKey]*memMember{}, groups: map[uuid.UUID]*memGroup{},
	}
}

// ---- builders from the system templates ----

func sysOrgTemplate(slug string) *OrgTemplate {
	t, ok := systemtemplates.Org(slug)
	if !ok {
		panic("no system org template " + slug)
	}
	return &OrgTemplate{
		ID: t.ID, Slug: t.Slug, Version: t.Version, Permissions: t.Permissions,
		FloorID: t.FloorID, BaseID: t.BaseID, Floor: t.Floor, Base: t.Base,
		HasCeiling: t.HasCeiling, Ceiling: t.Ceiling, CeilingProject: t.CeilingProject,
	}
}

type tplRef struct {
	id   uuid.UUID
	slug string
	set  Set
}

func sysProjectTemplate(slug string) tplRef {
	t, ok := systemtemplates.Project(slug)
	if !ok {
		panic("no system project template " + slug)
	}
	return tplRef{t.ID, t.Slug, t.Permissions}
}

func sysRepoTemplate(slug string) tplRef {
	t, ok := systemtemplates.Repo(slug)
	if !ok {
		panic("no system repo template " + slug)
	}
	return tplRef{t.ID, t.Slug, t.Permissions}
}

// ---- writes ----

func (m *memStore) bumpOrg(org uuid.UUID)   { m.orgEpoch[org]++ }
func (m *memStore) bumpUser(user uuid.UUID) { m.userEpoch[user]++ }
func (m *memStore) newUser() uuid.UUID      { u := uuid.New(); m.userActive[u] = true; return u }
func (m *memStore) newOrg(policy string) uuid.UUID {
	o := uuid.New()
	m.policy[o] = policy
	return o
}

func (m *memStore) setMember(org, user uuid.UUID, tpl *OrgTemplate, active bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.members[memKey{org, user}] = &memMember{active: active, tpl: tpl}
	m.bumpOrg(org)
}

func (m *memStore) removeMember(org, user uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.members, memKey{org, user})
	m.bumpOrg(org)
}

func (m *memStore) setUserActive(user uuid.UUID, active bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.userActive[user] = active
	m.bumpUser(user)
}

func (m *memStore) setPolicy(org uuid.UUID, policy string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy[org] = policy
	m.bumpOrg(org)
}

func (m *memStore) setOverride(org, project uuid.UUID, mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.overrides[org] == nil {
		m.overrides[org] = map[uuid.UUID]string{}
	}
	m.overrides[org][project] = mode
	m.bumpOrg(org)
}

func (m *memStore) newGroup(org uuid.UUID) uuid.UUID {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := uuid.New()
	m.groups[g] = &memGroup{org: org, members: map[uuid.UUID]time.Time{}}
	m.bumpOrg(org)
	return g
}

func (m *memStore) join(group, user uuid.UUID, expires time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.groups[group]
	g.members[user] = expires
	m.bumpOrg(g.org)
}

func (m *memStore) archiveGroup(group uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.groups[group]
	g.archived = true
	m.bumpOrg(g.org)
}

// assignOpts describes an assignment to create.
type assignOpts struct {
	kind      SubjectKind
	subject   uuid.UUID
	scope     ScopeType
	scopeID   uuid.UUID
	projectID uuid.UUID
	tpl       tplRef
	source    string
	expires   time.Time
}

func (m *memStore) assign(org uuid.UUID, o assignOpts) uuid.UUID {
	m.mu.Lock()
	defer m.mu.Unlock()
	if o.source == "" {
		o.source = AssignManual
	}
	a := &memAssign{org: org, Assignment: Assignment{
		ID: uuid.New(), SubjectKind: o.kind, SubjectID: o.subject, Scope: o.scope, ScopeID: o.scopeID,
		ProjectID: o.projectID, TemplateID: o.tpl.id, TemplateSlug: o.tpl.slug, TemplateVersion: 1,
		Permissions: o.tpl.set, Source: o.source, ExpiresAt: o.expires,
	}}
	m.assigns = append(m.assigns, a)
	m.bumpOrg(org)
	return a.ID
}

func (m *memStore) revoke(id uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.assigns {
		if a.ID == id {
			a.revoked = true
			m.bumpOrg(a.org)
		}
	}
}

// ---- engine.Store ----

var errInjected = errors.New("injected store failure")

func (m *memStore) Epochs(_ context.Context, user, org uuid.UUID) (Epochs, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.epochCalls++
	if m.epochErr != nil {
		return Epochs{}, m.epochErr
	}
	return Epochs{m.orgEpoch[org], m.userEpoch[user]}, nil
}

func (m *memStore) LoadAccess(_ context.Context, user, org uuid.UUID) (*AccessData, error) {
	m.mu.Lock()
	m.loads++
	if m.loadErr != nil {
		err := m.loadErr
		m.mu.Unlock()
		return nil, err
	}
	d := &AccessData{Epochs: Epochs{m.orgEpoch[org], m.userEpoch[user]}, Policy: m.policy[org]}
	if mem, ok := m.members[memKey{org, user}]; ok {
		d.Member, d.MemberActive, d.UserActive, d.Template = true, mem.active, m.userActive[user], mem.tpl
	}
	if len(m.overrides[org]) > 0 {
		d.ProjectOverrides = make(map[uuid.UUID]string, len(m.overrides[org]))
		for p, v := range m.overrides[org] {
			d.ProjectOverrides[p] = v
		}
	}
	for _, a := range m.assigns {
		if a.org != org || a.revoked {
			continue
		}
		out := a.Assignment
		switch a.SubjectKind {
		case SubjectUser:
			if a.SubjectID != user {
				continue
			}
		case SubjectGroup:
			g := m.groups[a.SubjectID]
			if g == nil || g.archived {
				continue
			}
			exp, in := g.members[user]
			if !in {
				continue
			}
			if !exp.IsZero() && (out.ExpiresAt.IsZero() || exp.Before(out.ExpiresAt)) {
				out.ExpiresAt = exp
			}
		}
		d.Assignments = append(d.Assignments, out)
	}
	hook := m.afterRead
	m.mu.Unlock()
	if hook != nil {
		hook()
	}
	return d, nil
}

func (m *memStore) loadCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loads
}

// ---- fake clock ----

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func must(t testing.TB, ok bool, msg string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(msg, args...)
	}
}
