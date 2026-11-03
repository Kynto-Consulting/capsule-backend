package environments

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

// memStore is an in-memory Store with the same atomic rules as the Postgres one.
type memStore struct {
	mu        sync.Mutex
	targets   map[uuid.UUID]Target
	envs      map[uuid.UUID]*Environment
	promos    map[uuid.UUID]*Promotion
	hist      map[uuid.UUID]*EnvDeployment // by promotion
	artifacts map[string]*Artifact         // project|sha
	arts      map[uuid.UUID]*Artifact
	audits    []AuditEntry
}

func newMemStore() *memStore {
	return &memStore{targets: map[uuid.UUID]Target{}, envs: map[uuid.UUID]*Environment{}, promos: map[uuid.UUID]*Promotion{},
		hist: map[uuid.UUID]*EnvDeployment{}, artifacts: map[string]*Artifact{}, arts: map[uuid.UUID]*Artifact{}}
}

func (m *memStore) actions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, a := range m.audits {
		out = append(out, a.Action)
	}
	return out
}

func (m *memStore) addArtifact(project uuid.UUID, sha string) *Artifact {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := &Artifact{DeploymentID: uuid.New(), SourceKey: "deployments/x/" + sha + ".tar.gz", SHA: sha, BuildStrategy: "docker", ContainerPort: 8080}
	m.artifacts[project.String()+"|"+sha] = a
	m.arts[a.DeploymentID] = a
	return a
}

func (m *memStore) Target(_ context.Context, id uuid.UUID) (Target, error) {
	if t, ok := m.targets[id]; ok {
		return t, nil
	}
	return Target{}, ErrNotFound
}
func (m *memStore) ListEnvs(_ context.Context, pid uuid.UUID) ([]Environment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Environment
	for _, e := range m.envs {
		if e.ProjectID == pid {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func (m *memStore) GetEnv(_ context.Context, pid uuid.UUID, name string) (*Environment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.envs {
		if e.ProjectID == pid && e.Name == name {
			c := *e
			return &c, nil
		}
	}
	return nil, ErrNotFound
}
func (m *memStore) GetEnvByID(_ context.Context, id uuid.UUID) (*Environment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.envs[id]; ok {
		c := *e
		return &c, nil
	}
	return nil, ErrNotFound
}
func (m *memStore) CreateEnv(_ context.Context, e *Environment, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.envs {
		if x.ProjectID == e.ProjectID && x.Name == e.Name {
			return ErrDuplicate
		}
	}
	c := *e
	m.envs[e.ID] = &c
	m.audits = append(m.audits, a)
	return nil
}
func (m *memStore) UpdateEnv(_ context.Context, e *Environment, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.envs[e.ID]; !ok {
		return ErrNotFound
	}
	c := *e
	m.envs[e.ID] = &c
	m.audits = append(m.audits, a)
	return nil
}
func (m *memStore) DeleteEnv(_ context.Context, _ uuid.UUID, id uuid.UUID, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.envs, id)
	m.audits = append(m.audits, a)
	return nil
}
func (m *memStore) CurrentDeployment(context.Context, uuid.UUID) (*EnvDeployment, error) {
	return nil, nil
}
func (m *memStore) ListEnvDeployments(context.Context, uuid.UUID, string, int) ([]EnvDeployment, string, error) {
	return nil, "", nil
}
func (m *memStore) SuccessfulSHA(_ context.Context, envID uuid.UUID, sha string) (*EnvDeployment, *Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.promos {
		if p.EnvironmentID == envID && p.SHA == sha && p.Status == StatusSuccess && p.SourceDeploymentID != nil {
			return m.hist[p.ID], m.arts[*p.SourceDeploymentID], nil
		}
	}
	return nil, nil, nil
}
func (m *memStore) FindArtifact(_ context.Context, pid uuid.UUID, sha string) (*Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.artifacts[pid.String()+"|"+sha], nil
}
func (m *memStore) ArtifactOf(_ context.Context, id uuid.UUID) (*Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.arts[id], nil
}
func (m *memStore) FindByIdempotency(_ context.Context, pid, by uuid.UUID, key string) (*Promotion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.promos {
		if p.ProjectID == pid && p.RequestedBy != nil && *p.RequestedBy == by && p.IdempotencyKey == key {
			c := *p
			return &c, nil
		}
	}
	return nil, nil
}
func (m *memStore) WriteAudit(_ context.Context, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audits = append(m.audits, a)
	return nil
}
func (m *memStore) CreatePromotion(_ context.Context, p *Promotion, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.promos {
		if p.IdempotencyKey != "" && x.ProjectID == p.ProjectID && x.IdempotencyKey == p.IdempotencyKey &&
			x.RequestedBy != nil && p.RequestedBy != nil && *x.RequestedBy == *p.RequestedBy {
			c := *x
			return &ExistingError{Kind: "idempotency", Promotion: &c}
		}
		if x.EnvironmentID == p.EnvironmentID && x.SHA == p.SHA && IsActive(x.Status) {
			c := *x
			return &ExistingError{Kind: "active", Promotion: &c}
		}
	}
	c := *p
	m.promos[p.ID] = &c
	m.hist[p.ID] = &EnvDeployment{ID: uuid.New(), EnvironmentID: p.EnvironmentID, PromotionID: p.ID, SHA: p.SHA, Status: EnvDeploymentStatus(p.Status)}
	m.audits = append(m.audits, a)
	return nil
}
func (m *memStore) GetPromotion(_ context.Context, id uuid.UUID) (*Promotion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.promos[id]; ok {
		c := *p
		c.Approvals = append([]Approval{}, p.Approvals...)
		return &c, nil
	}
	return nil, ErrNotFound
}
func (m *memStore) sorted(f func(*Promotion) bool) []Promotion {
	var out []Promotion
	for _, p := range m.promos {
		if f(p) {
			c := *p
			c.Approvals = append([]Approval{}, p.Approvals...)
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}
func (m *memStore) ListPromotions(_ context.Context, envID uuid.UUID, active bool) ([]Promotion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sorted(func(p *Promotion) bool { return p.EnvironmentID == envID && (!active || IsActive(p.Status)) }), nil
}
func (m *memStore) ListActive(_ context.Context, limit int) ([]Promotion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sorted(func(p *Promotion) bool { return IsActive(p.Status) }), nil
}
func (m *memStore) AddDecision(_ context.Context, d Decision, a AuditEntry) (*Promotion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.promos[d.PromotionID]
	if !ok {
		return nil, ErrNotFound
	}
	approve := d.Approval.Decision == "approved"
	if (approve && p.Status != StatusPending) || (!approve && p.Status != StatusPending && p.Status != StatusWaiting && p.Status != StatusApproved) {
		return nil, ErrInvalidState
	}
	for _, x := range p.Approvals {
		if x.UserID != nil && d.Approval.UserID != nil && *x.UserID == *d.Approval.UserID {
			return nil, ErrAlreadyDecided
		}
	}
	p.Approvals = append(p.Approvals, d.Approval)
	if !approve {
		p.Status, p.StatusReason, p.FinishedAt = StatusRejected, d.RejectReason, &d.RejectedAt
	} else {
		n := 0
		for _, x := range p.Approvals {
			if x.Decision == "approved" && (d.AllowSelf || !x.SelfApproval) {
				n++
			}
		}
		if n >= d.Required {
			q := d.QuorumAt
			p.Status, p.NotBefore, p.QuorumAt = d.QuorumStatus, d.QuorumNotBefore, &q
		}
	}
	m.hist[p.ID].Status = EnvDeploymentStatus(p.Status)
	m.audits = append(m.audits, a)
	c := *p
	c.Approvals = append([]Approval{}, p.Approvals...)
	return &c, nil
}
func (m *memStore) Transition(_ context.Context, id uuid.UUID, from []string, to string, pt Patch, a *AuditEntry) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.promos[id]
	if !ok {
		return false, nil
	}
	in := false
	for _, f := range from {
		in = in || f == p.Status
	}
	if !in {
		return false, nil
	}
	if to == StatusDeploying {
		for _, x := range m.promos {
			if x.EnvironmentID == p.EnvironmentID && x.Status == StatusDeploying {
				return false, nil
			}
		}
	}
	p.Status, p.StatusReason, p.NotBefore = to, pt.Reason, pt.NotBefore
	if pt.QuorumAt != nil {
		p.QuorumAt = pt.QuorumAt
	}
	if pt.StartedAt != nil {
		p.StartedAt = pt.StartedAt
	}
	if pt.FinishedAt != nil {
		p.FinishedAt = pt.FinishedAt
	}
	if pt.Required != nil {
		p.RequiredApprovals = *pt.Required
	}
	m.hist[id].Status = EnvDeploymentStatus(to)
	if a != nil {
		m.audits = append(m.audits, *a)
	}
	return true, nil
}
func (m *memStore) SetDeployment(_ context.Context, id, dep uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.promos[id].DeploymentID = &dep
	return nil
}
func (m *memStore) ExpireOverdue(_ context.Context, now time.Time) ([]Promotion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Promotion
	for _, p := range m.promos {
		if (p.Status == StatusPending || p.Status == StatusWaiting || p.Status == StatusApproved) && !p.ExpiresAt.After(now) {
			p.Status, p.FinishedAt = StatusExpired, &now
			out = append(out, *p)
		}
	}
	return out, nil
}
func (m *memStore) PendingForOrg(_ context.Context, orgID uuid.UUID, cursor string, limit int) ([]PendingRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PendingRow
	for _, p := range m.sorted(func(p *Promotion) bool { return p.Status == StatusPending && m.targets[p.ProjectID].OrgID == orgID }) {
		out = append(out, PendingRow{Promotion: p, Env: *m.envs[p.EnvironmentID]})
	}
	return out, nil
}

// ---- other fakes ----------------------------------------------------------------------------------

type fakeForge struct {
	mu       sync.Mutex
	branches map[string]string // name -> head sha
	ancestor map[string]bool   // "branch|sha" -> sha is an ancestor of branch
	checks   map[string][]gitcore.Check
	set      []gitcore.CheckInput
}

func newForge() *fakeForge {
	return &fakeForge{branches: map[string]string{}, ancestor: map[string]bool{}, checks: map[string][]gitcore.Check{}}
}
func (f *fakeForge) Enabled() bool { return true }
func (f *fakeForge) ListBranches(context.Context, gitcore.RepoRef, gitcore.Page) (gitcore.List[gitcore.Branch], error) {
	var l gitcore.List[gitcore.Branch]
	for n, s := range f.branches {
		l.Items = append(l.Items, gitcore.Branch{Name: n, SHA: s, Default: n == "main"})
	}
	return l, nil
}
func (f *fakeForge) ListTags(context.Context, gitcore.RepoRef, gitcore.Page) (gitcore.List[gitcore.Tag], error) {
	return gitcore.List[gitcore.Tag]{}, nil
}
func (f *fakeForge) Compare(_ context.Context, _ gitcore.RepoRef, base, head string) (*gitcore.Compare, error) {
	if f.ancestor[base+"|"+head] {
		return &gitcore.Compare{}, nil
	}
	return &gitcore.Compare{AheadBy: 1, Commits: []gitcore.Commit{{SHA: head}}}, nil
}
func (f *fakeForge) GetCommit(_ context.Context, _ gitcore.RepoRef, sha string) (*gitcore.Commit, error) {
	return &gitcore.Commit{SHA: sha}, nil
}
func (f *fakeForge) ListChecks(_ context.Context, _ gitcore.RepoRef, sha string) (*gitcore.CheckSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &gitcore.CheckSet{Items: f.checks[sha]}, nil
}
func (f *fakeForge) SetCheck(_ context.Context, _ gitcore.RepoRef, sha string, in gitcore.CheckInput) (*gitcore.Check, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.set = append(f.set, in)
	return &gitcore.Check{}, nil
}
func (f *fakeForge) lastCheck() gitcore.CheckInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.set) == 0 {
		return gitcore.CheckInput{}
	}
	return f.set[len(f.set)-1]
}

type fakeDeployer struct {
	mu      sync.Mutex
	calls   []Artifact
	status  string
	failErr error
}

func (d *fakeDeployer) Deploy(_ context.Context, _ uuid.UUID, a Artifact, _ *uuid.UUID, _ map[string]string) (uuid.UUID, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failErr != nil {
		return uuid.Nil, d.failErr
	}
	d.calls = append(d.calls, a)
	return uuid.New(), nil
}
func (d *fakeDeployer) Status(context.Context, uuid.UUID) (string, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.status == "" {
		return "deploying", "", nil
	}
	return d.status, "healthy", nil
}

type fakeDir struct {
	roles  map[uuid.UUID]authz.Role
	admins int
}

func (d fakeDir) Role(_ context.Context, u, _, _ uuid.UUID) (authz.Role, error) {
	return d.roles[u], nil
}
func (d fakeDir) Person(_ context.Context, u uuid.UUID) (Person, error) {
	return Person{Name: "user-" + u.String()[:4]}, nil
}
func (d fakeDir) CountAdmins(context.Context, uuid.UUID, uuid.UUID) (int, error) {
	return d.admins, nil
}

type fakePub struct {
	mu     sync.Mutex
	events []gitevents.Event
}

func (p *fakePub) Publish(_ context.Context, e gitevents.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, e)
	return nil
}
func (p *fakePub) names() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, e := range p.events {
		out = append(out, e.Name)
	}
	return out
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }
