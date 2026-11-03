package gitreview

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/gitsync"
)

// DomainProjects implements Projects on the existing repositories (Forgejo owner = org slug,
// repo = project slug, the A1 convention).
type DomainProjects struct {
	Projects domain.ProjectRepository
	Orgs     domain.OrganizationRepository
}

func (d DomainProjects) ByID(ctx context.Context, id uuid.UUID) (*Project, error) {
	p, err := d.Projects.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	o, err := d.Orgs.GetByID(ctx, p.OrgID)
	if err != nil {
		return nil, err
	}
	return &Project{ID: p.ID, OrgID: p.OrgID, Ref: gitcore.RepoRef{Owner: o.Slug, Repo: p.Slug}}, nil
}

func (d DomainProjects) ByRef(ctx context.Context, ref gitcore.RepoRef) (*Project, error) {
	o, err := d.Orgs.GetBySlug(ctx, ref.Owner)
	if err != nil {
		return nil, err
	}
	p, err := d.Projects.GetBySlug(ctx, o.ID, ref.Repo)
	if err != nil {
		return nil, err
	}
	return &Project{ID: p.ID, OrgID: p.OrgID, Ref: ref}, nil
}

// DirectoryRoster implements Roster with the same inputs the team reconciler uses: org members,
// access mode, explicit roles and Forgejo identities.
type DirectoryRoster struct {
	Dir interface {
		Members(ctx context.Context, orgID uuid.UUID) ([]gitsync.Member, error)
		Access(ctx context.Context, orgID, projectID uuid.UUID) (string, map[uuid.UUID]string, error)
	}
	IDs *gitsync.Identities
}

func (d DirectoryRoster) Members(ctx context.Context, p Project) ([]Member, error) {
	ms, err := d.Dir.Members(ctx, p.OrgID)
	if err != nil {
		return nil, err
	}
	mode, explicit, err := d.Dir.Access(ctx, p.OrgID, p.ID)
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(ms))
	for _, m := range ms {
		role := authz.Resolve(m.OrgRole, mode, explicit[m.UserID]).Role
		if role == "" {
			continue
		}
		id, err := d.IDs.Resolve(ctx, m.UserID, m.Email)
		if err != nil {
			continue // no identity yet: cannot be an owner or reviewer in Forgejo
		}
		out = append(out, Member{UserID: m.UserID, Login: strings.ToLower(id.ForgejoUsername), Email: m.Email, Role: role})
	}
	return out, nil
}

// MemStore is an in-memory AutoMergeStore (tests; also usable as a fallback without a database).
type MemStore struct {
	mu   sync.Mutex
	rows map[string]*AutoMerge
	Now  func() time.Time
}

func NewMemStore() *MemStore { return &MemStore{rows: map[string]*AutoMerge{}} }

func (m *MemStore) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func key(p uuid.UUID, n int) string { return fmt.Sprintf("%s#%d", p, n) }

func (m *MemStore) Arm(_ context.Context, a AutoMerge) (*AutoMerge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	a.State, a.Attempts, a.Reason, a.LastError, a.ClaimedUntil, a.LastAttemptAt = StateArmed, 0, "", "", nil, nil
	a.CreatedAt, a.UpdatedAt = now, now
	if a.NextAttemptAt.IsZero() {
		a.NextAttemptAt = now
	}
	c := a
	m.rows[key(a.ProjectID, a.PR)] = &c
	out := c
	return &out, nil
}

func (m *MemStore) Get(_ context.Context, p uuid.UUID, n int) (*AutoMerge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[key(p, n)]
	if !ok {
		return nil, ErrNotFound
	}
	c := *r
	return &c, nil
}

func (m *MemStore) Cancel(_ context.Context, p uuid.UUID, n int, reason string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[key(p, n)]
	if !ok || !r.Active() {
		return false, nil
	}
	r.State, r.Reason, r.UpdatedAt = StateCancelled, reason, m.now()
	return true, nil
}

func (m *MemStore) ListArmedByHead(_ context.Context, p uuid.UUID, sha string) ([]AutoMerge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []AutoMerge
	for _, r := range m.rows {
		if r.ProjectID == p && r.State == StateArmed && strings.EqualFold(r.HeadSHA, sha) {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (m *MemStore) ListDue(_ context.Context, now time.Time, limit int) ([]AutoMerge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []AutoMerge
	for _, r := range m.rows {
		due := (r.State == StateArmed && !r.NextAttemptAt.After(now)) ||
			(r.State == StateMerging && r.ClaimedUntil != nil && !r.ClaimedUntil.After(now))
		if due && len(out) < limit {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (m *MemStore) Claim(_ context.Context, p uuid.UUID, n int, sha string, now, lease time.Time) (*AutoMerge, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[key(p, n)]
	if !ok || !strings.EqualFold(r.HeadSHA, sha) {
		return nil, false, nil
	}
	if !(r.State == StateArmed || (r.State == StateMerging && r.ClaimedUntil != nil && !r.ClaimedUntil.After(now))) {
		return nil, false, nil
	}
	r.State, r.ClaimedUntil, r.LastAttemptAt, r.UpdatedAt = StateMerging, &lease, &now, now
	c := *r
	return &c, true, nil
}

func (m *MemStore) Release(_ context.Context, p uuid.UUID, n int, sha string, next time.Time, msg string, count bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rows[key(p, n)]; ok && r.State == StateMerging && strings.EqualFold(r.HeadSHA, sha) {
		r.State, r.ClaimedUntil, r.NextAttemptAt, r.LastError, r.UpdatedAt = StateArmed, nil, next, msg, m.now()
		if count {
			r.Attempts++
		}
	}
	return nil
}

func (m *MemStore) Defer(_ context.Context, p uuid.UUID, n int, next time.Time, note string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rows[key(p, n)]; ok && r.State == StateArmed {
		r.NextAttemptAt, r.LastError, r.UpdatedAt = next, note, m.now()
	}
	return nil
}

func (m *MemStore) Finish(_ context.Context, p uuid.UUID, n int, state, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rows[key(p, n)]; ok && r.Active() {
		r.State, r.Reason, r.ClaimedUntil, r.UpdatedAt = state, reason, nil, m.now()
	}
	return nil
}

var (
	_ AutoMergeStore        = (*MemStore)(nil)
	_ gitevents.Subscriber  = (*Service)(nil)
	_ gitsync.ReviewJanitor = Janitor{}
	_                       = errors.New
)
