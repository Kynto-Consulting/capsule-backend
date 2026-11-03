// Package gitimporttest holds in-memory doubles for gitimport (and its handlers): a Store, a
// MirrorStore, an Auditor, a Linker, a project repository and a fake GitHub API.
package gitimporttest

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitimport"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

// Mem implements gitimport.Store, MirrorStore, Auditor and Linker in memory.
type Mem struct {
	mu      sync.Mutex
	Key     string // encryption key of the mirror credential
	imports map[uuid.UUID]*gitimport.Import
	mirrors map[uuid.UUID]*gitimport.Mirror
	creds   map[uuid.UUID][]byte
	Audits  []gitimport.AuditRecord
	Ready   map[uuid.UUID]bool
	Now     func() time.Time
	// FailAudit makes Audit return an error (the service must carry on).
	FailAudit bool
}

// NewMem returns an empty Mem.
func NewMem() *Mem {
	return &Mem{Key: "test-secret-key", imports: map[uuid.UUID]*gitimport.Import{}, mirrors: map[uuid.UUID]*gitimport.Mirror{},
		creds: map[uuid.UUID][]byte{}, Ready: map[uuid.UUID]bool{}, Now: time.Now}
}

func cp(im *gitimport.Import) *gitimport.Import {
	c := *im
	c.Repos = make([]gitimport.RepoState, len(im.Repos))
	for i, r := range im.Repos {
		c.Repos[i] = r
		c.Repos[i].Warnings = append([]string{}, r.Warnings...)
	}
	return &c
}

func (m *Mem) CreateImport(_ context.Context, im *gitimport.Import) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if im.IdemKey != "" {
		for _, x := range m.imports {
			if x.OrgID == im.OrgID && x.IdemKey == im.IdemKey {
				return gitimport.ErrDuplicateKey
			}
		}
	}
	m.imports[im.ID] = cp(im)
	return nil
}

func (m *Mem) GetImport(_ context.Context, orgID, id uuid.UUID) (*gitimport.Import, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	im, ok := m.imports[id]
	if !ok || im.OrgID != orgID {
		return nil, domain.ErrNotFound
	}
	return cp(im), nil
}

func (m *Mem) FindByIdem(_ context.Context, orgID uuid.UUID, key string) (*gitimport.Import, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.imports {
		if x.OrgID == orgID && x.IdemKey == key {
			return cp(x), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *Mem) BusySlugs(_ context.Context, orgID uuid.UUID, slugs []string, except uuid.UUID) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, x := range m.imports {
		if x.OrgID != orgID || x.ID == except {
			continue
		}
		for _, r := range x.Repos {
			if r.Status != gitimport.StatusQueued && r.Status != gitimport.StatusRunning {
				continue
			}
			for _, s := range slugs {
				if s == r.Slug {
					out = append(out, s)
				}
			}
		}
	}
	return out, nil
}

func (m *Mem) SetStatus(_ context.Context, id uuid.UUID, status string, finished bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if im, ok := m.imports[id]; ok {
		im.Status, im.UpdatedAt = status, m.Now()
		if finished {
			t := m.Now()
			im.FinishedAt = &t
		}
	}
	return nil
}

func (m *Mem) Resume(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	im, ok := m.imports[id]
	if !ok {
		return domain.ErrNotFound
	}
	im.Status, im.Attempts, im.FinishedAt, im.UpdatedAt = gitimport.StatusQueued, im.Attempts+1, nil, m.Now()
	for i := range im.Repos {
		if im.Repos[i].Status != gitimport.StatusSuccess {
			im.Repos[i].Status, im.Repos[i].Error = gitimport.StatusQueued, ""
		}
	}
	return nil
}

func (m *Mem) BeginRepo(_ context.Context, id uuid.UUID, name string) (*gitimport.RepoState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	im, ok := m.imports[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	for i := range im.Repos {
		if im.Repos[i].Name == name {
			t := m.Now()
			im.Repos[i].Status, im.Repos[i].Attempts, im.Repos[i].StartedAt = gitimport.StatusRunning, im.Repos[i].Attempts+1, &t
			r := im.Repos[i]
			return &r, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *Mem) UpdateRepo(_ context.Context, id uuid.UUID, name string, u gitimport.RepoUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	im, ok := m.imports[id]
	if !ok {
		return domain.ErrNotFound
	}
	for i := range im.Repos {
		r := &im.Repos[i]
		if r.Name != name {
			continue
		}
		if u.Status != "" {
			r.Status = u.Status
		}
		if u.ProjectID != nil {
			r.ProjectID = u.ProjectID
		}
		if u.CreatedProject != nil {
			r.CreatedProject = *u.CreatedProject
		}
		r.Error = u.Error
		if u.Warnings != nil {
			r.Warnings = u.Warnings
		}
		if u.CodeOwners != nil {
			r.CodeOwners = u.CodeOwners
		}
		if u.Finished {
			t := m.Now()
			r.FinishedAt = &t
		}
		return nil
	}
	return domain.ErrNotFound
}

func (m *Mem) Touch(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if im, ok := m.imports[id]; ok {
		im.UpdatedAt = m.Now()
	}
	return nil
}

func (m *Mem) FailInterrupted(_ context.Context, before time.Time, msg string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, im := range m.imports {
		if (im.Status != gitimport.StatusQueued && im.Status != gitimport.StatusRunning) || !im.UpdatedAt.Before(before) {
			continue
		}
		ok := 0
		for i := range im.Repos {
			if im.Repos[i].Status == gitimport.StatusSuccess {
				ok++
			} else {
				im.Repos[i].Status, im.Repos[i].Error = gitimport.StatusFailed, msg
			}
		}
		im.Status = gitimport.StatusFailed
		if ok > 0 {
			im.Status = gitimport.StatusPartial
		}
		n++
	}
	return n, nil
}

// SetUpdatedAt back-dates an import's heartbeat (tests of Recover).
func (m *Mem) SetUpdatedAt(id uuid.UUID, t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.imports[id].UpdatedAt = t
}

// ---- mirrors --------------------------------------------------------------------------------

func (m *Mem) GetMirror(_ context.Context, projectID uuid.UUID) (*gitimport.Mirror, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mr, ok := m.mirrors[projectID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	c := *mr
	c.Branches = append([]string{}, mr.Branches...)
	c.HasCredential = len(m.creds[projectID]) > 0
	return &c, nil
}

func (m *Mem) PutMirror(_ context.Context, mr *gitimport.Mirror, credential *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *mr
	if old, ok := m.mirrors[mr.ProjectID]; ok {
		c.SyncingSince = old.SyncingSince // a replaced remote has never synced: last sync and error start over
	}
	m.mirrors[mr.ProjectID] = &c
	if credential != nil {
		if *credential == "" {
			delete(m.creds, mr.ProjectID)
		} else {
			enc, err := crypto.Encrypt([]byte(*credential), m.Key)
			if err != nil {
				return err
			}
			m.creds[mr.ProjectID] = enc
		}
	}
	return nil
}

func (m *Mem) Credential(_ context.Context, projectID uuid.UUID) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	enc := m.creds[projectID]
	if len(enc) == 0 {
		return "", nil
	}
	p, err := crypto.Decrypt(enc, m.Key)
	return string(p), err
}

func (m *Mem) DeleteMirror(_ context.Context, projectID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.mirrors[projectID]; !ok {
		return domain.ErrNotFound
	}
	delete(m.mirrors, projectID)
	delete(m.creds, projectID)
	return nil
}

func (m *Mem) RecordSync(_ context.Context, projectID uuid.UUID, at *time.Time, lastErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mr, ok := m.mirrors[projectID]; ok {
		mr.LastSyncAt, mr.LastError = at, lastErr
	}
	return nil
}

func (m *Mem) BeginSync(_ context.Context, projectID uuid.UUID, staleBefore time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mr, ok := m.mirrors[projectID]
	if !ok {
		return false, domain.ErrNotFound
	}
	if mr.SyncingSince != nil && mr.SyncingSince.After(staleBefore) {
		return false, nil
	}
	t := m.Now()
	mr.SyncingSince = &t
	return true, nil
}

func (m *Mem) EndSync(_ context.Context, projectID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mr, ok := m.mirrors[projectID]; ok {
		mr.SyncingSince = nil
	}
	return nil
}

// ---- audit, linker --------------------------------------------------------------------------

func (m *Mem) Audit(_ context.Context, r gitimport.AuditRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailAudit {
		return context.DeadlineExceeded
	}
	m.Audits = append(m.Audits, r)
	return nil
}

// AuditActions lists the recorded actions in order.
func (m *Mem) AuditActions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, a := range m.Audits {
		out = append(out, a.Action)
	}
	return out
}

func (m *Mem) MarkReady(_ context.Context, projectID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Ready[projectID] = true
	return nil
}

// Dump returns EVERYTHING persisted (imports, repos, mirrors with their encrypted credentials, audit
// rows) as one JSON string, so a test can search it for a secret.
func (m *Mem) Dump() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	enc := json.NewEncoder(&b)
	for _, im := range m.imports {
		_ = enc.Encode(struct {
			*gitimport.Import
			Repos []gitimport.RepoState
		}{im, im.Repos})
	}
	for id, mr := range m.mirrors {
		_ = enc.Encode(mr)
		_ = enc.Encode(m.creds[id])
	}
	_ = enc.Encode(m.Audits)
	return b.String()
}

// ---- projects -------------------------------------------------------------------------------

// Projects is an in-memory import project repository (GetBySlug/Create only).
type Projects struct {
	mu   sync.Mutex
	List map[string]*domain.Project // "org|slug"
	// FailCreate makes Create fail with this error.
	FailCreate error
}

func NewProjects() *Projects { return &Projects{List: map[string]*domain.Project{}} }

func (p *Projects) GetBySlug(_ context.Context, orgID uuid.UUID, slug string) (*domain.Project, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if x, ok := p.List[orgID.String()+"|"+slug]; ok {
		c := *x
		return &c, nil
	}
	return nil, domain.ErrNotFound
}

func (p *Projects) Create(_ context.Context, pr *domain.Project) (*domain.Project, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.FailCreate != nil {
		return nil, p.FailCreate
	}
	c := *pr
	c.ID = uuid.New()
	p.List[pr.OrgID.String()+"|"+pr.Slug] = &c
	r := c
	return &r, nil
}

// Add registers an existing project.
func (p *Projects) Add(orgID uuid.UUID, slug string) *domain.Project {
	pr, _ := p.Create(context.Background(), &domain.Project{OrgID: orgID, Slug: slug, Name: slug})
	return pr
}
