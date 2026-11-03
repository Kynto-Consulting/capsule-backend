// Package gittokenstest has in-memory doubles of everything gittokens depends on, for the
// package's own tests and for the handler tests. Nothing here talks to Postgres or Forgejo.
package gittokenstest

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gittokens"
)

// Clock is a manually advanced clock.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

func NewClock() *Clock { return &Clock{t: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)} }

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// MemStore implements gittokens.Store in memory.
type MemStore struct {
	mu     sync.Mutex
	Clock  *Clock
	Tokens map[uuid.UUID]*gittokens.Token
	Keys   map[uuid.UUID]*gittokens.SSHKey
	Audits []gittokens.AuditRecord
	seq    int
}

func NewMemStore(c *Clock) *MemStore {
	return &MemStore{Clock: c, Tokens: map[uuid.UUID]*gittokens.Token{}, Keys: map[uuid.UUID]*gittokens.SSHKey{}}
}

var _ gittokens.Store = (*MemStore)(nil)

func (m *MemStore) CreateToken(_ context.Context, t *gittokens.Token) (*gittokens.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *t
	c.ID = uuid.New()
	c.CreatedAt = m.Clock.Now().Add(time.Duration(m.seq) * time.Millisecond)
	m.seq++
	m.Tokens[c.ID] = &c
	out := c
	return &out, nil
}

func (m *MemStore) GetToken(_ context.Context, id uuid.UUID) (*gittokens.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Tokens[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	c := *t
	return &c, nil
}

func (m *MemStore) GetTokenByHash(_ context.Context, hash string) (*gittokens.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.Tokens {
		if t.Hash == hash {
			c := *t
			return &c, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *MemStore) ListUserTokens(_ context.Context, userID uuid.UUID, now time.Time) ([]*gittokens.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*gittokens.Token
	for _, t := range m.Tokens {
		if t.UserID == userID && t.Kind != gittokens.KindService && t.RevokedAt == nil && (t.Kind == gittokens.KindPersonal || now.Before(t.ExpiresAt)) {
			c := *t
			out = append(out, &c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemStore) ListServiceTokens(_ context.Context, projectID uuid.UUID, _ time.Time) ([]*gittokens.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*gittokens.Token
	for _, t := range m.Tokens {
		if t.Kind == gittokens.KindService && t.RevokedAt == nil && t.AllowsProject(projectID) {
			c := *t
			out = append(out, &c)
		}
	}
	return out, nil
}

func (m *MemStore) RevokeToken(_ context.Context, id uuid.UUID, reason string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Tokens[id]
	if !ok || t.RevokedAt != nil {
		return false, nil
	}
	now := m.Clock.Now()
	t.RevokedAt, t.RevokedReason = &now, reason
	return true, nil
}

func (m *MemStore) RevokeSession(_ context.Context, userID uuid.UUID, ref, reason string) ([]uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []uuid.UUID
	for id, t := range m.Tokens {
		if t.UserID == userID && t.SessionRef == ref && t.Kind == gittokens.KindEphemeral && t.RevokedAt == nil {
			now := m.Clock.Now()
			t.RevokedAt, t.RevokedReason = &now, reason
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (m *MemStore) PruneEphemeral(_ context.Context, userID uuid.UUID, keep int, now time.Time) ([]uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var act []*gittokens.Token
	for _, t := range m.Tokens {
		if t.UserID == userID && t.Kind == gittokens.KindEphemeral && t.RevokedAt == nil && now.Before(t.ExpiresAt) {
			act = append(act, t)
		}
	}
	sort.Slice(act, func(i, j int) bool { return act[i].CreatedAt.After(act[j].CreatedAt) })
	var ids []uuid.UUID
	for i := keep; i < len(act); i++ {
		n := m.Clock.Now()
		act[i].RevokedAt, act[i].RevokedReason = &n, "pruned"
		ids = append(ids, act[i].ID)
	}
	return ids, nil
}

func (m *MemStore) CountActive(_ context.Context, userID uuid.UUID, kind string, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, t := range m.Tokens {
		if t.UserID == userID && t.Kind == kind && t.RevokedAt == nil && now.Before(t.ExpiresAt) {
			n++
		}
	}
	return n, nil
}

func (m *MemStore) TouchUsed(_ context.Context, id uuid.UUID, ip string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Tokens[id]
	if !ok {
		return false, domain.ErrNotFound
	}
	first := t.LastUsedAt == nil
	now := m.Clock.Now()
	t.LastUsedAt, t.LastUsedIP = &now, ip
	return first, nil
}

func (m *MemStore) ListExpiring(_ context.Context, from, to time.Time, limit int) ([]*gittokens.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*gittokens.Token
	for _, t := range m.Tokens {
		if t.Kind != gittokens.KindEphemeral && t.RevokedAt == nil && t.ExpiryWarnedAt == nil && t.ExpiresAt.After(from) && !t.ExpiresAt.After(to) {
			c := *t
			out = append(out, &c)
		}
	}
	return out, nil
}

func (m *MemStore) MarkExpiryWarned(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Clock.Now()
	m.Tokens[id].ExpiryWarnedAt = &now
	return nil
}

func (m *MemStore) PurgeEphemeral(_ context.Context, cutoff time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for id, t := range m.Tokens {
		if t.Kind == gittokens.KindEphemeral && (t.ExpiresAt.Before(cutoff) || (t.RevokedAt != nil && t.RevokedAt.Before(cutoff))) {
			delete(m.Tokens, id)
			n++
		}
	}
	return n, nil
}

func (m *MemStore) Audit(_ context.Context, r gittokens.AuditRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Audits = append(m.Audits, r)
	return nil
}

// AuditActions lists the recorded actions in order.
func (m *MemStore) AuditActions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.Audits))
	for i, a := range m.Audits {
		out[i] = a.Action
	}
	return out
}

// ---- keys ----

func (m *MemStore) CreateKey(_ context.Context, k *gittokens.SSHKey) (*gittokens.SSHKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.Keys {
		if o.DeletedAt == nil && o.Fingerprint == k.Fingerprint {
			return nil, domain.ErrConflict
		}
	}
	c := *k
	c.ID = uuid.New()
	c.CreatedAt = m.Clock.Now().Add(time.Duration(m.seq) * time.Millisecond)
	m.seq++
	m.Keys[c.ID] = &c
	out := c
	return &out, nil
}

func (m *MemStore) GetKey(_ context.Context, id uuid.UUID) (*gittokens.SSHKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.Keys[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	c := *k
	return &c, nil
}

func (m *MemStore) ListKeys(_ context.Context, userID uuid.UUID) ([]*gittokens.SSHKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []*gittokens.SSHKey{}
	for _, k := range m.Keys {
		if k.UserID == userID && k.DeletedAt == nil {
			c := *k
			out = append(out, &c)
		}
	}
	return out, nil
}

func (m *MemStore) MarkKeySynced(_ context.Context, id uuid.UUID, fid int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := m.Keys[id]
	now := m.Clock.Now()
	k.ForgejoKeyID, k.SyncedAt, k.SyncError, k.SyncAttempts = &fid, &now, "", 0
	return nil
}

func (m *MemStore) MarkKeySyncFailed(_ context.Context, id uuid.UUID, msg string, next time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := m.Keys[id]
	k.SyncError, k.SyncAttempts, k.NextSyncAt = msg, k.SyncAttempts+1, next
	return nil
}

func (m *MemStore) SoftDeleteKey(_ context.Context, id uuid.UUID, next time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.Keys[id]
	if !ok || k.DeletedAt != nil {
		return domain.ErrNotFound
	}
	now := m.Clock.Now()
	k.DeletedAt, k.NextSyncAt, k.SyncAttempts, k.SyncError = &now, next, 0, ""
	return nil
}

func (m *MemStore) MarkKeyRemoved(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := m.Keys[id]
	k.ForgejoKeyID, k.SyncedAt, k.SyncError, k.SyncAttempts = nil, nil, "", 0
	return nil
}

func (m *MemStore) ListPendingKeys(_ context.Context, now time.Time, limit int) ([]*gittokens.SSHKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*gittokens.SSHKey
	for _, k := range m.Keys {
		if k.NextSyncAt.After(now) {
			continue
		}
		if (k.SyncedAt == nil && k.DeletedAt == nil) || (k.DeletedAt != nil && k.ForgejoKeyID != nil) {
			c := *k
			out = append(out, &c)
		}
	}
	return out, nil
}

// ---- access, directory, identity, sessions ----

// Access is a role table: Roles[user][project] = role ("" = none).
type Access struct {
	mu    sync.Mutex
	Roles map[uuid.UUID]map[uuid.UUID]authz.Role
	Err   error
}

func NewAccess() *Access { return &Access{Roles: map[uuid.UUID]map[uuid.UUID]authz.Role{}} }

func (a *Access) Set(user, project uuid.UUID, r authz.Role) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Roles[user] == nil {
		a.Roles[user] = map[uuid.UUID]authz.Role{}
	}
	a.Roles[user][project] = r
}

func (a *Access) Can(_ context.Context, user, _, project uuid.UUID, act authz.Action) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Err != nil {
		return false, a.Err
	}
	return authz.RoleAllows(a.Roles[user][project], act), nil
}

// Directory holds projects by slug.
type Directory struct{ Projects []gittokens.ProjectRef }

func (d *Directory) BySlugs(_ context.Context, org, proj string) (*gittokens.ProjectRef, error) {
	for _, p := range d.Projects {
		if p.OrgSlug == org && p.ProjectSlug == proj {
			c := p
			return &c, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (d *Directory) ByID(_ context.Context, id uuid.UUID) (*gittokens.ProjectRef, error) {
	for _, p := range d.Projects {
		if p.ProjectID == id {
			c := p
			return &c, nil
		}
	}
	return nil, domain.ErrNotFound
}

// Identity maps users to logins; a missing user is ErrNotFound.
type Identity struct {
	mu     sync.Mutex
	Logins map[uuid.UUID]string
}

func (i *Identity) ForgejoLogin(_ context.Context, u uuid.UUID) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if l, ok := i.Logins[u]; ok {
		return l, nil
	}
	return "", domain.ErrNotFound
}

// Sessions says which session refs are dead.
type Sessions struct {
	mu   sync.Mutex
	Dead map[string]bool
}

func (s *Sessions) Kill(ref string) {
	s.mu.Lock()
	if s.Dead == nil {
		s.Dead = map[string]bool{}
	}
	s.Dead[ref] = true
	s.mu.Unlock()
}

func (s *Sessions) Alive(_ context.Context, _ uuid.UUID, ref string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.Dead[ref], nil
}

// ForgejoKeys is a fake gitcore.Keys. Down makes every call fail like an unreachable Forgejo.
type ForgejoKeys struct {
	mu      sync.Mutex
	Down    bool
	Keys    map[string][]gitcore.SSHKey // login -> keys
	Actors  []string                    // actor of every call
	nextID  int64
	AddErr  error
	Deleted []int64
}

func NewForgejoKeys() *ForgejoKeys { return &ForgejoKeys{Keys: map[string][]gitcore.SSHKey{}} }

func (f *ForgejoKeys) down() error {
	if f.Down {
		return &gitcore.Error{Code: gitcore.CodeUpstream, Message: "forgejo unreachable"}
	}
	return nil
}

func (f *ForgejoKeys) ListSSHKeys(ctx context.Context) ([]gitcore.SSHKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := gitcore.ActorFrom(ctx)
	f.Actors = append(f.Actors, a)
	if err := f.down(); err != nil {
		return nil, err
	}
	return append([]gitcore.SSHKey(nil), f.Keys[a]...), nil
}

func (f *ForgejoKeys) AddSSHKey(ctx context.Context, title, key string, ro bool) (*gitcore.SSHKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := gitcore.ActorFrom(ctx)
	f.Actors = append(f.Actors, a)
	if err := f.down(); err != nil {
		return nil, err
	}
	if f.AddErr != nil {
		return nil, f.AddErr
	}
	f.nextID++
	k := gitcore.SSHKey{ID: f.nextID, Title: title, Key: key, Fingerprint: Fingerprint(key), ReadOnly: ro}
	f.Keys[a] = append(f.Keys[a], k)
	return &k, nil
}

func (f *ForgejoKeys) DeleteSSHKey(ctx context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := gitcore.ActorFrom(ctx)
	f.Actors = append(f.Actors, a)
	if err := f.down(); err != nil {
		return err
	}
	ks := f.Keys[a]
	for i, k := range ks {
		if k.ID == id {
			f.Keys[a] = append(ks[:i:i], ks[i+1:]...)
			f.Deleted = append(f.Deleted, id)
			return nil
		}
	}
	return &gitcore.Error{Code: gitcore.CodeNotFound, Message: "no such key"}
}

// Has reports whether login has a key with this fingerprint in the fake Forgejo.
func (f *ForgejoKeys) Has(login, fingerprint string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.Keys[login] {
		if k.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// ErrBoom is a generic failure for tests.
var ErrBoom = errors.New("boom")

// Fingerprint computes the SHA256 fingerprint of an OpenSSH public key line, like Forgejo reports.
func Fingerprint(key string) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return "SHA256:invalid"
	}
	return ssh.FingerprintSHA256(pub)
}
