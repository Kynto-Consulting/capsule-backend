// Package oidctest provides an in-memory oidc.Store and helpers for tests.
package oidctest

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/oidc"
)

// MemStore is a thread-safe in-memory oidc.Store.
type MemStore struct {
	mu       sync.Mutex
	Clients  map[uuid.UUID]*oidc.Client
	Requests map[string]*oidc.AuthRequest
	Codes    map[string]*oidc.Code // by hash
	Refresh  map[string]*oidc.RefreshToken
	Orgs     map[uuid.UUID][]oidc.OrgRole
	Taken    map[string]bool // base usernames reported as taken
	Now      func() time.Time
}

func NewMemStore() *MemStore {
	return &MemStore{
		Clients: map[uuid.UUID]*oidc.Client{}, Requests: map[string]*oidc.AuthRequest{},
		Codes: map[string]*oidc.Code{}, Refresh: map[string]*oidc.RefreshToken{},
		Orgs: map[uuid.UUID][]oidc.OrgRole{}, Taken: map[string]bool{}, Now: time.Now,
	}
}

func (m *MemStore) CreateClient(_ context.Context, c *oidc.Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *c
	m.Clients[c.ID] = &cp
	return nil
}

func (m *MemStore) find(match func(*oidc.Client) bool) (*oidc.Client, error) {
	for _, c := range m.Clients {
		if match(c) {
			cp := *c
			return &cp, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *MemStore) GetClientByClientID(_ context.Context, id string) (*oidc.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.find(func(c *oidc.Client) bool { return c.ClientID == id })
}

func (m *MemStore) GetClientByUUID(_ context.Context, id uuid.UUID) (*oidc.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.find(func(c *oidc.Client) bool { return c.ID == id })
}

func (m *MemStore) GetClient(_ context.Context, ref string) (*oidc.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.find(func(c *oidc.Client) bool { return c.ClientID == ref || c.ID.String() == ref })
}

func (m *MemStore) ListClients(_ context.Context, all bool, orgIDs []uuid.UUID) ([]*oidc.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*oidc.Client
	for _, c := range m.Clients {
		ok := all
		for _, o := range orgIDs {
			if c.OrgID != nil && *c.OrgID == o {
				ok = true
			}
		}
		if ok {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *MemStore) UpdateRedirectURIs(_ context.Context, id uuid.UUID, uris []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.Clients[id]
	if !ok || c.RevokedAt != nil {
		return domain.ErrNotFound
	}
	c.RedirectURIs = uris
	return nil
}

func (m *MemStore) RevokeClient(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.Clients[id]
	if !ok {
		return domain.ErrNotFound
	}
	now := m.Now()
	c.RevokedAt = &now
	for _, code := range m.Codes {
		if code.ClientUUID == id && code.RevokedAt == nil {
			code.RevokedAt = &now
		}
	}
	for _, t := range m.Refresh {
		if t.ClientUUID == id && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	return nil
}

func (m *MemStore) CreateRequest(_ context.Context, r *oidc.AuthRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *r
	m.Requests[r.ID] = &cp
	return nil
}

func (m *MemStore) GetRequest(_ context.Context, id string) (*oidc.AuthRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.Requests[id]
	if !ok || !m.Now().Before(r.ExpiresAt) {
		return nil, domain.ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (m *MemStore) TakeRequest(_ context.Context, id string) (*oidc.AuthRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.Requests[id]
	if !ok || !m.Now().Before(r.ExpiresAt) {
		return nil, domain.ErrNotFound
	}
	delete(m.Requests, id)
	return r, nil
}

func (m *MemStore) CreateCode(_ context.Context, c *oidc.Code) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *c
	m.Codes[c.CodeHash] = &cp
	return nil
}

func (m *MemStore) ConsumeCode(_ context.Context, hash string) (*oidc.Code, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.Codes[hash]
	if !ok {
		return nil, false, domain.ErrNotFound
	}
	if c.UsedAt != nil || c.RevokedAt != nil {
		cp := *c
		return &cp, false, nil
	}
	now := m.Now()
	c.UsedAt = &now
	cp := *c
	return &cp, true, nil
}

func (m *MemStore) RevokeGrant(_ context.Context, grantID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Now()
	for _, c := range m.Codes {
		if c.ID == grantID && c.RevokedAt == nil {
			c.RevokedAt = &now
		}
	}
	for _, t := range m.Refresh {
		if t.GrantID == grantID && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	return nil
}

func (m *MemStore) GrantActive(_ context.Context, grantID uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.Codes {
		if c.ID == grantID {
			return c.RevokedAt == nil, nil
		}
	}
	return false, nil
}

func (m *MemStore) CreateRefresh(_ context.Context, t *oidc.RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *t
	m.Refresh[t.TokenHash] = &cp
	return nil
}

func (m *MemStore) UseRefresh(_ context.Context, hash string) (*oidc.RefreshToken, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Refresh[hash]
	if !ok {
		return nil, false, domain.ErrNotFound
	}
	if t.UsedAt != nil || t.RevokedAt != nil || !m.Now().Before(t.ExpiresAt) {
		cp := *t
		return &cp, false, nil
	}
	now := m.Now()
	t.UsedAt = &now
	cp := *t
	return &cp, true, nil
}

func (m *MemStore) UserOrgs(_ context.Context, userID uuid.UUID) ([]oidc.OrgRole, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]oidc.OrgRole(nil), m.Orgs[userID]...), nil
}

func (m *MemStore) UsernameTaken(_ context.Context, _ uuid.UUID, base string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Taken[base], nil
}

// Users is a minimal domain.UserRepository for tests.
type Users struct {
	domain.UserRepository
	ByID map[uuid.UUID]*domain.User
}

func (u *Users) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if v, ok := u.ByID[id]; ok {
		cp := *v
		return &cp, nil
	}
	return nil, domain.ErrNotFound
}
