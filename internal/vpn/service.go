package vpn

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/pkg/crypto"
)

// ErrNotFound / ErrConflict are returned by stores.
var (
	ErrNotFound = errors.New("vpn: not found")
	ErrConflict = errors.New("vpn: already exists")
	ErrDisabled = errors.New("vpn: tunnel is disabled")
)

// Store persists tunnels and their audit trail.
type Store interface {
	Create(ctx context.Context, t *Tunnel) error
	GetByName(ctx context.Context, projectID uuid.UUID, name string) (*Tunnel, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Tunnel, error)
	List(ctx context.Context, projectID uuid.UUID) ([]*Tunnel, error)
	Delete(ctx context.Context, id uuid.UUID) error
	SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error
	SetStatus(ctx context.Context, id uuid.UUID, status string, handshake *time.Time, lastErr string) error
	AddEvent(ctx context.Context, e Event) error
	Events(ctx context.Context, tunnelID uuid.UUID, limit int) ([]Event, error)
}

// Service holds the business rules. The secret key is the same one used for project variables (AES-GCM).
type Service struct {
	Store     Store
	SecretKey string
	Now       func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Create validates the spec, encrypts the credentials as a project secret and stores the tunnel (one per project).
func (s *Service) Create(ctx context.Context, orgID, projectID uuid.UUID, actor string, createdBy *uuid.UUID, spec Spec) (*Tunnel, error) {
	spec, err := spec.Normalize()
	if err != nil {
		return nil, err
	}
	enc, err := crypto.Encrypt([]byte(spec.Secret), s.SecretKey)
	if err != nil {
		return nil, err
	}
	t := &Tunnel{
		ID: uuid.New(), OrgID: orgID, ProjectID: projectID, Name: spec.Name, Provider: spec.Provider, Host: spec.Host,
		CIDRs: spec.CIDRs, CertPin: spec.CertPin, Config: spec.Config, SecretEnc: enc, HasSecret: true, Enabled: true,
		MaxConns: spec.MaxConns, BandwidthBps: spec.BandwidthBps, Status: StatusDown, CreatedBy: createdBy,
		CreatedAt: s.now(), UpdatedAt: s.now(),
	}
	if err := s.Store.Create(ctx, t); err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, fmt.Errorf("%w: the project already has a tunnel (one tunnel per project)", ErrConflict)
		}
		return nil, err
	}
	msg := fmt.Sprintf("tunnel %s created (%s, %s, networks %v)", t.Name, t.Provider, t.Host, t.CIDRs)
	if t.Provider == ProviderFortiGate && t.CertPin == "" {
		msg += "; no certificate pin set (recommended)"
	}
	s.audit(ctx, t, EventCreated, msg, actor)
	return t, nil
}

// Secret decrypts the tunnel credentials. Only the agent claim path calls it.
func (s *Service) Secret(t *Tunnel) (string, error) {
	b, err := crypto.Decrypt(t.SecretEnc, s.SecretKey)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// SetEnabled is the kill switch: false drops the tunnel (agent) and refuses new use (claim).
func (s *Service) SetEnabled(ctx context.Context, t *Tunnel, enabled bool, actor string) error {
	if err := s.Store.SetEnabled(ctx, t.ID, enabled); err != nil {
		return err
	}
	if enabled {
		s.audit(ctx, t, EventEnabled, "tunnel enabled", actor)
		return s.Store.SetStatus(ctx, t.ID, StatusDown, nil, "")
	}
	s.audit(ctx, t, EventDisabled, "kill switch: tunnel disabled, connections dropped", actor)
	return s.Store.SetStatus(ctx, t.ID, StatusDisabled, nil, "")
}

// Delete removes the tunnel.
func (s *Service) Delete(ctx context.Context, t *Tunnel, actor string) error {
	s.audit(ctx, t, EventDeleted, "tunnel deleted", actor)
	return s.Store.Delete(ctx, t.ID)
}

// Report is the gateway's status report (health, reconnection).
func (s *Service) Report(ctx context.Context, t *Tunnel, status string, handshake *time.Time, lastErr, actor string) error {
	if !t.Enabled && status != StatusDown && status != StatusDisabled {
		return ErrDisabled // the kill switch holds: a gateway cannot report a disabled tunnel as up
	}
	if t.Status != status {
		kind := EventDown
		switch status {
		case StatusUp:
			kind = EventUp
			if t.Status == StatusError || t.Status == StatusDown && t.LastHandshakeAt != nil {
				kind = EventReconnect
			}
		case StatusConnecting:
			kind = EventConnecting
		}
		msg := string(kind)
		if lastErr != "" {
			msg += ": " + lastErr
		}
		s.audit(ctx, t, kind, msg, actor)
	}
	return s.Store.SetStatus(ctx, t.ID, status, handshake, lastErr)
}

// Audit writes an event (exported for the function runner).
func (s *Service) Audit(ctx context.Context, t *Tunnel, kind, msg, actor string) {
	s.audit(ctx, t, kind, msg, actor)
}

func (s *Service) audit(ctx context.Context, t *Tunnel, kind, msg, actor string) {
	_ = s.Store.AddEvent(ctx, Event{TunnelID: t.ID, ProjectID: t.ProjectID, At: s.now(), Kind: kind, Message: msg, Actor: actor})
}

// MemStore is an in-memory Store for tests and local use.
type MemStore struct {
	mu      sync.Mutex
	tunnels map[uuid.UUID]*Tunnel
	events  []Event
}

// NewMemStore creates an empty MemStore.
func NewMemStore() *MemStore { return &MemStore{tunnels: map[uuid.UUID]*Tunnel{}} }

func cp(t *Tunnel) *Tunnel { c := *t; return &c }

func (m *MemStore) Create(_ context.Context, t *Tunnel) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.tunnels {
		if o.ProjectID == t.ProjectID {
			return ErrConflict
		}
	}
	m.tunnels[t.ID] = cp(t)
	return nil
}
func (m *MemStore) GetByName(_ context.Context, p uuid.UUID, name string) (*Tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.tunnels {
		if o.ProjectID == p && o.Name == name {
			return cp(o), nil
		}
	}
	return nil, ErrNotFound
}
func (m *MemStore) GetByID(_ context.Context, id uuid.UUID) (*Tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if o, ok := m.tunnels[id]; ok {
		return cp(o), nil
	}
	return nil, ErrNotFound
}
func (m *MemStore) List(_ context.Context, p uuid.UUID) ([]*Tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Tunnel
	for _, o := range m.tunnels {
		if o.ProjectID == p {
			out = append(out, cp(o))
		}
	}
	return out, nil
}
func (m *MemStore) Delete(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tunnels, id)
	return nil
}
func (m *MemStore) SetEnabled(_ context.Context, id uuid.UUID, e bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.tunnels[id]
	if !ok {
		return ErrNotFound
	}
	o.Enabled = e
	o.UpdatedAt = time.Now()
	return nil
}
func (m *MemStore) SetStatus(_ context.Context, id uuid.UUID, st string, hs *time.Time, e string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.tunnels[id]
	if !ok {
		return ErrNotFound
	}
	o.Status, o.LastError = st, e
	if hs != nil {
		o.LastHandshakeAt = hs
	}
	return nil
}
func (m *MemStore) AddEvent(_ context.Context, e Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.ID = int64(len(m.events) + 1)
	m.events = append(m.events, e)
	return nil
}
func (m *MemStore) Events(_ context.Context, id uuid.UUID, limit int) ([]Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Event
	for i := len(m.events) - 1; i >= 0 && len(out) < limit; i-- {
		if m.events[i].TunnelID == id {
			out = append(out, m.events[i])
		}
	}
	return out, nil
}
