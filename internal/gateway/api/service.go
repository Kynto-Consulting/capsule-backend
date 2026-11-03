package api

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gateway/store"
	"github.com/kynto/capsule/backend/internal/gitaudit"
)

// Service is the control plane. It is safe for concurrent use.
type Service struct {
	d      Deps
	cfg    Config
	now    func() time.Time
	log    *slog.Logger
	signer *Signer
	lim    *limiter

	wakeMu sync.Mutex
	wake   chan struct{} // closed (and replaced) on every local change: wakes long-polls

	idxMu  sync.Mutex
	idxRev int64
	idx    *routeIndex

	syncMu   sync.Mutex
	syncedAt map[uuid.UUID]time.Time
}

// New builds the Service. cfg should come from ConfigFromEnv (WithDefaults is applied again, harmlessly).
func New(d Deps) (*Service, error) {
	cfg := d.Config.WithDefaults()
	now := d.Now
	if now == nil {
		now = time.Now
	}
	signer, err := NewSigner(cfg.SigningKey, cfg.SigningPrevious)
	if err != nil {
		return nil, err
	}
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		d: d, cfg: cfg, now: now, log: logger, signer: signer,
		lim:      newLimiter(cfg, now),
		wake:     make(chan struct{}),
		idxRev:   -1,
		syncedAt: map[uuid.UUID]time.Time{},
	}, nil
}

// Config returns the effective configuration.
func (s *Service) Config() Config { return s.cfg }

// Signer returns the cgc_ signer (nil when no signing key is configured).
func (s *Service) Signer() *Signer { return s.signer }

// notify wakes every long-poll (called after any change this process made).
func (s *Service) notify() {
	s.wakeMu.Lock()
	close(s.wake)
	s.wake = make(chan struct{})
	s.wakeMu.Unlock()
}

func (s *Service) waiter() <-chan struct{} {
	s.wakeMu.Lock()
	defer s.wakeMu.Unlock()
	return s.wake
}

// ---- route index (authorize resolves a route by id; the store resolves by host or by service name) ----

type routeIndex struct {
	rev    int64
	routes map[uuid.UUID]*store.RouteView
	leases map[uuid.UUID]store.LeaseView // by service id
}

// index returns the route index at the current revision, rebuilding it only when the revision moved.
func (s *Service) index(ctx context.Context) (*routeIndex, error) {
	rev, err := s.d.Store.Revision(ctx)
	if err != nil {
		return nil, err
	}
	s.idxMu.Lock()
	defer s.idxMu.Unlock()
	if s.idx != nil && s.idxRev == rev {
		return s.idx, nil
	}
	snap, err := s.d.Store.Snapshot(ctx, -1)
	if err != nil {
		return nil, err
	}
	ix := &routeIndex{rev: snap.Rev, routes: make(map[uuid.UUID]*store.RouteView, len(snap.Routes)), leases: make(map[uuid.UUID]store.LeaseView, len(snap.Leases))}
	for i := range snap.Routes {
		r := snap.Routes[i]
		ix.routes[r.ID] = &r
	}
	for _, l := range snap.Leases {
		ix.leases[l.ServiceID] = l
	}
	s.idx, s.idxRev = ix, snap.Rev
	return ix, nil
}

// ---- audit -----------------------------------------------------------------------------------------

// auditEvent writes an audit row. Metadata must never carry a token; callers pass ids and names only.
func (s *Service) auditEvent(ctx context.Context, e gitaudit.Entry) {
	if s.d.Audit == nil || e.OrgID == uuid.Nil {
		return
	}
	if e.ActorLabel == "" && e.UserID == nil {
		e.ActorLabel = "gateway"
	}
	if err := s.d.Audit.Append(ctx, e); err != nil {
		s.log.Warn("gateway: audit write failed", "action", e.Action, "error", err.Error())
	}
}

// ---- errors ----------------------------------------------------------------------------------------

// Error is a typed control-plane error mapped to an HTTP status by the handlers.
type Error struct {
	Status  int
	Code    string
	Message string
	Hint    string
	Details map[string]any
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errBadRequest(msg string) *Error {
	return &Error{Status: 400, Code: "invalid_request", Message: msg}
}
func errNotFound() *Error { return &Error{Status: 404, Code: "not_found", Message: "not found"} }
func errForbidden(msg string) *Error {
	return &Error{Status: 403, Code: "forbidden", Message: msg}
}

func asError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// mapStoreErr turns a store error into a typed error (nil for nil).
func mapStoreErr(err error) error {
	if err == nil {
		return nil
	}
	var q *store.QuotaError
	switch {
	case errors.Is(err, store.ErrNotFound):
		return errNotFound()
	case errors.Is(err, store.ErrInvalid):
		return errBadRequest("invalid value")
	case errors.Is(err, store.ErrPortPoolExhausted):
		return &Error{Status: 409, Code: "port_pool_exhausted", Message: "No hay puertos aleatorios libres en este momento.",
			Hint: "Use capsule://<proyecto>/<servicio> (no necesita puerto) o libere un acceso."}
	case errors.As(err, &q):
		return &Error{Status: 409, Code: "port_quota_exceeded", Message: "Cuota de puertos aleatorios alcanzada.",
			Hint: "Libere un acceso o pida mas cuota.", Details: map[string]any{"scope": q.Scope, "limit": q.Limit}}
	case errors.Is(err, store.ErrConflict):
		return &Error{Status: 409, Code: "service_name_taken", Message: "name already used in this project"}
	}
	return err
}
