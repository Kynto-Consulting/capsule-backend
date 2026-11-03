// Package store is the persistence contract of the universal gateway (docs/gateway/PLAN.md 5.1):
// named services per project, their two accesses (gateway primary, direct_port secondary), the route table
// read by the data plane, the random-port pool with leases/quarantine/quotas and the organisation policy.
//
// The service is the NAME of the configured port: unique per project, DNS-label format.
package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// Typed errors. Callers must map ErrNotFound to the SAME response as "not authorised" (no enumeration).
var (
	ErrNotFound          = errors.New("gateway: not found")
	ErrConflict          = errors.New("gateway: already exists")
	ErrInvalid           = errors.New("gateway: invalid value")
	ErrPortPoolExhausted = errors.New("gateway: random port pool exhausted")
	ErrQuotaExceeded     = errors.New("gateway: random port quota exceeded")
)

// QuotaError carries which limit was hit; errors.Is(err, ErrQuotaExceeded) is true.
type QuotaError struct {
	Scope string // "org" | "project"
	Limit int
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("gateway: random port quota exceeded (%s limit %d)", e.Scope, e.Limit)
}
func (e *QuotaError) Is(target error) bool { return target == ErrQuotaExceeded }

// Access kinds and defaults.
const (
	AccessGateway    = "gateway"
	AccessDirectPort = "direct_port"

	TransportTCP = "tcp"
	TransportUDP = "udp"

	ModePassthrough = "passthrough"
	ModeTerminate   = "terminate"

	PolicyWarn  = "warn"
	PolicyError = "error"

	DefaultMaxRandomPortsOrg     = 20
	DefaultMaxRandomPortsProject = 5
)

var (
	serviceNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	protocols     = map[string]bool{"http": true, "tls": true, "postgres": true, "mysql": true, "redis": true, "mongo": true, "ssh": true, "tcp": true, "udp": true}
)

// ValidServiceName reports whether name is a DNS label (1-63 chars, [a-z0-9-], no edge hyphen).
func ValidServiceName(name string) bool { return len(name) <= 63 && serviceNameRe.MatchString(name) }

// ValidProtocol reports whether p is a supported application protocol.
func ValidProtocol(p string) bool { return protocols[p] }

// Service is a named port of a project (ProjectID is uuid.Nil for organisation-level databases).
type Service struct {
	ID            uuid.UUID
	OrgID         uuid.UUID
	ProjectID     uuid.UUID
	Name          string
	Protocol      string
	ContainerPort int
	DefaultAccess string
	ProjectPortID *uuid.UUID
	DatabaseID    *uuid.UUID
	Accesses      []Access
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Access is one of the (at most two) ways to reach a service.
type Access struct {
	ID        uuid.UUID
	ServiceID uuid.UUID
	Kind      string
	Enabled   bool
	Port      *int // direct_port: the published host port
}

// NewService is the input of CreateService. DirectPort, when set, also creates the direct_port access.
type NewService struct {
	OrgID         uuid.UUID
	ProjectID     uuid.UUID // uuid.Nil = organisation level
	Name          string
	Protocol      string
	ContainerPort int
	DefaultAccess string // "" = gateway
	ProjectPortID *uuid.UUID
	DatabaseID    *uuid.UUID
	DirectPort    *int
}

// Route maps a host/SNI to an internal destination.
type Route struct {
	ID        uuid.UUID
	ServiceID uuid.UUID
	Host      string
	Transport string
	Protocol  string
	DestHost  string
	DestPort  int
	Mode      string
	Enabled   bool
	Rev       int64
}

// NewRoute is the input of UpsertRoute (unique per transport+host; a host cannot move between services).
type NewRoute struct {
	ServiceID uuid.UUID
	Host      string
	Transport string // "" = tcp
	Protocol  string // "" = service protocol
	DestHost  string
	DestPort  int
	Mode      string // "" = passthrough
	Enabled   bool
}

// RouteView is a route joined with the identity the data plane needs to authorise the connection.
type RouteView struct {
	Route
	OrgID       uuid.UUID
	ProjectID   uuid.UUID
	ServiceName string
}

// LeaseView is an active random-port lease as the data plane needs it (it listens on Port).
type LeaseView struct {
	Port      int
	ServiceID uuid.UUID
	ProjectID uuid.UUID
	OrgID     uuid.UUID
}

// Snapshot is the full route table at Rev. When the caller passed since == Rev, Unchanged is true and
// Routes/Leases are empty (long-poll answer).
type Snapshot struct {
	Rev       int64
	Unchanged bool
	Routes    []RouteView
	Leases    []LeaseView
}

// Lease is a random public port assigned to a service.
type Lease struct {
	ID         uuid.UUID
	Port       int
	ServiceID  uuid.UUID
	ProjectID  uuid.UUID
	OrgID      uuid.UUID
	State      string // active | released
	LeasedAt   time.Time
	ReleasedAt *time.Time
	LastConnAt *time.Time
}

// PoolStats counts pool ports by state.
type PoolStats struct{ Free, Leased, Quarantine, Total int }

// Quotas are the per-organisation random-port limits.
type Quotas struct{ MaxRandomPorts, MaxRandomPortsPerProject int }

// RouteStore is the persistence interface of the gateway control plane and data plane.
// Reads used by the data plane never return disabled routes or routes whose gateway access is disabled.
type RouteStore interface {
	// Route resolution. ErrNotFound for unknown / disabled (callers answer exactly as "not authorised").
	ResolveRoute(ctx context.Context, transport, host string) (*RouteView, error)
	ResolveService(ctx context.Context, projectID uuid.UUID, name, transport string) (*RouteView, error)
	// Snapshot returns the route table and active leases; since == current rev gives Unchanged.
	Snapshot(ctx context.Context, since int64) (*Snapshot, error)
	Revision(ctx context.Context) (int64, error)

	// Services, accesses, routes.
	CreateService(ctx context.Context, in NewService) (*Service, error)
	GetService(ctx context.Context, id uuid.UUID) (*Service, error)
	ListServices(ctx context.Context, projectID uuid.UUID) ([]*Service, error)
	DeleteService(ctx context.Context, id uuid.UUID, quarantine time.Duration) error
	SetAccess(ctx context.Context, serviceID uuid.UUID, kind string, enabled bool, port *int) (*Access, error)
	SetDefaultAccess(ctx context.Context, serviceID uuid.UUID, kind string) error
	UpsertRoute(ctx context.Context, in NewRoute) (*Route, error)
	DeleteRoute(ctx context.Context, id uuid.UUID) error

	// Random-port pool.
	SeedPortPool(ctx context.Context, lo, hi int) (int, error)
	LeasePort(ctx context.Context, serviceID uuid.UUID) (*Lease, error)
	ReleaseLease(ctx context.Context, serviceID uuid.UUID, quarantine time.Duration) error
	TouchLease(ctx context.Context, port int) error
	ReleaseIdle(ctx context.Context, idleBefore time.Time, quarantine time.Duration) (int, error)
	// SweepPool returns expired quarantine ports to free and reclaims leased ports with no active lease.
	SweepPool(ctx context.Context) (int, error)
	PoolStats(ctx context.Context) (PoolStats, error)
	GetQuotas(ctx context.Context, orgID uuid.UUID) (Quotas, error)
	SetQuotas(ctx context.Context, orgID uuid.UUID, q Quotas) error

	// Organisation policy for connections that bypass the gateway: warn | error.
	GetOrgPolicy(ctx context.Context, orgID uuid.UUID) (string, error)
	SetOrgPolicy(ctx context.Context, orgID uuid.UUID, policy string) error
}
