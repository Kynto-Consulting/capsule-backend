package domain

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Transport protocols of a published project port.
const (
	ProtoTCP = "tcp"
	ProtoUDP = "udp"
)

// NormalizeProtocol maps "" to tcp and lower-cases; ok is false for anything
// other than tcp or udp.
func NormalizeProtocol(p string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", ProtoTCP:
		return ProtoTCP, true
	case ProtoUDP:
		return ProtoUDP, true
	}
	return "", false
}

// PortRule allows one CIDR to reach a project's published TCP or UDP port.
type PortRule struct {
	ID          uuid.UUID  `json:"id"`
	PortID      uuid.UUID  `json:"-"`
	Protocol    string     `json:"-"`
	CIDR        string     `json:"cidr"`
	Description string     `json:"description"`
	CreatedBy   *uuid.UUID `json:"-"`
	CreatedAt   time.Time  `json:"-"`
}

// ProjectPort is one extra TCP or UDP port a project's container publishes on the host.
type ProjectPort struct {
	ID            uuid.UUID
	ProjectID     uuid.UUID
	Name          string
	ContainerPort int
	Protocol      string
	HostPort      int
	CreatedAt     time.Time
	Rules         []*PortRule
}

// PortSpec is a requested port (input of a replace).
type PortSpec struct {
	Name          string
	ContainerPort int
	Protocol      string // tcp (default) or udp
}

// PortMapping is a published container->host port pair. Protocol "" means tcp.
type PortMapping struct {
	ContainerPort int
	HostPort      int
	Protocol      string
}

// DesiredPortRule is a rule joined with its port (startup sweep).
type DesiredPortRule struct {
	ProjectID uuid.UUID
	Protocol  string
	HostPort  int
	CIDR      string
}

// ProjectPortRepository persists project ports and their access rules.
type ProjectPortRepository interface {
	// List returns the ports of a project (ordered by container port, protocol) with their rules.
	List(ctx context.Context, projectID uuid.UUID) ([]*ProjectPort, error)
	// UsedHostPorts returns every host port in [from, to] already taken for the
	// protocol: uniqueness is per (port, protocol). tcp also counts databases
	// and deployments; udp only counts UDP project ports.
	UsedHostPorts(ctx context.Context, protocol string, from, to int) (map[int]bool, error)
	// Replace makes the stored ports equal to ports (exact host ports, already
	// assigned). Ports are keyed by (container port, protocol). Rules of kept
	// ports survive; rules of removed ports go away.
	Replace(ctx context.Context, projectID uuid.UUID, ports []*ProjectPort) ([]*ProjectPort, error)
	// AddRule inserts a rule on the port with that container port and protocol.
	// ErrNotFound when the port does not exist, ErrConflict for a duplicate CIDR, ErrRuleLimit past max.
	AddRule(ctx context.Context, projectID uuid.UUID, containerPort int, protocol string, rule *PortRule, max int) (*PortRule, error)
	DeleteRule(ctx context.Context, projectID, ruleID uuid.UUID) error
	// ListDesired returns every rule of every live project port.
	ListDesired(ctx context.Context) ([]DesiredPortRule, error)
	DeleteAll(ctx context.Context, projectID uuid.UUID) error
}
