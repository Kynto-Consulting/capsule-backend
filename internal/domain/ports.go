package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// PortRule allows one CIDR to reach a project's published TCP port.
type PortRule struct {
	ID          uuid.UUID  `json:"id"`
	PortID      uuid.UUID  `json:"-"`
	CIDR        string     `json:"cidr"`
	Description string     `json:"description"`
	CreatedBy   *uuid.UUID `json:"-"`
	CreatedAt   time.Time  `json:"-"`
}

// ProjectPort is one extra TCP port a project's container publishes on the host.
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
}

// PortMapping is a published container->host port pair.
type PortMapping struct {
	ContainerPort int
	HostPort      int
}

// DesiredPortRule is a rule joined with its port (startup sweep).
type DesiredPortRule struct {
	ProjectID uuid.UUID
	HostPort  int
	CIDR      string
}

// ProjectPortRepository persists project ports and their access rules.
type ProjectPortRepository interface {
	// List returns the ports of a project (ordered by container port) with their rules.
	List(ctx context.Context, projectID uuid.UUID) ([]*ProjectPort, error)
	// UsedHostPorts returns every host port in [from, to] already taken by
	// project ports, databases or deployments.
	UsedHostPorts(ctx context.Context, from, to int) (map[int]bool, error)
	// Replace makes the stored ports equal to ports (exact host ports, already
	// assigned). Rules of kept ports survive; rules of removed ports go away.
	Replace(ctx context.Context, projectID uuid.UUID, ports []*ProjectPort) ([]*ProjectPort, error)
	// AddRule inserts a rule on the port with that container port. ErrNotFound
	// when the port does not exist, ErrConflict for a duplicate CIDR, ErrRuleLimit past max.
	AddRule(ctx context.Context, projectID uuid.UUID, containerPort int, rule *PortRule, max int) (*PortRule, error)
	DeleteRule(ctx context.Context, projectID, ruleID uuid.UUID) error
	// ListDesired returns every rule of every live project port.
	ListDesired(ctx context.Context) ([]DesiredPortRule, error)
	DeleteAll(ctx context.Context, projectID uuid.UUID) error
}
