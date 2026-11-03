package api

import (
	"context"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gateway/store"
)

// RepoIPLists reads THE lists netaccess enforces on the firewall, so editing a list in the dashboard changes both access
// paths at once (PLAN 5.1, 12.1):
//   - a service that mirrors a database: that database's access rules;
//   - a service that mirrors a project port: that port's rules;
//   - any other service: the project's IP allowlist (empty = public, as for the application itself).
//
// For the first two, "no rules" means nobody (exactly what the firewall does for the direct port today).
type RepoIPLists struct {
	Databases domain.DatabaseAccessRepository
	Ports     domain.ProjectPortRepository
	Network   domain.ProjectNetworkRepository
}

// AllowedCIDRs implements IPLists.
func (r RepoIPLists) AllowedCIDRs(ctx context.Context, svc *store.Service) ([]string, bool, error) {
	switch {
	case svc.DatabaseID != nil && r.Databases != nil:
		rules, err := r.Databases.List(ctx, *svc.DatabaseID)
		if err != nil {
			return nil, true, err
		}
		out := make([]string, 0, len(rules))
		for _, ru := range rules {
			out = append(out, ru.CIDR)
		}
		return out, true, nil
	case svc.ProjectPortID != nil && r.Ports != nil:
		ports, err := r.Ports.List(ctx, svc.ProjectID)
		if err != nil {
			return nil, true, err
		}
		for _, p := range ports {
			if p.ID != *svc.ProjectPortID {
				continue
			}
			out := make([]string, 0, len(p.Rules))
			want := domain.ProtoTCP
			if svc.Protocol == "udp" {
				want = domain.ProtoUDP
			}
			for _, ru := range p.Rules {
				if ru.Protocol != "" && ru.Protocol != want {
					continue // a udp rule does not open the tcp port of the same number, and the other way round
				}
				out = append(out, ru.CIDR)
			}
			return out, true, nil
		}
		return nil, true, nil // the port vanished: nobody
	case svc.ProjectID != uuid.Nil && r.Network != nil:
		l, err := r.Network.GetIPAllowlist(ctx, svc.ProjectID)
		if err != nil {
			return nil, true, err
		}
		return l, len(l) > 0, nil
	}
	return nil, false, nil
}

// RepoSources adapts the ports and databases repositories to Sources.
type RepoSources struct {
	PortRepo domain.ProjectPortRepository
	DBRepo   domain.DatabaseRepository
}

// Ports implements Sources.
func (r RepoSources) Ports(ctx context.Context, projectID uuid.UUID) ([]*domain.ProjectPort, error) {
	if r.PortRepo == nil {
		return nil, nil
	}
	return r.PortRepo.List(ctx, projectID)
}

// Databases implements Sources.
func (r RepoSources) Databases(ctx context.Context, projectID uuid.UUID) ([]*domain.Database, error) {
	if r.DBRepo == nil {
		return nil, nil
	}
	return r.DBRepo.ListByProject(ctx, projectID)
}
