package api

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gateway/store"
)

// RouteJSON is a route as the data plane reads it (API.openapi.yaml: Route).
type RouteJSON struct {
	ID        uuid.UUID `json:"id"`
	ServiceID uuid.UUID `json:"service_id"`
	ProjectID uuid.UUID `json:"project_id"`
	OrgID     uuid.UUID `json:"org_id"`
	Service   string    `json:"service"`
	Host      string    `json:"host"`
	Transport string    `json:"transport"`
	Protocol  string    `json:"protocol"`
	DestHost  string    `json:"dest_host"`
	DestPort  int       `json:"dest_port"`
	Mode      string    `json:"mode"`
	Rev       int64     `json:"rev"`
}

// LeaseJSON is an active random-port lease (the data plane listens on Port).
type LeaseJSON struct {
	Port      int       `json:"port"`
	ServiceID uuid.UUID `json:"service_id"`
	ProjectID uuid.UUID `json:"project_id"`
	OrgID     uuid.UUID `json:"org_id"`
}

// SnapshotJSON is the full route table at Rev.
type SnapshotJSON struct {
	Rev    int64       `json:"rev"`
	Routes []RouteJSON `json:"routes"`
	Leases []LeaseJSON `json:"leases"`
}

// WaitRoutes serves GET /internal/gateway/routes. since < 0 means "the caller has nothing": it answers at once.
// When since equals the current revision it waits up to wait for a change (a local change wakes it immediately,
// a change made by another process is seen within PollInterval) and returns changed=false on timeout (HTTP 304).
func (s *Service) WaitRoutes(ctx context.Context, since int64, wait time.Duration) (snap *SnapshotJSON, changed bool, err error) {
	if wait > s.cfg.MaxWait {
		wait = s.cfg.MaxWait
	}
	if wait < 0 {
		wait = 0
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	poll := time.NewTicker(s.cfg.PollInterval)
	defer poll.Stop()
	for {
		wake := s.waiter() // taken before reading the revision: a change in between is not missed
		rev, err := s.d.Store.Revision(ctx)
		if err != nil {
			return nil, false, err
		}
		if rev != since {
			sn, err := s.d.Store.Snapshot(ctx, since)
			if err != nil {
				return nil, false, err
			}
			if !sn.Unchanged {
				return toJSON(sn.Rev, sn.Routes, sn.Leases), true, nil
			}
			rev = sn.Rev
		}
		select {
		case <-ctx.Done():
			return &SnapshotJSON{Rev: rev}, false, nil
		case <-deadline.C:
			return &SnapshotJSON{Rev: rev}, false, nil
		case <-wake:
		case <-poll.C:
		}
	}
}

func toJSON(rev int64, routes []store.RouteView, leases []store.LeaseView) *SnapshotJSON {
	out := &SnapshotJSON{Rev: rev, Routes: make([]RouteJSON, 0, len(routes)), Leases: make([]LeaseJSON, 0, len(leases))}
	for _, r := range routes {
		out.Routes = append(out.Routes, RouteJSON{ID: r.ID, ServiceID: r.ServiceID, ProjectID: r.ProjectID, OrgID: r.OrgID, Service: r.ServiceName,
			Host: r.Host, Transport: r.Transport, Protocol: r.Protocol, DestHost: r.DestHost, DestPort: r.DestPort, Mode: r.Mode, Rev: r.Rev})
	}
	for _, l := range leases {
		out.Leases = append(out.Leases, LeaseJSON{Port: l.Port, ServiceID: l.ServiceID, ProjectID: l.ProjectID, OrgID: l.OrgID})
	}
	return out
}
