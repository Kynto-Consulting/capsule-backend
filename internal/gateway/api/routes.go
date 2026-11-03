package api

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gateway/store"
)

// RouteJSON is a route as the data plane reads it (API.openapi.yaml: Route).
type RouteJSON struct {
	ID          uuid.UUID `json:"id"`
	ServiceID   uuid.UUID `json:"service_id"`
	ProjectID   uuid.UUID `json:"project_id"`
	OrgID       uuid.UUID `json:"org_id"`
	Service     string    `json:"service"`
	ProjectSlug string    `json:"project_slug"` // slug carried by the capsule/1 header: (project_slug, service, transport) resolves a route
	Host        string    `json:"host"`
	Transport   string    `json:"transport"`
	Protocol    string    `json:"protocol"`
	DestHost    string    `json:"dest_host"`
	DestPort    int       `json:"dest_port"`
	Mode        string    `json:"mode"`
	Rev         int64     `json:"rev"`
}

// LeaseJSON is an active random-port lease (the data plane listens on Port).
type LeaseJSON struct {
	Port      int       `json:"port"`
	ServiceID uuid.UUID `json:"service_id"`
	ProjectID uuid.UUID `json:"project_id"`
	OrgID     uuid.UUID `json:"org_id"`
	RouteID   uuid.UUID `json:"route_id,omitempty"`  // route the port forwards through (the tcp one when a service has both)
	Transport string    `json:"transport,omitempty"` // tcp | udp | both: what the service routes
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
				out := toJSON(sn.Rev, sn.Routes, sn.Leases)
				s.fillSlugs(ctx, out)
				return out, true, nil
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
	type svcRoutes struct {
		id       uuid.UUID
		tcp, udp bool
	}
	bySvc := map[uuid.UUID]*svcRoutes{}
	for _, r := range routes {
		out.Routes = append(out.Routes, RouteJSON{ID: r.ID, ServiceID: r.ServiceID, ProjectID: r.ProjectID, OrgID: r.OrgID, Service: r.ServiceName,
			Host: r.Host, Transport: r.Transport, Protocol: r.Protocol, DestHost: r.DestHost, DestPort: r.DestPort, Mode: r.Mode, Rev: r.Rev})
		sr := bySvc[r.ServiceID]
		if sr == nil {
			sr = &svcRoutes{}
			bySvc[r.ServiceID] = sr
		}
		if r.Transport == "udp" {
			sr.udp = true
			if sr.id == uuid.Nil {
				sr.id = r.ID
			}
		} else {
			sr.tcp = true
			sr.id = r.ID
		}
	}
	for _, l := range leases {
		lj := LeaseJSON{Port: l.Port, ServiceID: l.ServiceID, ProjectID: l.ProjectID, OrgID: l.OrgID}
		if sr := bySvc[l.ServiceID]; sr != nil {
			lj.RouteID = sr.id
			switch {
			case sr.tcp && sr.udp:
				lj.Transport = "both"
			case sr.udp:
				lj.Transport = "udp"
			default:
				lj.Transport = "tcp"
			}
		}
		out.Leases = append(out.Leases, lj)
	}
	return out
}

type slugEntry struct {
	slug    string
	expires time.Time
}

// fillSlugs sets project_slug on every route (one lookup per distinct project, cached 60 s).
func (s *Service) fillSlugs(ctx context.Context, out *SnapshotJSON) {
	now := s.now()
	s.slugMu.Lock()
	if s.slugs == nil {
		s.slugs = map[uuid.UUID]slugEntry{}
	}
	s.slugMu.Unlock()
	for i := range out.Routes {
		id := out.Routes[i].ProjectID
		s.slugMu.Lock()
		e, ok := s.slugs[id]
		s.slugMu.Unlock()
		if !ok || now.After(e.expires) {
			p, err := s.d.Projects.GetByID(ctx, id)
			if err != nil || p == nil {
				continue // a route without slug is reachable by name, not through the tunnel
			}
			e = slugEntry{slug: p.Slug, expires: now.Add(time.Minute)}
			s.slugMu.Lock()
			s.slugs[id] = e
			s.slugMu.Unlock()
		}
		out.Routes[i].ProjectSlug = e.slug
	}
}
