package api

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gateway/store"
)

// minSyncGap spares the database when several calls of one project arrive together.
const minSyncGap = 5 * time.Second

// syncProject mirrors the project's published ports (project_ports) and databases as gateway services, without
// changing how they behave today: a mirrored service starts with default_access=direct_port, its direct access
// enabled with the current host port and the gateway access OFF (migration 000060 does the same for what already
// existed). Services whose source disappeared are removed; a changed host port is copied over.
func (s *Service) syncProject(ctx context.Context, p *domain.Project, force bool) error {
	if s.d.Sources == nil {
		return nil
	}
	s.syncMu.Lock()
	if !force && s.now().Sub(s.syncedAt[p.ID]) < minSyncGap {
		s.syncMu.Unlock()
		return nil
	}
	s.syncedAt[p.ID] = s.now()
	s.syncMu.Unlock()

	ports, err := s.d.Sources.Ports(ctx, p.ID)
	if err != nil {
		return err
	}
	dbs, err := s.d.Sources.Databases(ctx, p.ID)
	if err != nil {
		return err
	}
	svcs, err := s.d.Store.ListServices(ctx, p.ID)
	if err != nil {
		return err
	}
	used := map[string]bool{}
	byPort := map[uuid.UUID]*store.Service{}
	byDB := map[uuid.UUID]*store.Service{}
	for _, sv := range svcs {
		used[sv.Name] = true
		if sv.ProjectPortID != nil {
			byPort[*sv.ProjectPortID] = sv
		}
		if sv.DatabaseID != nil {
			byDB[*sv.DatabaseID] = sv
		}
	}
	changed := false

	livePort := map[uuid.UUID]bool{}
	for _, pp := range ports {
		livePort[pp.ID] = true
		if sv := byPort[pp.ID]; sv != nil {
			if s.copyDirectPort(ctx, sv, pp.HostPort) {
				s.reapplyRoute(ctx, sv.ID, p)
				changed = true
			}
			continue
		}
		base := slugLabel(pp.Name, 50)
		if base == "" {
			base = "port-" + strconv.Itoa(pp.ContainerPort)
		}
		proto, suffix := "tcp", "-"+strconv.Itoa(pp.ContainerPort)
		if pp.Protocol == domain.ProtoUDP {
			proto, suffix = "udp", "-"+strconv.Itoa(pp.ContainerPort)+"-udp"
		}
		name := uniqueName(base, suffix, used)
		id, hp := pp.ID, pp.HostPort
		if err := s.createMirror(ctx, store.NewService{
			OrgID: p.OrgID, ProjectID: p.ID, Name: name, Protocol: proto, ContainerPort: pp.ContainerPort,
			DefaultAccess: store.AccessDirectPort, ProjectPortID: &id, DirectPort: &hp,
		}); err != nil {
			s.log.Warn("gateway: mirroring project port failed", "project_id", p.ID.String(), "error", err.Error())
			continue
		}
		changed = true
	}
	liveDB := map[uuid.UUID]bool{}
	for _, db := range dbs {
		if db.Status == "deleted" {
			continue
		}
		liveDB[db.ID] = true
		if sv := byDB[db.ID]; sv != nil {
			if db.Port > 0 && s.copyDirectPort(ctx, sv, db.Port) {
				s.reapplyRoute(ctx, sv.ID, p)
				changed = true
			}
			continue
		}
		if db.Port <= 0 {
			continue // not provisioned yet: mirrored on a later call
		}
		base := slugLabel(db.Name, 50)
		if base == "" {
			base = "db-" + db.ID.String()[:8]
		}
		name := uniqueName(base, "-"+db.ID.String()[:8], used)
		id, hp := db.ID, db.Port
		if err := s.createMirror(ctx, store.NewService{
			OrgID: p.OrgID, ProjectID: p.ID, Name: name, Protocol: dbProtocol(db.Engine), ContainerPort: db.Port,
			DefaultAccess: store.AccessDirectPort, DatabaseID: &id, DirectPort: &hp,
		}); err != nil {
			s.log.Warn("gateway: mirroring database failed", "project_id", p.ID.String(), "error", err.Error())
			continue
		}
		changed = true
	}
	// Sources that no longer exist (soft-deleted databases keep their row, so the cascade does not fire).
	for _, sv := range svcs {
		orphan := (sv.ProjectPortID != nil && !livePort[*sv.ProjectPortID]) || (sv.DatabaseID != nil && !liveDB[*sv.DatabaseID])
		if !orphan {
			continue
		}
		if err := s.d.Store.DeleteService(ctx, sv.ID, s.cfg.Quarantine); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.Warn("gateway: removing orphan service failed", "service_id", sv.ID.String(), "error", err.Error())
			continue
		}
		changed = true
	}
	if changed {
		s.notify()
	}
	return nil
}

// createMirror creates a mirrored service with its gateway access disabled. A concurrent creator winning the race
// (ErrConflict) is not an error.
func (s *Service) createMirror(ctx context.Context, in store.NewService) error {
	sv, err := s.d.Store.CreateService(ctx, in)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil
		}
		return err
	}
	_, err = s.d.Store.SetAccess(ctx, sv.ID, store.AccessGateway, false, nil)
	return err
}

// copyDirectPort keeps the direct access port equal to the live host port. It reports whether it changed anything.
func (s *Service) copyDirectPort(ctx context.Context, sv *store.Service, host int) bool {
	for _, a := range sv.Accesses {
		if a.Kind != store.AccessDirectPort {
			continue
		}
		if a.Port != nil && *a.Port == host {
			return false
		}
		hp := host
		if _, err := s.d.Store.SetAccess(ctx, sv.ID, store.AccessDirectPort, a.Enabled, &hp); err != nil {
			s.log.Warn("gateway: updating direct port failed", "service_id", sv.ID.String(), "error", err.Error())
			return false
		}
		return true
	}
	return false
}

func accessOf(sv *store.Service, kind string) *store.Access {
	for i := range sv.Accesses {
		if sv.Accesses[i].Kind == kind {
			return &sv.Accesses[i]
		}
	}
	return nil
}

func gatewayEnabled(sv *store.Service) bool {
	a := accessOf(sv, store.AccessGateway)
	return a != nil && a.Enabled
}

func lowerTrim(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
