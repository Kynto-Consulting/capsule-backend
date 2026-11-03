package api

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gateway/store"
	"github.com/kynto/capsule/backend/internal/gitaudit"
)

// Actor is who performs a change (for the audit trail).
type Actor struct {
	UserID uuid.UUID
	IP     string
}

// AccessView is an access of a service.
type AccessView struct {
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	Port    *int   `json:"port"`
}

// ServiceView is the API shape of a service (API.openapi.yaml: Service).
type ServiceView struct {
	ID            uuid.UUID    `json:"id"`
	Name          string       `json:"name"`
	Protocol      string       `json:"protocol"`
	ContainerPort int          `json:"container_port"`
	DefaultAccess string       `json:"default_access"`
	Accesses      []AccessView `json:"accesses"`
	Host          string       `json:"host,omitempty"`       // SNI/Host of the gateway name
	ManagedBy     string       `json:"managed_by,omitempty"` // "project_port" | "database" when it mirrors an existing port
	CreatedAt     time.Time    `json:"created_at"`
}

func (s *Service) view(sv *store.Service, p *domain.Project) ServiceView {
	v := ServiceView{ID: sv.ID, Name: sv.Name, Protocol: sv.Protocol, ContainerPort: sv.ContainerPort, DefaultAccess: sv.DefaultAccess,
		Accesses: make([]AccessView, 0, len(sv.Accesses)), CreatedAt: sv.CreatedAt}
	for _, a := range sv.Accesses {
		v.Accesses = append(v.Accesses, AccessView{Kind: a.Kind, Enabled: a.Enabled, Port: a.Port})
	}
	switch {
	case sv.ProjectPortID != nil:
		v.ManagedBy = "project_port"
	case sv.DatabaseID != nil:
		v.ManagedBy = "database"
	}
	if h, err := s.serviceHost(sv, p); err == nil {
		v.Host = h
	}
	return v
}

// ListServices returns the project's services (after mirroring its ports and databases).
func (s *Service) ListServices(ctx context.Context, p *domain.Project) ([]ServiceView, error) {
	if err := s.syncProject(ctx, p, true); err != nil {
		return nil, err
	}
	svcs, err := s.d.Store.ListServices(ctx, p.ID)
	if err != nil {
		return nil, mapStoreErr(err)
	}
	out := make([]ServiceView, 0, len(svcs))
	for _, sv := range svcs {
		out = append(out, s.view(sv, p))
	}
	return out, nil
}

// findService resolves a service by name inside the project; it mirrors the project's ports once when the name is unknown.
func (s *Service) findService(ctx context.Context, p *domain.Project, name string) (*store.Service, error) {
	name = lowerTrim(name)
	if !store.ValidServiceName(name) {
		return nil, errNotFound()
	}
	for attempt := 0; attempt < 2; attempt++ {
		svcs, err := s.d.Store.ListServices(ctx, p.ID)
		if err != nil {
			return nil, mapStoreErr(err)
		}
		for _, sv := range svcs {
			if sv.Name == name {
				return sv, nil
			}
		}
		if attempt == 0 {
			if err := s.syncProject(ctx, p, false); err != nil {
				return nil, err
			}
		}
	}
	return nil, errNotFound()
}

// CreateInput is the body of POST .../gateway/services.
type CreateInput struct {
	Name          string `json:"name"`
	Protocol      string `json:"protocol"`
	ContainerPort int    `json:"container_port"`
	Mode          string `json:"mode"`
	DefaultAccess string `json:"default_access"`
}

// CreateService exposes a new service through the gateway (a service and its enabled gateway access plus the route).
func (s *Service) CreateService(ctx context.Context, p *domain.Project, a Actor, in CreateInput) (*ServiceView, error) {
	in.Name = lowerTrim(in.Name)
	if !store.ValidServiceName(in.Name) {
		return nil, errBadRequest("name must be a DNS label: lowercase letters, digits and hyphens, 1-63 characters")
	}
	if in.Protocol == "" {
		in.Protocol = "tcp"
	}
	if !store.ValidProtocol(in.Protocol) {
		return nil, errBadRequest("unsupported protocol")
	}
	if in.ContainerPort < 1 || in.ContainerPort > 65535 {
		return nil, errBadRequest("container_port must be between 1 and 65535")
	}
	if in.Mode == "" {
		in.Mode = store.ModePassthrough
	}
	if in.Mode != store.ModePassthrough && in.Mode != store.ModeTerminate {
		return nil, errBadRequest("mode must be passthrough or terminate")
	}
	if in.DefaultAccess != "" && in.DefaultAccess != store.AccessGateway {
		return nil, errBadRequest("a new service has no direct port: default_access must be gateway")
	}
	if err := s.syncProject(ctx, p, false); err != nil { // so the name check sees existing ports
		return nil, err
	}
	sv, err := s.d.Store.CreateService(ctx, store.NewService{
		OrgID: p.OrgID, ProjectID: p.ID, Name: in.Name, Protocol: in.Protocol, ContainerPort: in.ContainerPort, DefaultAccess: store.AccessGateway,
	})
	if err != nil {
		return nil, mapStoreErr(err)
	}
	if err := s.applyRoute(ctx, sv, p, true, in.Mode); err != nil {
		_ = s.d.Store.DeleteService(ctx, sv.ID, s.cfg.Quarantine) // do not leave a half-exposed service
		return nil, err
	}
	s.notify()
	s.auditEvent(ctx, gitaudit.Entry{OrgID: p.OrgID, ProjectID: &p.ID, UserID: uidPtr(a.UserID), Action: "gateway.service.create", ResourceType: "gateway_service",
		ResourceID: &sv.ID, IP: a.IP, Metadata: map[string]any{"service": sv.Name, "protocol": sv.Protocol, "mode": in.Mode}})
	fresh, err := s.d.Store.GetService(ctx, sv.ID)
	if err != nil {
		return nil, mapStoreErr(err)
	}
	v := s.view(fresh, p)
	return &v, nil
}

// UpdateInput is the body of PATCH .../gateway/services/{service}. Nil fields are left as they are.
type UpdateInput struct {
	GatewayEnabled    *bool   `json:"gateway_enabled"`
	DirectPortEnabled *bool   `json:"direct_port_enabled"`
	DefaultAccess     *string `json:"default_access"`
	Mode              *string `json:"mode"`
}

// UpdateService changes the gateway access, the default access or the route mode.
// The direct port is NOT opened or closed here: it belongs to the ports/databases API (and the firewall reconciler),
// so asking for a different direct_port_enabled is rejected instead of pretending to change a firewall rule.
func (s *Service) UpdateService(ctx context.Context, p *domain.Project, a Actor, name string, in UpdateInput) (*ServiceView, error) {
	sv, err := s.findService(ctx, p, name)
	if err != nil {
		return nil, err
	}
	if in.GatewayEnabled == nil && in.DirectPortEnabled == nil && in.DefaultAccess == nil && in.Mode == nil {
		return nil, errBadRequest("nothing to change")
	}
	if in.Mode != nil && *in.Mode != store.ModePassthrough && *in.Mode != store.ModeTerminate {
		return nil, errBadRequest("mode must be passthrough or terminate")
	}
	if in.DefaultAccess != nil && *in.DefaultAccess != store.AccessGateway && *in.DefaultAccess != store.AccessDirectPort {
		return nil, errBadRequest("default_access must be gateway or direct_port")
	}
	if in.DirectPortEnabled != nil {
		da := accessOf(sv, store.AccessDirectPort)
		cur := da != nil && da.Enabled
		if *in.DirectPortEnabled != cur {
			e := errBadRequest("the direct port is opened or closed from the ports or databases settings, not here")
			e.Hint = "Use the access rules of the port or database; the gateway does not change firewall rules."
			return nil, e
		}
	}
	wantGW := gatewayEnabled(sv)
	if in.GatewayEnabled != nil {
		wantGW = *in.GatewayEnabled
	}
	if in.DefaultAccess != nil {
		t := accessOf(sv, *in.DefaultAccess)
		enabledAfter := t != nil && t.Enabled
		if *in.DefaultAccess == store.AccessGateway {
			enabledAfter = wantGW
		}
		if !enabledAfter {
			return nil, errBadRequest("default_access points to an access that is not enabled")
		}
	}
	mode := ""
	if in.Mode != nil {
		mode = *in.Mode
	}
	if in.GatewayEnabled != nil || in.Mode != nil {
		if wantGW {
			if _, err := s.d.Store.SetAccess(ctx, sv.ID, store.AccessGateway, true, nil); err != nil {
				return nil, mapStoreErr(err)
			}
			if err := s.applyRoute(ctx, sv, p, true, mode); err != nil {
				return nil, err
			}
		} else {
			if _, err := s.d.Store.SetAccess(ctx, sv.ID, store.AccessGateway, false, nil); err != nil {
				return nil, mapStoreErr(err)
			}
			_ = s.applyRoute(ctx, sv, p, false, mode) // best effort: the snapshot already hides it
			if err := s.d.Store.ReleaseLease(ctx, sv.ID, s.cfg.Quarantine); err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, mapStoreErr(err)
			}
		}
	}
	if in.DefaultAccess != nil && *in.DefaultAccess != sv.DefaultAccess {
		if err := s.d.Store.SetDefaultAccess(ctx, sv.ID, *in.DefaultAccess); err != nil {
			return nil, mapStoreErr(err)
		}
	}
	s.notify()
	meta := map[string]any{"service": sv.Name}
	if in.GatewayEnabled != nil {
		meta["gateway_enabled"] = *in.GatewayEnabled
	}
	if in.DefaultAccess != nil {
		meta["default_access"] = *in.DefaultAccess
	}
	if in.Mode != nil {
		meta["mode"] = *in.Mode
	}
	s.auditEvent(ctx, gitaudit.Entry{OrgID: p.OrgID, ProjectID: &p.ID, UserID: uidPtr(a.UserID), Action: "gateway.service.update", ResourceType: "gateway_service",
		ResourceID: &sv.ID, IP: a.IP, Metadata: meta})
	fresh, err := s.d.Store.GetService(ctx, sv.ID)
	if err != nil {
		return nil, mapStoreErr(err)
	}
	v := s.view(fresh, p)
	return &v, nil
}

// DeleteService closes a service. A service that mirrors an existing port or database only loses its gateway access
// (the port or database itself is untouched); one created through the API is removed. Its random port goes to quarantine.
func (s *Service) DeleteService(ctx context.Context, p *domain.Project, a Actor, name string) error {
	sv, err := s.findService(ctx, p, name)
	if err != nil {
		return err
	}
	if sv.ProjectPortID != nil || sv.DatabaseID != nil {
		if _, err := s.d.Store.SetAccess(ctx, sv.ID, store.AccessGateway, false, nil); err != nil {
			return mapStoreErr(err)
		}
		_ = s.applyRoute(ctx, sv, p, false, "")
		if err := s.d.Store.ReleaseLease(ctx, sv.ID, s.cfg.Quarantine); err != nil && !errors.Is(err, store.ErrNotFound) {
			return mapStoreErr(err)
		}
	} else if err := s.d.Store.DeleteService(ctx, sv.ID, s.cfg.Quarantine); err != nil {
		return mapStoreErr(err)
	}
	s.notify()
	s.auditEvent(ctx, gitaudit.Entry{OrgID: p.OrgID, ProjectID: &p.ID, UserID: uidPtr(a.UserID), Action: "gateway.service.delete", ResourceType: "gateway_service",
		ResourceID: &sv.ID, IP: a.IP, Metadata: map[string]any{"service": sv.Name}})
	return nil
}

// applyRoute writes the service's route (host, destination, mode, enabled). mode "" keeps the current one.
func (s *Service) applyRoute(ctx context.Context, sv *store.Service, p *domain.Project, enabled bool, mode string) error {
	host, err := s.serviceHost(sv, p)
	if err != nil {
		return err
	}
	dh, dp, err := s.destFor(sv)
	if err != nil {
		return err
	}
	if mode == "" {
		mode = store.ModePassthrough
		if cur, err := s.d.Store.ResolveService(ctx, p.ID, sv.Name, transportOf(sv.Protocol)); err == nil && cur.Mode != "" {
			mode = cur.Mode
		}
	}
	if _, err := s.d.Store.UpsertRoute(ctx, store.NewRoute{
		ServiceID: sv.ID, Host: host, Transport: transportOf(sv.Protocol), Protocol: sv.Protocol, DestHost: dh, DestPort: dp, Mode: mode, Enabled: enabled,
	}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return &Error{Status: 409, Code: "host_in_use", Message: "the name for this service is already used by another project", Hint: "Rename the service."}
		}
		return mapStoreErr(err)
	}
	return nil
}

// reapplyRoute refreshes the destination of an enabled route after its host port changed.
func (s *Service) reapplyRoute(ctx context.Context, id uuid.UUID, p *domain.Project) {
	sv, err := s.d.Store.GetService(ctx, id)
	if err != nil || !gatewayEnabled(sv) {
		return
	}
	if err := s.applyRoute(ctx, sv, p, true, ""); err != nil {
		s.log.Warn("gateway: refreshing route destination failed", "service_id", id.String(), "error", err.Error())
	}
}

func uidPtr(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
