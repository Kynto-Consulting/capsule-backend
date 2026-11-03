package api

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gateway/store"
	"github.com/kynto/capsule/backend/internal/gitaudit"
)

// ConnectionString is one way to reach a service (API.openapi.yaml: ConnectionString). Never carries a password.
type ConnectionString struct {
	Access      string `json:"access"` // gateway | direct_port
	Kind        string `json:"kind"`   // sni_name | capsule_uri | random_port | direct_port
	Value       string `json:"value"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	Command     string `json:"command,omitempty"`
	Recommended bool   `json:"recommended,omitempty"`
	Warning     string `json:"warning,omitempty"`
}

// ConnectionInfo is the response of connection-info.
type ConnectionInfo struct {
	Service           string             `json:"service"`
	Protocol          string             `json:"protocol"`
	ConnectionStrings []ConnectionString `json:"connection_strings"`
	// ConnectionString is the old field: it keeps the DIRECT string while the contract migrates in two steps (PLAN 12.1).
	ConnectionString string `json:"connection_string,omitempty"`
}

// DirectWarning is the mandatory warning of the direct (secondary) method.
const DirectWarning = "Puerto no estandar: requiere que su IP este permitida; el certificado es autofirmado. Prefiera la conexion por el gateway."

var defaultPorts = map[string]int{"postgres": 5432, "mysql": 3306, "redis": 6379, "mongo": 27017, "http": 443, "tls": 443}

func sniValue(protocol, host string) (string, int) {
	port := defaultPorts[protocol]
	switch protocol {
	case "http":
		return "https://" + host, 443
	case "postgres":
		return fmt.Sprintf("postgresql://%s:%d/?sslmode=require", host, port), port
	case "mysql":
		return fmt.Sprintf("mysql://%s:%d/?ssl-mode=REQUIRED", host, port), port
	case "redis":
		return fmt.Sprintf("rediss://%s:%d", host, port), port
	case "mongo":
		return fmt.Sprintf("mongodb://%s:%d/?tls=true", host, port), port
	case "tls":
		return fmt.Sprintf("%s:%d", host, port), port
	}
	return "", 0
}

// ConnectionInfo returns the connection strings of a service, the gateway ones first.
func (s *Service) ConnectionInfo(ctx context.Context, p *domain.Project, name string) (*ConnectionInfo, error) {
	sv, err := s.findService(ctx, p, name)
	if err != nil {
		return nil, err
	}
	info := &ConnectionInfo{Service: sv.Name, Protocol: sv.Protocol, ConnectionStrings: []ConnectionString{}}
	route := p.Slug + "/" + sv.Name
	if gatewayEnabled(sv) {
		if host, err := s.serviceHost(sv, p); err == nil {
			if v, port := sniValue(sv.Protocol, host); v != "" {
				info.ConnectionStrings = append(info.ConnectionStrings, ConnectionString{Access: store.AccessGateway, Kind: "sni_name", Value: v, Host: host, Port: port, Recommended: true})
			}
		}
		info.ConnectionStrings = append(info.ConnectionStrings, ConnectionString{
			Access: store.AccessGateway, Kind: "capsule_uri", Value: "capsule://" + route, Host: "tcp.apps." + s.cfg.Zone, Port: 443,
			Command: "capsule connect " + route, Recommended: len(info.ConnectionStrings) == 0,
		})
		if ix, err := s.index(ctx); err == nil {
			if l, ok := ix.leases[sv.ID]; ok {
				if host, err := s.appsHost(sv, p); err == nil {
					info.ConnectionStrings = append(info.ConnectionStrings, ConnectionString{
						Access: store.AccessGateway, Kind: "random_port", Value: host + ":" + strconv.Itoa(l.Port), Host: host, Port: l.Port,
					})
				}
			}
		}
	}
	if da := accessOf(sv, store.AccessDirectPort); da != nil && da.Enabled && da.Port != nil && s.cfg.TCPHost != "" {
		v := s.cfg.TCPHost + ":" + strconv.Itoa(*da.Port)
		info.ConnectionStrings = append(info.ConnectionStrings, ConnectionString{
			Access: store.AccessDirectPort, Kind: "direct_port", Value: v, Host: s.cfg.TCPHost, Port: *da.Port, Warning: DirectWarning,
		})
		info.ConnectionString = v
	}
	return info, nil
}

// ConnectionTokenResult is the response of connection-token. The token is shown once and never logged.
type ConnectionTokenResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Route     string    `json:"route"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
}

// IssueConnectionToken emits a cgc_ token restricted to this service (one route, one use, at most 5 minutes).
// The caller has already checked project.connect.
func (s *Service) IssueConnectionToken(ctx context.Context, p *domain.Project, a Actor, name string) (*ConnectionTokenResult, error) {
	if s.signer == nil {
		return nil, &Error{Status: 501, Code: "not_configured", Message: "connection tokens are not configured on this server",
			Hint: "Set " + EnvSigningKey + " (base64 Ed25519 seed)."}
	}
	sv, err := s.findService(ctx, p, name)
	if err != nil {
		return nil, err
	}
	if !gatewayEnabled(sv) {
		return nil, errNotFound() // same answer as "does not exist"
	}
	route := p.Slug + "/" + sv.Name
	tok, jti, exp, err := s.signer.Issue(a.UserID.String(), route, s.now(), CGCMaxLife)
	if err != nil {
		return nil, err
	}
	s.auditEvent(ctx, gitaudit.Entry{OrgID: p.OrgID, ProjectID: &p.ID, UserID: uidPtr(a.UserID), Action: "gateway.token.issue", ResourceType: "gateway_service",
		ResourceID: &sv.ID, IP: a.IP, Metadata: map[string]any{"service": sv.Name, "jti": jti, "type": "cgc"}})
	return &ConnectionTokenResult{Token: tok, ExpiresAt: exp, Route: route, Host: "tcp.apps." + s.cfg.Zone, Port: 443}, nil
}

// PortLeaseView is the API shape of an active random-port lease.
type PortLeaseView struct {
	Port             int        `json:"port"`
	Host             string     `json:"host"`
	State            string     `json:"state"`
	LeasedAt         time.Time  `json:"leased_at"`
	LastConnAt       *time.Time `json:"last_conn_at"`
	PlannedReleaseAt *time.Time `json:"planned_release_at"`
}

// LeasePort gives the service a random fallback port (idempotent). It makes sure the service has its gateway route,
// because the data plane forwards a leased port through that route.
func (s *Service) LeasePort(ctx context.Context, p *domain.Project, a Actor, name string) (*PortLeaseView, error) {
	sv, err := s.findService(ctx, p, name)
	if err != nil {
		return nil, err
	}
	if !gatewayEnabled(sv) {
		return nil, &Error{Status: 409, Code: "invalid_request", Message: "enable the gateway access of the service first"}
	}
	host, err := s.appsHost(sv, p)
	if err != nil {
		return nil, err
	}
	l, err := s.d.Store.LeasePort(ctx, sv.ID)
	if err != nil {
		return nil, mapStoreErr(err)
	}
	s.notify()
	s.auditEvent(ctx, gitaudit.Entry{OrgID: p.OrgID, ProjectID: &p.ID, UserID: uidPtr(a.UserID), Action: "gateway.port.lease", ResourceType: "gateway_service",
		ResourceID: &sv.ID, IP: a.IP, Metadata: map[string]any{"service": sv.Name, "port": l.Port}})
	base := l.LeasedAt
	if l.LastConnAt != nil {
		base = *l.LastConnAt
	}
	rel := base.Add(s.cfg.IdleRelease)
	return &PortLeaseView{Port: l.Port, Host: host, State: "active", LeasedAt: l.LeasedAt, LastConnAt: l.LastConnAt, PlannedReleaseAt: &rel}, nil
}

// ReleasePort frees the service's random port; it stays in quarantine before it can be reused.
func (s *Service) ReleasePort(ctx context.Context, p *domain.Project, a Actor, name string) error {
	sv, err := s.findService(ctx, p, name)
	if err != nil {
		return err
	}
	if err := s.d.Store.ReleaseLease(ctx, sv.ID, s.cfg.Quarantine); err != nil {
		return mapStoreErr(err)
	}
	s.notify()
	s.auditEvent(ctx, gitaudit.Entry{OrgID: p.OrgID, ProjectID: &p.ID, UserID: uidPtr(a.UserID), Action: "gateway.port.release", ResourceType: "gateway_service",
		ResourceID: &sv.ID, IP: a.IP, Metadata: map[string]any{"service": sv.Name}})
	return nil
}

// ---- organisation policy ----------------------------------------------------------------------------

// OrgPolicyView is the API shape of the organisation policy.
type OrgPolicyView struct {
	GatewayPolicy            string `json:"gateway_policy"`
	MaxRandomPorts           int    `json:"max_random_ports"`
	MaxRandomPortsPerProject int    `json:"max_random_ports_per_project"`
}

// OrgPolicy returns the policy and the random-port quotas.
func (s *Service) OrgPolicy(ctx context.Context, orgID uuid.UUID) (*OrgPolicyView, error) {
	pol, err := s.d.Store.GetOrgPolicy(ctx, orgID)
	if err != nil {
		return nil, mapStoreErr(err)
	}
	q, err := s.d.Store.GetQuotas(ctx, orgID)
	if err != nil {
		return nil, mapStoreErr(err)
	}
	return &OrgPolicyView{GatewayPolicy: pol, MaxRandomPorts: q.MaxRandomPorts, MaxRandomPortsPerProject: q.MaxRandomPortsPerProject}, nil
}

// SetOrgPolicy changes gateway_policy (warn | error). The caller has checked owner/admin.
func (s *Service) SetOrgPolicy(ctx context.Context, orgID uuid.UUID, a Actor, policy string) (*OrgPolicyView, error) {
	if policy != store.PolicyWarn && policy != store.PolicyError {
		return nil, errBadRequest("gateway_policy must be warn or error")
	}
	old, err := s.d.Store.GetOrgPolicy(ctx, orgID)
	if err != nil {
		return nil, mapStoreErr(err)
	}
	if err := s.d.Store.SetOrgPolicy(ctx, orgID, policy); err != nil {
		if errors.Is(err, store.ErrInvalid) {
			return nil, errBadRequest("gateway_policy must be warn or error")
		}
		return nil, mapStoreErr(err)
	}
	s.auditEvent(ctx, gitaudit.Entry{OrgID: orgID, UserID: uidPtr(a.UserID), Action: "gateway.policy.set", ResourceType: "organization", ResourceID: &orgID, IP: a.IP,
		OldValues: map[string]any{"gateway_policy": old}, NewValues: map[string]any{"gateway_policy": policy}})
	return s.OrgPolicy(ctx, orgID)
}
