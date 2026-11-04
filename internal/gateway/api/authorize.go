package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gateway/store"
	"github.com/kynto/capsule/backend/internal/gitaudit"
	"github.com/kynto/capsule/backend/internal/netaccess"
)

// Credential types of the authorize request.
const (
	CredCap  = "cap"  // cap_ API token
	CredCgt  = "cgt"  // git token (only for services marked git: none exist yet, always refused)
	CredCgc  = "cgc"  // short-lived signed connection token
	CredCgs  = "cgs"  // service token
	CredNone = "none" // no credential
)

// Deny reasons. Only DenyIPDenied is ever distinguishable, and only after the credential was accepted for the service.
const (
	DenyUnauthorized = "unauthorized"
	DenyIPDenied     = "ip_denied"
	DenyQuota        = "quota"
	DenyUnavailable  = "unavailable"
)

// AuthorizeRequest is the body of POST /internal/gateway/authorize.
type AuthorizeRequest struct {
	RouteID        string `json:"route_id"`
	SrcIP          string `json:"src_ip"`
	CredentialType string `json:"credential_type"`
	Credential     string `json:"credential"` // never logged, never audited
	Access         string `json:"access"`     // sni_name | capsule_uri | random_port
	Port           int    `json:"port"`       // leased port, when access = random_port
}

// AuthorizeResponse is the decision. DenyReason is for the data plane's own audit only.
type AuthorizeResponse struct {
	Allow             bool   `json:"allow"`
	PrincipalID       string `json:"principal_id,omitempty"`
	DenyReason        string `json:"deny_reason,omitempty"`
	MaxConns          int    `json:"max_conns,omitempty"`
	MaxConnsPerIP     int    `json:"max_conns_per_ip,omitempty"`
	IdleTimeoutSecond int    `json:"idle_timeout_seconds,omitempty"`
	CacheTTLSeconds   int    `json:"cache_ttl_seconds"`
}

type principal struct {
	kind   string    // cap | cgs | cgc
	id     string    // token id or jti: the only identifier ever logged
	userID uuid.UUID // Nil for service tokens
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hasScope(scopes string, want ...string) bool {
	parts := strings.Split(scopes, ",")
	var any bool
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			any = true
			for _, w := range want {
				if p == w {
					return true
				}
			}
		}
	}
	return !any // legacy rows without scopes are unrestricted
}

// Authorize decides whether the credential may connect to the route from src_ip. It is called by the data plane for every
// new connection (the data plane caches an allow for at most 30 s, never a cgc_ allow).
//
// Order (PROTOCOL 11.3/12): rate limit -> credential -> permission on the service -> IP list -> allow.
// "route does not exist", "credential invalid", "credential of another project" and "no permission" all produce the
// same {allow:false, deny_reason:"unauthorized"} and the same work, and feed the failed-attempt limiter.
func (s *Service) Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResponse, error) {
	addr, ok := netaccess.ParseIP(req.SrcIP)
	if !ok || strings.Contains(req.SrcIP, "%") { // zone identifiers are not accepted (PROTOCOL 12.1)
		return nil, errBadRequest("src_ip must be an IPv4 or IPv6 address")
	}
	src := addr.String()
	routeID, rerr := uuid.Parse(req.RouteID)
	if rerr != nil {
		return nil, errBadRequest("route_id must be a uuid")
	}
	ctype := strings.ToLower(strings.TrimSpace(req.CredentialType))
	switch ctype {
	case CredCap, CredCgt, CredCgc, CredCgs, CredNone:
	default:
		return nil, errBadRequest("unknown credential_type")
	}
	if len(req.Credential) > 2048 {
		return nil, errBadRequest("credential too long")
	}
	if ok, wait := s.lim.Allow(src); !ok {
		secs := int(wait/time.Second) + 1
		s.log.Warn("gateway: authorize rate limited", "ip", src, "credential_type", ctype)
		return nil, &Error{Status: 429, Code: "rate_limited", Message: "too many attempts", Details: map[string]any{"retry_after_seconds": secs}}
	}

	// Resolve the route (it may not exist: the work below is the same either way).
	var rv *store.RouteView
	var proj *domain.Project
	var svc *store.Service
	ix, err := s.index(ctx)
	if err != nil {
		return nil, err
	}
	if r := ix.routes[routeID]; r != nil && r.ProjectID != uuid.Nil {
		rv = r
		if p, err := s.d.Projects.GetByID(ctx, r.ProjectID); err == nil && p.OrgID == r.OrgID {
			proj = p
		}
	}
	routeName := ""
	if proj != nil && rv != nil {
		routeName = proj.Slug + "/" + rv.ServiceName
	}

	if ctype == CredNone {
		// "none" is valid ONLY for a random port (UDP and credential-less TCP): anything else is plain unauthorized.
		return s.authorizeAnonymous(ctx, req, src, rv, ix), nil
	}
	pr := s.authenticate(ctx, ctype, req.Credential, rv, routeName)
	authorised := pr != nil && rv != nil && proj != nil
	if authorised && pr.userID != uuid.Nil { // user principals need project.connect now (role may have changed)
		acc, err := s.d.Authz.Access(ctx, pr.userID, rv.OrgID, rv.ProjectID)
		if err != nil {
			return nil, err
		}
		authorised = acc.Member && !acc.Hidden && authz.RoleAllows(acc.Role, authz.ProjectConnect)
	}
	if !authorised {
		blocked := s.lim.Fail(src)
		s.recordDeny(ctx, rv, nil, ctype, req.Access, src, DenyUnauthorized, blocked)
		return &AuthorizeResponse{Allow: false, DenyReason: DenyUnauthorized}, nil
	}

	// From here the caller proved permission on this service: more specific answers may be given.
	svc, err = s.d.Store.GetService(ctx, rv.ServiceID)
	if err != nil {
		s.recordDeny(ctx, rv, pr, ctype, req.Access, src, DenyUnavailable, false)
		return &AuthorizeResponse{Allow: false, DenyReason: DenyUnavailable}, nil
	}
	if req.Access == "random_port" {
		if _, leased := ix.leases[rv.ServiceID]; !leased {
			s.recordDeny(ctx, rv, pr, ctype, req.Access, src, DenyUnavailable, false)
			return &AuthorizeResponse{Allow: false, DenyReason: DenyUnavailable}, nil
		}
	}
	cidrs, restricted, err := s.d.IPLists.AllowedCIDRs(ctx, svc)
	if err != nil { // fail closed
		s.log.Warn("gateway: ip list unavailable", "service_id", svc.ID.String(), "error", err.Error())
		s.recordDeny(ctx, rv, pr, ctype, req.Access, src, DenyUnavailable, false)
		return &AuthorizeResponse{Allow: false, DenyReason: DenyUnavailable}, nil
	}
	if restricted && !netaccess.ContainsIP(cidrs, src) {
		s.recordDeny(ctx, rv, pr, ctype, req.Access, src, DenyIPDenied, false)
		return &AuthorizeResponse{Allow: false, DenyReason: DenyIPDenied}, nil
	}

	if req.Access == "random_port" && req.Port > 0 {
		_ = s.d.Store.TouchLease(ctx, req.Port)
	}
	if pr.kind == CredCgs {
		if id, err := uuid.Parse(pr.id); err == nil && s.d.SvcTokens != nil {
			_ = s.d.SvcTokens.TouchUsed(ctx, id)
		}
	}
	ttl := int(s.cfg.AuthCacheTTL / time.Second)
	if pr.kind == CredCgc {
		ttl = 0 // single use: the data plane must not cache it
	}
	s.auditEvent(ctx, gitaudit.Entry{OrgID: rv.OrgID, ProjectID: &rv.ProjectID, UserID: uidPtr(pr.userID), Action: "gateway.connect.allow", ResourceType: "gateway_service",
		ResourceID: &rv.ServiceID, IP: src, Metadata: map[string]any{"service": rv.ServiceName, "access": req.Access, "credential_type": ctype, "principal": pr.id}})
	return &AuthorizeResponse{
		Allow: true, PrincipalID: pr.id, MaxConns: s.cfg.MaxConns, MaxConnsPerIP: s.cfg.MaxConnsPerIP,
		IdleTimeoutSecond: int(s.cfg.IdleTimeout / time.Second), CacheTTLSeconds: ttl,
	}, nil
}

// authenticate validates the credential and its scope against the route. It returns nil on any failure. It always does
// the hashing work, whatever the credential type or the route.
func (s *Service) authenticate(ctx context.Context, ctype, cred string, rv *store.RouteView, routeName string) *principal {
	now := s.now()
	hash := sha256Hex(cred) // always computed
	switch ctype {
	case CredCap:
		if !strings.HasPrefix(cred, "cap_") {
			return nil
		}
		t, err := s.d.APITokens.GetByHash(ctx, hash)
		if err != nil || t == nil || t.RevokedAt != nil || (t.ExpiresAt != nil && !now.Before(*t.ExpiresAt)) {
			return nil
		}
		if !hasScope(t.Scopes, "*", "gateway", "gateway:connect") {
			return nil // deploy / security-only tokens carry no connect permission
		}
		if t.ProjectID != nil && (rv == nil || *t.ProjectID != rv.ProjectID) {
			return nil
		}
		if !s.userActive(ctx, t.UserID) {
			return nil
		}
		return &principal{kind: CredCap, id: t.ID.String(), userID: t.UserID}
	case CredCgs:
		if s.d.SvcTokens == nil || !strings.HasPrefix(cred, CGSPrefix) {
			return nil
		}
		t, err := s.d.SvcTokens.GetByHash(ctx, hash)
		if err != nil || t == nil || !t.Active(now) {
			return nil
		}
		if rv == nil || t.ProjectID != rv.ProjectID || t.OrgID != rv.OrgID || (t.ServiceID != nil && *t.ServiceID != rv.ServiceID) {
			return nil
		}
		return &principal{kind: CredCgs, id: t.ID.String()}
	case CredCgc:
		if s.signer == nil || !strings.HasPrefix(cred, CGCPrefix) {
			return nil
		}
		// A route is required to check the claim; with none we still verify against an impossible one (same work, always fails).
		want := routeName
		if want == "" {
			want = "/"
		}
		c, err := s.signer.Verify(cred, want, now)
		if err != nil || rv == nil {
			return nil
		}
		uid, err := uuid.Parse(c.Sub)
		if err != nil || !s.userActive(ctx, uid) {
			return nil
		}
		return &principal{kind: CredCgc, id: c.Jti, userID: uid}
	}
	return nil // cgt and none
}

func (s *Service) userActive(ctx context.Context, id uuid.UUID) bool {
	if s.d.Users == nil {
		return true
	}
	u, err := s.d.Users.GetByID(ctx, id)
	return err == nil && u != nil && u.DeletedAt == nil
}

// recordDeny logs the verdict (never the credential) and audits it when the route is known.
func (s *Service) recordDeny(ctx context.Context, rv *store.RouteView, pr *principal, ctype, access, src, reason string, blocked bool) {
	attrs := []any{"ip", src, "credential_type", ctype, "reason", reason, "access", access}
	if blocked {
		attrs = append(attrs, "blocked", true)
	}
	if rv == nil {
		s.log.Info("gateway: connection denied", attrs...)
		return
	}
	meta := map[string]any{"service": rv.ServiceName, "access": access, "credential_type": ctype, "reason": reason}
	var uid *uuid.UUID
	if pr != nil {
		meta["principal"] = pr.id
		uid = uidPtr(pr.userID)
	}
	s.log.Info("gateway: connection denied", append(attrs, "service_id", rv.ServiceID.String())...)
	s.auditEvent(ctx, gitaudit.Entry{OrgID: rv.OrgID, ProjectID: &rv.ProjectID, UserID: uid, Action: "gateway.connect.deny", ResourceType: "gateway_service",
		ResourceID: &rv.ServiceID, IP: src, Metadata: meta})
}

// authorizeAnonymous decides a connection that carries no credential (credential_type "none") by name (access "sni_name": the
// route must exist with its gateway access on; the name is protected by the IP list plus the database/SSH login behind it)
// or to a leased random port (access "random_port",
// access "random_port"). Only these hold, all of them:
//  1. the route exists and the port has an active lease for THAT route's service;
//  2. the port is inside the pool range;
//  3. the service's IP list (the one netaccess enforces) contains the source address. An empty or missing list denies
//     everybody here: a random port is never open to the world, even if the project's list is empty ("public").
//
// Every failure is the same uniform denial (and feeds the failed-attempt limiter). The allow is cacheable for at most 30 s.
func (s *Service) authorizeAnonymous(ctx context.Context, req AuthorizeRequest, src string, rv *store.RouteView, ix *routeIndex) *AuthorizeResponse {
	deny := func() *AuthorizeResponse {
		blocked := s.lim.Fail(src)
		s.recordDeny(ctx, rv, nil, CredNone, req.Access, src, DenyUnauthorized, blocked)
		return &AuthorizeResponse{Allow: false, DenyReason: DenyUnauthorized}
	}
	random := req.Access == "random_port"
	if rv == nil || (!random && req.Access != "sni_name") || (random && req.Port < 1) {
		return deny()
	}
	if random {
		l, leased := ix.leases[rv.ServiceID]
		if !leased || l.Port != req.Port {
			return deny()
		}
		if s.cfg.PoolOff || req.Port < s.cfg.PoolLo || req.Port > s.cfg.PoolHi {
			return deny()
		}
	}
	svc, err := s.d.Store.GetService(ctx, rv.ServiceID)
	if err != nil {
		return deny()
	}
	cidrs, restricted, err := s.d.IPLists.AllowedCIDRs(ctx, svc)
	if err != nil || !restricted || len(cidrs) == 0 || !netaccess.ContainsIP(cidrs, src) {
		return deny()
	}
	if random {
		_ = s.d.Store.TouchLease(ctx, req.Port)
	}
	pid := "sni:" + rv.ServiceName
	if random {
		pid = "port:" + strconv.Itoa(req.Port)
	}
	s.auditEvent(ctx, gitaudit.Entry{OrgID: rv.OrgID, ProjectID: &rv.ProjectID, Action: "gateway.connect.allow", ResourceType: "gateway_service",
		ResourceID: &rv.ServiceID, IP: src, Metadata: map[string]any{"service": rv.ServiceName, "access": req.Access, "credential_type": CredNone, "principal": pid}})
	return &AuthorizeResponse{Allow: true, PrincipalID: pid, MaxConns: s.cfg.MaxConns, MaxConnsPerIP: s.cfg.MaxConnsPerIP,
		IdleTimeoutSecond: int(s.cfg.IdleTimeout / time.Second), CacheTTLSeconds: int(s.cfg.AuthCacheTTL / time.Second)}
}
