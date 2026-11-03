package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitaudit"
)

// cgs_ service tokens (PROTOCOL 11.1): for agents, CI and applications. One project and, optionally, one service;
// only project.connect; mandatory expiry of at most 90 days; revocable. Only the SHA-256 of the value is stored.
const (
	CGSPrefix        = "cgs_"
	MaxServiceTokenD = 90
)

// ServiceTokenInput is the body of POST .../gateway/service-tokens.
type ServiceTokenInput struct {
	Name          string `json:"name"`
	Service       string `json:"service"`         // optional: restrict to one service
	ExpiresInDays int    `json:"expires_in_days"` // 1..90, default 90
}

// ServiceTokenCreated is returned once; Token is never shown again.
type ServiceTokenCreated struct {
	*ServiceToken
	Token string `json:"token"`
}

func newCGS() (plain string, err error) {
	b := make([]byte, 32) // 256 bits
	if _, err = rand.Read(b); err != nil {
		return "", err
	}
	return CGSPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// CreateServiceToken issues a cgs_ token. The caller has checked the network permission (admin).
func (s *Service) CreateServiceToken(ctx context.Context, p *domain.Project, a Actor, in ServiceTokenInput) (*ServiceTokenCreated, error) {
	if s.d.SvcTokens == nil {
		return nil, &Error{Status: 501, Code: "not_configured", Message: "service tokens are not configured on this server"}
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		return nil, errBadRequest("name is required (1-100 characters)")
	}
	days := in.ExpiresInDays
	if days == 0 {
		days = MaxServiceTokenD
	}
	if days < 1 || days > MaxServiceTokenD {
		return nil, errBadRequest("expires_in_days must be between 1 and 90")
	}
	now := s.now()
	n, err := s.d.SvcTokens.CountActive(ctx, p.ID, now)
	if err != nil {
		return nil, err
	}
	if n >= s.cfg.ServiceTokenMax {
		return nil, &Error{Status: 409, Code: "quota_exceeded", Message: "too many active service tokens in this project", Hint: "Revoke tokens that are no longer used."}
	}
	var svcID *uuid.UUID
	if sn := lowerTrim(in.Service); sn != "" {
		sv, err := s.findService(ctx, p, sn)
		if err != nil {
			return nil, err
		}
		id := sv.ID
		svcID = &id
	}
	plain, err := newCGS()
	if err != nil {
		return nil, err
	}
	t := &ServiceToken{
		ID: uuid.New(), OrgID: p.OrgID, ProjectID: p.ID, ServiceID: svcID, Name: in.Name, Hash: sha256Hex(plain),
		Prefix: plain[:len(CGSPrefix)+4], CreatedBy: uidPtr(a.UserID), CreatedAt: now, ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour),
	}
	if err := s.d.SvcTokens.Create(ctx, t); err != nil {
		return nil, err
	}
	s.auditEvent(ctx, gitaudit.Entry{OrgID: p.OrgID, ProjectID: &p.ID, UserID: uidPtr(a.UserID), Action: "gateway.token.create", ResourceType: "gateway_token",
		ResourceID: &t.ID, IP: a.IP, Metadata: map[string]any{"name": t.Name, "type": "cgs", "prefix": t.Prefix, "expires_at": t.ExpiresAt.Format(time.RFC3339)}})
	return &ServiceTokenCreated{ServiceToken: t, Token: plain}, nil
}

// ListServiceTokens lists the project's tokens (never their values).
func (s *Service) ListServiceTokens(ctx context.Context, p *domain.Project) ([]*ServiceToken, error) {
	if s.d.SvcTokens == nil {
		return []*ServiceToken{}, nil
	}
	out, err := s.d.SvcTokens.List(ctx, p.ID)
	if out == nil {
		out = []*ServiceToken{}
	}
	return out, err
}

// RevokeServiceToken revokes a token; it stops working for new connections within the data plane's 30 s cache.
func (s *Service) RevokeServiceToken(ctx context.Context, p *domain.Project, a Actor, id uuid.UUID) error {
	if s.d.SvcTokens == nil {
		return errNotFound()
	}
	ok, err := s.d.SvcTokens.Revoke(ctx, p.ID, id)
	if err != nil {
		return err
	}
	if !ok {
		return errNotFound()
	}
	s.auditEvent(ctx, gitaudit.Entry{OrgID: p.OrgID, ProjectID: &p.ID, UserID: uidPtr(a.UserID), Action: "gateway.token.revoke", ResourceType: "gateway_token",
		ResourceID: &id, IP: a.IP, Metadata: map[string]any{"type": "cgs"}})
	return nil
}
