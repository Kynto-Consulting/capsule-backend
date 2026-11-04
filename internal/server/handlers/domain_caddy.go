package handlers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/ingress"
)

// SetIngress selects the ingress mode. With ingress.ModeCaddy (no ALB) custom
// domains are verified by DNS only and Caddy issues the TLS certificate on demand
// (see TLSAskHandler); with the zero value / ModeALB the ACM + ALB flow of
// domain_ssl.go is used, unchanged. resolver may be nil (system resolver).
func (h *DomainHandler) SetIngress(c ingress.Config, resolver ingress.Resolver) {
	h.ingress = c
	if resolver == nil {
		resolver = &net.Resolver{}
	}
	h.resolver = resolver
}

// domainResponse is the body of Create: the domain plus how to point DNS at Capsule.
type domainResponse struct {
	*domain.Domain
	Instructions string           `json:"instructions"`
	DNSRecords   []ingress.Record `json:"dns_records,omitempty"`
}

// verifyResponse is the body of Verify: the domain plus the verification message.
type verifyResponse struct {
	*domain.Domain
	Message    string           `json:"message,omitempty"`
	DNSRecords []ingress.Record `json:"dns_records,omitempty"`
}

// newDomain builds the row to insert for name. In caddy mode the name is validated and
// normalised and the record is the DNS target of the ingress; errMsg is a Spanish
// validation message (empty when valid).
func (h *DomainHandler) newDomain(orgID uuid.UUID, projectID *uuid.UUID, name, provider string) (d *domain.Domain, errMsg string) {
	d = &domain.Domain{
		OrgID:       orgID,
		ProjectID:   projectID,
		DomainName:  name,
		RecordType:  "CNAME",
		RecordValue: h.albDNSName,
		Status:      "pending",
		DNSProvider: provider,
	}
	if !h.ingress.Caddy() {
		return d, ""
	}
	n, err := ingress.NormalizeDomain(name)
	if err != nil {
		return nil, err.Error()
	}
	if h.ingress.Reserved(n) {
		return nil, "ese nombre pertenece a la plataforma y no puede usarse como dominio personalizado"
	}
	d.DomainName = n
	d.Status = ingress.StatusPendingDNS
	d.RecordType, d.RecordValue = "CNAME", ""
	if recs := h.ingress.Records(n); len(recs) > 0 {
		d.RecordType, d.RecordValue = recs[0].Type, recs[0].Value
	}
	return d, ""
}

// instructionsFor returns the user-facing DNS instructions and records for d.
func (h *DomainHandler) instructionsFor(d *domain.Domain) (string, []ingress.Record) {
	if h.ingress.Caddy() {
		return h.ingress.Instructions(d.DomainName), h.ingress.Records(d.DomainName)
	}
	return fmt.Sprintf("Point CNAME %s → %s", d.DomainName, h.albDNSName), nil
}

// respondCreateError maps a repository error; in caddy mode a duplicate name is a 409.
func (h *DomainHandler) respondCreateError(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	if h.ingress.Caddy() && errors.As(err, &pg) && pg.Code == "23505" {
		respondError(w, http.StatusConflict, "DOMAIN_EXISTS", "ese dominio ya está registrado en Capsule")
		return
	}
	respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create domain")
}

// verifyCaddy checks DNS only (no AWS) and persists status and TLS state.
// Caddy issues the certificate on the first request once the domain is active.
func (h *DomainHandler) verifyCaddy(ctx context.Context, d *domain.Domain) (verifyResponse, error) {
	vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res := ingress.Verify(vctx, h.resolver, h.ingress, d.DomainName)
	if err := h.domains.UpdateStatus(ctx, d.ID, res.Status, d.RecordValue); err != nil {
		return verifyResponse{}, err
	}
	d.Status = res.Status
	active := res.Status == ingress.StatusActive
	if active != d.SSLEnabled || d.VerificationToken != "" {
		if err := h.domains.UpdateSSL(ctx, d.ID, active, ""); err != nil {
			h.logger.Warn("persist domain TLS state", "error", err)
		} else {
			d.SSLEnabled, d.VerificationToken = active, ""
		}
	}
	return verifyResponse{Domain: d, Message: res.Message, DNSRecords: h.ingress.Records(d.DomainName)}, nil
}

// route53Records is the record set (create/delete) the customer's zone needs.
func (h *DomainHandler) route53Records(name string) []*r53types.ResourceRecordSet {
	if !h.ingress.Caddy() {
		return []*r53types.ResourceRecordSet{{
			Name: aws.String(name), Type: r53types.RRTypeCname, TTL: aws.Int64(300),
			ResourceRecords: []r53types.ResourceRecord{{Value: aws.String(h.albDNSName)}},
		}}
	}
	var out []*r53types.ResourceRecordSet
	for _, rec := range h.ingress.Records(name) {
		typ := r53types.RRTypeCname
		switch rec.Type {
		case "A":
			typ = r53types.RRTypeA
		case "AAAA":
			typ = r53types.RRTypeAaaa
		}
		out = append(out, &r53types.ResourceRecordSet{
			Name: aws.String(name), Type: typ, TTL: aws.Int64(300),
			ResourceRecords: []r53types.ResourceRecord{{Value: aws.String(rec.Value)}},
		})
	}
	return out
}
