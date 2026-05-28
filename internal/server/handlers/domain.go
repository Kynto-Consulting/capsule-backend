package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

// DomainHandler handles custom domain operations.
type DomainHandler struct {
	domains    domain.DomainRepository
	orgs       domain.OrganizationRepository
	projects   domain.ProjectRepository
	aws        *awsclient.Clients
	albDNSName string
	logger     *slog.Logger
}

// NewDomainHandler creates a DomainHandler.
func NewDomainHandler(
	domains domain.DomainRepository,
	orgs domain.OrganizationRepository,
	projects domain.ProjectRepository,
	awsClients *awsclient.Clients,
	albDNSName string,
	logger *slog.Logger,
) *DomainHandler {
	return &DomainHandler{
		domains:    domains,
		orgs:       orgs,
		projects:   projects,
		aws:        awsClients,
		albDNSName: albDNSName,
		logger:     logger,
	}
}

// List returns all domains for a project.
func (h *DomainHandler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && project.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get project")
		return
	}

	domains, err := h.domains.ListByProject(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list domains")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"data": domains})
}

// Create registers a new custom domain.
func (h *DomainHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && project.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get project")
		return
	}

	_ = user

	var req struct {
		DomainName  string `json:"domain_name"`
		DNSProvider string `json:"dns_provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.DomainName == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "domain_name is required")
		return
	}
	if req.DNSProvider != "route53" && req.DNSProvider != "external" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "dns_provider must be route53 or external")
		return
	}

	d, err := h.domains.Create(r.Context(), &domain.Domain{
		OrgID:       orgID,
		ProjectID:   &projectID,
		DomainName:  req.DomainName,
		RecordType:  "CNAME",
		RecordValue: h.albDNSName,
		Status:      "pending",
		DNSProvider: req.DNSProvider,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create domain")
		return
	}

	// If Route53, create the CNAME record automatically in the background.
	if req.DNSProvider == "route53" && h.aws != nil {
		go h.createRoute53Record(d)
	}

	type domainResponse struct {
		*domain.Domain
		Instructions string `json:"instructions"`
	}

	respondJSON(w, http.StatusCreated, domainResponse{
		Domain:       d,
		Instructions: fmt.Sprintf("Point CNAME %s → %s", req.DomainName, h.albDNSName),
	})
}

// ListByOrg returns all domains for an org regardless of project.
func (h *DomainHandler) ListByOrg(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}
	domains, err := h.domains.ListByOrg(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list domains")
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": domains})
}

// CreateOrgLevel registers a domain not tied to a project.
func (h *DomainHandler) CreateOrgLevel(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}
	_ = user

	var req struct {
		DomainName  string `json:"domain_name"`
		DNSProvider string `json:"dns_provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.DomainName == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "domain_name is required")
		return
	}
	if req.DNSProvider != "route53" && req.DNSProvider != "external" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "dns_provider must be route53 or external")
		return
	}

	d, err := h.domains.Create(r.Context(), &domain.Domain{
		OrgID:       orgID,
		ProjectID:   nil,
		DomainName:  req.DomainName,
		RecordType:  "CNAME",
		RecordValue: h.albDNSName,
		Status:      "pending",
		DNSProvider: req.DNSProvider,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create domain")
		return
	}
	if req.DNSProvider == "route53" && h.aws != nil {
		go h.createRoute53Record(d)
	}

	type domainResponse struct {
		*domain.Domain
		Instructions string `json:"instructions"`
	}
	respondJSON(w, http.StatusCreated, domainResponse{
		Domain:       d,
		Instructions: fmt.Sprintf("Point CNAME %s → %s", req.DomainName, h.albDNSName),
	})
}

// Verify checks DNS propagation and marks the domain active or failed.
func (h *DomainHandler) Verify(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	domainID, err := uuid.Parse(chi.URLParam(r, "domainID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid domain id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	d, err := h.domains.GetByID(r.Context(), domainID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "domain not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	status := h.verifyDNS(d.DomainName, h.albDNSName)
	if err := h.domains.UpdateStatus(r.Context(), domainID, status, d.RecordValue); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update domain status")
		return
	}
	d.Status = status
	respondJSON(w, http.StatusOK, d)
}

// Delete removes a domain and its Route53 record if applicable.
func (h *DomainHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	domainID, err := uuid.Parse(chi.URLParam(r, "domainID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid domain id")
		return
	}

	if ok, _ := h.orgs.IsMember(r.Context(), orgID, user.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}

	d, err := h.domains.GetByID(r.Context(), domainID)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "domain not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	_ = user

	if err := h.domains.Delete(r.Context(), domainID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete domain")
		return
	}

	if d.DNSProvider == "route53" && h.aws != nil {
		go h.deleteRoute53Record(d)
	}

	respondNoContent(w)
}

// --- helpers ---

func (h *DomainHandler) createRoute53Record(d *domain.Domain) {
	ctx := context.Background()

	// Find the hosted zone for this domain.
	zones, err := h.aws.Route53.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{
		DNSName: aws.String(d.DomainName),
	})
	if err != nil || len(zones.HostedZones) == 0 {
		h.logger.Warn("could not find Route53 hosted zone", "domain", d.DomainName, "error", err)
		return
	}

	zoneID := aws.ToString(zones.HostedZones[0].Id)

	_, err = h.aws.Route53.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &r53types.ChangeBatch{
			Changes: []r53types.Change{
				{
					Action: r53types.ChangeActionCreate,
					ResourceRecordSet: &r53types.ResourceRecordSet{
						Name: aws.String(d.DomainName),
						Type: r53types.RRTypeCname,
						TTL:  aws.Int64(300),
						ResourceRecords: []r53types.ResourceRecord{
							{Value: aws.String(h.albDNSName)},
						},
					},
				},
			},
		},
	})
	if err != nil {
		h.logger.Error("failed to create Route53 CNAME record", "domain", d.DomainName, "error", err)
	} else {
		h.logger.Info("Route53 CNAME record created", "domain", d.DomainName, "target", h.albDNSName)
	}
}

func (h *DomainHandler) deleteRoute53Record(d *domain.Domain) {
	ctx := context.Background()

	zones, err := h.aws.Route53.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{
		DNSName: aws.String(d.DomainName),
	})
	if err != nil || len(zones.HostedZones) == 0 {
		h.logger.Warn("could not find Route53 hosted zone for deletion", "domain", d.DomainName)
		return
	}

	zoneID := aws.ToString(zones.HostedZones[0].Id)

	_, err = h.aws.Route53.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &r53types.ChangeBatch{
			Changes: []r53types.Change{
				{
					Action: r53types.ChangeActionDelete,
					ResourceRecordSet: &r53types.ResourceRecordSet{
						Name: aws.String(d.DomainName),
						Type: r53types.RRTypeCname,
						TTL:  aws.Int64(300),
						ResourceRecords: []r53types.ResourceRecord{
							{Value: aws.String(h.albDNSName)},
						},
					},
				},
			},
		},
	})
	if err != nil {
		h.logger.Error("failed to delete Route53 CNAME record", "domain", d.DomainName, "error", err)
	}
}

// verifyDNS performs a CNAME lookup and checks whether it resolves to the ALB.
func (h *DomainHandler) verifyDNS(domainName, albDNS string) string {
	resolver := net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cname, err := resolver.LookupCNAME(ctx, domainName)
	if err != nil {
		h.logger.Warn("DNS CNAME lookup failed", "domain", domainName, "error", err)
		return "failed"
	}

	// Strip trailing dot from CNAME result
	if len(cname) > 0 && cname[len(cname)-1] == '.' {
		cname = cname[:len(cname)-1]
	}

	if cname == albDNS {
		return "active"
	}

	h.logger.Info("DNS verification failed: CNAME mismatch",
		"domain", domainName, "got", cname, "expected", albDNS)
	return "failed"
}
