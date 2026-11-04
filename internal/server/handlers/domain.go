package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/ingress"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

// DomainHandler handles custom domain operations.
type DomainHandler struct {
	authzHolder
	domains    domain.DomainRepository
	orgs       domain.OrganizationRepository
	projects   domain.ProjectRepository
	aws        *awsclient.Clients
	albDNSName string
	ingress    ingress.Config   // zero value = ALB mode
	resolver   ingress.Resolver // DNS resolver used by the no-ALB verification
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

	if !h.authorize(w, r, h.orgs, orgID, projectID, authz.ProjectRead) {
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

	if !h.authorize(w, r, h.orgs, orgID, projectID, authz.ProjectOps) {
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

	newD, vmsg := h.newDomain(orgID, &projectID, req.DomainName, req.DNSProvider)
	if vmsg != "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", vmsg)
		return
	}
	d, err := h.domains.Create(r.Context(), newD)
	if err != nil {
		h.respondCreateError(w, err)
		return
	}

	// If Route53, create the DNS record automatically in the background.
	if req.DNSProvider == "route53" && h.aws != nil {
		go h.createRoute53Record(d)
	}

	instr, recs := h.instructionsFor(d)
	respondJSON(w, http.StatusCreated, domainResponse{Domain: d, Instructions: instr, DNSRecords: recs})
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
	visible, err := h.service(h.orgs).Visibility(r.Context(), user.ID, orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check permissions")
		return
	}
	kept := domains[:0]
	for _, d := range domains {
		if d.ProjectID == nil || visible(*d.ProjectID) {
			kept = append(kept, d)
		}
	}
	domains = kept
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

	newD, vmsg := h.newDomain(orgID, nil, req.DomainName, req.DNSProvider)
	if vmsg != "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", vmsg)
		return
	}
	d, err := h.domains.Create(r.Context(), newD)
	if err != nil {
		h.respondCreateError(w, err)
		return
	}
	if req.DNSProvider == "route53" && h.aws != nil {
		go h.createRoute53Record(d)
	}

	instr, recs := h.instructionsFor(d)
	respondJSON(w, http.StatusCreated, domainResponse{Domain: d, Instructions: instr, DNSRecords: recs})
}

// Verify checks DNS propagation and marks the domain active or failed.
func (h *DomainHandler) Verify(w http.ResponseWriter, r *http.Request) {
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

	urlProject, ok := h.authorizeOptionalProject(w, r, h.orgs, orgID, authz.ProjectOps)
	if !ok {
		return
	}

	d, err := h.domains.GetByID(r.Context(), domainID)
	if err == domain.ErrNotFound || (err == nil && d.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "domain not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	if !h.authorizeResourceProject(w, r, h.orgs, orgID, urlProject, d.ProjectID, authz.ProjectOps) {
		return
	}

	if h.ingress.Caddy() {
		// No ALB: DNS ownership only; Caddy issues the certificate on demand.
		resp, err := h.verifyCaddy(r.Context(), d)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update domain status")
			return
		}
		respondJSON(w, http.StatusOK, resp)
		return
	}

	status := h.verifyDNS(d.DomainName, h.albDNSName)
	if err := h.domains.UpdateStatus(r.Context(), domainID, status, d.RecordValue); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update domain status")
		return
	}
	d.Status = status

	// Once DNS points at the ALB, drive the ACM cert + ALB wiring. This is what
	// gives the custom domain HTTPS and stops it falling through to the landing
	// page: request a DNS-validated cert, surface its validation CNAME, and —
	// once issued — attach the cert and add host rules to the backend TG.
	if status == "active" {
		sslEnabled, validation, sslErr := h.provisionDomainSSL(r.Context(), d)
		if sslErr != nil {
			h.logger.Warn("domain SSL provisioning", "domain", d.DomainName, "error", sslErr)
		} else {
			d.SSLEnabled = sslEnabled
			if validation != "" {
				d.VerificationToken = validation
			}
			if err := h.domains.UpdateSSL(r.Context(), domainID, sslEnabled, validation); err != nil {
				h.logger.Warn("persist domain SSL", "error", err)
			}
		}
	}
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

	urlProject, ok := h.authorizeOptionalProject(w, r, h.orgs, orgID, authz.ProjectOps)
	if !ok {
		return
	}

	d, err := h.domains.GetByID(r.Context(), domainID)
	if err == domain.ErrNotFound || (err == nil && d.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "domain not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	if !h.authorizeResourceProject(w, r, h.orgs, orgID, urlProject, d.ProjectID, authz.ProjectOps) {
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

	var changes []r53types.Change
	for _, rs := range h.route53Records(d.DomainName) {
		changes = append(changes, r53types.Change{Action: r53types.ChangeActionCreate, ResourceRecordSet: rs})
	}
	if len(changes) == 0 {
		h.logger.Warn("no DNS target configured for Route53 record", "domain", d.DomainName)
		return
	}
	_, err = h.aws.Route53.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch:  &r53types.ChangeBatch{Changes: changes},
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

	var changes []r53types.Change
	for _, rs := range h.route53Records(d.DomainName) {
		changes = append(changes, r53types.Change{Action: r53types.ChangeActionDelete, ResourceRecordSet: rs})
	}
	if len(changes) == 0 {
		return
	}
	_, err = h.aws.Route53.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch:  &r53types.ChangeBatch{Changes: changes},
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
