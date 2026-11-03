package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/netaccess"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/internal/service"
)

func portProtoName(p string) string {
	n, _ := domain.NormalizeProtocol(p)
	return n
}

// ProjectPortsHandler manages the extra TCP and UDP ports a project publishes on the app host.
type ProjectPortsHandler struct {
	authzHolder
	orgs              domain.OrganizationRepository
	projects          domain.ProjectRepository
	deployments       domain.DeploymentRepository
	svc               *service.PortsService
	fargateConfigured bool
	logger            *slog.Logger
}

func NewProjectPortsHandler(
	orgs domain.OrganizationRepository,
	projects domain.ProjectRepository,
	deployments domain.DeploymentRepository,
	svc *service.PortsService,
	fargateConfigured bool,
	logger *slog.Logger,
) *ProjectPortsHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &ProjectPortsHandler{orgs: orgs, projects: projects, deployments: deployments, svc: svc, fargateConfigured: fargateConfigured, logger: logger}
}

type portsCtx struct {
	user      *domain.User
	role      string
	projectID uuid.UUID
	project   *domain.Project
}

// load validates ids, feature availability, membership and project ownership.
// It writes the error response itself.
func (h *ProjectPortsHandler) load(w http.ResponseWriter, r *http.Request, write bool) (*portsCtx, bool) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return nil, false
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return nil, false
	}
	if !h.svc.Enabled() {
		respondError(w, http.StatusNotImplemented, "NOT_CONFIGURED",
			"la gestión de puertos TCP/UDP no está configurada en este servidor (falta APP_SECURITY_GROUP_ID)")
		return nil, false
	}
	role, err := h.orgs.GetMemberRole(r.Context(), orgID, user.ID)
	if err != nil {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return nil, false
	}
	act := authz.ProjectRead
	if write {
		act = authz.ProjectNetwork
	}
	if !h.authorize(w, r, h.orgs, orgID, projectID, act) {
		return nil, false
	}
	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && project.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return nil, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get project")
		return nil, false
	}
	return &portsCtx{user: user, role: role, projectID: projectID, project: project}, true
}

// supported answers 400 UNSUPPORTED for projects that do not run as docker on the host.
func (h *ProjectPortsHandler) supported(w http.ResponseWriter, r *http.Request, pc *portsCtx) bool {
	dep, err := h.deployments.GetLatestSuccessfulByProject(r.Context(), pc.projectID)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get deployments")
		return false
	}
	if errors.Is(err, domain.ErrNotFound) {
		dep = nil
	}
	if !service.SupportsPorts(pc.project, dep, h.fargateConfigured) {
		respondError(w, http.StatusBadRequest, "UNSUPPORTED",
			"los puertos extra (TCP y UDP) solo están disponibles para proyectos desplegados como contenedores docker en el host de Capsule (no fargate, lambda ni estáticos)")
		return false
	}
	return true
}

type portCIDRJSON struct {
	ID          uuid.UUID `json:"id"`
	CIDR        string    `json:"cidr"`
	Description string    `json:"description"`
}

type portJSON struct {
	Name          string         `json:"name"`
	ContainerPort int            `json:"container_port"`
	Protocol      string         `json:"protocol"`
	HostPort      int            `json:"host_port"`
	Access        string         `json:"access"`
	CIDRs         []portCIDRJSON `json:"cidrs"`
}

type portsResponse struct {
	AddressHost string     `json:"address_host"`
	Ports       []portJSON `json:"ports"`
}

// portAccess is private (no rules), allowlist (rules) or public (0.0.0.0/0).
func portAccess(rules []*domain.PortRule) string {
	if len(rules) == 0 {
		return "private"
	}
	for _, r := range rules {
		if netaccess.IsPublicCIDR(r.CIDR) {
			return "public"
		}
	}
	return "allowlist"
}

func (h *ProjectPortsHandler) respondPorts(w http.ResponseWriter, ports []*domain.ProjectPort) {
	out := portsResponse{AddressHost: h.svc.Host(), Ports: make([]portJSON, 0, len(ports))}
	for _, p := range ports {
		cidrs := make([]portCIDRJSON, 0, len(p.Rules))
		for _, r := range p.Rules {
			cidrs = append(cidrs, portCIDRJSON{ID: r.ID, CIDR: r.CIDR, Description: r.Description})
		}
		out.Ports = append(out.Ports, portJSON{
			Name: p.Name, ContainerPort: p.ContainerPort, Protocol: portProtoName(p.Protocol), HostPort: p.HostPort,
			Access: portAccess(p.Rules), CIDRs: cidrs,
		})
	}
	respondJSON(w, http.StatusOK, out)
}

func (h *ProjectPortsHandler) fail(w http.ResponseWriter, err error, msg string) {
	var pe *service.PortsError
	if errors.As(err, &pe) {
		respondError(w, pe.Status, pe.Code, pe.Message)
		return
	}
	h.logger.Error(msg, "error", err)
	respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", msg)
}

// GET /orgs/{o}/projects/{p}/ports
func (h *ProjectPortsHandler) List(w http.ResponseWriter, r *http.Request) {
	pc, ok := h.load(w, r, false)
	if !ok {
		return
	}
	ports, err := h.svc.List(r.Context(), pc.projectID)
	if err != nil {
		h.fail(w, err, "failed to list ports")
		return
	}
	h.respondPorts(w, ports)
}

// PUT /orgs/{o}/projects/{p}/ports   {"ports":[{"name","container_port","protocol"}]}
func (h *ProjectPortsHandler) Replace(w http.ResponseWriter, r *http.Request) {
	pc, ok := h.load(w, r, true)
	if !ok {
		return
	}
	var body struct {
		Ports []struct {
			Name          string `json:"name"`
			ContainerPort int    `json:"container_port"`
			Protocol      string `json:"protocol"`
		} `json:"ports"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	in := make([]service.PortInput, 0, len(body.Ports))
	for _, p := range body.Ports {
		in = append(in, service.PortInput{Name: p.Name, ContainerPort: p.ContainerPort, Protocol: p.Protocol})
	}
	specs, err := h.svc.ValidateSpecs(in)
	if err != nil {
		h.fail(w, err, "invalid ports")
		return
	}
	if !h.supported(w, r, pc) {
		return
	}
	ports, err := h.svc.Replace(r.Context(), pc.projectID, specs)
	if err != nil {
		h.fail(w, err, "failed to update ports")
		return
	}
	h.respondPorts(w, ports)
}

// POST /orgs/{o}/projects/{p}/ports/{container_port}/access   {"cidr","description","allow_public"}
func (h *ProjectPortsHandler) AddAccess(w http.ResponseWriter, r *http.Request) {
	pc, ok := h.load(w, r, true)
	if !ok {
		return
	}
	containerPort, err := strconv.Atoi(chi.URLParam(r, "containerPort"))
	if err != nil || containerPort < 1 || containerPort > 65535 {
		respondError(w, http.StatusBadRequest, "INVALID_PORT", "invalid container port")
		return
	}
	var body struct {
		CIDR        string `json:"cidr"`
		Description string `json:"description"`
		AllowPublic bool   `json:"allow_public"`
		Protocol    string `json:"protocol"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	proto, ok := accessProtocol(w, r, body.Protocol)
	if !ok {
		return
	}
	if len(body.Description) > 200 {
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "description is limited to 200 characters")
		return
	}
	cidr, ok := checkPortCIDR(w, body.CIDR, body.AllowPublic, pc.role)
	if !ok {
		return
	}
	rule, err := h.svc.AddRule(r.Context(), pc.projectID, containerPort, proto, cidr, body.Description, pc.user.ID)
	if err != nil {
		h.fail(w, err, "failed to save access rule")
		return
	}
	respondJSON(w, http.StatusCreated, portCIDRJSON{ID: rule.ID, CIDR: rule.CIDR, Description: rule.Description})
}

// DELETE /orgs/{o}/projects/{p}/ports/{container_port}/access/{ruleID}
func (h *ProjectPortsHandler) RemoveAccess(w http.ResponseWriter, r *http.Request) {
	pc, ok := h.load(w, r, true)
	if !ok {
		return
	}
	containerPort, err := strconv.Atoi(chi.URLParam(r, "containerPort"))
	if err != nil || containerPort < 1 || containerPort > 65535 {
		respondError(w, http.StatusBadRequest, "INVALID_PORT", "invalid container port")
		return
	}
	ruleID, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid rule id")
		return
	}
	proto, ok := accessProtocol(w, r, "")
	if !ok {
		return
	}
	if err := h.svc.RemoveRule(r.Context(), pc.projectID, containerPort, proto, ruleID); err != nil {
		h.fail(w, err, "failed to delete access rule")
		return
	}
	respondNoContent(w)
}

// accessProtocol resolves the protocol of an access request: the body value, else
// the ?protocol= query, else tcp. It writes the 400 itself.
func accessProtocol(w http.ResponseWriter, r *http.Request, fromBody string) (string, bool) {
	raw := fromBody
	if raw == "" {
		raw = r.URL.Query().Get("protocol")
	}
	proto, ok := domain.NormalizeProtocol(raw)
	if !ok {
		respondError(w, http.StatusBadRequest, "INVALID_PROTOCOL", "protocolo no soportado ("+raw+"): usa tcp o udp")
		return "", false
	}
	return proto, true
}

// Cleanup revokes the firewall rules of a deleted project and drops its ports.
func (h *ProjectPortsHandler) Cleanup(projectID uuid.UUID) {
	if h == nil || h.svc == nil {
		return
	}
	h.svc.Cleanup(projectID)
}

// checkPortCIDR validates one CIDR and enforces the public-access gate (owner/admin only).
func checkPortCIDR(w http.ResponseWriter, raw string, allowPublic bool, role string) (string, bool) {
	cidr, err := netaccess.NormalizeCIDR(raw, true)
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_CIDR", err.Error())
		return "", false
	}
	if netaccess.IsPublicCIDR(cidr) {
		if !allowPublic {
			respondError(w, http.StatusBadRequest, "PUBLIC_NOT_ALLOWED",
				cidr+" exposes the port to the whole internet; send \"allow_public\": true to confirm")
			return "", false
		}
		if !isOrgAdmin(role) {
			respondError(w, http.StatusForbidden, "FORBIDDEN", "only owners and admins can open a port to the public internet")
			return "", false
		}
	}
	return cidr, true
}

// DBPortRange exposes the database host port range (CAPSULE_DB_PORT_RANGE) so
// the extra-port allocator never hands out ports of that range.
func DBPortRange() (from, to int) { return dbPortRange() }
