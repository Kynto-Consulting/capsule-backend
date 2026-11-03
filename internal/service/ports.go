package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/netaccess"
)

const (
	// MaxPortsPerProject is the maximum number of extra TCP ports of a project.
	MaxPortsPerProject = 10
	// DefaultPortRange is the host port range used when CAPSULE_PORT_RANGE is unset.
	DefaultPortRange = "41000-41999"
	maxPortNameLen   = 40
)

// ErrNothingToRestart is returned by a PortsRestarter when the project has no
// running docker deployment yet: the ports are stored and applied on the next deploy.
var ErrNothingToRestart = errors.New("project has no docker deployment to restart")

// PortsError is a user-facing failure with its HTTP status and API error code.
type PortsError struct {
	Status  int
	Code    string
	Message string
}

func (e *PortsError) Error() string { return e.Message }

func portsErr(status int, code, format string, a ...any) *PortsError {
	return &PortsError{Status: status, Code: code, Message: fmt.Sprintf(format, a...)}
}

// PortsFirewall applies project port rules to the host security group.
// *netaccess.Reconciler implements it.
type PortsFirewall interface {
	ReconcileProjectPorts(ctx context.Context, projectID uuid.UUID, desired []netaccess.PortDesired) error
	SyncAllPorts(ctx context.Context, desired []netaccess.PortDesired) error
}

// PortsRestarter recreates a project's container with the given extra ports,
// without rebuilding the image. It returns ErrNothingToRestart when there is
// nothing running to recreate.
type PortsRestarter interface {
	Recreate(ctx context.Context, projectID uuid.UUID, extra []domain.PortMapping) error
}

// PortsConfig configures PortsService.
type PortsConfig struct {
	From, To int    // host port range handed out to projects
	Host     string // address_host shown to users
	// Reserved container ports that can never be published (22, 2375, 2376 are always added).
	Reserved []int
	// AvoidHost are host port ranges never handed out (database range, API port).
	AvoidHost [][2]int
	// InUse reports whether a host port is currently bound by some process (optional).
	InUse func(port int) bool
}

// PortsService owns the extra TCP ports of projects.
type PortsService struct {
	repo      domain.ProjectPortRepository
	firewall  PortsFirewall // nil => feature disabled
	restarter PortsRestarter
	cfg       PortsConfig
	reserved  map[int]bool
	logger    *slog.Logger
	mu        sync.Mutex
}

func NewPortsService(repo domain.ProjectPortRepository, fw PortsFirewall, rs PortsRestarter, cfg PortsConfig, logger *slog.Logger) *PortsService {
	if logger == nil {
		logger = slog.Default()
	}
	reserved := map[int]bool{22: true, 2375: true, 2376: true}
	for _, p := range cfg.Reserved {
		reserved[p] = true
	}
	return &PortsService{repo: repo, firewall: fw, restarter: rs, cfg: cfg, reserved: reserved, logger: logger}
}

// Enabled reports whether the firewall is configured (APP_SECURITY_GROUP_ID).
func (s *PortsService) Enabled() bool { return s != nil && s.firewall != nil && s.repo != nil }

// Range returns the host range as "from-to".
func (s *PortsService) Range() string { return fmt.Sprintf("%d-%d", s.cfg.From, s.cfg.To) }

// Host returns the address users connect to.
func (s *PortsService) Host() string { return s.cfg.Host }

// ParsePortRange parses "41000-41999"; empty selects DefaultPortRange.
func ParsePortRange(raw string) (from, to int, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = DefaultPortRange
	}
	if _, err := fmt.Sscanf(raw, "%d-%d", &from, &to); err != nil || from < 1024 || to < from || to > 65535 {
		return 0, 0, fmt.Errorf("invalid port range %q (want e.g. %s)", raw, DefaultPortRange)
	}
	return from, to, nil
}

var portNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]*$`)

// ValidateSpecs checks and normalises a requested port list.
func (s *PortsService) ValidateSpecs(in []PortInput) ([]domain.PortSpec, error) {
	if len(in) > MaxPortsPerProject {
		return nil, portsErr(http.StatusUnprocessableEntity, "LIMIT_EXCEEDED", "a project can publish at most %d extra ports", MaxPortsPerProject)
	}
	seen := map[int]bool{}
	out := make([]domain.PortSpec, 0, len(in))
	for _, p := range in {
		proto := strings.ToLower(strings.TrimSpace(p.Protocol))
		if proto != "" && proto != "tcp" {
			return nil, portsErr(http.StatusBadRequest, "INVALID_PROTOCOL", "only tcp ports are supported (got %q)", p.Protocol)
		}
		if p.ContainerPort < 1 || p.ContainerPort > 65535 {
			return nil, portsErr(http.StatusBadRequest, "INVALID_PORT", "container_port must be between 1 and 65535 (got %d)", p.ContainerPort)
		}
		if s.reserved[p.ContainerPort] {
			return nil, portsErr(http.StatusBadRequest, "RESERVED_PORT", "container port %d is reserved and cannot be published", p.ContainerPort)
		}
		if seen[p.ContainerPort] {
			return nil, portsErr(http.StatusBadRequest, "DUPLICATE_PORT", "container port %d is listed twice", p.ContainerPort)
		}
		seen[p.ContainerPort] = true
		name := strings.TrimSpace(p.Name)
		if name == "" {
			name = "port-" + strconv.Itoa(p.ContainerPort)
		}
		if len(name) > maxPortNameLen || !portNameRE.MatchString(name) {
			return nil, portsErr(http.StatusBadRequest, "INVALID_NAME", "port name must be 1-%d characters (letters, digits, space, _ . -)", maxPortNameLen)
		}
		out = append(out, domain.PortSpec{Name: name, ContainerPort: p.ContainerPort})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ContainerPort < out[j].ContainerPort })
	return out, nil
}

// PortInput is one requested port as received from the API.
type PortInput struct {
	Name          string
	ContainerPort int
	Protocol      string
}

func (s *PortsService) avoided(p int) bool {
	for _, r := range s.cfg.AvoidHost {
		if p >= r[0] && p <= r[1] {
			return true
		}
	}
	return false
}

// allocate picks the lowest free host port of the range. used is updated.
func (s *PortsService) allocate(used map[int]bool) (int, error) {
	for p := s.cfg.From; p <= s.cfg.To; p++ {
		if used[p] || s.avoided(p) {
			continue
		}
		if s.cfg.InUse != nil && s.cfg.InUse(p) {
			continue
		}
		used[p] = true
		return p, nil
	}
	return 0, portsErr(http.StatusConflict, "PORT_RANGE_EXHAUSTED", "no free host port left in %s", s.Range())
}

// Assign computes the final port list: ports already published keep their
// host port, new ones get a fresh one. The result is sorted by container port.
func (s *PortsService) assign(projectID uuid.UUID, current []*domain.ProjectPort, specs []domain.PortSpec, used map[int]bool) ([]*domain.ProjectPort, error) {
	byContainer := map[int]*domain.ProjectPort{}
	for _, p := range current {
		byContainer[p.ContainerPort] = p
	}
	out := make([]*domain.ProjectPort, 0, len(specs))
	for _, sp := range specs {
		if old, ok := byContainer[sp.ContainerPort]; ok {
			out = append(out, &domain.ProjectPort{
				ID: old.ID, ProjectID: projectID, Name: sp.Name, ContainerPort: sp.ContainerPort,
				Protocol: "tcp", HostPort: old.HostPort, Rules: old.Rules,
			})
			continue
		}
		hp, err := s.allocate(used)
		if err != nil {
			return nil, err
		}
		out = append(out, &domain.ProjectPort{
			ProjectID: projectID, Name: sp.Name, ContainerPort: sp.ContainerPort, Protocol: "tcp", HostPort: hp,
		})
	}
	return out, nil
}

// Mappings converts ports to docker publish pairs.
func Mappings(ports []*domain.ProjectPort) []domain.PortMapping {
	out := make([]domain.PortMapping, 0, len(ports))
	for _, p := range ports {
		out = append(out, domain.PortMapping{ContainerPort: p.ContainerPort, HostPort: p.HostPort})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ContainerPort < out[j].ContainerPort })
	return out
}

func sameMappings(a, b []domain.PortMapping) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func desiredFor(projectID uuid.UUID, ports []*domain.ProjectPort) []netaccess.PortDesired {
	var out []netaccess.PortDesired
	for _, p := range ports {
		for _, r := range p.Rules {
			out = append(out, netaccess.PortDesired{ProjectID: projectID, HostPort: p.HostPort, CIDR: r.CIDR})
		}
	}
	return out
}

func (s *PortsService) firewallError(projectID uuid.UUID, err error) *PortsError {
	s.logger.Error("applying project port rules failed", "project_id", projectID, "error", err)
	if errors.Is(err, netaccess.ErrRuleLimit) {
		return portsErr(http.StatusConflict, "SG_RULE_LIMIT", "%s", err.Error())
	}
	return portsErr(http.StatusBadGateway, "FIREWALL_ERROR", "could not apply the rules to the host firewall: %s (nothing was changed)", err.Error())
}

// resync re-applies the stored state after a failed persist (best effort).
func (s *PortsService) resync(ctx context.Context, projectID uuid.UUID) {
	ports, err := s.repo.List(ctx, projectID)
	if err != nil {
		return
	}
	if err := s.firewall.ReconcileProjectPorts(ctx, projectID, desiredFor(projectID, ports)); err != nil {
		s.logger.Warn("resync of project port rules failed", "project_id", projectID, "error", err)
	}
}

// List returns the stored ports (with rules) of a project.
func (s *PortsService) List(ctx context.Context, projectID uuid.UUID) ([]*domain.ProjectPort, error) {
	return s.repo.List(ctx, projectID)
}

// Replace makes the project's extra ports equal to specs and restarts its
// container with the new publish flags (no image rebuild). On any failure the
// previous container configuration is restored and nothing is persisted.
func (s *PortsService) Replace(ctx context.Context, projectID uuid.UUID, specs []domain.PortSpec) ([]*domain.ProjectPort, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, err := s.repo.List(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing ports: %w", err)
	}
	used, err := s.repo.UsedHostPorts(ctx, s.cfg.From, s.cfg.To)
	if err != nil {
		return nil, fmt.Errorf("listing used ports: %w", err)
	}
	next, err := s.assign(projectID, current, specs, used)
	if err != nil {
		return nil, err
	}
	oldMap, newMap := Mappings(current), Mappings(next)
	changed := !sameMappings(oldMap, newMap)

	restarted := false
	if changed && s.restarter != nil {
		if err := s.restarter.Recreate(ctx, projectID, newMap); err != nil {
			if !errors.Is(err, ErrNothingToRestart) {
				return nil, s.rollbackError(ctx, projectID, oldMap, err)
			}
		} else {
			restarted = true
		}
	}
	undo := func(cause error) error {
		if restarted {
			return s.rollbackError(ctx, projectID, oldMap, cause)
		}
		return cause
	}

	if changed {
		// AWS first: revoke the rules of removed ports before persisting.
		if err := s.firewall.ReconcileProjectPorts(ctx, projectID, desiredFor(projectID, next)); err != nil {
			fe := s.firewallError(projectID, err)
			if restarted {
				return nil, s.rollbackError(ctx, projectID, oldMap, fe)
			}
			return nil, fe
		}
	}
	stored, err := s.repo.Replace(ctx, projectID, next)
	if err != nil {
		s.logger.Error("persisting project ports failed", "project_id", projectID, "error", err)
		s.resync(ctx, projectID)
		if errors.Is(err, domain.ErrConflict) {
			return nil, undo(portsErr(http.StatusConflict, "PORT_CONFLICT", "a host port was taken concurrently; retry"))
		}
		return nil, undo(portsErr(http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save ports"))
	}
	return stored, nil
}

// rollbackError restores the previous container and builds the API error.
func (s *PortsService) rollbackError(ctx context.Context, projectID uuid.UUID, old []domain.PortMapping, cause error) error {
	s.logger.Error("restarting project container with new ports failed", "project_id", projectID, "error", cause)
	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	var pe *PortsError
	msg := cause.Error()
	if errors.As(cause, &pe) {
		msg = pe.Message
	}
	if rbErr := s.restarter.Recreate(rbCtx, projectID, old); rbErr != nil && !errors.Is(rbErr, ErrNothingToRestart) {
		s.logger.Error("rollback of project container failed", "project_id", projectID, "error", rbErr)
		return portsErr(http.StatusBadGateway, "RESTART_FAILED",
			"the container could not be restarted with the new ports (%s) and restoring the previous configuration also failed (%s); redeploy the project", msg, rbErr.Error())
	}
	if pe != nil {
		return pe
	}
	return portsErr(http.StatusBadGateway, "RESTART_FAILED",
		"the container could not be restarted with the new ports (%s); the previous configuration was restored and nothing changed", msg)
}

// AddRule opens a published port to one CIDR. AWS first, persisted only if it accepts.
func (s *PortsService) AddRule(ctx context.Context, projectID uuid.UUID, containerPort int, cidr, description string, createdBy uuid.UUID) (*domain.PortRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ports, err := s.repo.List(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing ports: %w", err)
	}
	var port *domain.ProjectPort
	for _, p := range ports {
		if p.ContainerPort == containerPort {
			port = p
		}
	}
	if port == nil {
		return nil, portsErr(http.StatusNotFound, "NOT_FOUND", "port %d is not published by this project", containerPort)
	}
	for _, r := range port.Rules {
		if r.CIDR == cidr {
			return nil, portsErr(http.StatusConflict, "ALREADY_EXISTS", "that CIDR already has access")
		}
	}
	if len(port.Rules) >= netaccess.MaxRulesPerPort {
		return nil, portsErr(http.StatusUnprocessableEntity, "LIMIT_EXCEEDED", "a port can have at most %d access rules", netaccess.MaxRulesPerPort)
	}
	desired := append(desiredFor(projectID, ports), netaccess.PortDesired{ProjectID: projectID, HostPort: port.HostPort, CIDR: cidr})
	if err := s.firewall.ReconcileProjectPorts(ctx, projectID, desired); err != nil {
		return nil, s.firewallError(projectID, err)
	}
	by := createdBy
	rule, err := s.repo.AddRule(ctx, projectID, containerPort, &domain.PortRule{CIDR: cidr, Description: strings.TrimSpace(description), CreatedBy: &by}, netaccess.MaxRulesPerPort)
	if err != nil {
		s.resync(ctx, projectID)
		switch {
		case errors.Is(err, domain.ErrConflict):
			return nil, portsErr(http.StatusConflict, "ALREADY_EXISTS", "that CIDR already has access")
		case errors.Is(err, domain.ErrRuleLimit):
			return nil, portsErr(http.StatusUnprocessableEntity, "LIMIT_EXCEEDED", "a port can have at most %d access rules", netaccess.MaxRulesPerPort)
		case errors.Is(err, domain.ErrNotFound):
			return nil, portsErr(http.StatusNotFound, "NOT_FOUND", "port %d is not published by this project", containerPort)
		}
		s.logger.Error("persisting port rule failed", "project_id", projectID, "error", err)
		return nil, portsErr(http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save access rule")
	}
	return rule, nil
}

// RemoveRule closes access for one rule. containerPort must match the rule's port.
func (s *PortsService) RemoveRule(ctx context.Context, projectID uuid.UUID, containerPort int, ruleID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ports, err := s.repo.List(ctx, projectID)
	if err != nil {
		return fmt.Errorf("listing ports: %w", err)
	}
	found := false
	var keep []netaccess.PortDesired
	for _, p := range ports {
		for _, r := range p.Rules {
			if r.ID == ruleID && p.ContainerPort == containerPort {
				found = true
				continue
			}
			keep = append(keep, netaccess.PortDesired{ProjectID: projectID, HostPort: p.HostPort, CIDR: r.CIDR})
		}
	}
	if !found {
		return portsErr(http.StatusNotFound, "NOT_FOUND", "access rule not found")
	}
	if err := s.firewall.ReconcileProjectPorts(ctx, projectID, keep); err != nil {
		return s.firewallError(projectID, err)
	}
	if err := s.repo.DeleteRule(ctx, projectID, ruleID); err != nil && !errors.Is(err, domain.ErrNotFound) {
		s.logger.Error("deleting port rule failed", "project_id", projectID, "error", err)
		s.resync(ctx, projectID)
		return portsErr(http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete access rule")
	}
	return nil
}

// Cleanup revokes every firewall rule of a deleted project and drops its stored ports.
func (s *PortsService) Cleanup(projectID uuid.UUID) {
	if !s.Enabled() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.firewall.ReconcileProjectPorts(ctx, projectID, nil); err != nil {
		// Stored ports stay so the startup sweep can retry (it revokes orphans of deleted projects).
		s.logger.Warn("revoking project port rules failed", "project_id", projectID, "error", err)
		return
	}
	if err := s.repo.DeleteAll(ctx, projectID); err != nil {
		s.logger.Warn("deleting project ports failed", "project_id", projectID, "error", err)
	}
}

// Sweep re-applies every stored rule and revokes owned orphans (startup).
func (s *PortsService) Sweep(ctx context.Context) error {
	if !s.Enabled() {
		return nil
	}
	rules, err := s.repo.ListDesired(ctx)
	if err != nil {
		return fmt.Errorf("listing port rules: %w", err)
	}
	items := make([]netaccess.PortDesired, 0, len(rules))
	for _, d := range rules {
		items = append(items, netaccess.PortDesired{ProjectID: d.ProjectID, HostPort: d.HostPort, CIDR: d.CIDR})
	}
	if err := s.firewall.SyncAllPorts(ctx, items); err != nil {
		return err
	}
	s.logger.Info("project port rules reconciled", "rules", len(items))
	return nil
}

// ExtraPorts returns the publish pairs of a project (used by new deployments).
func (s *PortsService) ExtraPorts(ctx context.Context, projectID uuid.UUID) ([]domain.PortMapping, error) {
	ports, err := s.repo.List(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return Mappings(ports), nil
}

// SupportsPorts reports whether a project deploys as a docker container on the
// app host. deployment is the latest successful deployment (nil if none);
// fargateConfigured says whether the default strategy resolves to Fargate.
func SupportsPorts(project *domain.Project, deployment *domain.Deployment, fargateConfigured bool) bool {
	if deployment != nil {
		// Only the docker-on-host flow records a host port.
		return deployment.HostPort != nil && *deployment.HostPort > 0
	}
	switch project.BuildStrategy {
	case "lambda", "static":
		return false
	case "docker":
		return true
	}
	return !fargateConfigured
}

// PortFree reports whether nothing is listening on the TCP port of this machine.
func PortFree(port int) bool {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// ---- docker side -----------------------------------------------------------

// dockerRunArgs builds the `docker run` arguments of a project container. The
// primary HTTP port is published on hostPort; extra ports are published too.
func dockerRunArgs(name, volume, image string, env []string, injectPort bool, containerPort, hostPort int, extra []domain.PortMapping) []string {
	args := []string{"run", "-d", "--name", name, "--restart", "unless-stopped"}
	for _, kv := range env {
		args = append(args, "-e", kv)
	}
	if injectPort {
		args = append(args, "-e", fmt.Sprintf("PORT=%d", containerPort))
	}
	args = append(args, "-p", fmt.Sprintf("%d:%d", hostPort, containerPort))
	for _, m := range extra {
		args = append(args, "-p", fmt.Sprintf("%d:%d", m.HostPort, m.ContainerPort))
	}
	return append(args, "-v", fmt.Sprintf("%s:/data", volume), image)
}

// userPortFromEnv returns the valid PORT=... value of the user's env, if any.
func userPortFromEnv(env []string) (int, bool) {
	port, ok := 0, false
	for _, kv := range env {
		if strings.HasPrefix(kv, "PORT=") {
			if p, err := strconv.Atoi(strings.TrimPrefix(kv, "PORT=")); err == nil && p > 0 && p < 65536 {
				port, ok = p, true
			}
		}
	}
	return port, ok
}

// SetExtraPorts registers the source of a project's extra published ports,
// consulted when a new deployment starts its container.
func (w *DeployWorker) SetExtraPorts(fn func(ctx context.Context, projectID uuid.UUID) ([]domain.PortMapping, error)) {
	w.extraPorts = fn
}

// dockerRestarter recreates a project's container from the image of its last
// successful deployment, keeping volume, env vars and network.
type dockerRestarter struct {
	deployments domain.DeploymentRepository
	env         func(ctx context.Context, deploymentID, projectID uuid.UUID) ([]string, error)
	docker      func(ctx context.Context, args ...string) ([]byte, error)
	logger      *slog.Logger
}

// PortsRestarter returns the restarter bound to this worker's repositories.
func (w *DeployWorker) PortsRestarter() PortsRestarter {
	return &dockerRestarter{
		deployments: w.deployments,
		env:         w.fetchEnvVarsForDocker,
		docker: func(ctx context.Context, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		},
		logger: w.logger,
	}
}

func (d *dockerRestarter) Recreate(ctx context.Context, projectID uuid.UUID, extra []domain.PortMapping) error {
	dep, err := d.deployments.GetLatestSuccessfulByProject(ctx, projectID)
	if err != nil || dep == nil {
		if err == nil || errors.Is(err, domain.ErrNotFound) {
			return ErrNothingToRestart
		}
		return fmt.Errorf("looking up the last successful deployment: %w", err)
	}
	if dep.HostPort == nil || *dep.HostPort <= 0 {
		return ErrNothingToRestart // not a docker-on-host deployment
	}
	env, err := d.env(ctx, dep.ID, projectID)
	if err != nil {
		return fmt.Errorf("loading env vars: %w", err)
	}
	containerPort := dep.ContainerPort
	if p, ok := userPortFromEnv(env); ok {
		containerPort = p
	}
	if containerPort <= 0 {
		containerPort = 3000
	}
	_, userSet := userPortFromEnv(env)

	short := strings.ReplaceAll(projectID.String(), "-", "")[:12]
	name := "capsule-app-" + short
	volume := "capsule-data-" + projectID.String()

	// Never remove the running container if its image is not there to recreate it.
	if out, err := d.docker(ctx, "image", "inspect", name); err != nil {
		return fmt.Errorf("image %s is not available (%s)", name, strings.TrimSpace(string(out)))
	}
	_, _ = d.docker(ctx, "rm", "-f", name)
	args := dockerRunArgs(name, volume, name, env, !userSet, containerPort, *dep.HostPort, extra)
	if out, err := d.docker(ctx, args...); err != nil {
		_, _ = d.docker(ctx, "rm", "-f", name) // clear a half-created container
		return fmt.Errorf("docker run failed: %s", strings.TrimSpace(string(out)))
	}
	if out, err := d.docker(ctx, "network", "connect", "capsule-prod_capsule-net", name); err != nil && d.logger != nil {
		d.logger.Warn("ports restart: could not connect to backend network (proxy disabled)", "project_id", projectID, "error", string(out))
	}
	return nil
}
