package netaccess

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// PortDescPrefix marks security group rules owned by Capsule for project ports.
// TCP rules (the original form, also what rules created before UDP support
// look like): "capsule:port:<projectID>:<hostPort>:<cidr>". UDP rules carry the
// protocol: "capsule:port:udp:<projectID>:<hostPort>:<cidr>". It never overlaps
// with DescPrefix ("capsule:db:") nor with the gateway's "capsule:gw", and each
// diff only considers rules carrying its own prefix.
const PortDescPrefix = "capsule:port:"

// MinPortRulePort is the lowest host port a project port rule may open.
const MinPortRulePort = 1024

// MaxRulesPerPort is the maximum number of access rules per project port
// (per (port, protocol)).
const MaxRulesPerPort = 25

// PortDesired is one wanted rule: allow cidr to reach a project's host port.
// Protocol "" means tcp.
type PortDesired struct {
	ProjectID uuid.UUID
	Protocol  string
	HostPort  int
	CIDR      string
}

func (d PortDesired) proto() string { return normProto(d.Protocol) }

// normProto maps "" to tcp and lower-cases.
func normProto(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return "tcp"
	}
	return p
}

// RuleProtocol returns the protocol of a listed rule ("" is tcp).
func (r Rule) RuleProtocol() string { return normProto(r.Protocol) }

// PortDescription builds the ownership description of a TCP project port rule.
func PortDescription(projectID uuid.UUID, hostPort int, cidr string) string {
	return PortDescriptionProto(projectID, "tcp", hostPort, cidr)
}

// PortDescriptionProto builds the ownership description for a project port
// rule of the given protocol. TCP keeps the historical format.
func PortDescriptionProto(projectID uuid.UUID, protocol string, hostPort int, cidr string) string {
	if normProto(protocol) == "udp" {
		return PortDescPrefix + "udp:" + projectID.String() + ":" + strconv.Itoa(hostPort) + ":" + cidr
	}
	return PortDescPrefix + projectID.String() + ":" + strconv.Itoa(hostPort) + ":" + cidr
}

// parseOwnedPort decodes the project id, protocol, host port and cidr of an owned rule.
func parseOwnedPort(desc string) (uuid.UUID, string, int, string, bool) {
	if !strings.HasPrefix(desc, PortDescPrefix) {
		return uuid.Nil, "", 0, "", false
	}
	rest := strings.TrimPrefix(desc, PortDescPrefix)
	proto := "tcp"
	if strings.HasPrefix(rest, "udp:") {
		proto = "udp"
		rest = rest[4:]
	}
	if len(rest) < 37 || rest[36] != ':' {
		return uuid.Nil, "", 0, "", false
	}
	id, err := uuid.Parse(rest[:36])
	if err != nil {
		return uuid.Nil, "", 0, "", false
	}
	rest = rest[37:]
	i := strings.IndexByte(rest, ':')
	if i <= 0 {
		return uuid.Nil, "", 0, "", false
	}
	port, err := strconv.Atoi(rest[:i])
	if err != nil || port <= 0 || port > 65535 {
		return uuid.Nil, "", 0, "", false
	}
	return id, proto, port, rest[i+1:], true
}

type portKey struct {
	project uuid.UUID
	proto   string
	port    int
	cidr    string
}

// PortPlan is the diff between desired and current owned project port rules.
type PortPlan struct {
	Add    []PortDesired
	Revoke []Rule
}

// DiffPorts computes what to add and revoke. Only rules whose description
// carries PortDescPrefix are candidates for revoking (rules of other owners,
// including the "capsule:db:" and "capsule:gw" ones, SSH and so on, are never
// touched). A rule matches a wanted entry only with the same project, protocol,
// port and CIDR; one that carries our prefix but sits on another protocol or
// port is stale and gets revoked. scope limits the revoke candidates to one
// project (nil = every owned rule: startup sweep).
func DiffPorts(desired []PortDesired, current []Rule, scope *uuid.UUID) PortPlan {
	want := map[portKey]PortDesired{}
	for _, d := range desired {
		want[portKey{d.ProjectID, d.proto(), d.HostPort, d.CIDR}] = d
	}
	have := map[portKey]bool{}
	var plan PortPlan
	for _, r := range current {
		pid, proto, port, cidr, ok := parseOwnedPort(r.Description)
		if !ok {
			continue // not ours: never touch
		}
		if scope != nil && pid != *scope {
			continue
		}
		k := portKey{pid, proto, port, cidr}
		if _, wanted := want[k]; wanted && SameCIDR(r.CIDR, cidr) && r.Port == port && r.RuleProtocol() == proto && !have[k] {
			have[k] = true
			continue
		}
		plan.Revoke = append(plan.Revoke, r)
	}
	for k, d := range want {
		if scope != nil && d.ProjectID != *scope {
			continue
		}
		if !have[k] {
			plan.Add = append(plan.Add, d)
		}
	}
	sort.Slice(plan.Add, func(i, j int) bool {
		a, b := plan.Add[i], plan.Add[j]
		if a.ProjectID != b.ProjectID {
			return a.ProjectID.String() < b.ProjectID.String()
		}
		if a.proto() != b.proto() {
			return a.proto() < b.proto()
		}
		if a.HostPort != b.HostPort {
			return a.HostPort < b.HostPort
		}
		return a.CIDR < b.CIDR
	})
	return plan
}

// ReconcileProjectPorts makes the owned rules of one project equal to desired
// (every entry must belong to projectID; others are ignored). An empty list
// removes all of the project's port rules.
func (r *Reconciler) ReconcileProjectPorts(ctx context.Context, projectID uuid.UUID, desired []PortDesired) error {
	var own []PortDesired
	for _, d := range desired {
		if d.ProjectID == projectID {
			own = append(own, d)
		}
	}
	return r.applyPorts(ctx, own, &projectID)
}

// SyncAllPorts reconciles every project: desired is the full wanted state and
// any owned port rule not in it (deleted project, removed port) is revoked.
func (r *Reconciler) SyncAllPorts(ctx context.Context, desired []PortDesired) error {
	return r.applyPorts(ctx, desired, nil)
}

// validatePortDesired refuses entries that must never reach the firewall: an
// unknown protocol or a port outside 1024-65535.
func validatePortDesired(desired []PortDesired) error {
	for _, d := range desired {
		if p := d.proto(); p != "tcp" && p != "udp" {
			return fmt.Errorf("protocolo %q no soportado para el puerto %d (solo tcp o udp)", d.Protocol, d.HostPort)
		}
		if d.HostPort < MinPortRulePort || d.HostPort > 65535 {
			return fmt.Errorf("el puerto %d/%s está fuera del rango permitido (%d-65535)", d.HostPort, d.proto(), MinPortRulePort)
		}
	}
	return nil
}

func (r *Reconciler) applyPorts(ctx context.Context, desired []PortDesired, scope *uuid.UUID) error {
	if err := validatePortDesired(desired); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	current, err := r.ec2.ListIngressRules(ctx, r.sgID)
	if err != nil {
		return fmt.Errorf("listing security group rules: %w", err)
	}
	plan := DiffPorts(desired, current, scope)

	if len(plan.Revoke) > 0 {
		ids := make([]string, 0, len(plan.Revoke))
		for _, rr := range plan.Revoke {
			ids = append(ids, rr.RuleID)
		}
		if err := r.ec2.RevokeIngressByID(ctx, r.sgID, ids); err != nil {
			return fmt.Errorf("revoking security group rules: %w", err)
		}
	}
	for _, d := range plan.Add {
		if err := r.ec2.AuthorizeIngressProto(ctx, r.sgID, d.proto(), d.HostPort, d.CIDR, PortDescriptionProto(d.ProjectID, d.proto(), d.HostPort, d.CIDR)); err != nil {
			if IsDuplicate(err) {
				continue
			}
			if IsLimitExceeded(err) {
				return fmt.Errorf("%w (%v)", ErrRuleLimit, err)
			}
			return fmt.Errorf("authorizing %s on port %d/%s: %w", d.CIDR, d.HostPort, d.proto(), err)
		}
	}
	return nil
}
