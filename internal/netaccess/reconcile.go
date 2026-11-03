package netaccess

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// DescPrefix marks security group rules owned by Capsule. The full description
// is "capsule:db:<dbID>:<cidr>". Rules without this prefix are never touched.
const DescPrefix = "capsule:db:"

// ErrRuleLimit is returned when AWS refuses more rules for the security group.
var ErrRuleLimit = errors.New("the host security group has reached its AWS rule limit; remove unused access rules or ask the platform admin to raise the quota")

// Rule is a minimal view of an ingress rule of the managed security group.
type Rule struct {
	RuleID string
	// Protocol is "tcp" or "udp"; "" (a rule built without it) is tcp.
	Protocol    string
	Port        int
	CIDR        string
	Description string
}

// EC2API is the minimal EC2 surface the reconciler needs (injectable for tests).
type EC2API interface {
	// ListIngressRules returns every single-port TCP and UDP ingress rule of the
	// security group, IPv4 and IPv6 (Rule.CIDR holds either family). Other
	// protocols and port ranges are not listed, so they are never touched.
	ListIngressRules(ctx context.Context, sgID string) ([]Rule, error)
	// AuthorizeIngress opens one TCP port for one CIDR.
	AuthorizeIngress(ctx context.Context, sgID string, port int, cidr, description string) error
	// AuthorizeIngressProto opens one port on protocol "tcp" or "udp" for one CIDR.
	AuthorizeIngressProto(ctx context.Context, sgID, protocol string, port int, cidr, description string) error
	// RevokeIngressByID revokes exactly the given rules (by security-group-rule id).
	RevokeIngressByID(ctx context.Context, sgID string, ruleIDs []string) error
}

// Desired is one wanted rule: allow cidr to reach the database's host port.
type Desired struct {
	DBID uuid.UUID
	Port int
	CIDR string
}

// Description builds the ownership description for a rule.
func Description(dbID uuid.UUID, cidr string) string {
	return DescPrefix + dbID.String() + ":" + cidr
}

// parseOwned returns the db id and cidr encoded in an owned rule's description.
func parseOwned(desc string) (uuid.UUID, string, bool) {
	if !strings.HasPrefix(desc, DescPrefix) {
		return uuid.Nil, "", false
	}
	rest := strings.TrimPrefix(desc, DescPrefix)
	if len(rest) < 37 || rest[36] != ':' {
		return uuid.Nil, "", false
	}
	id, err := uuid.Parse(rest[:36])
	if err != nil {
		return uuid.Nil, "", false
	}
	return id, rest[37:], true
}

type key struct {
	db   uuid.UUID
	port int
	cidr string
}

// Plan is the diff between desired and current owned rules.
type Plan struct {
	Add    []Desired
	Revoke []Rule
}

// Diff computes what to add and revoke. Only rules whose description carries
// our prefix are candidates for revoking; scope limits the revoke candidates
// to a single database (nil = all owned rules, used by the startup sweep).
func Diff(desired []Desired, current []Rule, scope *uuid.UUID) Plan {
	want := map[key]Desired{}
	for _, d := range desired {
		want[key{d.DBID, d.Port, d.CIDR}] = d
	}
	have := map[key]bool{}
	var plan Plan
	for _, r := range current {
		id, cidr, ok := parseOwned(r.Description)
		if !ok || r.RuleProtocol() != "tcp" { // databases are TCP: a UDP rule is never ours
			continue // not ours: never touch
		}
		if scope != nil && id != *scope {
			continue
		}
		k := key{id, r.Port, cidr}
		if _, wanted := want[k]; wanted && SameCIDR(r.CIDR, cidr) && !have[k] {
			have[k] = true
			continue
		}
		plan.Revoke = append(plan.Revoke, r)
	}
	for k, d := range want {
		if !have[k] {
			plan.Add = append(plan.Add, d)
		}
	}
	sort.Slice(plan.Add, func(i, j int) bool {
		if plan.Add[i].DBID != plan.Add[j].DBID {
			return plan.Add[i].DBID.String() < plan.Add[j].DBID.String()
		}
		return plan.Add[i].CIDR < plan.Add[j].CIDR
	})
	return plan
}

// Reconciler applies desired database access rules to one security group.
type Reconciler struct {
	ec2  EC2API
	sgID string
	mu   sync.Mutex
}

// NewReconciler returns nil when ec2 or sgID is missing (feature disabled).
func NewReconciler(ec2 EC2API, sgID string) *Reconciler {
	if ec2 == nil || strings.TrimSpace(sgID) == "" {
		return nil
	}
	return &Reconciler{ec2: ec2, sgID: sgID}
}

// ReconcileDB makes the owned rules of one database equal to cidrs on port.
// An empty cidrs list (or port 0) removes all of its rules.
func (r *Reconciler) ReconcileDB(ctx context.Context, dbID uuid.UUID, port int, cidrs []string) error {
	var desired []Desired
	if port > 0 {
		for _, c := range cidrs {
			desired = append(desired, Desired{DBID: dbID, Port: port, CIDR: c})
		}
	}
	return r.apply(ctx, desired, &dbID)
}

// SyncAll reconciles every database: desired is the full wanted state and any
// owned rule not in it (for example of a deleted database) is revoked.
func (r *Reconciler) SyncAll(ctx context.Context, desired []Desired) error {
	return r.apply(ctx, desired, nil)
}

func (r *Reconciler) apply(ctx context.Context, desired []Desired, scope *uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	current, err := r.ec2.ListIngressRules(ctx, r.sgID)
	if err != nil {
		return fmt.Errorf("listing security group rules: %w", err)
	}
	plan := Diff(desired, current, scope)

	// Revoke first so freed slots are available to the additions.
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
		if err := r.ec2.AuthorizeIngress(ctx, r.sgID, d.Port, d.CIDR, Description(d.DBID, d.CIDR)); err != nil {
			if IsDuplicate(err) {
				continue
			}
			if IsLimitExceeded(err) {
				return fmt.Errorf("%w (%v)", ErrRuleLimit, err)
			}
			return fmt.Errorf("authorizing %s on port %d: %w", d.CIDR, d.Port, err)
		}
	}
	return nil
}
