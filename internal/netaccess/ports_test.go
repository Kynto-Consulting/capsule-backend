package netaccess

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestPortDescriptionRoundTrip(t *testing.T) {
	p := uuid.New()
	d := PortDescription(p, 41005, "10.0.0.0/8")
	id, port, cidr, ok := parseOwnedPort(d)
	if !ok || id != p || port != 41005 || cidr != "10.0.0.0/8" {
		t.Fatalf("round trip failed: %v %v %v %v", id, port, cidr, ok)
	}
	for _, bad := range []string{"", "capsule:db:" + p.String() + ":1.2.3.4/32", "capsule:port:xyz", "capsule:port:" + p.String() + ":abc:1.2.3.4/32", "capsule:port:" + p.String() + ":0:1.2.3.4/32"} {
		if _, _, _, ok := parseOwnedPort(bad); ok {
			t.Errorf("%q must not parse", bad)
		}
	}
}

func TestDiffPortsNeverTouchesForeignOrDBRules(t *testing.T) {
	p := uuid.New()
	db := uuid.New()
	current := []Rule{
		{RuleID: "sgr-ssh", Port: 22, CIDR: "1.2.3.4/32", Description: "ssh admin"},
		{RuleID: "sgr-none", Port: 443, CIDR: "0.0.0.0/0", Description: ""},
		{RuleID: "sgr-db", Port: 40001, CIDR: "9.9.9.0/24", Description: Description(db, "9.9.9.0/24")},
		{RuleID: "sgr-keep", Port: 41000, CIDR: "10.0.0.0/8", Description: PortDescription(p, 41000, "10.0.0.0/8")},
		{RuleID: "sgr-stale", Port: 41000, CIDR: "11.0.0.0/8", Description: PortDescription(p, 41000, "11.0.0.0/8")},
	}
	desired := []PortDesired{{p, 41000, "10.0.0.0/8"}, {p, 41001, "12.0.0.0/8"}}
	// Scoped and global sweeps both revoke only owned stale rules.
	for _, scope := range []*uuid.UUID{&p, nil} {
		plan := DiffPorts(desired, current, scope)
		if len(plan.Revoke) != 1 || plan.Revoke[0].RuleID != "sgr-stale" {
			t.Fatalf("revoke = %+v", plan.Revoke)
		}
		if len(plan.Add) != 1 || plan.Add[0].HostPort != 41001 {
			t.Fatalf("add = %+v", plan.Add)
		}
	}
}

func TestDiffPortsOrphansAndScope(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	current := []Rule{
		{RuleID: "sgr-a", Port: 41000, CIDR: "10.0.0.0/8", Description: PortDescription(a, 41000, "10.0.0.0/8")},
		{RuleID: "sgr-b", Port: 41001, CIDR: "10.0.0.0/8", Description: PortDescription(b, 41001, "10.0.0.0/8")},
		// description says 41002 but the rule is on another port: drifted, revoke and re-add.
		{RuleID: "sgr-drift", Port: 41999, CIDR: "10.0.0.0/8", Description: PortDescription(a, 41002, "10.0.0.0/8")},
	}
	// Project a scoped, nothing wanted: only a's rules go; b untouched.
	plan := DiffPorts(nil, current, &a)
	if len(plan.Revoke) != 2 {
		t.Fatalf("scoped revoke = %+v", plan.Revoke)
	}
	for _, r := range plan.Revoke {
		if r.RuleID == "sgr-b" {
			t.Fatal("scoped diff touched another project")
		}
	}
	// Global sweep with nothing wanted: all three orphans.
	if plan := DiffPorts(nil, current, nil); len(plan.Revoke) != 3 {
		t.Fatalf("sweep revoke = %+v", plan.Revoke)
	}
	// Drift is repaired.
	plan = DiffPorts([]PortDesired{{a, 41002, "10.0.0.0/8"}}, current, &a)
	if len(plan.Add) != 1 || plan.Add[0].HostPort != 41002 {
		t.Fatalf("drift add = %+v", plan.Add)
	}
}

func TestReconcileProjectPortsAppliesAndKeepsDBRules(t *testing.T) {
	p, db := uuid.New(), uuid.New()
	f := &fakeEC2{rules: []Rule{
		{RuleID: "sgr-db", Port: 40001, CIDR: "9.9.9.0/24", Description: Description(db, "9.9.9.0/24")},
		{RuleID: "sgr-old", Port: 41003, CIDR: "5.0.0.0/8", Description: PortDescription(p, 41003, "5.0.0.0/8")},
	}}
	r := NewReconciler(f, "sg-1")
	err := r.ReconcileProjectPorts(context.Background(), p, []PortDesired{{p, 41000, "10.0.0.0/8"}, {uuid.New(), 41500, "1.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.revoked) != 1 || f.revoked[0] != "sgr-old" {
		t.Fatalf("revoked = %v", f.revoked)
	}
	if len(f.authorize) != 1 {
		t.Fatalf("authorize = %v (entries of other projects must be ignored)", f.authorize)
	}
	// The db rule survived.
	found := false
	for _, rr := range f.rules {
		if rr.RuleID == "sgr-db" {
			found = true
		}
	}
	if !found {
		t.Fatal("database rule was removed")
	}
	// Empty desired removes everything of the project.
	if err := r.ReconcileProjectPorts(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	for _, rr := range f.rules {
		if _, _, _, ok := parseOwnedPort(rr.Description); ok {
			t.Fatalf("port rule left behind: %+v", rr)
		}
	}
}

func TestSyncAllPortsRevokesOrphans(t *testing.T) {
	gone := uuid.New()
	f := &fakeEC2{rules: []Rule{
		{RuleID: "sgr-x", Port: 41010, CIDR: "5.0.0.0/8", Description: PortDescription(gone, 41010, "5.0.0.0/8")},
		{RuleID: "sgr-foreign", Port: 8080, CIDR: "5.0.0.0/8", Description: "manual"},
	}}
	if err := NewReconciler(f, "sg-1").SyncAllPorts(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(f.revoked) != 1 || f.revoked[0] != "sgr-x" {
		t.Fatalf("revoked = %v", f.revoked)
	}
}
