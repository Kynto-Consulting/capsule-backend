package netaccess

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

type fakeEC2 struct {
	rules     []Rule
	next      int
	authorize []string
	revoked   []string
	authErr   error
	listErr   error
}

func (f *fakeEC2) ListIngressRules(context.Context, string) ([]Rule, error) {
	return append([]Rule(nil), f.rules...), f.listErr
}

func (f *fakeEC2) AuthorizeIngress(ctx context.Context, sg string, port int, cidr, desc string) error {
	return f.AuthorizeIngressProto(ctx, sg, "tcp", port, cidr, desc)
}

func (f *fakeEC2) AuthorizeIngressProto(_ context.Context, _ string, proto string, port int, cidr, desc string) error {
	if f.authErr != nil {
		return f.authErr
	}
	f.next++
	entry := fmt.Sprintf("%d|%s|%s", port, cidr, desc)
	if proto != "tcp" {
		entry = proto + "|" + entry
	}
	f.authorize = append(f.authorize, entry)
	f.rules = append(f.rules, Rule{RuleID: fmt.Sprintf("sgr-new%d", f.next), Protocol: proto, Port: port, CIDR: cidr, Description: desc})
	return nil
}

func (f *fakeEC2) RevokeIngressByID(_ context.Context, _ string, ids []string) error {
	for _, id := range ids {
		f.revoked = append(f.revoked, id)
		for i, r := range f.rules {
			if r.RuleID == id {
				f.rules = append(f.rules[:i], f.rules[i+1:]...)
				break
			}
		}
	}
	return nil
}

func ownedCIDRs(f *fakeEC2, db uuid.UUID) []string {
	var out []string
	for _, r := range f.rules {
		if id, c, ok := parseOwned(r.Description); ok && id == db {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

var foreign = []Rule{
	{RuleID: "sgr-ssh", Port: 22, CIDR: "0.0.0.0/0", Description: "SSH from anywhere"},
	{RuleID: "sgr-tf", Port: 40000, CIDR: "203.0.113.0/24", Description: "Capsule databases (dedicated port range)"},
	{RuleID: "sgr-nodesc", Port: 40010, CIDR: "198.51.100.1/32", Description: ""},
	// looks similar but is NOT ours (different prefix)
	{RuleID: "sgr-lookalike", Port: 40011, CIDR: "198.51.100.2/32", Description: "capsule-db:manual"},
}

func TestReconcileAddsMissingAndUsesOwnershipDescription(t *testing.T) {
	db := uuid.New()
	f := &fakeEC2{rules: append([]Rule(nil), foreign...)}
	r := NewReconciler(f, "sg-1")
	if err := r.ReconcileDB(context.Background(), db, 40123, []string{"203.0.113.5/32", "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	if len(f.authorize) != 2 {
		t.Fatalf("authorized %v", f.authorize)
	}
	want := fmt.Sprintf("40123|203.0.113.5/32|capsule:db:%s:203.0.113.5/32", db)
	found := false
	for _, a := range f.authorize {
		if a == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %q in %v", want, f.authorize)
	}
	if len(f.revoked) != 0 {
		t.Fatalf("nothing should be revoked, got %v", f.revoked)
	}
}

func TestReconcileIsIdempotent(t *testing.T) {
	db := uuid.New()
	f := &fakeEC2{rules: append([]Rule(nil), foreign...)}
	r := NewReconciler(f, "sg-1")
	for i := 0; i < 3; i++ {
		if err := r.ReconcileDB(context.Background(), db, 40123, []string{"203.0.113.5/32"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.authorize) != 1 || len(f.revoked) != 0 {
		t.Fatalf("authorize=%v revoked=%v", f.authorize, f.revoked)
	}
}

func TestReconcileNeverRevokesForeignRules(t *testing.T) {
	db := uuid.New()
	f := &fakeEC2{rules: append([]Rule(nil), foreign...)}
	r := NewReconciler(f, "sg-1")
	_ = r.ReconcileDB(context.Background(), db, 40123, []string{"203.0.113.5/32"})
	// remove everything we own, scoped
	if err := r.ReconcileDB(context.Background(), db, 40123, nil); err != nil {
		t.Fatal(err)
	}
	// and the global sweep with an empty desired state
	if err := r.SyncAll(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	for _, id := range f.revoked {
		for _, fr := range foreign {
			if id == fr.RuleID {
				t.Fatalf("revoked foreign rule %s", id)
			}
		}
	}
	if len(f.rules) != len(foreign) {
		t.Fatalf("foreign rules changed: %v", f.rules)
	}
}

func TestReconcileRemovesDroppedCIDRsOnlyForThatDatabase(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	f := &fakeEC2{rules: append([]Rule(nil), foreign...)}
	r := NewReconciler(f, "sg-1")
	ctx := context.Background()
	_ = r.ReconcileDB(ctx, a, 40001, []string{"203.0.113.5/32", "203.0.113.6/32"})
	_ = r.ReconcileDB(ctx, b, 40002, []string{"203.0.113.5/32"})

	if err := r.ReconcileDB(ctx, a, 40001, []string{"203.0.113.6/32"}); err != nil {
		t.Fatal(err)
	}
	if got := ownedCIDRs(f, a); len(got) != 1 || got[0] != "203.0.113.6/32" {
		t.Fatalf("db a rules: %v", got)
	}
	if got := ownedCIDRs(f, b); len(got) != 1 {
		t.Fatalf("db b must be untouched: %v", got)
	}
}

func TestSyncAllRevokesOrphansAndFixesPortDrift(t *testing.T) {
	live, dead := uuid.New(), uuid.New()
	f := &fakeEC2{rules: append([]Rule(nil), foreign...)}
	f.rules = append(f.rules,
		Rule{RuleID: "sgr-orphan", Port: 40050, CIDR: "203.0.113.9/32", Description: Description(dead, "203.0.113.9/32")},
		// right cidr, wrong port (database was recreated on another port)
		Rule{RuleID: "sgr-drift", Port: 40060, CIDR: "203.0.113.5/32", Description: Description(live, "203.0.113.5/32")},
	)
	r := NewReconciler(f, "sg-1")
	if err := r.SyncAll(context.Background(), []Desired{{DBID: live, Port: 40070, CIDR: "203.0.113.5/32"}}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(f.revoked)
	if len(f.revoked) != 2 || f.revoked[0] != "sgr-drift" || f.revoked[1] != "sgr-orphan" {
		t.Fatalf("revoked %v", f.revoked)
	}
	if len(f.authorize) != 1 || f.authorize[0][:5] != "40070" {
		t.Fatalf("authorized %v", f.authorize)
	}
}

func TestDiffRemovesDuplicateOwnedRules(t *testing.T) {
	db := uuid.New()
	d := Description(db, "203.0.113.5/32")
	cur := []Rule{
		{RuleID: "a", Port: 40001, CIDR: "203.0.113.5/32", Description: d},
		{RuleID: "b", Port: 40001, CIDR: "203.0.113.5/32", Description: d},
	}
	plan := Diff([]Desired{{DBID: db, Port: 40001, CIDR: "203.0.113.5/32"}}, cur, &db)
	if len(plan.Add) != 0 || len(plan.Revoke) != 1 || plan.Revoke[0].RuleID != "b" {
		t.Fatalf("%+v", plan)
	}
}

// apiErr implements smithy.APIError.
type apiErr struct{ code string }

func (e apiErr) Error() string                 { return e.code }
func (e apiErr) ErrorCode() string             { return e.code }
func (e apiErr) ErrorMessage() string          { return e.code }
func (e apiErr) ErrorFault() smithy.ErrorFault { return smithy.FaultUnknown }

func TestReconcileMapsAWSLimitAndDuplicate(t *testing.T) {
	db := uuid.New()
	f := &fakeEC2{authErr: apiErr{"RulesPerSecurityGroupLimitExceeded"}}
	err := NewReconciler(f, "sg-1").ReconcileDB(context.Background(), db, 40001, []string{"203.0.113.5/32"})
	if !errors.Is(err, ErrRuleLimit) {
		t.Fatalf("want ErrRuleLimit, got %v", err)
	}

	f = &fakeEC2{authErr: apiErr{"InvalidPermission.Duplicate"}}
	if err := NewReconciler(f, "sg-1").ReconcileDB(context.Background(), db, 40001, []string{"203.0.113.5/32"}); err != nil {
		t.Fatalf("duplicate must be treated as success, got %v", err)
	}

	f = &fakeEC2{authErr: errors.New("boom")}
	if err := NewReconciler(f, "sg-1").ReconcileDB(context.Background(), db, 40001, []string{"203.0.113.5/32"}); err == nil || errors.Is(err, ErrRuleLimit) {
		t.Fatalf("want generic error, got %v", err)
	}

	f = &fakeEC2{listErr: errors.New("denied")}
	if err := NewReconciler(f, "sg-1").SyncAll(context.Background(), nil); err == nil {
		t.Fatal("list error must surface")
	}
}

func TestNewReconcilerDisabledWithoutSG(t *testing.T) {
	if NewReconciler(&fakeEC2{}, "") != nil || NewReconciler(nil, "sg-1") != nil {
		t.Fatal("must be nil when not configured")
	}
}
