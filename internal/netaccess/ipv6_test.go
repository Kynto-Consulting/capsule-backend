package netaccess

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/uuid"
)

var foreign6 = []Rule{
	{RuleID: "sgr-ssh6", Port: 22, CIDR: "::/0", Description: "SSH from anywhere v6"},
	{RuleID: "sgr-web6", Port: 443, CIDR: "::/0", Description: ""},
	{RuleID: "sgr-look6", Port: 40011, CIDR: "2001:db8::1/128", Description: "capsule-db:manual"},
}

func TestDescriptionIPv6RoundTripAndLength(t *testing.T) {
	db, p := uuid.New(), uuid.New()
	long := "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
	for _, c := range []string{"2001:db8::/32", "::/0", long} {
		id, cidr, ok := parseOwned(Description(db, c))
		if !ok || id != db || cidr != c {
			t.Errorf("db round trip %q: %v %v %v", c, id, cidr, ok)
		}
		pid, port, cidr, ok := parseOwnedPort(PortDescription(p, 41005, c))
		if !ok || pid != p || port != 41005 || cidr != c {
			t.Errorf("port round trip %q: %v %v %v %v", c, pid, port, cidr, ok)
		}
	}
	// EC2: <=255 chars, charset a-zA-Z0-9 space ._-:/()#,@[]+=&;{}!$* (':' allowed)
	d := PortDescription(p, 65535, long)
	if len(d) > 255 {
		t.Fatalf("description too long: %d", len(d))
	}
	for _, r := range d {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-:/()#,@[]+=&;{}!$*", r) {
			t.Fatalf("character %q not allowed in an SG rule description", r)
		}
	}
}

func TestReconcileBothFamiliesDiffAndForeign(t *testing.T) {
	db, other := uuid.New(), uuid.New()
	f := &fakeEC2{rules: append([]Rule(nil), foreign...)}
	f.rules = append(f.rules, foreign6...)
	f.rules = append(f.rules, Rule{RuleID: "sgr-other6", Port: 40200, CIDR: "2001:db8:9::/48", Description: Description(other, "2001:db8:9::/48")})
	r := NewReconciler(f, "sg-1")
	ctx := context.Background()

	want := []string{"203.0.113.5/32", "2001:db8:1::/48", "2001:db8:2::1/128"}
	if err := r.ReconcileDB(ctx, db, 40123, want); err != nil {
		t.Fatal(err)
	}
	if got := ownedCIDRs(f, db); strings.Join(got, ",") != "2001:db8:1::/48,2001:db8:2::1/128,203.0.113.5/32" {
		t.Fatalf("owned: %v", got)
	}
	n := len(f.authorize)
	if err := r.ReconcileDB(ctx, db, 40123, want); err != nil || len(f.authorize) != n || len(f.revoked) != 0 {
		t.Fatalf("not idempotent: %v %d %v", err, len(f.authorize), f.revoked)
	}
	if err := r.ReconcileDB(ctx, db, 40123, []string{"2001:db8:1::/48"}); err != nil {
		t.Fatal(err)
	}
	if len(f.revoked) != 2 {
		t.Fatalf("revoked: %v", f.revoked)
	}
	if err := r.ReconcileDB(ctx, db, 40124, []string{"2001:db8:1::/48"}); err != nil {
		t.Fatal(err)
	}
	left := map[string]bool{}
	for _, rr := range f.rules {
		left[rr.RuleID] = true
	}
	for _, id := range []string{"sgr-ssh", "sgr-ssh6", "sgr-web6", "sgr-look6", "sgr-other6", "sgr-tf", "sgr-nodesc", "sgr-lookalike"} {
		if !left[id] {
			t.Errorf("foreign rule %s was revoked", id)
		}
	}
	if err := r.ReconcileDB(ctx, db, 40124, nil); err != nil {
		t.Fatal(err)
	}
	if got := ownedCIDRs(f, db); len(got) != 0 {
		t.Fatalf("leftovers: %v", got)
	}
}

func TestSyncAllOrphansV6AndCIDRSpellingDrift(t *testing.T) {
	db, gone := uuid.New(), uuid.New()
	f := &fakeEC2{rules: []Rule{
		{RuleID: "sgr-keep", Port: 40001, CIDR: "2001:DB8::/32", Description: Description(db, "2001:db8::/32")},
		{RuleID: "sgr-orphan", Port: 40002, CIDR: "2001:db8:5::/48", Description: Description(gone, "2001:db8:5::/48")},
		{RuleID: "sgr-wrongcidr", Port: 40001, CIDR: "2001:db8:7::/48", Description: Description(db, "2001:db8::/32")},
		{RuleID: "sgr-foreign", Port: 40001, CIDR: "::/0", Description: "manual"},
	}}
	r := NewReconciler(f, "sg-1")
	if err := r.SyncAll(context.Background(), []Desired{{DBID: db, Port: 40001, CIDR: "2001:db8::/32"}}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.revoked, ",") != "sgr-orphan,sgr-wrongcidr" || len(f.authorize) != 0 {
		t.Fatalf("revoked=%v authorize=%v", f.revoked, f.authorize)
	}
}

func TestReconcilePortsBothFamilies(t *testing.T) {
	p, q := uuid.New(), uuid.New()
	f := &fakeEC2{rules: append(append([]Rule(nil), foreign...), foreign6...)}
	f.rules = append(f.rules, Rule{RuleID: "sgr-q", Port: 41100, CIDR: "2001:db8::/32", Description: PortDescription(q, 41100, "2001:db8::/32")})
	r := NewReconciler(f, "sg-1")
	ctx := context.Background()
	want := []PortDesired{{p, 41005, "198.51.100.0/24"}, {p, 41005, "2001:db8:a::/48"}}
	if err := r.ReconcileProjectPorts(ctx, p, want); err != nil {
		t.Fatal(err)
	}
	if err := r.ReconcileProjectPorts(ctx, p, want); err != nil || len(f.revoked) != 0 {
		t.Fatalf("idempotency: %v %v", err, f.revoked)
	}
	if err := r.ReconcileProjectPorts(ctx, p, want[:1]); err != nil || len(f.revoked) != 1 {
		t.Fatalf("v6 drop: %v %v", err, f.revoked)
	}
	if err := r.SyncAllPorts(ctx, nil); err != nil {
		t.Fatal(err)
	}
	left := map[string]bool{}
	for _, rr := range f.rules {
		left[rr.RuleID] = true
	}
	if left["sgr-q"] {
		t.Error("orphan v6 port rule of a deleted project must be revoked")
	}
	for _, id := range []string{"sgr-ssh6", "sgr-web6", "sgr-look6", "sgr-ssh"} {
		if !left[id] {
			t.Errorf("foreign %s revoked", id)
		}
	}
}

type recEC2 struct {
	describe []ec2types.SecurityGroupRule
	auth     []*ec2.AuthorizeSecurityGroupIngressInput
}

func (c *recEC2) DescribeSecurityGroupRules(context.Context, *ec2.DescribeSecurityGroupRulesInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupRulesOutput, error) {
	return &ec2.DescribeSecurityGroupRulesOutput{SecurityGroupRules: c.describe}, nil
}
func (c *recEC2) AuthorizeSecurityGroupIngress(_ context.Context, in *ec2.AuthorizeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error) {
	c.auth = append(c.auth, in)
	return &ec2.AuthorizeSecurityGroupIngressOutput{}, nil
}
func (c *recEC2) RevokeSecurityGroupIngress(context.Context, *ec2.RevokeSecurityGroupIngressInput, ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
	return &ec2.RevokeSecurityGroupIngressOutput{}, nil
}

func TestAWSAdapterSendsRangesPerFamily(t *testing.T) {
	c := &recEC2{}
	a := AWSAdapter{Client: c}
	ctx := context.Background()
	if err := a.AuthorizeIngress(ctx, "sg-1", 5432, "203.0.113.0/24", "capsule:db:x"); err != nil {
		t.Fatal(err)
	}
	if err := a.AuthorizeIngress(ctx, "sg-1", 5432, "2001:db8::/32", "capsule:db:y"); err != nil {
		t.Fatal(err)
	}
	v4, v6 := c.auth[0].IpPermissions[0], c.auth[1].IpPermissions[0]
	if len(v4.IpRanges) != 1 || len(v4.Ipv6Ranges) != 0 || aws.ToString(v4.IpRanges[0].CidrIp) != "203.0.113.0/24" {
		t.Errorf("v4 permission: %+v", v4)
	}
	if len(v6.Ipv6Ranges) != 1 || len(v6.IpRanges) != 0 || aws.ToString(v6.Ipv6Ranges[0].CidrIpv6) != "2001:db8::/32" || aws.ToString(v6.Ipv6Ranges[0].Description) != "capsule:db:y" {
		t.Errorf("v6 permission: %+v", v6)
	}
}

func TestAWSAdapterListsBothFamilies(t *testing.T) {
	tcp := aws.String("tcp")
	c := &recEC2{describe: []ec2types.SecurityGroupRule{
		{SecurityGroupRuleId: aws.String("a"), IpProtocol: tcp, FromPort: aws.Int32(80), ToPort: aws.Int32(80), CidrIpv4: aws.String("0.0.0.0/0")},
		{SecurityGroupRuleId: aws.String("b"), IpProtocol: tcp, FromPort: aws.Int32(80), ToPort: aws.Int32(80), CidrIpv6: aws.String("::/0"), Description: aws.String("web")},
		{SecurityGroupRuleId: aws.String("c"), IpProtocol: tcp, FromPort: aws.Int32(80), ToPort: aws.Int32(80)},
		{SecurityGroupRuleId: aws.String("d"), IsEgress: aws.Bool(true), IpProtocol: tcp, FromPort: aws.Int32(80), ToPort: aws.Int32(80), CidrIpv6: aws.String("::/0")},
		{SecurityGroupRuleId: aws.String("e"), IpProtocol: tcp, FromPort: aws.Int32(1000), ToPort: aws.Int32(2000), CidrIpv6: aws.String("::/0")},
	}}
	got, err := AWSAdapter{Client: c}.ListIngressRules(context.Background(), "sg-1")
	if err != nil || len(got) != 2 || got[0].CIDR != "0.0.0.0/0" || got[1].CIDR != "::/0" || got[1].Description != "web" || got[1].Port != 80 {
		t.Fatalf("%v %+v", err, got)
	}
}
