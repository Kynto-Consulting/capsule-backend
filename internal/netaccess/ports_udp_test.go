package netaccess

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

func TestPortDescriptionProtoRoundTrip(t *testing.T) {
	p := uuid.New()
	long := "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
	for _, tc := range []struct{ proto, cidr string }{
		{"tcp", "10.0.0.0/8"}, {"udp", "10.0.0.0/8"}, {"udp", "2001:db8::/32"}, {"udp", long}, {"", "1.2.3.4/32"},
	} {
		d := PortDescriptionProto(p, tc.proto, 41007, tc.cidr)
		id, proto, port, cidr, ok := parseOwnedPort(d)
		want := tc.proto
		if want == "" {
			want = "tcp"
		}
		if !ok || id != p || proto != want || port != 41007 || cidr != tc.cidr {
			t.Errorf("%+v: %v %v %v %v %v", tc, id, proto, port, cidr, ok)
		}
		if len(d) > 255 || !strings.HasPrefix(d, PortDescPrefix) {
			t.Errorf("bad description %q", d)
		}
	}
	// TCP keeps the historical format byte for byte.
	if got, want := PortDescriptionProto(p, "tcp", 41000, "10.0.0.0/8"), "capsule:port:"+p.String()+":41000:10.0.0.0/8"; got != want {
		t.Errorf("tcp format changed: %q", got)
	}
	if got := PortDescriptionProto(p, "udp", 41000, "10.0.0.0/8"); !strings.HasPrefix(got, "capsule:port:udp:") {
		t.Errorf("udp description must carry the protocol: %q", got)
	}
}

func TestDiffPortsTCPAndUDPSameNumber(t *testing.T) {
	p := uuid.New()
	current := []Rule{
		// legacy TCP rule read with no protocol: implicit tcp, must be adopted untouched
		{RuleID: "sgr-tcp", Port: 41000, CIDR: "10.0.0.0/8", Description: PortDescription(p, 41000, "10.0.0.0/8")},
	}
	desired := []PortDesired{
		{ProjectID: p, HostPort: 41000, CIDR: "10.0.0.0/8"},                  // tcp (implicit)
		{ProjectID: p, Protocol: "tcp", HostPort: 41000, CIDR: "10.0.0.0/8"}, // same, explicit
		{ProjectID: p, Protocol: "udp", HostPort: 41000, CIDR: "10.0.0.0/8"}, // same number, udp
		{ProjectID: p, Protocol: "udp", HostPort: 41000, CIDR: "2001:db8::/32"},
	}
	plan := DiffPorts(desired, current, &p)
	if len(plan.Revoke) != 0 {
		t.Fatalf("legacy tcp rule must be adopted, got revoke %+v", plan.Revoke)
	}
	if len(plan.Add) != 2 || plan.Add[0].proto() != "udp" || plan.Add[1].proto() != "udp" {
		t.Fatalf("add = %+v", plan.Add)
	}
}

func TestDiffPortsUDPNeverRevokesForeign(t *testing.T) {
	p, db := uuid.New(), uuid.New()
	current := []Rule{
		{RuleID: "sgr-ssh", Protocol: "tcp", Port: 22, CIDR: "1.2.3.4/32", Description: "ssh"},
		{RuleID: "sgr-ssh6", Protocol: "tcp", Port: 22, CIDR: "2001:db8::/32", Description: "ssh v6"},
		{RuleID: "sgr-gw", Protocol: "tcp", Port: 443, CIDR: "0.0.0.0/0", Description: "capsule:gw:tcp-entry"},
		{RuleID: "sgr-gwudp", Protocol: "udp", Port: 443, CIDR: "0.0.0.0/0", Description: "capsule:gw:udp-entry"},
		{RuleID: "sgr-dns", Protocol: "udp", Port: 5353, CIDR: "0.0.0.0/0", Description: "manual udp"},
		{RuleID: "sgr-db", Protocol: "tcp", Port: 40001, CIDR: "9.9.9.0/24", Description: Description(db, "9.9.9.0/24")},
		{RuleID: "sgr-keep", Protocol: "udp", Port: 41100, CIDR: "10.0.0.0/8", Description: PortDescriptionProto(p, "udp", 41100, "10.0.0.0/8")},
		{RuleID: "sgr-stale", Protocol: "udp", Port: 41100, CIDR: "11.0.0.0/8", Description: PortDescriptionProto(p, "udp", 41100, "11.0.0.0/8")},
		// our description, wrong protocol on the wire: stale, revoked and re-added
		{RuleID: "sgr-wrongproto", Protocol: "tcp", Port: 41101, CIDR: "10.0.0.0/8", Description: PortDescriptionProto(p, "udp", 41101, "10.0.0.0/8")},
	}
	desired := []PortDesired{
		{ProjectID: p, Protocol: "udp", HostPort: 41100, CIDR: "10.0.0.0/8"},
		{ProjectID: p, Protocol: "udp", HostPort: 41101, CIDR: "10.0.0.0/8"},
	}
	for _, scope := range []*uuid.UUID{&p, nil} {
		plan := DiffPorts(desired, current, scope)
		got := map[string]bool{}
		for _, r := range plan.Revoke {
			got[r.RuleID] = true
		}
		if len(got) != 2 || !got["sgr-stale"] || !got["sgr-wrongproto"] {
			t.Fatalf("revoke = %+v", plan.Revoke)
		}
		if len(plan.Add) != 1 || plan.Add[0].HostPort != 41101 {
			t.Fatalf("add = %+v", plan.Add)
		}
	}
}

func TestDBDiffIgnoresUDPRules(t *testing.T) {
	db := uuid.New()
	current := []Rule{{RuleID: "sgr-x", Protocol: "udp", Port: 40001, CIDR: "9.9.9.0/24", Description: Description(db, "9.9.9.0/24")}}
	if plan := Diff(nil, current, &db); len(plan.Revoke) != 0 {
		t.Fatalf("a udp rule is never a database rule: %+v", plan.Revoke)
	}
}

func TestReconcileUDPIPv4AndIPv6(t *testing.T) {
	p := uuid.New()
	f := &fakeEC2{rules: []Rule{
		{RuleID: "sgr-ssh", Protocol: "tcp", Port: 22, CIDR: "0.0.0.0/0", Description: "ssh"},
		{RuleID: "sgr-old", Protocol: "udp", Port: 41050, CIDR: "5.0.0.0/8", Description: PortDescriptionProto(p, "udp", 41050, "5.0.0.0/8")},
	}}
	r := NewReconciler(f, "sg-1")
	want := []PortDesired{
		{ProjectID: p, Protocol: "udp", HostPort: 41000, CIDR: "10.0.0.0/8"},
		{ProjectID: p, Protocol: "udp", HostPort: 41000, CIDR: "2001:db8::/32"},
		{ProjectID: p, HostPort: 41000, CIDR: "10.0.0.0/8"},
	}
	if err := r.ReconcileProjectPorts(context.Background(), p, want); err != nil {
		t.Fatal(err)
	}
	if len(f.revoked) != 1 || f.revoked[0] != "sgr-old" {
		t.Fatalf("revoked = %v", f.revoked)
	}
	if len(f.authorize) != 3 {
		t.Fatalf("authorize = %v", f.authorize)
	}
	udp, tcp := 0, 0
	for _, rr := range f.rules {
		switch rr.Protocol {
		case "udp":
			udp++
		case "tcp":
			if rr.RuleID != "sgr-ssh" {
				tcp++
			}
		}
	}
	if udp != 2 || tcp != 1 {
		t.Fatalf("udp=%d tcp=%d rules=%+v", udp, tcp, f.rules)
	}
	// idempotent: a second pass changes nothing
	before := len(f.authorize)
	if err := r.ReconcileProjectPorts(context.Background(), p, want); err != nil || len(f.authorize) != before || len(f.revoked) != 1 {
		t.Fatalf("not idempotent: %v %v %v", err, f.authorize, f.revoked)
	}
	// removing everything keeps ssh
	if err := r.ReconcileProjectPorts(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 1 || f.rules[0].RuleID != "sgr-ssh" {
		t.Fatalf("rules = %+v", f.rules)
	}
}

func TestReconcileRejectsBadProtocolAndRange(t *testing.T) {
	p := uuid.New()
	for _, d := range []PortDesired{
		{ProjectID: p, Protocol: "sctp", HostPort: 41000, CIDR: "10.0.0.0/8"},
		{ProjectID: p, Protocol: "udp", HostPort: 22, CIDR: "10.0.0.0/8"},
		{ProjectID: p, Protocol: "udp", HostPort: 70000, CIDR: "10.0.0.0/8"},
	} {
		f := &fakeEC2{rules: []Rule{{RuleID: "sgr-old", Port: 41003, CIDR: "5.0.0.0/8", Description: PortDescription(p, 41003, "5.0.0.0/8")}}}
		err := NewReconciler(f, "sg-1").ReconcileProjectPorts(context.Background(), p, []PortDesired{d})
		if err == nil || len(f.authorize) != 0 || len(f.revoked) != 0 {
			t.Errorf("%+v: err=%v auth=%v revoked=%v (nothing may change)", d, err, f.authorize, f.revoked)
		}
	}
}

func TestReconcileUDPLimitExceeded(t *testing.T) {
	p := uuid.New()
	f := &fakeEC2{authErr: &smithy.GenericAPIError{Code: "RulesPerSecurityGroupLimitExceeded", Message: "limit"}}
	err := NewReconciler(f, "sg-1").ReconcileProjectPorts(context.Background(), p, []PortDesired{{ProjectID: p, Protocol: "udp", HostPort: 41000, CIDR: "10.0.0.0/8"}})
	if err == nil || !strings.Contains(err.Error(), ErrRuleLimit.Error()) {
		t.Fatalf("want ErrRuleLimit, got %v", err)
	}
}

func TestAWSAdapterUDP(t *testing.T) {
	c := &recEC2{describe: []ec2types.SecurityGroupRule{
		{SecurityGroupRuleId: aws.String("t"), IpProtocol: aws.String("tcp"), FromPort: aws.Int32(41000), ToPort: aws.Int32(41000), CidrIpv4: aws.String("10.0.0.0/8"), Description: aws.String("x")},
		{SecurityGroupRuleId: aws.String("u"), IpProtocol: aws.String("udp"), FromPort: aws.Int32(41000), ToPort: aws.Int32(41000), CidrIpv4: aws.String("10.0.0.0/8")},
		{SecurityGroupRuleId: aws.String("u6"), IpProtocol: aws.String("udp"), FromPort: aws.Int32(41000), ToPort: aws.Int32(41000), CidrIpv6: aws.String("2001:db8::/32")},
		{SecurityGroupRuleId: aws.String("urange"), IpProtocol: aws.String("udp"), FromPort: aws.Int32(41000), ToPort: aws.Int32(41010), CidrIpv4: aws.String("10.0.0.0/8")},
		{SecurityGroupRuleId: aws.String("icmp"), IpProtocol: aws.String("icmp"), FromPort: aws.Int32(-1), ToPort: aws.Int32(-1), CidrIpv4: aws.String("0.0.0.0/0")},
		{SecurityGroupRuleId: aws.String("all"), IpProtocol: aws.String("-1"), CidrIpv4: aws.String("0.0.0.0/0")},
	}}
	a := AWSAdapter{Client: c}
	got, err := a.ListIngressRules(context.Background(), "sg-1")
	if err != nil || len(got) != 3 {
		t.Fatalf("%v %+v", err, got)
	}
	if got[0].RuleProtocol() != "tcp" || got[1].RuleProtocol() != "udp" || got[2].RuleProtocol() != "udp" || got[2].CIDR != "2001:db8::/32" {
		t.Fatalf("protocols: %+v", got)
	}
	ctx := context.Background()
	if err := a.AuthorizeIngressProto(ctx, "sg-1", "udp", 41000, "10.0.0.0/8", "capsule:port:udp:x"); err != nil {
		t.Fatal(err)
	}
	if err := a.AuthorizeIngressProto(ctx, "sg-1", "UDP", 41000, "2001:db8::/32", "d"); err != nil {
		t.Fatal(err)
	}
	if err := a.AuthorizeIngress(ctx, "sg-1", 41000, "10.0.0.0/8", "d"); err != nil {
		t.Fatal(err)
	}
	proto := func(i int) string { return aws.ToString(c.auth[i].IpPermissions[0].IpProtocol) }
	if proto(0) != "udp" || proto(1) != "udp" || proto(2) != "tcp" {
		t.Errorf("protocols sent: %s %s %s", proto(0), proto(1), proto(2))
	}
	if len(c.auth[1].IpPermissions[0].Ipv6Ranges) != 1 {
		t.Errorf("udp ipv6 must use Ipv6Ranges")
	}
	if err := a.AuthorizeIngressProto(ctx, "sg-1", "icmp", 1, "10.0.0.0/8", "d"); err == nil {
		t.Error("icmp must be refused")
	}
}
