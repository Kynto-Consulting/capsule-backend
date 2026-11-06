package fnagent

import (
	"strings"
	"testing"
)

func TestSafeTunnelLine(t *testing.T) {
	cases := map[string]string{
		"ERROR:  VPN authentication failed.": "ERROR:  VPN authentication failed.",
		"  INFO:   Connected to gateway.  ":  "INFO:   Connected to gateway.",
		"DEBUG:  password = hunter2":         "",
		"Set-Cookie: SVPNCOOKIE=abc":         "",
		"":                                   "",
	}
	for in, want := range cases {
		if got := safeTunnelLine(in); got != want {
			t.Errorf("safeTunnelLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTunnelProgram(t *testing.T) {
	if got := tunnelProgram([]string{"netns", "exec", "capsule-x", "openfortivpn", "h:1"}); got != "openfortivpn" {
		t.Errorf("got %q", got)
	}
	if got := tunnelProgram([]string{"/usr/sbin/openvpn"}); got != "openvpn" {
		t.Errorf("got %q", got)
	}
}

func TestTransportRulesLetAnswersBack(t *testing.T) {
	rs := transportRules("cvabc", "161.1.2.3")
	var back, drop, out int = -1, -1, -1
	for i, r := range rs {
		j := strings.Join(r, " ")
		switch {
		case strings.Contains(j, "-o cvabc -s 161.1.2.3/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"):
			back = i
		case strings.Contains(j, "-i cvabc -j DROP"):
			drop = i
		case strings.Contains(j, "-i cvabc -d 161.1.2.3/32 -j ACCEPT"):
			out = i
		}
		if r[0] != "-I" && !(r[0] == "-t" && r[2] == "-I") {
			t.Errorf("rule %q must be inserted (-I) so it runs before Docker's FORWARD chains", j)
		}
	}
	// -I puts each rule on top: the DROP must be inserted before (so it ends below) both ACCEPTs.
	if back < 0 || drop < 0 || out < 0 || !(drop < out && drop < back) {
		t.Fatalf("answers rule missing or DROP would shadow an ACCEPT: %v", rs)
	}
	if got := strings.Join(deleteRule(rs[1]), " "); got != "-D FORWARD -i cvabc -j DROP" {
		t.Errorf("deleteRule = %q", got)
	}
}

func TestTunnelDevice(t *testing.T) {
	out := "1: lo: <LOOPBACK,UP> mtu 65536\n4: ppp0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1354\n10: cp8cda9c7a059f@if11: <BROADCAST> mtu 1500\n"
	if got := tunnelDevice(out); got != "ppp0" {
		t.Fatalf("tunnelDevice = %q, want ppp0", got)
	}
	if got := tunnelDevice("1: lo: <LOOPBACK>\n10: cp8cda@if11: <BROADCAST>\n"); got != "" {
		t.Fatalf("no tunnel interface: got %q", got)
	}
}
