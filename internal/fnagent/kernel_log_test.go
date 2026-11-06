package fnagent

import "testing"

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
