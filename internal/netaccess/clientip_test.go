package netaccess

import "testing"

func TestClientIP(t *testing.T) {
	cases := []struct {
		name, remote, xff, want string
	}{
		{"direct, no header", "198.51.100.9:5555", "", "198.51.100.9"},
		{"alb appended client", "10.0.1.5:4000", "203.0.113.7", "203.0.113.7"},
		// attacker sends X-Forwarded-For: 1.1.1.1 ; the ALB appends the real address
		{"spoofed first value ignored", "10.0.1.5:4000", "1.1.1.1, 203.0.113.7", "203.0.113.7"},
		{"many spoofed values", "10.0.1.5:4000", "9.9.9.9, 8.8.8.8, 203.0.113.7", "203.0.113.7"},
		// via the frontend container: ALB-added client, then the frontend appended the ALB private address
		{"infra hop skipped", "172.18.0.4:4000", "1.1.1.1, 203.0.113.7, 10.0.1.5", "203.0.113.7"},
		{"spoofed private entry on the left", "10.0.1.5:4000", "10.9.9.9, 203.0.113.7", "203.0.113.7"},
		{"all private falls back to right-most", "10.0.1.5:4000", "192.168.1.2, 10.0.0.9", "10.0.0.9"},
		{"garbage right-most skipped", "10.0.1.5:4000", "203.0.113.7, nonsense", "203.0.113.7"},
		{"garbage only uses remote", "198.51.100.9:1", "nonsense", "198.51.100.9"},
		{"ipv6 client", "10.0.1.5:4000", "2001:db8::7", "2001:db8::7"},
		{"mapped ipv4", "10.0.1.5:4000", "::ffff:203.0.113.7", "203.0.113.7"},
		{"remote without port", "198.51.100.9", "", "198.51.100.9"},
	}
	for _, c := range cases {
		if got := ClientIP(c.remote, c.xff); got != c.want {
			t.Errorf("%s: ClientIP(%q,%q)=%q want %q", c.name, c.remote, c.xff, got, c.want)
		}
	}
}
