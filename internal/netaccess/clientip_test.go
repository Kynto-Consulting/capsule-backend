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

func TestClientIPv6(t *testing.T) {
	cases := []struct {
		name, remote, xff, want string
	}{
		{"alb appends v6 client", "10.0.1.5:4000", "2001:db8::7", "2001:db8::7"},
		{"canonicalised", "10.0.1.5:4000", "2001:DB8:0:0:0:0:0:7", "2001:db8::7"},
		{"brackets", "10.0.1.5:4000", "[2001:db8::7]", "2001:db8::7"},
		{"brackets and port", "10.0.1.5:4000", "[2001:db8::7]:51234", "2001:db8::7"},
		{"v4 with port", "10.0.1.5:4000", "203.0.113.7:51234", "203.0.113.7"},
		{"spoofed v6 on the left", "10.0.1.5:4000", "2001:db8::bad, 2001:db8::7", "2001:db8::7"},
		{"spoofed v4 then real v6", "10.0.1.5:4000", "1.1.1.1, 2001:db8::7", "2001:db8::7"},
		{"spoofed v6 then real v4", "10.0.1.5:4000", "2001:db8::bad, 203.0.113.7", "203.0.113.7"},
		{"alb hop is ULA", "[fd00::5]:4000", "2001:db8::bad, 2001:db8::7, fd12:3456::5", "2001:db8::7"},
		{"link-local hop skipped", "10.0.1.5:4000", "2001:db8::7, fe80::1", "2001:db8::7"},
		{"link-local with zone skipped", "10.0.1.5:4000", "2001:db8::7, fe80::1%eth0", "2001:db8::7"},
		{"loopback skipped", "10.0.1.5:4000", "2001:db8::7, ::1", "2001:db8::7"},
		{"unspecified skipped", "10.0.1.5:4000", "2001:db8::7, ::", "2001:db8::7"},
		{"multicast skipped", "10.0.1.5:4000", "2001:db8::7, ff02::1", "2001:db8::7"},
		{"mapped private skipped", "10.0.1.5:4000", "2001:db8::7, ::ffff:10.0.0.9", "2001:db8::7"},
		{"all infra falls back to right-most", "10.0.1.5:4000", "fc00::1, fd00::9", "fd00::9"},
		{"remote v6 with port", "[2001:db8::9]:5555", "", "2001:db8::9"},
		{"remote bare v6", "2001:db8::9", "", "2001:db8::9"},
		{"remote v6 bracket no port", "[2001:db8::9]", "", "2001:db8::9"},
		{"garbage uses v6 remote", "[2001:db8::9]:1", "nonsense, [bad", "2001:db8::9"},
	}
	for _, c := range cases {
		if got := ClientIP(c.remote, c.xff); got != c.want {
			t.Errorf("%s: ClientIP(%q,%q)=%q want %q", c.name, c.remote, c.xff, got, c.want)
		}
	}
}

// Caddy (no ALB) appends the address of the connecting peer to X-Forwarded-For (reverse_proxy default
// without trusted_proxies): the real client is the LAST element, anything to the left is client-controlled.
func TestClientIPBehindCaddy(t *testing.T) {
	cases := []struct {
		name, remote, xff, want string
	}{
		{"direct client", "172.18.0.2:4444", "198.51.100.7", "198.51.100.7"},
		{"forged left elements", "172.18.0.2:4444", "1.2.3.4, 8.8.8.8, 198.51.100.7", "198.51.100.7"},
		{"forged private left", "172.18.0.2:4444", "127.0.0.1, 10.0.0.9, 198.51.100.7", "198.51.100.7"},
		{"ipv6 client", "172.18.0.2:4444", "9.9.9.9, 2001:db8::77", "2001:db8::77"},
		{"ipv6 bracketed with port", "172.18.0.2:4444", "9.9.9.9, [2001:db8::77]:5555", "2001:db8::77"},
		{"extra private hop after client", "172.18.0.2:4444", "1.2.3.4, 198.51.100.7, 172.18.0.3", "198.51.100.7"},
		{"garbage entries skipped", "172.18.0.2:4444", "unknown, 198.51.100.7, ", "198.51.100.7"},
		{"no header: socket peer", "172.18.0.2:4444", "", "172.18.0.2"},
		{"internal call, private only", "172.18.0.2:4444", "172.18.0.9", "172.18.0.9"},
	}
	for _, c := range cases {
		if got := ClientIP(c.remote, c.xff); got != c.want {
			t.Errorf("%s: ClientIP(%q, %q) = %q, want %q", c.name, c.remote, c.xff, got, c.want)
		}
	}
	for xff, want := range map[string]bool{"": false, "172.18.0.9": false, "127.0.0.1, 10.1.1.1": false, "1.2.3.4, 10.1.1.1": true, "garbage": false, "[2001:db8::1]:443": true, "fe80::1, fd00::2": false} {
		if got := HasPublicForwarded(xff); got != want {
			t.Errorf("HasPublicForwarded(%q) = %v, want %v", xff, got, want)
		}
	}
}

// Caddy -> backend chain (no ALB): Caddy appends the peer address it saw as the LAST element; anything to
// the left was sent by the client and may be forged.
func TestClientIPCaddyChain(t *testing.T) {
	cases := []struct{ name, remote, xff, want string }{
		{"single", "172.18.0.2:40000", "198.51.100.7", "198.51.100.7"},
		{"forged left", "172.18.0.2:40000", "1.2.3.4, 10.0.0.1, 198.51.100.7", "198.51.100.7"},
		{"forged public left only trusted last", "172.18.0.2:40000", "8.8.8.8, 198.51.100.7", "198.51.100.7"},
		{"ipv6 client", "172.18.0.2:40000", "9.9.9.9, 2001:db8::5", "2001:db8::5"},
		{"no xff", "172.18.0.2:40000", "", "172.18.0.2"},
	}
	for _, c := range cases {
		if got := ClientIP(c.remote, c.xff); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestHasPublicForwarded(t *testing.T) {
	for xff, want := range map[string]bool{
		"": false, "10.0.0.1": false, "172.18.0.2, fd00::1": false, "198.51.100.7": true,
		"10.0.0.1, 2001:db8::5": true, "garbage": false, "[2001:db8::1]:443": true,
	} {
		if got := HasPublicForwarded(xff); got != want {
			t.Errorf("%q: %v want %v", xff, got, want)
		}
	}
}
