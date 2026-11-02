package netaccess

import "testing"

func TestNormalizeCIDR(t *testing.T) {
	cases := []struct {
		in          string
		allowPublic bool
		want        string
		wantErr     bool
	}{
		{"203.0.113.7/32", false, "203.0.113.7/32", false},
		{"203.0.113.7", false, "203.0.113.7/32", false},
		{" 203.0.113.0/24 ", false, "203.0.113.0/24", false},
		{"203.0.113.9/24", false, "203.0.113.0/24", false}, // host bits cleared
		{"10.0.0.0/8", false, "10.0.0.0/8", false},         // private ranges are valid
		{"192.168.1.10/32", false, "192.168.1.10/32", false},
		{"10.0.0.0/7", false, "", true}, // prefix shorter than /8
		{"128.0.0.0/1", true, "", true}, // still rejected even with allow_public
		{"0.0.0.0/0", false, "", true},  // public needs opt-in
		{"0.0.0.0/0", true, "0.0.0.0/0", false},
		{"1.2.3.4/0", true, "0.0.0.0/0", false}, // any /0 canonicalises to the public CIDR
		{"::/0", true, "", true},                // IPv6 unsupported
		{"2001:db8::1", false, "", true},
		{"300.1.1.1/32", false, "", true},
		{"1.2.3.4/33", false, "", true},
		{"", false, "", true},
		{"banana", false, "", true},
	}
	for _, c := range cases {
		got, err := NormalizeCIDR(c.in, c.allowPublic)
		if (err != nil) != c.wantErr {
			t.Errorf("NormalizeCIDR(%q,%v) err=%v wantErr=%v", c.in, c.allowPublic, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeCIDR(%q,%v)=%q want %q", c.in, c.allowPublic, got, c.want)
		}
	}
}

func TestContainsIP(t *testing.T) {
	list := []string{"203.0.113.0/24", "198.51.100.5/32", "garbage"}
	for ip, want := range map[string]bool{
		"203.0.113.77":       true,
		"198.51.100.5":       true,
		"198.51.100.6":       false,
		"8.8.8.8":            false,
		"::ffff:203.0.113.1": true, // IPv4-mapped
		"2001:db8::1":        false,
		"not-an-ip":          false,
	} {
		if got := ContainsIP(list, ip); got != want {
			t.Errorf("ContainsIP(%q)=%v want %v", ip, got, want)
		}
	}
	if ContainsIP(nil, "1.2.3.4") {
		t.Error("empty list must not match (callers treat empty as public)")
	}
}
