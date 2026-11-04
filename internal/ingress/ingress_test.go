package ingress

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

type fakeResolver struct {
	cname map[string]string
	ips   map[string][]string
}

func (f fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if c, ok := f.cname[host]; ok {
		return c + ".", nil
	}
	return host + ".", nil // no CNAME: the canonical name is the host itself
}

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	v, ok := f.ips[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []net.IPAddr
	for _, s := range v {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

type brokenResolver struct{ fakeResolver }

func (brokenResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, errors.New("servfail")
}

func TestResolveMode(t *testing.T) {
	cases := []struct {
		explicit, arn string
		want          Mode
	}{
		{"", "", ModeCaddy},
		{"", "arn:aws:elasticloadbalancing:x", ModeALB},
		{"caddy", "arn:aws:elasticloadbalancing:x", ModeCaddy},
		{"CADDY", "", ModeCaddy},
		{"alb", "", ModeALB},
		{"otra-cosa", "", ModeCaddy},
		{"otra-cosa", "arn", ModeALB},
	}
	for _, c := range cases {
		if got := Resolve(c.explicit, c.arn, "", "", "").Mode; got != c.want {
			t.Errorf("Resolve(%q, %q) = %s, want %s", c.explicit, c.arn, got, c.want)
		}
	}
}

func TestRecords(t *testing.T) {
	c := Resolve("caddy", "", "Ingress.Apps.Example.com.", "203.0.113.9", "2001:db8::9")
	if r := c.Records("a.b.com"); len(r) != 1 || r[0] != (Record{"CNAME", "a.b.com", "ingress.apps.example.com"}) {
		t.Errorf("with host: %+v", r)
	}
	c.Host = ""
	r := c.Records("a.b.com")
	if len(r) != 2 || r[0].Type != "A" || r[1].Type != "AAAA" {
		t.Errorf("A/AAAA: %+v", r)
	}
	c.IPv4, c.IPv6 = "", ""
	if len(c.Records("a.b.com")) != 0 || !strings.Contains(c.Instructions("a.b.com"), "contacta al administrador") {
		t.Error("nothing configured must say so")
	}
}

func TestNormalizeDomain(t *testing.T) {
	ok := map[string]string{"Mi-Sitio.COM": "mi-sitio.com", " app.cliente.pe. ": "app.cliente.pe", "a1.b2.example.org": "a1.b2.example.org"}
	for in, want := range ok {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("%q => %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "localhost", "*.example.com", "ex ample.com", "example.com:443", "http://example.com", "10.0.0.1", "::1",
		"-a.example.com", "a-.example.com", "a..example.com", "exa_mple.com", strings.Repeat("a", 64) + ".com", "ñandú.pe"} {
		if got, err := NormalizeDomain(bad); err == nil {
			t.Errorf("%q should be rejected, got %q", bad, got)
		}
	}
}

func TestReserved(t *testing.T) {
	c := Config{Host: "ingress.apps.example.com", AppsDomain: "apps.example.com", OwnHosts: []string{"app.example.com", "api.example.com"}}
	for h, want := range map[string]bool{
		"app.example.com": true, "API.example.com.": true, "apps.example.com": true, "x.apps.example.com": true,
		"ingress.apps.example.com": true, "cliente.com": false, "example.com": false, "notapps.example.com": false,
	} {
		if got := c.Reserved(h); got != want {
			t.Errorf("Reserved(%q) = %v, want %v", h, got, want)
		}
	}
}

func cfgHost() Config {
	return Config{Mode: ModeCaddy, Host: "ingress.apps.example.com", IPv4: "203.0.113.9", IPv6: "2001:db8::9"}
}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	res := fakeResolver{
		cname: map[string]string{"www.ok.com": "ingress.apps.example.com"},
		ips: map[string][]string{
			"ingress.apps.example.com": {"203.0.113.9", "2001:db8::9"},
			"www.ok.com":               {"203.0.113.9"},
			"apex.ok.com":              {"203.0.113.9", "2001:db8::9"},
			"v4only.ok.com":            {"203.0.113.9"},
			"mapped.ok.com":            {"::ffff:203.0.113.9"},
			"otro.com":                 {"198.51.100.7"},
			"mixto.com":                {"203.0.113.9", "198.51.100.7"},
		},
	}
	cases := []struct {
		host, want string
		msg        string
	}{
		{"www.ok.com", StatusActive, ""},
		{"apex.ok.com", StatusActive, ""},
		{"v4only.ok.com", StatusActive, ""},
		{"mapped.ok.com", StatusActive, ""},
		{"otro.com", StatusFailed, "198.51.100.7"},
		{"mixto.com", StatusFailed, "198.51.100.7"},
		{"nuevo.com", StatusPendingDNS, "todavía no resuelve"},
	}
	for _, c := range cases {
		r := Verify(ctx, res, cfgHost(), c.host)
		if r.Status != c.want || !strings.Contains(r.Message, c.msg) || r.Message == "" {
			t.Errorf("%s: %+v, want %s containing %q", c.host, r, c.want, c.msg)
		}
	}
	// IP-only configuration (no ingress host): the A/AAAA records are compared directly.
	ipOnly := Config{Mode: ModeCaddy, IPv4: "203.0.113.9"}
	if r := Verify(ctx, res, ipOnly, "v4only.ok.com"); r.Status != StatusActive {
		t.Errorf("ip-only active: %+v", r)
	}
	if r := Verify(ctx, res, ipOnly, "otro.com"); r.Status != StatusFailed {
		t.Errorf("ip-only failed: %+v", r)
	}
	// Nothing configured, or resolver errors: never "active".
	if r := Verify(ctx, res, Config{Mode: ModeCaddy}, "www.ok.com"); r.Status != StatusFailed {
		t.Errorf("unconfigured: %+v", r)
	}
	if r := Verify(ctx, brokenResolver{res}, cfgHost(), "otro.com"); r.Status != StatusPendingDNS {
		t.Errorf("resolver error: %+v", r)
	}
}
