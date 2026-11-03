package netaccess

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type sharedCases struct {
	Normalize []struct {
		In     string `json:"in"`
		Public bool   `json:"public"`
		Want   string `json:"want"`
	} `json:"normalize"`
	Contains []struct {
		List []string `json:"list"`
		IP   string   `json:"ip"`
		Want bool     `json:"want"`
	} `json:"contains"`
}

// The same table is run by the CLI (Go) and the dashboard (vitest), so the
// three implementations cannot diverge silently. The canonical copy lives in
// <repo>/testdata; each module keeps an identical copy so it can be tested alone.
func loadShared(t *testing.T) sharedCases {
	t.Helper()
	b, err := os.ReadFile("testdata/cidr_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	if canon, err := os.ReadFile("../../../testdata/cidr_cases.json"); err == nil && !bytes.Equal(canon, b) {
		t.Error("testdata/cidr_cases.json differs from the canonical <repo>/testdata/cidr_cases.json; copy it over")
	}
	var c sharedCases
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNormalizeCIDRShared(t *testing.T) {
	for _, c := range loadShared(t).Normalize {
		got, err := NormalizeCIDR(c.In, c.Public)
		if (err != nil) != (c.Want == "") {
			t.Errorf("NormalizeCIDR(%q,%v) = %q, err=%v; want %q", c.In, c.Public, got, err, c.Want)
			continue
		}
		if got != c.Want {
			t.Errorf("NormalizeCIDR(%q,%v)=%q want %q", c.In, c.Public, got, c.Want)
		}
	}
}

func TestContainsIPShared(t *testing.T) {
	for _, c := range loadShared(t).Contains {
		if got := ContainsIP(c.List, c.IP); got != c.Want {
			t.Errorf("ContainsIP(%v,%q)=%v want %v", c.List, c.IP, got, c.Want)
		}
	}
}

func TestNormalizeCIDRIdempotentAndPublicKind(t *testing.T) {
	for _, c := range loadShared(t).Normalize {
		if c.Want == "" {
			continue
		}
		again, err := NormalizeCIDR(c.Want, c.Public)
		if err != nil || again != c.Want {
			t.Errorf("canonical %q is not stable: %q %v", c.Want, again, err)
		}
		if IsPublicCIDR(c.Want) != (c.Want == "0.0.0.0/0" || c.Want == "::/0") {
			t.Errorf("IsPublicCIDR(%q)", c.Want)
		}
		if len(c.Want) > 43 {
			t.Errorf("%q exceeds the varchar(43) column", c.Want)
		}
	}
}

func TestIsIPv6CIDRAndSameCIDR(t *testing.T) {
	for in, want := range map[string]bool{"2001:db8::/32": true, "::/0": true, "10.0.0.0/8": false, "::ffff:1.2.3.0/120": false, "x": false} {
		if got := IsIPv6CIDR(in); got != want {
			t.Errorf("IsIPv6CIDR(%q)=%v", in, got)
		}
	}
	if !SameCIDR("2001:DB8::/32", "2001:db8::/32") || SameCIDR("2001:db8::/32", "2001:db8::/33") || SameCIDR("x", "y") {
		t.Error("SameCIDR")
	}
	if !SameCIDR("x", "x") {
		t.Error("identical strings are the same")
	}
}
