package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMyIPFamilyAndIPv6(t *testing.T) {
	h := NewNetworkHandler(nil, nil, nil, nil)
	srv := stack(http.HandlerFunc(h.MyIP))
	cases := []struct {
		name, remote, xff, ip, family string
	}{
		{"v4", "10.0.1.5:1", "203.0.113.7", "203.0.113.7", "ipv4"},
		{"v6", "10.0.1.5:1", "2001:db8::7", "2001:db8::7", "ipv6"},
		{"v6 brackets+port", "10.0.1.5:1", "[2001:DB8::7]:5000", "2001:db8::7", "ipv6"},
		{"spoofed v4 before real v6", "10.0.1.5:1", "1.1.1.1, 2001:db8::7", "2001:db8::7", "ipv6"},
		{"mapped", "10.0.1.5:1", "::ffff:203.0.113.7", "203.0.113.7", "ipv4"},
		{"direct v6 socket", "[2001:db8::9]:4444", "", "2001:db8::9", "ipv6"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/network/my-ip", nil)
		req.RemoteAddr = c.remote
		if c.xff != "" {
			req.Header.Set("X-Forwarded-For", c.xff)
		}
		req.Header.Set("X-Real-IP", "9.9.9.9")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		var out map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != 200 || out["ip"] != c.ip || out["family"] != c.family {
			t.Errorf("%s: %d %v", c.name, rec.Code, out)
		}
	}
}

func TestAllowlistCacheIPv6Clients(t *testing.T) {
	pid := uuid.New()
	repo := &fakeNetRepo{lists: map[uuid.UUID][]string{pid: {"203.0.113.0/24", "2001:db8:1::/48"}}}
	c := NewAllowlistCache(repo, time.Minute)
	for ip, want := range map[string]bool{
		"2001:db8:1::5":      true,
		"2001:db8:1:ffff::1": true,
		"2001:db8:2::5":      false,
		"203.0.113.9":        true,
		"::ffff:203.0.113.9": true,
		"2001:db9::1":        false,
		"garbage":            false,
	} {
		got, err := c.Allowed(context.Background(), pid, ip)
		if err != nil || got != want {
			t.Errorf("Allowed(%q)=%v,%v want %v", ip, got, err, want)
		}
	}
	// an IPv4-only list denies IPv6 clients; an empty list is public for both
	repo.lists[pid] = []string{"203.0.113.0/24"}
	c.Invalidate(pid)
	if ok, _ := c.Allowed(context.Background(), pid, "2001:db8::1"); ok {
		t.Error("IPv4-only allowlist must not admit an IPv6 client")
	}
	repo.lists[pid] = nil
	c.Invalidate(pid)
	if ok, _ := c.Allowed(context.Background(), pid, "2001:db8::1"); !ok {
		t.Error("empty list is public for IPv6 too")
	}
}

func TestNormalizeAllowlistIPv6(t *testing.T) {
	got, err := normalizeAllowlist([]string{"2001:DB8:0::1", "2001:db8::1/128", "203.0.113.9", "::ffff:203.0.113.9", "2001:db8::5/48"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2001:db8::1/128", "203.0.113.9/32", "2001:db8::/48"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v want %v", got, want)
		}
	}
	for _, bad := range []string{"::/0", "0.0.0.0/0", "2001:db8::/16", "fe80::1%eth0"} {
		if _, err := normalizeAllowlist([]string{bad}); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}
