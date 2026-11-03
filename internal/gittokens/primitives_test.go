package gittokens

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateShapeAndHash(t *testing.T) {
	plain, hash, err := Generate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !WellFormed(plain) || !strings.HasPrefix(plain, Prefix) {
		t.Fatalf("bad token shape: %q", plain)
	}
	if len(plain) != 4+64 {
		t.Fatalf("token must be cgt_ + 64 hex chars (256 bits), got len %d", len(plain))
	}
	if hash != Hash(plain) || len(hash) != 64 || strings.Contains(hash, plain) {
		t.Fatal("hash must be the hex SHA-256 of the token")
	}
	p2, _, _ := Generate(nil)
	if p2 == plain {
		t.Fatal("tokens must be random")
	}
	if DisplayPrefix(plain) != plain[:8] {
		t.Fatal("display prefix is cgt_ + 4 chars")
	}
}

func TestWellFormed(t *testing.T) {
	good, _, _ := Generate(nil)
	bad := []string{"", "cgt_", "cgt_zz" + good[6:], good[:len(good)-1], good + "0", "CGT_" + good[4:], strings.ToUpper(good)}
	if !WellFormed(good) {
		t.Fatal("good token rejected")
	}
	for _, b := range bad {
		if WellFormed(b) {
			t.Fatalf("%q must be rejected", b)
		}
	}
}

func TestConstantTimeComparisons(t *testing.T) {
	a, b := Hash("x"), Hash("y")
	if !HashEqual(a, a) || HashEqual(a, b) || HashEqual(a, a[:10]) {
		t.Fatal("HashEqual")
	}
	if !SecretEqual("s3cret", "s3cret") || SecretEqual("s3cret", "s3cre") || SecretEqual("", "x") {
		t.Fatal("SecretEqual")
	}
}

func TestIPLimiterRateAndFailures(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	l := newIPLimiter(1, 3, 2, 10*time.Second, clock)

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("1.1.1.1"); !ok {
			t.Fatalf("request %d within burst must pass", i)
		}
	}
	if ok, wait := l.Allow("1.1.1.1"); ok || wait <= 0 {
		t.Fatal("request over the burst must be limited with a wait")
	}
	if ok, _ := l.Allow("2.2.2.2"); !ok {
		t.Fatal("other IPs are independent")
	}
	now = now.Add(5 * time.Second)
	if ok, _ := l.Allow("1.1.1.1"); !ok {
		t.Fatal("tokens refill with time")
	}

	// Two failures exhaust the failure allowance: even a would-be valid request is limited.
	l.Fail("3.3.3.3")
	l.Fail("3.3.3.3")
	if ok, wait := l.Allow("3.3.3.3"); ok || wait <= 0 {
		t.Fatal("IP with exhausted failure allowance must be blocked")
	}
	now = now.Add(11 * time.Second)
	if ok, _ := l.Allow("3.3.3.3"); !ok {
		t.Fatal("failure allowance refills")
	}
}

func TestIPLimiterBoundedMemory(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := newIPLimiter(1, 1, 1, time.Second, func() time.Time { return now })
	for i := 0; i < maxLimiterEntries+50; i++ {
		l.Allow(strings.Repeat("a", 1) + time.Duration(i).String())
	}
	if len(l.m) > maxLimiterEntries {
		t.Fatalf("limiter map grew past its cap: %d", len(l.m))
	}
}

func TestConfigCapsCacheTTL(t *testing.T) {
	c := Config{CacheTTL: 10 * time.Minute}.withDefaults()
	if c.CacheTTL != 30*time.Second {
		t.Fatalf("cache ttl must be capped at 30s, got %s", c.CacheTTL)
	}
	if c.EphemeralTTL != time.Hour || c.EphemeralMax != 12*time.Hour || c.PersonalMaxDays != 90 || c.RenewBefore != 10*time.Minute {
		t.Fatalf("SPEC defaults changed: %+v", c)
	}
	c = Config{EphemeralTTL: 99 * time.Hour}.withDefaults()
	if c.EphemeralTTL != 12*time.Hour {
		t.Fatal("ephemeral ttl is capped at 12h")
	}
}
