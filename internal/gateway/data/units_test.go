package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- relay ----------

func tcpPair(t testing.TB) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c, <-ch
}

func TestRelayHalfCloseBothWays(t *testing.T) {
	// cA <-> [gwA relay gwB] <-> cB
	cA, gwA := tcpPair(t)
	gwB, cB := tcpPair(t)
	done := make(chan RelayResult, 1)
	go func() { done <- Relay(gwA, gwB, RelayOptions{Idle: 5 * time.Second, HalfIdle: 5 * time.Second}) }()

	io.WriteString(cA, "request")
	cA.(*net.TCPConn).CloseWrite() // A finished writing
	buf, _ := io.ReadAll(io.LimitReader(cB, 7))
	if string(buf) != "request" {
		t.Fatalf("B got %q", buf)
	}
	rest, _ := io.ReadAll(cB) // B must see EOF (the FIN was relayed)
	if len(rest) != 0 {
		t.Fatalf("unexpected %q", rest)
	}
	io.WriteString(cB, "late-reply") // opposite direction still open
	cB.Close()
	got, _ := io.ReadAll(cA)
	if string(got) != "late-reply" {
		t.Fatalf("A got %q after its own half-close", got)
	}
	select {
	case r := <-done:
		if r.AToB != 7 || r.BToA != 10 || r.Reason != CloseNormal {
			t.Fatalf("%+v", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not end")
	}
}

func TestRelayResetAbortsBoth(t *testing.T) {
	cA, gwA := tcpPair(t)
	gwB, cB := tcpPair(t)
	done := make(chan RelayResult, 1)
	go func() { done <- Relay(gwA, gwB, RelayOptions{Idle: 5 * time.Second}) }()
	cA.(*net.TCPConn).SetLinger(0)
	cA.Close() // RST
	cB.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := cB.Read(make([]byte, 1)); err == nil {
		t.Fatal("B must see the connection end")
	}
	r := <-done
	if r.Reason == CloseNormal {
		t.Fatalf("reason %q after a reset", r.Reason)
	}
}

func TestRelayIdleTimeoutAndActivityInEitherDirection(t *testing.T) {
	cA, gwA := tcpPair(t)
	gwB, cB := tcpPair(t)
	done := make(chan RelayResult, 1)
	go func() { done <- Relay(gwA, gwB, RelayOptions{Idle: 400 * time.Millisecond}) }()
	// traffic only B->A keeps the whole connection alive
	for i := 0; i < 6; i++ {
		time.Sleep(150 * time.Millisecond)
		if _, err := io.WriteString(cB, "x"); err != nil {
			t.Fatalf("connection died while active: %v", err)
		}
		cA.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := cA.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-done:
		t.Fatal("closed while active")
	default:
	}
	start := time.Now()
	r := <-done // now silent: closed by idle
	if r.Reason != CloseIdle {
		t.Fatalf("reason %q", r.Reason)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("idle close took %v", el)
	}
	cA.Close()
	cB.Close()
}

func TestRelayHalfCloseIdleShorter(t *testing.T) {
	cA, gwA := tcpPair(t)
	gwB, cB := tcpPair(t)
	done := make(chan RelayResult, 1)
	go func() { done <- Relay(gwA, gwB, RelayOptions{Idle: time.Hour, HalfIdle: 300 * time.Millisecond}) }()
	cA.(*net.TCPConn).CloseWrite()
	start := time.Now()
	select {
	case r := <-done:
		if r.Reason != CloseIdle || time.Since(start) > 2*time.Second {
			t.Fatalf("%+v after %v", r, time.Since(start))
		}
	case <-time.After(4 * time.Second):
		t.Fatal("half-closed connection must be reaped by the half-close idle limit")
	}
	cA.Close()
	cB.Close()
}

func TestRelayLargeTransferIntegrity(t *testing.T) {
	cA, gwA := tcpPair(t)
	gwB, cB := tcpPair(t)
	go Relay(gwA, gwB, RelayOptions{Idle: 10 * time.Second})
	const size = 16 << 20
	go func() {
		blk := make([]byte, 64<<10)
		for i := range blk {
			blk[i] = byte(i * 7)
		}
		for sent := 0; sent < size; sent += len(blk) {
			cA.Write(blk)
		}
		cA.(*net.TCPConn).CloseWrite()
	}()
	n, _ := io.Copy(io.Discard, cB)
	if n != size {
		t.Fatalf("got %d of %d bytes", n, size)
	}
}

// ---------- authorizer ----------

func TestAuthorizerCacheTTLAndKeys(t *testing.T) {
	cp := newFakeControl()
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	a := &Authorizer{CP: cp, Now: func() time.Time { return time.Unix(0, now.Load()) }}
	req := AuthorizeRequest{RouteID: "r", SrcIP: "1.2.3.4", CredentialType: "cap", Credential: "cap_x", Access: "capsule_uri"}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if d, err := a.Authorize(ctx, req); err != nil || !d.Allow {
			t.Fatal(d, err)
		}
	}
	if cp.authCalls.Load() != 1 {
		t.Fatalf("expected one control call (cache), got %d", cp.authCalls.Load())
	}
	other := req
	other.SrcIP = "1.2.3.5"
	a.Authorize(ctx, other)
	other = req
	other.Credential = "cap_y"
	a.Authorize(ctx, other)
	if cp.authCalls.Load() != 3 {
		t.Fatalf("different IP/credential must miss the cache: %d", cp.authCalls.Load())
	}
	now.Add(int64(31 * time.Second)) // past the 30 s ceiling
	a.Authorize(ctx, req)
	if cp.authCalls.Load() != 4 {
		t.Fatalf("expired entry must be refreshed: %d", cp.authCalls.Load())
	}
	if a.CacheLen() == 0 {
		t.Fatal("cache empty")
	}
	// the cache never holds the credential in clear
	for k := range a.cache {
		if strings.Contains(string(k[:]), "cap_x") {
			t.Fatal("credential stored in clear")
		}
	}
}

func TestAuthorizerNeverCachesSingleUseTokens(t *testing.T) {
	cp := newFakeControl()
	a := &Authorizer{CP: cp}
	req := AuthorizeRequest{RouteID: "r", SrcIP: "1.2.3.4", CredentialType: CredCgc, Credential: "cgc_x.y.z"}
	for i := 0; i < 3; i++ {
		a.Authorize(context.Background(), req)
	}
	if cp.authCalls.Load() != 3 || a.CacheLen() != 0 {
		t.Fatalf("cgc decisions must always reach the control plane: calls=%d cached=%d", cp.authCalls.Load(), a.CacheLen())
	}
}

func TestAuthorizerNegativeTTLAndTransientReasons(t *testing.T) {
	cp := newFakeControl()
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	a := &Authorizer{CP: cp, Now: func() time.Time { return time.Unix(0, now.Load()) }}
	cp.Decide = func(AuthorizeRequest) AuthorizeResponse {
		return AuthorizeResponse{Allow: false, DenyReason: "unauthorized", CacheTTLSeconds: 30}
	}
	req := AuthorizeRequest{RouteID: "r", SrcIP: "1.2.3.4", CredentialType: "cap", Credential: "cap_x"}
	a.Authorize(context.Background(), req)
	a.Authorize(context.Background(), req)
	if cp.authCalls.Load() != 1 {
		t.Fatal("denials are cached briefly")
	}
	now.Add(int64(6 * time.Second)) // failures are never cached beyond 5 s
	a.Authorize(context.Background(), req)
	if cp.authCalls.Load() != 2 {
		t.Fatalf("negative entries must expire within 5 s: %d", cp.authCalls.Load())
	}
	cp.Decide = func(AuthorizeRequest) AuthorizeResponse { return AuthorizeResponse{Allow: false, DenyReason: "quota"} }
	req.Credential = "cap_q"
	a.Authorize(context.Background(), req)
	a.Authorize(context.Background(), req)
	if cp.authCalls.Load() != 4 {
		t.Fatal("quota denials must not be cached")
	}
}

func TestAuthorizerSingleFlightAndErrors(t *testing.T) {
	cp := newFakeControl()
	gate := make(chan struct{})
	cp.Decide = func(AuthorizeRequest) AuthorizeResponse { <-gate; return AuthorizeResponse{Allow: true} }
	a := &Authorizer{CP: cp}
	req := AuthorizeRequest{RouteID: "r", SrcIP: "1.2.3.4", CredentialType: "none"}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); a.Authorize(context.Background(), req) }()
	}
	time.Sleep(100 * time.Millisecond)
	close(gate)
	wg.Wait()
	if cp.authCalls.Load() != 1 {
		t.Fatalf("20 identical concurrent questions must produce one control call, got %d", cp.authCalls.Load())
	}
	// errors are not cached and fail closed
	cp.down.Store(true)
	req.RouteID = "r2"
	for i := 0; i < 2; i++ {
		if _, err := a.Authorize(context.Background(), req); err == nil {
			t.Fatal("control failure must surface")
		}
	}
}

func TestAuthorizerStaleGraceIsOptIn(t *testing.T) {
	cp := newFakeControl()
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	a := &Authorizer{CP: cp, StaleGrace: time.Minute, Now: func() time.Time { return time.Unix(0, now.Load()) }}
	req := AuthorizeRequest{RouteID: "r", SrcIP: "1.2.3.4", CredentialType: "none"}
	a.Authorize(context.Background(), req)
	cp.down.Store(true)
	now.Add(int64(40 * time.Second))
	if d, err := a.Authorize(context.Background(), req); err != nil || !d.Allow {
		t.Fatalf("within the grace an allow may be reused: %v %v", d, err)
	}
	now.Add(int64(2 * time.Minute))
	if _, err := a.Authorize(context.Background(), req); err == nil {
		t.Fatal("beyond the grace it must fail closed")
	}
}

// ---------- limits ----------

func TestIPTracker(t *testing.T) {
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	tr := &IPTracker{MaxPre: 3, Rate: 5, Burst: 5, FailMax: 3, FailWindow: time.Minute, BlockFor: 5 * time.Minute, Now: func() time.Time { return time.Unix(0, now.Load()) }}
	ip := netip.MustParseAddr("203.0.113.9")
	for i := 0; i < 3; i++ {
		if ok, _ := tr.Enter(ip); !ok {
			t.Fatalf("enter %d refused", i)
		}
	}
	if ok, why := tr.Enter(ip); ok || why != LimitPreauth {
		t.Fatalf("4th concurrent must be refused with preauth, got %v %q", ok, why)
	}
	rt := &IPTracker{MaxPre: 100, Rate: 5, Burst: 5, Now: func() time.Time { return time.Unix(0, now.Load()) }}
	for i := 0; i < 5; i++ {
		if ok, _ := rt.Enter(ip); !ok {
			t.Fatalf("burst enter %d refused", i)
		}
	}
	if ok, why := rt.Enter(ip); ok || why != LimitRate {
		t.Fatalf("beyond the burst the rate limit applies, got %v %q", ok, why)
	}
	now.Add(int64(2 * time.Second))
	if ok, _ := rt.Enter(ip); !ok {
		t.Fatal("tokens must refill")
	}
	// brute force block
	b := netip.MustParseAddr("198.51.100.1")
	tr.Fail(b)
	tr.Fail(b)
	if tr.Blocked(b) {
		t.Fatal("blocked too early")
	}
	if !tr.Fail(b) || !tr.Blocked(b) {
		t.Fatal("3rd failure must block")
	}
	now.Add(int64(6 * time.Minute))
	if tr.Blocked(b) {
		t.Fatal("block must expire after 5 minutes")
	}
	// IPv6 clients are grouped by /64
	v6a, v6b := netip.MustParseAddr("2001:db8:1:2::1"), netip.MustParseAddr("2001:db8:1:2:ffff::9")
	if ipKey(v6a) != ipKey(v6b) || ipKey(v6a) == ipKey(netip.MustParseAddr("2001:db8:1:3::1")) {
		t.Fatal("/64 grouping")
	}
	if ipKey(netip.MustParseAddr("::ffff:1.2.3.4")) != netip.MustParseAddr("1.2.3.4") {
		t.Fatal("mapped IPv4 must canonicalise")
	}
}

func TestRouteLimits(t *testing.T) {
	l := &RouteLimits{DefaultMax: 2, DefaultMaxIP: 1, RouteRate: 1000}
	a, b := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2")
	r1, why := l.Acquire("r", a, 0, 0)
	if why != LimitNone {
		t.Fatal(why)
	}
	if _, why := l.Acquire("r", a, 0, 0); why != LimitIP {
		t.Fatalf("second from the same IP: %q", why)
	}
	r2, _ := l.Acquire("r", b, 0, 0)
	if _, why := l.Acquire("r", netip.MustParseAddr("3.3.3.3"), 0, 0); why != LimitRoute {
		t.Fatalf("route max: %q", why)
	}
	r1()
	r1() // idempotent
	if l.Count("r") != 1 {
		t.Fatalf("count %d", l.Count("r"))
	}
	r2()
	if l.Count("r") != 0 || len(l.perIP) != 0 {
		t.Fatal("state must be released")
	}
	// the control plane's value overrides the default
	rs := []func(){}
	for i := 0; i < 5; i++ {
		rel, why := l.Acquire("big", a, 5, 5)
		if why != LimitNone {
			t.Fatalf("override: %q at %d", why, i)
		}
		rs = append(rs, rel)
	}
	for _, r := range rs {
		r()
	}
	fast := &RouteLimits{DefaultMax: 1000, DefaultMaxIP: 1000, RouteRate: 5}
	var refused int
	for i := 0; i < 50; i++ {
		if _, why := fast.Acquire("x", a, 0, 0); why == LimitRate {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("per-route new connection rate must apply")
	}
}

// ---------- routes manager ----------

func TestTableLookups(t *testing.T) {
	pid := "p1"
	tb := NewTable(&Snapshot{Rev: 7, Routes: []Route{
		{ID: "1", Host: "A.Apps.Test.", DestHost: "h", DestPort: 1, Transport: "tcp", Protocol: "tls", Mode: "passthrough", Service: "s", Project: "proj", ProjectID: &pid},
		{ID: "2", Host: "*.db.test", DestHost: "h", DestPort: 2, Transport: "tcp"},
		{ID: "3", Host: "x.db.test", DestHost: "h", DestPort: 3, Transport: "tcp"},
		{ID: "4", Host: "u.apps.test", DestHost: "h", DestPort: 4, Transport: "udp"},
		{ID: "5", Host: "bad.apps.test", DestHost: "", DestPort: 4, Transport: "tcp"},
		{ID: "6", Host: "bad2.apps.test", DestHost: "h", DestPort: 70000, Transport: "tcp"},
		{ID: "7", Host: "slug.apps.test", DestHost: "h", DestPort: 7, Transport: "tcp", Service: "db", ProjectSlug: "other"},
	}})
	if tb.LookupHost("a.apps.test").ID != "1" {
		t.Fatal("exact, case and trailing dot normalised")
	}
	if tb.LookupHost("y.db.test").ID != "2" || tb.LookupHost("x.db.test").ID != "3" {
		t.Fatal("wildcard vs exact precedence")
	}
	if tb.LookupHost("db.test") != nil || tb.LookupHost("") != nil {
		t.Fatal("apex / empty")
	}
	if tb.LookupHost("u.apps.test") != nil || len(tb.UDP) != 1 {
		t.Fatal("UDP routes belong to the UDP plane")
	}
	if tb.LookupHost("bad.apps.test") != nil || tb.LookupHost("bad2.apps.test") != nil {
		t.Fatal("half-defined destinations must never be routable")
	}
	if tb.LookupService("proj", "s").ID != "1" || tb.LookupService("other", "db").ID != "7" || tb.LookupService("proj", "x") != nil {
		t.Fatal("service lookup")
	}
	var nilT *Table
	if nilT.LookupHost("a") != nil || nilT.Len() != 0 {
		t.Fatal("nil table")
	}
}

func TestRouteManagerDegradation(t *testing.T) {
	cp := newFakeControl()
	cp.SetRoutes(5, rt("r", "a.test", "tls", "passthrough", "127.0.0.1:1"))
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	dir := t.TempDir()
	m := &RouteManager{CP: cp, Log: slog.New(slog.NewJSONHandler(io.Discard, nil)), Wait: 200 * time.Millisecond,
		MaxAge: time.Hour, CacheFile: filepath.Join(dir, "routes.json"), Now: func() time.Time { return time.Unix(0, now.Load()) }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	waitFor(t, 3*time.Second, func() bool { return m.Ready() && m.Rev() == 5 })
	cp.down.Store(true)
	now.Add(int64(30 * time.Minute))
	if m.Table() == nil || m.Table().LookupHost("a.test") == nil {
		t.Fatal("must serve the last table within the max age")
	}
	now.Add(int64(31 * time.Minute))
	if m.Table() != nil || m.Ready() {
		t.Fatal("must stop serving a table older than the max age")
	}
	cp.down.Store(false)
	waitFor(t, 5*time.Second, m.Ready)
	// restart during an outage: the on-disk copy provides routes
	cp.down.Store(true)
	m2 := &RouteManager{CP: cp, Log: slog.New(slog.NewJSONHandler(io.Discard, nil)), MaxAge: time.Hour, CacheFile: m.CacheFile}
	if !m2.LoadCache() || m2.Table().LookupHost("a.test") == nil {
		t.Fatal("cache file must restore routes")
	}
	st, err := os.Stat(m.CacheFile)
	if err != nil || st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("cache file permissions: %v %v", st, err)
	}
	m3 := &RouteManager{CP: cp, Log: m.Log, MaxAge: time.Nanosecond, CacheFile: m.CacheFile}
	time.Sleep(5 * time.Millisecond)
	if m3.LoadCache() {
		t.Fatal("a cache older than the max age must be ignored")
	}
}

func TestRouteManagerFirstPollEmptyTable(t *testing.T) {
	cp := newFakeControl() // revision 0, no routes
	m := &RouteManager{CP: cp, Log: slog.New(slog.NewJSONHandler(io.Discard, nil)), Wait: 100 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	waitFor(t, 3*time.Second, m.Ready)
}

// ---------- cgc ----------

func TestCGCVerifier(t *testing.T) {
	pub, priv := newEd(t)
	pub2, priv2 := newEd(t)
	v := &CGCVerifier{Keys: []CGCKey{{KID: "new", Pub: pub}, {KID: "old", Pub: pub2}}}
	now := time.Now()
	ok := mintCGC(t, priv, "new", "p/s", now.Add(time.Minute), "jti-aaaaaaaaaaaaaaaa")
	if sub, jti, err := v.Verify(ok, "p/s", now); err != nil || sub != "user-1" || jti != "jti-aaaaaaaaaaaaaaaa" {
		t.Fatal(sub, jti, err)
	}
	if _, _, err := v.Verify(ok, "p/s", now); !errors.Is(err, ErrCGCReplay) {
		t.Fatalf("second use: %v", err)
	}
	if _, _, err := v.Verify(mintCGC(t, priv2, "old", "p/s", now.Add(time.Minute), "jti-bbbbbbbbbbbbbbbb"), "p/s", now); err != nil {
		t.Fatalf("previous key must still verify (rotation): %v", err)
	}
	if _, _, err := v.Verify(mintCGC(t, priv, "new", "p/other", now.Add(time.Minute), "jti-cccccccccccccccc"), "p/s", now); !errors.Is(err, ErrCGCInvalid) {
		t.Fatalf("route mismatch: %v", err)
	}
	if _, _, err := v.Verify(mintCGC(t, priv, "new", "p/s", now.Add(-time.Hour), "jti-dddddddddddddddd"), "p/s", now); !errors.Is(err, ErrCGCExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, _, err := v.Verify(mintCGC(t, priv, "new", "p/s", now.Add(-10*time.Second), "jti-eeeeeeeeeeeeeeee"), "p/s", now); err != nil {
		t.Fatalf("within the 30 s skew: %v", err)
	}
	// signature by an unknown key, tampering, wrong alg, junk
	_, privX := newEd(t)
	for name, tok := range map[string]string{
		"unknown key": mintCGC(t, privX, "new", "p/s", now.Add(time.Minute), "jti-ffffffffffffffff"),
		"junk":        "cgc_not.a.jwt",
		"no prefix":   strings.TrimPrefix(ok, "cgc_"),
		"two parts":   "cgc_a.b",
		"alg none":    "cgc_eyJhbGciOiJub25lIn0.e30.",
	} {
		if _, _, err := v.Verify(tok, "p/s", now); !errors.Is(err, ErrCGCInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	tampered := ok[:len(ok)-3] + "AAA"
	if _, _, err := v.Verify(tampered, "p/s", now); !errors.Is(err, ErrCGCInvalid) {
		t.Errorf("tampered: %v", err)
	}
	v.Sweep(now.Add(time.Hour))
	if len(v.seen) != 0 {
		t.Fatal("sweep must drop old jti")
	}
}

// ---------- config ----------

func TestConfigFromEnv(t *testing.T) {
	env := map[string]string{
		"CAPSULE_GW_LISTEN":           "[::]:443=tls+pg,[::]:5432=pg,127.0.0.1:80=http",
		"CAPSULE_GW_ZONE":             "Apps.Example.Test",
		"CAPSULE_GW_CONTROL_URL":      "http://backend:8080",
		"CAPSULE_GW_SECRET":           "s3cr3t",
		"CAPSULE_GW_ROUTES_MAX_AGE":   "90m",
		"CAPSULE_GW_MAX_CONNS":        "123",
		"CAPSULE_GW_REUSEPORT":        "false",
		"CAPSULE_GW_NEW_CONNS_PER_IP": "7.5",
	}
	c, err := ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Listeners) != 3 || c.Listeners[0].Addr != "[::]:443" || len(c.Listeners[0].Allow) != 2 || c.Listeners[0].Allow[1] != KindPGSSL || c.Listeners[2].Allow[0] != KindHTTP {
		t.Fatalf("%+v", c.Listeners)
	}
	if c.RoutesMaxAge != 90*time.Minute || c.MaxConns != 123 || c.ReusePort || c.NewConnsPerIP != 7.5 || c.Secret != "s3cr3t" {
		t.Fatalf("%+v", c)
	}
	hs := c.TunnelHostSet()
	if !hs["tcp.apps.example.test"] || !hs["udp.apps.example.test"] {
		t.Fatalf("tunnel hosts %v", hs)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := ConfigFromEnv(func(k string) string {
		return map[string]string{"CAPSULE_GW_IDLE_TIMEOUT": "soon", "CAPSULE_GW_LISTEN": ",,"}[k]
	}); err == nil || !strings.Contains(err.Error(), "CAPSULE_GW_IDLE_TIMEOUT") {
		t.Fatalf("bad values must be reported: %v", err)
	}
	empty, _ := ConfigFromEnv(func(string) string { return "" })
	if empty.Validate() == nil {
		t.Fatal("control URL and secret are required")
	}
	// secret from a file never appears in error text
	dir := t.TempDir()
	f := filepath.Join(dir, "secret")
	os.WriteFile(f, []byte("from-file\n"), 0o600)
	c2, _ := ConfigFromEnv(func(k string) string { return map[string]string{"CAPSULE_GW_SECRET_FILE": f}[k] })
	if c2.Secret != "from-file" {
		t.Fatalf("secret file: %q", c2.Secret)
	}
}

func TestFileCertsReload(t *testing.T) {
	dir := t.TempDir()
	write := func(cn string) (string, string) {
		cert := selfSigned(t, cn, cn+".test")
		return writePair(t, dir, cn, cert)
	}
	c1, k1 := write("one")
	fc, err := NewFileCerts([]string{c1}, []string{k1})
	if err != nil {
		t.Fatal(err)
	}
	got := func() string {
		cert, err := fc.GetCertificate(helloFor("one.test"))
		if err != nil {
			return err.Error()
		}
		sum := sha256.Sum256(cert.Certificate[0])
		return hex.EncodeToString(sum[:])
	}
	before := got()
	if _, err := fc.GetCertificate(helloFor("other.test")); err == nil {
		t.Fatal("no certificate for an unrelated name")
	}
	// renewal: overwrite files with a new certificate for the same name and reload
	cert := selfSigned(t, "one", "one.test")
	writePairAt(t, c1, k1, cert)
	if err := fc.Reload(); err != nil {
		t.Fatal(err)
	}
	if got() == before {
		t.Fatal("reload must pick up the renewed certificate")
	}
	// a broken file keeps the previous certificate
	os.WriteFile(c1, []byte("garbage"), 0o600)
	if fc.Reload() == nil {
		t.Fatal("garbage must fail")
	}
	if got() == "no certificate loaded" {
		t.Fatal("previous certificate must stay in force")
	}
	if _, err := NewFileCerts(nil, nil); err == nil {
		t.Fatal("empty lists")
	}
}
