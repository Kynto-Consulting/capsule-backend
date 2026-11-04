package api

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"time"

	"github.com/kynto/capsule/backend/internal/gateway/data"
)

// Round trip with the REAL data-plane client (gateway/data.HTTPControl) against the REAL handlers.
func TestRoundTripWithDataPlaneHTTPControl(t *testing.T) {
	e := newEnv(t)
	e.expose("db", "postgres", 5432)
	srv := httptest.NewServer(e.router())
	defer srv.Close()
	ctx := context.Background()

	bad, _ := data.NewHTTPControl(srv.URL, "wrong")
	if _, err := bad.Routes(ctx, 0, 0); err != data.ErrControlUnauthorized {
		t.Fatalf("wrong secret: %v", err)
	}
	cp, err := data.NewHTTPControl(srv.URL, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := cp.Routes(ctx, 0, time.Second)
	if err != nil || snap == nil || len(snap.Routes) != 1 {
		t.Fatalf("routes: %v %+v", err, snap)
	}
	r := snap.Routes[0]
	if r.ProjectSlug != "shop" || r.Service != "db" || r.Transport != "tcp" || r.Host != "db-shop.db.example.test" ||
		r.DestPort != 5432 || r.Mode != "passthrough" || r.ProjectID == nil || *r.ProjectID != e.project.ID.String() || r.OrgID != e.org.String() {
		t.Fatalf("route as the data plane decodes it: %+v", r)
	}
	if again, err := cp.Routes(ctx, snap.Rev, 0); err != nil || again != nil {
		t.Fatalf("304 must decode as (nil, nil): %v %+v", err, again)
	}

	tok := e.capToken(e.admin, nil)
	res, err := cp.Authorize(ctx, data.AuthorizeRequest{RouteID: r.ID, SrcIP: "203.0.113.9", CredentialType: data.CredCap, Credential: tok, Access: data.AccessCapsuleURI})
	if err != nil || !res.Allow || res.PrincipalID == "" || res.MaxConns != 200 || res.CacheTTLSeconds != 30 {
		t.Fatalf("authorize allow: %v %+v", err, res)
	}
	res, err = cp.Authorize(ctx, data.AuthorizeRequest{RouteID: r.ID, SrcIP: "203.0.113.9", CredentialType: data.CredCap, Credential: "cap_nope"})
	if err != nil || res.Allow || res.DenyReason != "unauthorized" {
		t.Fatalf("authorize deny: %v %+v", err, res)
	}
	cgs, _ := e.svc.CreateServiceToken(ctx, e.project, Actor{UserID: e.admin}, ServiceTokenInput{Name: "ci"})
	if res, err := cp.Authorize(ctx, data.AuthorizeRequest{RouteID: r.ID, SrcIP: "2001:db8::1", CredentialType: data.CredCgs, Credential: cgs.Token, Access: data.AccessSNI}); err != nil || !res.Allow {
		t.Fatalf("cgs over IPv6: %v %+v", err, res)
	}
	// a blocked address maps to the data plane's rate-limit error
	for i := 0; i < 10; i++ {
		_, _ = cp.Authorize(ctx, data.AuthorizeRequest{RouteID: r.ID, SrcIP: "198.51.100.9", CredentialType: data.CredCap, Credential: "cap_x"})
	}
	if _, err := cp.Authorize(ctx, data.AuthorizeRequest{RouteID: r.ID, SrcIP: "198.51.100.9", CredentialType: data.CredCap, Credential: "cap_x"}); err != data.ErrControlRateLimited {
		t.Fatalf("429 must map to ErrControlRateLimited, got %v", err)
	}
}

func TestRoundTripRandomPortWithoutCredential(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.expose("game", "udp", 7777)
	e.expose("web", "http", 80)
	e.st.SeedPortPool(ctx, 20000, 20010)
	lease, err := e.svc.LeasePort(ctx, e.project, Actor{UserID: e.admin}, "game")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(e.router())
	defer srv.Close()
	cp, _ := data.NewHTTPControl(srv.URL, testSecret)

	snap, err := cp.Routes(ctx, 0, time.Second)
	if err != nil || snap == nil {
		t.Fatalf("routes: %v", err)
	}
	var udpRoute *data.Route
	for i := range snap.Routes {
		if snap.Routes[i].Service == "game" {
			udpRoute = &snap.Routes[i]
		}
	}
	if udpRoute == nil || udpRoute.Transport != "udp" || udpRoute.ProjectSlug != "shop" || udpRoute.ServiceID == "" {
		t.Fatalf("udp route in the snapshot: %+v", udpRoute)
	}
	if len(snap.Leases) != 1 || snap.Leases[0].Port != lease.Port {
		t.Fatalf("leases: %+v", snap.Leases)
	}
	var raw SnapshotJSON
	e.do(e.router(), "GET", "/internal/gateway/routes?wait=0", "", nil, secretHdr).json(t, &raw)
	if raw.Leases[0].RouteID.String() != udpRoute.ID || raw.Leases[0].Transport != "udp" {
		t.Fatalf("lease route/transport: %+v", raw.Leases[0])
	}

	ask := func(ip string, port int, access, ctype string) *data.AuthorizeResponse {
		res, err := cp.Authorize(ctx, data.AuthorizeRequest{RouteID: udpRoute.ID, SrcIP: ip, CredentialType: ctype, Access: access, Port: port})
		if err != nil {
			t.Fatalf("authorize %s:%d: %v", ip, port, err)
		}
		return res
	}
	// empty list: denied, even though a project with an empty list is "public" for everything else
	e.ips.restricted, e.ips.cidrs = true, nil
	if ask("203.0.113.9", lease.Port, "random_port", data.CredNone).Allow {
		t.Fatal("an empty list must deny a random port")
	}
	e.ips.restricted, e.ips.cidrs = false, nil
	if ask("203.0.113.9", lease.Port, "random_port", data.CredNone).Allow {
		t.Fatal("no list at all must deny a random port too")
	}
	e.ips.restricted, e.ips.cidrs = true, []string{"203.0.113.0/24", "2001:db8::/32"}
	ok := ask("203.0.113.9", lease.Port, "random_port", data.CredNone)
	if !ok.Allow || ok.CacheTTLSeconds != 30 || ok.PrincipalID == "" {
		t.Fatalf("allowed ip: %+v", ok)
	}
	if !ask("2001:db8::7", lease.Port, "random_port", data.CredNone).Allow || !ask("::ffff:203.0.113.9", lease.Port, "random_port", data.CredNone).Allow {
		t.Fatal("IPv6 and mapped IPv4 must follow the list")
	}
	uniform := ask("198.51.100.1", lease.Port, "random_port", data.CredNone)
	if uniform.Allow || uniform.DenyReason != "unauthorized" {
		t.Fatalf("denied ip: %+v", uniform)
	}
	for name, r := range map[string]*data.AuthorizeResponse{
		"port without a lease": ask("203.0.113.9", lease.Port+1, "random_port", data.CredNone),
		"port out of range":    ask("203.0.113.9", 40001, "random_port", data.CredNone),
		"port 0":               ask("203.0.113.9", 0, "random_port", data.CredNone),
		"none on capsule_uri":  ask("203.0.113.9", lease.Port, "capsule_uri", data.CredNone),
	} {
		if r.Allow || r.DenyReason != "unauthorized" {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// a lease of ANOTHER service does not open this route
	if _, err := e.svc.LeasePort(ctx, e.project, Actor{UserID: e.admin}, "web"); err != nil {
		t.Fatal(err)
	}
	e.st.mu.Lock()
	otherPort := e.st.leases[e.routeServiceID("web")].Port
	e.st.mu.Unlock()
	if ask("203.0.113.9", otherPort, "random_port", data.CredNone).Allow {
		t.Fatal("a port leased to another service must not authorize this route")
	}
	acts := e.audit.actions()
	var allow, deny int
	for _, a := range acts {
		if a == "gateway.connect.allow" {
			allow++
		} else if a == "gateway.connect.deny" {
			deny++
		}
	}
	if allow != 3 || deny < 8 {
		t.Fatalf("audit rows allow=%d deny=%d", allow, deny)
	}
}

func TestRoundTripSNINameWithoutCredential(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.expose("db", "postgres", 5432)
	srv := httptest.NewServer(e.router())
	defer srv.Close()
	cp, _ := data.NewHTTPControl(srv.URL, testSecret)
	route := e.routeID("db").String()
	ask := func(routeID, ip, access string) *data.AuthorizeResponse {
		res, err := cp.Authorize(ctx, data.AuthorizeRequest{RouteID: routeID, SrcIP: ip, CredentialType: data.CredNone, Access: access})
		if err != nil {
			t.Fatalf("authorize %s: %v", ip, err)
		}
		return res
	}
	e.ips.restricted, e.ips.cidrs = true, nil
	if ask(route, "203.0.113.9", data.AccessSNI).Allow {
		t.Fatal("an empty list must deny access by name without credential")
	}
	e.ips.restricted = false
	if ask(route, "203.0.113.9", data.AccessSNI).Allow {
		t.Fatal("no list must deny too")
	}
	e.ips.restricted, e.ips.cidrs = true, []string{"203.0.113.0/24", "2001:db8::/32"}
	ok := ask(route, "203.0.113.9", data.AccessSNI)
	if !ok.Allow || ok.PrincipalID != "sni:db" || ok.CacheTTLSeconds != 30 || ok.MaxConns == 0 {
		t.Fatalf("allowed ip: %+v", ok)
	}
	if !ask(route, "2001:db8::5", data.AccessSNI).Allow || !ask(route, "::ffff:203.0.113.9", data.AccessSNI).Allow {
		t.Fatal("IPv6 and mapped IPv4 must follow the list")
	}
	for name, r := range map[string]*data.AuthorizeResponse{
		"ip outside the list": ask(route, "198.51.100.1", data.AccessSNI),
		"unknown route":       ask(uuid.NewString(), "203.0.113.9", data.AccessSNI),
		"capsule_uri":         ask(route, "203.0.113.9", data.AccessCapsuleURI),
		"no access":           ask(route, "203.0.113.9", ""),
	} {
		if r.Allow || r.DenyReason != "unauthorized" {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// a route whose gateway access is off is not in the table: denied
	off := false
	if _, err := e.svc.UpdateService(ctx, e.project, Actor{UserID: e.admin}, "db", UpdateInput{GatewayEnabled: &off}); err != nil {
		t.Fatal(err)
	}
	if ask(route, "203.0.113.9", data.AccessSNI).Allow {
		t.Fatal("a disabled route must deny")
	}
	allow, deny := 0, 0
	for _, a := range e.audit.actions() {
		switch a {
		case "gateway.connect.allow":
			allow++
		case "gateway.connect.deny":
			deny++
		}
	}
	if allow != 3 || deny < 5 {
		t.Fatalf("audit allow=%d deny=%d", allow, deny)
	}
}
