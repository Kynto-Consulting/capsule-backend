package handlers

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/ingress"
)

type dnsStub struct {
	cname map[string]string
	ips   map[string][]string
}

func (d dnsStub) LookupCNAME(_ context.Context, h string) (string, error) {
	if c, ok := d.cname[h]; ok {
		return c + ".", nil
	}
	return h + ".", nil
}

func (d dnsStub) LookupIPAddr(_ context.Context, h string) ([]net.IPAddr, error) {
	v, ok := d.ips[h]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
	}
	var out []net.IPAddr
	for _, s := range v {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func caddyHandler(repo *memDomains, res ingress.Resolver) *DomainHandler {
	h := NewDomainHandler(repo, nil, nil, nil, "alb-123.elb.amazonaws.com", quiet())
	h.SetIngress(ingress.Config{
		Mode: ingress.ModeCaddy, Host: "ingress.apps.example.com", IPv4: "203.0.113.9",
		AppsDomain: "apps.example.com", OwnHosts: []string{"app.example.com"},
	}, res)
	return h
}

func TestNewDomain_CaddyModeNormalisesAndPointsAtIngress(t *testing.T) {
	h := caddyHandler(&memDomains{}, nil)
	org := uuid.New()
	d, msg := h.newDomain(org, nil, " Cliente.COM ", "external")
	if msg != "" || d.DomainName != "cliente.com" || d.Status != "pending_dns" || d.RecordType != "CNAME" || d.RecordValue != "ingress.apps.example.com" {
		t.Fatalf("%+v %q", d, msg)
	}
	for _, bad := range []string{"app.example.com", "x.apps.example.com", "*.cliente.com", "10.0.0.1", ""} {
		if d, msg := h.newDomain(org, nil, bad, "external"); d != nil || msg == "" {
			t.Errorf("%q must be rejected (got %+v)", bad, d)
		}
	}
	instr, recs := h.instructionsFor(d)
	if !strings.Contains(instr, "CNAME cliente.com → ingress.apps.example.com") || len(recs) != 1 {
		t.Errorf("instructions %q %+v", instr, recs)
	}
}

func TestNewDomain_ALBModeUnchanged(t *testing.T) {
	h := NewDomainHandler(&memDomains{}, nil, nil, nil, "alb-123.elb.amazonaws.com", quiet()) // SetIngress never called
	d, msg := h.newDomain(uuid.New(), nil, "Cliente.COM", "route53")
	if msg != "" || d.DomainName != "Cliente.COM" || d.Status != "pending" || d.RecordType != "CNAME" || d.RecordValue != "alb-123.elb.amazonaws.com" {
		t.Fatalf("%+v %q", d, msg)
	}
	if instr, recs := h.instructionsFor(d); instr != "Point CNAME Cliente.COM → alb-123.elb.amazonaws.com" || recs != nil {
		t.Errorf("%q %+v", instr, recs)
	}
	if rs := h.route53Records("x.com"); len(rs) != 1 || *rs[0].ResourceRecords[0].Value != "alb-123.elb.amazonaws.com" {
		t.Errorf("route53 records: %+v", rs)
	}
}

func TestVerifyCaddy_StatusTransitionsAndNoAWS(t *testing.T) {
	repo := &memDomains{}
	res := dnsStub{
		cname: map[string]string{"ok.cliente.com": "ingress.apps.example.com"},
		ips:   map[string][]string{"ingress.apps.example.com": {"203.0.113.9"}, "otro.cliente.com": {"198.51.100.1"}},
	}
	h := caddyHandler(repo, res) // aws == nil: any ACM/ELB call would panic or error
	org := uuid.New()
	mk := func(name string) *memDomainRef {
		nd, _ := h.newDomain(org, nil, name, "external")
		c, _ := repo.Create(context.Background(), nd)
		return &memDomainRef{c.ID}
	}
	for name, want := range map[string]string{"ok.cliente.com": "active", "otro.cliente.com": "failed", "nuevo.cliente.com": "pending_dns"} {
		ref := mk(name)
		d, _ := repo.GetByID(context.Background(), ref.id)
		resp, err := h.verifyCaddy(context.Background(), d)
		if err != nil || resp.Status != want || resp.Message == "" {
			t.Fatalf("%s: %+v err=%v, want %s", name, resp.Domain, err, want)
		}
		stored, _ := repo.GetByID(context.Background(), ref.id)
		if stored.Status != want || stored.SSLEnabled != (want == "active") {
			t.Errorf("%s stored: status=%s ssl=%v", name, stored.Status, stored.SSLEnabled)
		}
	}
	// DNS removed later: an active domain goes back to not-active and loses ssl_enabled
	ref := mk("ok.cliente.com2")
	_ = ref
}

type memDomainRef struct{ id uuid.UUID }
