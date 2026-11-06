package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const k44 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func wgSpec() Spec {
	return Spec{Name: "Estudio", Provider: "wireguard", Host: "203.0.113.5:51820", CIDRs: []string{"10.48.0.7/24"},
		Secret: `{"private_key":"` + k44 + `","peer_public_key":"` + k44 + `","address":"10.99.0.2/32"}`}
}

func TestNormalize(t *testing.T) {
	s, err := wgSpec().Normalize()
	if err != nil || s.Name != "estudio" || s.CIDRs[0] != "10.48.0.0/24" || s.MaxConns != DefaultMaxConns {
		t.Fatalf("%+v %v", s, err)
	}
	bad := []func(*Spec){
		func(s *Spec) { s.Name = "Bad Name!" },
		func(s *Spec) { s.Provider = "pptp" },
		func(s *Spec) { s.Host = "nohost" },
		func(s *Spec) { s.CIDRs = nil },
		func(s *Spec) { s.CIDRs = []string{"0.0.0.0/0"} },
		func(s *Spec) { s.CertPin = "zz" },
		func(s *Spec) { s.Secret = "" },
		func(s *Spec) { s.Secret = `{"private_key":"x"}` },
		func(s *Spec) { s.MaxConns = 999 },
	}
	for i, f := range bad {
		sp := wgSpec()
		f(&sp)
		if _, err := sp.Normalize(); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: expected ErrInvalid, got %v", i, err)
		}
	}
}

func TestCreateEncryptsAndOneTunnelPerProject(t *testing.T) {
	svc := &Service{Store: NewMemStore(), SecretKey: "unit-test-key-0123456789abcdef"}
	org, proj := uuid.New(), uuid.New()
	tn, err := svc.Create(context.Background(), org, proj, "user:ana", nil, wgSpec())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(tn.SecretEnc), "private_key") {
		t.Fatal("secret stored in clear")
	}
	plain, err := svc.Secret(tn)
	if err != nil || !strings.Contains(plain, "private_key") {
		t.Fatalf("decrypt: %v", err)
	}
	if _, err := svc.Create(context.Background(), org, proj, "user:ana", nil, wgSpec()); !errors.Is(err, ErrConflict) {
		t.Fatalf("second tunnel in project: %v", err)
	}
	if _, err := svc.Create(context.Background(), org, uuid.New(), "u", nil, wgSpec()); err != nil {
		t.Fatalf("other project must work: %v", err)
	}
}

func TestKillSwitchAndAudit(t *testing.T) {
	st := NewMemStore()
	svc := &Service{Store: st, SecretKey: "unit-test-key-0123456789abcdef"}
	tn, _ := svc.Create(context.Background(), uuid.New(), uuid.New(), "u", nil, wgSpec())
	if err := svc.SetEnabled(context.Background(), tn, false, "user:ana"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetByID(context.Background(), tn.ID)
	if got.Enabled || got.Status != StatusDisabled {
		t.Fatalf("%+v", got)
	}
	if err := svc.Report(context.Background(), got, StatusUp, nil, "", "gateway"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("report on disabled tunnel: %v", err)
	}
	ev, _ := st.Events(context.Background(), tn.ID, 10)
	kinds := []string{}
	for _, e := range ev {
		kinds = append(kinds, e.Kind)
	}
	if strings.Join(kinds, ",") != "disabled,created" {
		t.Fatalf("audit trail = %v", kinds)
	}
}

func TestRenderLaunch(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	tn := Tunnel{Provider: ProviderFortiGate, Host: "161.1.2.3:10443", CIDRs: []string{"10.48.0.0/24"}, CertPin: pin}
	l, err := RenderLaunch(tn, `{"username":"ana","password":"s3cr3t-pass"}`)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Join(l.Argv, " ")
	for _, want := range []string{"openfortivpn 161.1.2.3:10443", "--no-routes", "--no-dns", "--trusted-cert " + pin} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv missing %q: %s", want, argv)
		}
	}
	if strings.Contains(argv, "s3cr3t-pass") {
		t.Fatal("password leaked to argv")
	}
	if !strings.Contains(l.Files["openfortivpn.conf"], "s3cr3t-pass") {
		t.Fatal("password must be in the private file")
	}
	o, _ := RenderLaunch(Tunnel{Provider: ProviderOpenVPN, Host: "1.2.3.4:1194", CIDRs: []string{"10.48.0.0/24"}}, `{"username":"a","password":"bbbbbb"}`)
	if !strings.Contains(o.Files["client.ovpn"], "route 10.48.0.0 255.255.255.0") || !strings.Contains(o.Files["client.ovpn"], "route-nopull") {
		t.Fatalf("ovpn: %s", o.Files["client.ovpn"])
	}
	i, _ := RenderLaunch(Tunnel{Provider: ProviderIPsec, Host: "1.2.3.4:500", CIDRs: []string{"10.48.0.0/24"}}, `{"psk":"psk-value-1"}`)
	if !strings.Contains(i.Files["swanctl.conf"], "remote_ts = 10.48.0.0/24") {
		t.Fatalf("ipsec: %s", i.Files["swanctl.conf"])
	}
	if _, err := RenderLaunch(Tunnel{Provider: ProviderWireGuard}, "{}"); err == nil {
		t.Fatal("wireguard has no namespace launch")
	}
	script := NamespaceScript(l, "161.1.2.3")
	if !strings.HasPrefix(script, "iptables -P INPUT DROP") || !strings.Contains(script, "-d 10.48.0.0/24 -j ACCEPT") || strings.Contains(script, "0.0.0.0/0") {
		t.Fatalf("script: %s", script)
	}
}

func TestRedactor(t *testing.T) {
	r := NewRedactor()
	r.AddJSONValues(`{"username":"ana","password":"hunter2-long","x":1}`)
	got := r.Mask("login ana with hunter2-long ok")
	if strings.Contains(got, "hunter2-long") || !strings.Contains(got, "***") {
		t.Fatal(got)
	}
}
