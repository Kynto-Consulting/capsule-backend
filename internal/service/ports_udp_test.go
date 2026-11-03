package service

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

func TestValidateSpecsUDP(t *testing.T) {
	s := newTestPorts(newFakePortRepo(), &fakeFirewall{}, nil)
	out, err := s.ValidateSpecs([]PortInput{
		{ContainerPort: 5000, Protocol: "UDP"}, {ContainerPort: 5000}, {ContainerPort: 5000, Protocol: "tcp", Name: "x"},
	})
	if code(err) != "DUPLICATE_PORT" {
		t.Fatalf("tcp listed twice (implicit and explicit) must be a duplicate: %v %v", out, err)
	}
	out, err = s.ValidateSpecs([]PortInput{{ContainerPort: 5000, Protocol: "UDP"}, {ContainerPort: 5000}})
	if err != nil || len(out) != 2 || out[0].Protocol != "tcp" || out[1].Protocol != "udp" {
		t.Fatalf("same number on tcp and udp must be valid and sorted: %+v %v", out, err)
	}
	if _, err := s.ValidateSpecs([]PortInput{{ContainerPort: 5000, Protocol: "udp"}, {ContainerPort: 5000, Protocol: "udp"}}); code(err) != "DUPLICATE_PORT" {
		t.Errorf("udp twice: %v", err)
	}
	_, err = s.ValidateSpecs([]PortInput{{ContainerPort: 5000, Protocol: "sctp"}})
	if code(err) != "INVALID_PROTOCOL" || !strings.Contains(err.Error(), "tcp o udp") {
		t.Errorf("sctp must fail in Spanish: %v", err)
	}
	if _, err := s.ValidateSpecs([]PortInput{{ContainerPort: 70000, Protocol: "udp"}}); code(err) != "INVALID_PORT" {
		t.Errorf("udp port out of range: %v", err)
	}
	// 22 and the API port are TCP services: reserved for tcp only.
	if _, err := s.ValidateSpecs([]PortInput{{ContainerPort: 22}}); code(err) != "RESERVED_PORT" {
		t.Errorf("22/tcp: %v", err)
	}
	if _, err := s.ValidateSpecs([]PortInput{{ContainerPort: 22, Protocol: "udp"}}); err != nil {
		t.Errorf("22/udp is not reserved: %v", err)
	}
}

func TestReplaceAllocatesPerProtocol(t *testing.T) {
	repo := newFakePortRepo()
	repo.foreignUsed[41000] = true // a database/deployment holds TCP 41000
	rs := &fakeRestarter{}
	s := newTestPorts(repo, &fakeFirewall{}, rs)
	pid := uuid.New()
	stored, err := s.Replace(context.Background(), pid, []domain.PortSpec{
		{Name: "game", ContainerPort: 7777, Protocol: "tcp"},
		{Name: "game-udp", ContainerPort: 7777, Protocol: "udp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, p := range stored {
		got[p.Protocol] = p.HostPort
	}
	if got["tcp"] != 41001 {
		t.Errorf("tcp must skip the taken 41000: %v", got)
	}
	if got["udp"] != 41000 {
		t.Errorf("udp slots are independent of tcp ones: %v", got)
	}
	if len(rs.calls) != 1 || len(rs.calls[0]) != 2 {
		t.Fatalf("restart calls = %v", rs.calls)
	}
	// A second udp port gets the next udp number; the existing ones keep theirs.
	stored, err = s.Replace(context.Background(), pid, []domain.PortSpec{
		{Name: "game", ContainerPort: 7777, Protocol: "tcp"},
		{Name: "game-udp", ContainerPort: 7777, Protocol: "udp"},
		{Name: "voice", ContainerPort: 9000, Protocol: "udp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range stored {
		switch {
		case p.Protocol == "tcp" && p.ContainerPort == 7777 && p.HostPort != 41001,
			p.Protocol == "udp" && p.ContainerPort == 7777 && p.HostPort != 41000,
			p.Protocol == "udp" && p.ContainerPort == 9000 && p.HostPort != 41001:
			t.Errorf("unexpected host port: %+v", p)
		}
	}
	// Dropping the udp twin keeps the tcp port and its host port.
	stored, err = s.Replace(context.Background(), pid, []domain.PortSpec{{Name: "game", ContainerPort: 7777, Protocol: "tcp"}})
	if err != nil || len(stored) != 1 || stored[0].Protocol != "tcp" || stored[0].HostPort != 41001 {
		t.Fatalf("%+v %v", stored, err)
	}
}

func TestAllocateHonoursUDPInUse(t *testing.T) {
	repo := newFakePortRepo()
	s := NewPortsService(repo, &fakeFirewall{}, nil, PortsConfig{
		From: 41000, To: 41002,
		InUse:    func(p int) bool { return p == 41001 }, // TCP bound
		InUseUDP: func(p int) bool { return p == 41000 }, // UDP bound
	}, nil)
	stored, err := s.Replace(context.Background(), uuid.New(), []domain.PortSpec{
		{Name: "a", ContainerPort: 1000, Protocol: "tcp"}, {Name: "b", ContainerPort: 1000, Protocol: "udp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range stored {
		if p.Protocol == "tcp" && p.HostPort != 41000 || p.Protocol == "udp" && p.HostPort != 41001 {
			t.Errorf("%+v", p)
		}
	}
}

func TestRangeExhaustedPerProtocol(t *testing.T) {
	repo := newFakePortRepo()
	s := NewPortsService(repo, &fakeFirewall{}, nil, PortsConfig{From: 41000, To: 41000}, nil)
	pid := uuid.New()
	if _, err := s.Replace(context.Background(), pid, []domain.PortSpec{{Name: "a", ContainerPort: 1, Protocol: "udp"}, {Name: "b", ContainerPort: 2, Protocol: "udp"}}); code(err) != "PORT_RANGE_EXHAUSTED" {
		t.Fatalf("want exhausted, got %v", err)
	}
	if _, err := s.Replace(context.Background(), pid, []domain.PortSpec{{Name: "a", ContainerPort: 1, Protocol: "udp"}, {Name: "b", ContainerPort: 1, Protocol: "tcp"}}); err != nil {
		t.Fatalf("one tcp and one udp fit in a one-port range: %v", err)
	}
}

func TestUDPRulesReachTheFirewallWithProtocol(t *testing.T) {
	repo := newFakePortRepo()
	fw := &fakeFirewall{}
	s := newTestPorts(repo, fw, &fakeRestarter{nothing: true})
	pid := uuid.New()
	if _, err := s.Replace(context.Background(), pid, []domain.PortSpec{
		{Name: "t", ContainerPort: 5000, Protocol: "tcp"}, {Name: "u", ContainerPort: 5000, Protocol: "udp"},
	}); err != nil {
		t.Fatal(err)
	}
	r, err := s.AddRule(context.Background(), pid, 5000, "udp", "203.0.113.5/32", "game", uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	last := fw.reconciled[len(fw.reconciled)-1]
	if len(last) != 1 || last[0].Protocol != "udp" || last[0].CIDR != "203.0.113.5/32" {
		t.Fatalf("firewall got %+v", last)
	}
	if r.CIDR != "203.0.113.5/32" {
		t.Fatalf("rule = %+v", r)
	}
	// The same CIDR on the tcp twin is a different rule.
	if _, err := s.AddRule(context.Background(), pid, 5000, "tcp", "203.0.113.5/32", "", uuid.New()); err != nil {
		t.Fatalf("tcp twin: %v", err)
	}
	if _, err := s.AddRule(context.Background(), pid, 5000, "udp", "203.0.113.5/32", "", uuid.New()); code(err) != "ALREADY_EXISTS" {
		t.Fatalf("duplicate on udp: %v", err)
	}
	if _, err := s.AddRule(context.Background(), pid, 6000, "udp", "10.0.0.0/8", "", uuid.New()); code(err) != "NOT_FOUND" {
		t.Fatalf("missing udp port: %v", err)
	}
	if _, err := s.AddRule(context.Background(), pid, 5000, "sctp", "10.0.0.0/8", "", uuid.New()); code(err) != "INVALID_PROTOCOL" {
		t.Fatalf("sctp: %v", err)
	}
	// Removing with the wrong protocol does not find the rule.
	if err := s.RemoveRule(context.Background(), pid, 5000, "tcp", r.ID); code(err) != "NOT_FOUND" {
		t.Fatalf("wrong protocol: %v", err)
	}
	if err := s.RemoveRule(context.Background(), pid, 5000, "udp", r.ID); err != nil {
		t.Fatal(err)
	}
	keep := fw.reconciled[len(fw.reconciled)-1]
	if len(keep) != 1 || keep[0].Protocol != "tcp" {
		t.Fatalf("only the tcp rule must remain desired: %+v", keep)
	}
	// Sweep carries the protocol too.
	if err := s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	sw := fw.synced[len(fw.synced)-1]
	if len(sw) != 1 || sw[0].Protocol != "tcp" {
		t.Fatalf("sweep = %+v", sw)
	}
}

func TestDockerRunArgsUDP(t *testing.T) {
	args := strings.Join(dockerRunArgs("c", "v", "img", nil, true, 3000, 20500, []domain.PortMapping{
		{ContainerPort: 7777, HostPort: 41001, Protocol: "tcp"},
		{ContainerPort: 7777, HostPort: 41000, Protocol: "udp"},
		{ContainerPort: 25565, HostPort: 41002},                  // implicit tcp
		{ContainerPort: 0, HostPort: 41003, Protocol: "udp"},     // invalid internal port: never published
		{ContainerPort: 80, HostPort: 70000, Protocol: "udp"},    // invalid host port
		{ContainerPort: 80, HostPort: 41004, Protocol: "sctp"},   // unknown protocol
		{ContainerPort: 65536, HostPort: 41005, Protocol: "tcp"}, // invalid internal port
	}), " ")
	for _, want := range []string{"-p 20500:3000", "-p 41001:7777 ", "-p 41000:7777/udp", "-p 41002:25565 "} {
		if !strings.Contains(args+" ", want) {
			t.Errorf("missing %q in %s", want, args)
		}
	}
	for _, bad := range []string{"41003", "70000", "41004", "41005"} {
		if strings.Contains(args, bad) {
			t.Errorf("%s must not be published: %s", bad, args)
		}
	}
	if strings.Contains(args, "41001:7777/udp") || strings.Contains(args, "41000:7777 ") {
		t.Errorf("protocol mixed up: %s", args)
	}
}

func TestPortFreeUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no udp socket available")
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	if PortFreeUDP(port) {
		// bound on 127.0.0.1 only: the wildcard bind may still succeed on some systems
		t.Skip("wildcard udp bind does not conflict with a loopback bind here")
	}
}
