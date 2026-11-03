//go:build dbtest

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/kynto/capsule/backend/internal/domain"
)

// TestProjectPortsUDPMigrationUpDown: 000064 on top of data created before it,
// the schema it enables, idempotence, and the down file.
func TestProjectPortsUDPMigrationUpDown(t *testing.T) {
	pool := freshDB(t)
	ctx := context.Background()
	applyUpTo(t, pool, 63)
	f := newFx(t, pool)
	u := f.user("", time.Now())
	org := f.org(u)
	proj := f.project(org, "")
	var portID string
	if err := pool.QueryRow(ctx, `INSERT INTO project_ports (project_id, name, container_port, host_port) VALUES ($1,'pg',5432,41000) RETURNING id`, proj).Scan(&portID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_port_rules (port_id, cidr) VALUES ($1,'10.0.0.0/8')`, portID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_ports (project_id, container_port, protocol, host_port) VALUES ($1,1,'udp',41001)`, proj); err == nil {
		t.Fatal("udp must be refused before 000064")
	}

	up, _ := MigrationsFS.ReadFile("migrations/000064_project_ports_udp.up.sql")
	down, _ := MigrationsFS.ReadFile("migrations/000064_project_ports_udp.down.sql")
	for i := 0; i < 2; i++ { // twice: the up file is re-runnable
		if _, err := pool.Exec(ctx, string(up)); err != nil {
			t.Fatalf("up #%d: %v", i+1, err)
		}
	}
	var proto, ruleProto string
	_ = pool.QueryRow(ctx, `SELECT protocol FROM project_ports WHERE id=$1`, portID).Scan(&proto)
	_ = pool.QueryRow(ctx, `SELECT protocol FROM project_port_rules WHERE port_id=$1`, portID).Scan(&ruleProto)
	if proto != "tcp" || ruleProto != "tcp" {
		t.Fatalf("existing rows must stay tcp: %q %q", proto, ruleProto)
	}
	// same number on tcp and udp, container and host side
	var udpID string
	if err := pool.QueryRow(ctx, `INSERT INTO project_ports (project_id, name, container_port, protocol, host_port) VALUES ($1,'pg-udp',5432,'udp',41000) RETURNING id`, proj).Scan(&udpID); err != nil {
		t.Fatalf("udp twin: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_port_rules (port_id, protocol, cidr) VALUES ($1,'udp','10.0.0.0/8')`, udpID); err != nil {
		t.Fatal(err)
	}
	for name, sql := range map[string]string{
		"duplicate (container, proto)": `INSERT INTO project_ports (project_id, container_port, protocol, host_port) VALUES ($1,5432,'udp',41002)`,
		"duplicate (host, proto)":      `INSERT INTO project_ports (project_id, container_port, protocol, host_port) VALUES ($1,6000,'udp',41000)`,
		"unknown protocol":             `INSERT INTO project_ports (project_id, container_port, protocol, host_port) VALUES ($1,6001,'sctp',41003)`,
	} {
		if _, err := pool.Exec(ctx, sql, proj); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// a rule cannot disagree with its port
	if _, err := pool.Exec(ctx, `INSERT INTO project_port_rules (port_id, protocol, cidr) VALUES ($1,'tcp','11.0.0.0/8')`, udpID); err == nil {
		t.Error("rule with another protocol than its port accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_port_rules (port_id, protocol, cidr) VALUES ($1,'sctp','11.0.0.0/8')`, portID); err == nil {
		t.Error("rule with unknown protocol accepted")
	}

	// down: udp ports and their rules go, tcp data stays, tcp-only constraints are back
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM project_ports WHERE project_id=$1`, proj).Scan(&n)
	if n != 1 {
		t.Fatalf("after down want only the tcp port, got %d", n)
	}
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM project_port_rules WHERE port_id=$1`, portID).Scan(&n)
	if n != 1 {
		t.Fatalf("tcp rule must survive the down: %d", n)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_ports (project_id, container_port, protocol, host_port) VALUES ($1,7,'udp',41009)`, proj); err == nil {
		t.Error("udp accepted after down")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_ports (project_id, container_port, host_port) VALUES ($1,5432,41010)`, proj); err == nil {
		t.Error("unique (project, container_port) not restored")
	}
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down twice: %v", err)
	}
	if _, err := pool.Exec(ctx, string(up)); err != nil {
		t.Fatalf("up after down: %v", err)
	}
}

func TestProjectPortsUDPRepository(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewProjectPortRepository(pool)
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)
	p1, p2 := f.project(org, ""), f.project(org, "")
	h := randPort()

	out, err := r.Replace(ctx, p1, []*domain.ProjectPort{
		{Name: "game", ContainerPort: 7777, Protocol: "tcp", HostPort: h},
		{Name: "game-udp", ContainerPort: 7777, Protocol: "udp", HostPort: h}, // same host number, other protocol
	})
	if err != nil || len(out) != 2 || out[0].Protocol != "tcp" || out[1].Protocol != "udp" {
		t.Fatalf("replace tcp+udp: %+v %v", out, err)
	}
	// uniqueness is per (port, protocol): another project cannot take udp h
	if _, err := r.Replace(ctx, p2, []*domain.ProjectPort{{Name: "x", ContainerPort: 1, Protocol: "udp", HostPort: h}}); err != domain.ErrConflict {
		t.Fatalf("udp host port reuse: %v", err)
	}
	usedUDP, err := r.UsedHostPorts(ctx, "udp", h, h)
	if err != nil || !usedUDP[h] {
		t.Fatalf("udp used: %v %v", usedUDP, err)
	}
	if _, err := r.Replace(ctx, p1, []*domain.ProjectPort{{Name: "game", ContainerPort: 7777, Protocol: "tcp", HostPort: h}}); err != nil {
		t.Fatal(err)
	}
	usedUDP, _ = r.UsedHostPorts(ctx, "udp", h, h)
	usedTCP, _ := r.UsedHostPorts(ctx, "tcp", h, h)
	if usedUDP[h] || !usedTCP[h] {
		t.Fatalf("after dropping the udp twin: udp=%v tcp=%v", usedUDP, usedTCP)
	}
	// p2 can now take udp h
	if _, err := r.Replace(ctx, p2, []*domain.ProjectPort{{Name: "x", ContainerPort: 1, Protocol: "udp", HostPort: h}}); err != nil {
		t.Fatalf("udp h free again: %v", err)
	}
	// restore the twin on another host number and use rules
	if _, err := r.Replace(ctx, p1, []*domain.ProjectPort{
		{Name: "game", ContainerPort: 7777, Protocol: "tcp", HostPort: h},
		{Name: "game-udp", ContainerPort: 7777, Protocol: "udp", HostPort: h + 1},
	}); err != nil {
		t.Fatal(err)
	}
	mk := func(c string) *domain.PortRule { return &domain.PortRule{CIDR: c, Description: "d", CreatedBy: &u} }
	ru, err := r.AddRule(ctx, p1, 7777, "udp", mk("203.0.113.5/32"), 3)
	if err != nil || ru.Protocol != "udp" {
		t.Fatalf("udp rule: %+v %v", ru, err)
	}
	if _, err := r.AddRule(ctx, p1, 7777, "tcp", mk("203.0.113.5/32"), 3); err != nil {
		t.Fatalf("same cidr on the tcp twin is a separate rule: %v", err)
	}
	if _, err := r.AddRule(ctx, p1, 7777, "udp", mk("203.0.113.5/32"), 3); err != domain.ErrConflict {
		t.Fatalf("dup udp rule: %v", err)
	}
	if _, err := r.AddRule(ctx, p1, 8888, "udp", mk("203.0.113.6/32"), 3); err != domain.ErrNotFound {
		t.Fatalf("rule on missing udp port: %v", err)
	}
	if _, err := r.AddRule(ctx, p1, 7777, "udp", mk("2001:db8::/32"), 3); err != nil {
		t.Fatalf("ipv6 on udp: %v", err)
	}
	if _, err := r.AddRule(ctx, p1, 7777, "udp", mk("203.0.113.9/32"), 2); err != domain.ErrRuleLimit {
		t.Fatalf("limit is per (port, protocol): %v", err)
	}
	ports, err := r.List(ctx, p1)
	if err != nil || len(ports) != 2 || len(ports[0].Rules) != 1 || len(ports[1].Rules) != 2 || ports[1].Rules[0].Protocol != "udp" {
		t.Fatalf("list: %+v %v", ports, err)
	}
	des, err := r.ListDesired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	udp, tcp := 0, 0
	for _, d := range des {
		if d.ProjectID != p1 {
			continue
		}
		if d.Protocol == "udp" && d.HostPort == h+1 {
			udp++
		}
		if d.Protocol == "tcp" && d.HostPort == h {
			tcp++
		}
	}
	if udp != 2 || tcp != 1 {
		t.Fatalf("desired udp=%d tcp=%d: %+v", udp, tcp, des)
	}
	// dropping the udp port takes its rules with it
	if _, err := r.Replace(ctx, p1, []*domain.ProjectPort{{Name: "game", ContainerPort: 7777, Protocol: "tcp", HostPort: h}}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM project_port_rules WHERE protocol='udp' AND port_id IN (SELECT id FROM project_ports WHERE project_id=$1)`, p1).Scan(&n)
	if n != 0 {
		t.Fatalf("udp rules left behind: %d", n)
	}
	_ = r.DeleteAll(ctx, p1)
	_ = r.DeleteAll(ctx, p2)
}
