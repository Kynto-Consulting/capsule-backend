//go:build dbtest

package repository

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

// GET /internal/tls/ask answers from GetByHostname: only verified|active domains attached to a project
// are found, the lookup is exact on the (lower-case) name and uses the unique index of domains.domain_name.
func TestDomainRepository_GetByHostname_ForTLSAsk(t *testing.T) {
	pool := accessDB(t)
	ctx := context.Background()
	f := newFx(t, pool)

	var owner uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO users (email,password_hash,name,role) VALUES ($1,'x','U','member') RETURNING id`,
		uuid.NewString()+"@x.io").Scan(&owner); err != nil {
		t.Fatal(err)
	}
	org := f.org(owner)
	proj := f.project(org, "ask")

	repo := NewDomainRepository(pool)
	mk := func(name, status string, pid *uuid.UUID) {
		t.Helper()
		if _, err := repo.Create(ctx, &domain.Domain{OrgID: org, ProjectID: pid, DomainName: name,
			RecordType: "CNAME", Status: status, DNSProvider: "external"}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	mk("activo.example.com", "active", &proj)
	mk("verificado.example.com", "verified", &proj)
	mk("pendiente.example.com", "pending_dns", &proj)
	mk("fallido.example.com", "failed", &proj)
	mk("huerfano.example.com", "active", nil)

	for host, wantFound := range map[string]bool{
		"activo.example.com":      true,
		"verificado.example.com":  true,
		"pendiente.example.com":   false,
		"fallido.example.com":     false,
		"desconocido.example.com": false,
		"ACTIVO.example.com":      false, // callers normalise to lower case first
	} {
		d, err := repo.GetByHostname(ctx, host)
		switch {
		case wantFound && err != nil:
			t.Errorf("%s: %v", host, err)
		case wantFound && d.ProjectID == nil:
			t.Errorf("%s: project not set", host)
		case !wantFound && !errors.Is(err, domain.ErrNotFound):
			t.Errorf("%s: want ErrNotFound, got %v", host, err)
		}
	}
	// org-level domains (no project) are returned; the ask handler refuses them.
	if d, err := repo.GetByHostname(ctx, "huerfano.example.com"); err != nil || d.ProjectID != nil {
		t.Errorf("org-level domain: %v %+v", err, d)
	}

	// The lookup is an index scan on uq_domains_name, not a sequential scan.
	if _, err := pool.Exec(ctx, `SET enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(ctx, `EXPLAIN SELECT id FROM domains WHERE domain_name = 'activo.example.com' AND status IN ('verified','active') LIMIT 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	plan := ""
	for rows.Next() {
		var line string
		_ = rows.Scan(&line)
		plan += line + "\n"
	}
	if !strings.Contains(plan, "uq_domains_name") {
		t.Errorf("expected the unique index in the plan, got:\n%s", plan)
	}
}
