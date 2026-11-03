//go:build dbtest

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestCIDRColumnsHoldIPv6 checks migration 000059: the cidr columns of
// database_access_rules and project_port_rules widen from varchar(18) and a
// 43-char IPv6 CIDR fits, while before the migration it does not.
func TestCIDRColumnsHoldIPv6(t *testing.T) {
	ctx := context.Background()
	pool := freshDB(t)
	applyUpTo(t, pool, 58)
	f := newFx(t, pool)
	user := f.user("", time.Now())
	org := f.org(user)
	proj := f.project(org, "")

	var portID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO project_ports (project_id, container_port, host_port) VALUES ($1, 8080, 20001) RETURNING id`, proj).Scan(&portID); err != nil {
		t.Fatal(err)
	}
	long := "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
	if len(long) != 43 {
		t.Fatalf("fixture length %d", len(long))
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_port_rules (port_id, cidr) VALUES ($1,$2)`, portID, long); err == nil {
		t.Fatal("varchar(18) should reject an IPv6 CIDR before 000059")
	}

	up, err := MigrationsFS.ReadFile("migrations/000059_cidr_ipv6.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // second run proves idempotence
		if _, err := pool.Exec(ctx, string(up)); err != nil {
			t.Fatalf("000059 run %d: %v", i+1, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_port_rules (port_id, cidr) VALUES ($1,$2)`, portID, long); err != nil {
		t.Fatalf("port rule IPv6: %v", err)
	}
	var maxLen int
	for _, tbl := range []string{"database_access_rules", "project_port_rules"} {
		if err := pool.QueryRow(ctx, `SELECT character_maximum_length FROM information_schema.columns WHERE table_name=$1 AND column_name='cidr'`, tbl).Scan(&maxLen); err != nil {
			t.Fatal(err)
		}
		if maxLen != 43 {
			t.Errorf("%s.cidr length = %d, want 43", tbl, maxLen)
		}
	}
}
