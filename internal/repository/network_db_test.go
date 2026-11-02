//go:build dbtest

package repository

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
)

// Run with: TEST_DATABASE_URL=postgres://... go test -tags dbtest ./internal/repository -run TestNetworkDB
// against a throwaway database (it applies every migration and writes fixtures).
func TestNetworkDB(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	var userID, orgID, projID, dbID uuid.UUID
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(pool.QueryRow(ctx, `INSERT INTO users (email, password_hash, name) VALUES ($1,'x','T') RETURNING id`, uuid.NewString()+"@x.io").Scan(&userID))
	must(pool.QueryRow(ctx, `INSERT INTO organizations (name, slug, owner_id) VALUES ('O',$2,$1) RETURNING id`, userID, uuid.NewString()).Scan(&orgID))
	must(pool.QueryRow(ctx, `INSERT INTO projects (org_id, name, slug) VALUES ($1,'P',$2) RETURNING id`, orgID, uuid.NewString()).Scan(&projID))
	must(pool.QueryRow(ctx, `INSERT INTO databases (project_id, org_id, name, host, db_name, credentials_enc, port, status)
		VALUES ($1,$2,'d','h','db',convert_to('x','UTF8'),40123,'available') RETURNING id`, projID, orgID).Scan(&dbID))

	repo := NewDatabaseAccessRepository(pool)
	rule := func(c string) *domain.DatabaseAccessRule {
		return &domain.DatabaseAccessRule{DatabaseID: dbID, CIDR: c, Description: "d"}
	}

	// Add + duplicate + list
	a, err := repo.Add(ctx, rule("203.0.113.5/32"), 3)
	must(err)
	if a.ID == uuid.Nil || a.CIDR != "203.0.113.5/32" {
		t.Fatalf("add returned %+v", a)
	}
	if _, err := repo.Add(ctx, rule("203.0.113.5/32"), 3); err != domain.ErrConflict {
		t.Fatalf("duplicate add: want ErrConflict, got %v", err)
	}
	_, err = repo.Add(ctx, rule("198.51.100.0/24"), 3)
	must(err)
	_, err = repo.Add(ctx, rule("192.0.2.0/24"), 3)
	must(err)
	if _, err := repo.Add(ctx, rule("10.0.0.0/8"), 3); err != domain.ErrRuleLimit {
		t.Fatalf("limit: want ErrRuleLimit, got %v", err)
	}
	list, err := repo.List(ctx, dbID)
	must(err)
	if len(list) != 3 {
		t.Fatalf("list len %d", len(list))
	}

	// Desired (startup reconcile)
	des, err := repo.ListDesired(ctx)
	must(err)
	if len(des) != 3 || des[0].Port != 40123 {
		t.Fatalf("desired %+v", des)
	}

	// Replace: keeps one, adds one, drops two
	out, err := repo.Replace(ctx, dbID, []*domain.DatabaseAccessRule{rule("198.51.100.0/24"), rule("100.64.0.0/10")}, userID)
	must(err)
	if len(out) != 2 {
		t.Fatalf("replace len %d", len(out))
	}
	got := map[string]bool{}
	for _, r := range out {
		got[r.CIDR] = true
	}
	if !got["198.51.100.0/24"] || !got["100.64.0.0/10"] {
		t.Fatalf("replace result %v", got)
	}
	// Replace is idempotent and can empty the list
	_, err = repo.Replace(ctx, dbID, []*domain.DatabaseAccessRule{rule("198.51.100.0/24"), rule("100.64.0.0/10")}, userID)
	must(err)
	out, err = repo.Replace(ctx, dbID, nil, userID)
	must(err)
	if len(out) != 0 {
		t.Fatalf("empty replace len %d", len(out))
	}

	// Delete / DeleteAll
	r1, err := repo.Add(ctx, rule("203.0.113.9/32"), 5)
	must(err)
	must(repo.Delete(ctx, dbID, r1.ID))
	if err := repo.Delete(ctx, dbID, r1.ID); err != domain.ErrNotFound {
		t.Fatalf("second delete: want ErrNotFound, got %v", err)
	}
	_, err = repo.Add(ctx, rule("203.0.113.10/32"), 5)
	must(err)
	must(repo.DeleteAll(ctx, dbID))
	if l, _ := repo.List(ctx, dbID); len(l) != 0 {
		t.Fatalf("deleteall left %d", len(l))
	}

	// Project allowlist
	nr := NewProjectNetworkRepository(pool)
	if l, err := nr.GetIPAllowlist(ctx, projID); err != nil || len(l) != 0 {
		t.Fatalf("empty allowlist: %v %v", l, err)
	}
	must(nr.SetIPAllowlist(ctx, projID, []string{"203.0.113.0/24", "198.51.100.7/32"}))
	l, err := nr.GetIPAllowlist(ctx, projID)
	must(err)
	if len(l) != 2 {
		t.Fatalf("allowlist %v", l)
	}
	must(nr.SetIPAllowlist(ctx, projID, nil))
	if l, _ := nr.GetIPAllowlist(ctx, projID); len(l) != 0 {
		t.Fatalf("cleared allowlist %v", l)
	}
}
