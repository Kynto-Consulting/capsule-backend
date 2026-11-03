//go:build dbtest

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/connaudit"
)

// Run with: go test -tags dbtest ./internal/repository -run ConnAudit (TEST_DATABASE_URL set).
func TestConnAuditRepoDB(t *testing.T) {
	pool := sharedPool(t)
	ctx := context.Background()
	var orgID, projID, depID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organizations (name, slug) VALUES ('ca','ca-`+uuid.NewString()[:8]+`') RETURNING id`).Scan(&orgID); err != nil {
		t.Skipf("fixture insert failed (schema drift): %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO projects (org_id, name, slug) VALUES ($1,'p','p-`+uuid.NewString()[:8]+`') RETURNING id`, orgID).Scan(&projID); err != nil {
		t.Skipf("fixture insert failed (schema drift): %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO deployments (project_id, version, status) VALUES ($1,'v','queued') RETURNING id`, projID).Scan(&depID); err != nil {
		t.Skipf("fixture insert failed (schema drift): %v", err)
	}
	r := NewConnAuditRepository(pool)
	if m, err := r.Mode(ctx, projID); err != nil || m != connaudit.ModeWarn {
		t.Fatalf("default mode %v %v", m, err)
	}
	if err := r.SetMode(ctx, projID, connaudit.ModeStrict); err != nil {
		t.Fatal(err)
	}
	if m, _ := r.Mode(ctx, projID); m != connaudit.ModeStrict {
		t.Fatal("mode not stored")
	}
	f := []connaudit.Finding{{ID: "aaaaaaaaaaaa", Severity: connaudit.SevCritical, Kind: connaudit.KindMetadata, Source: "env:X", Endpoint: "http://169.254.169.254:80"}}
	if err := r.SaveFindings(ctx, depID, f); err != nil {
		t.Fatal(err)
	}
	got, err := r.FindingsFor(ctx, []uuid.UUID{depID})
	if err != nil || len(got[depID]) != 1 || got[depID][0].ID != "aaaaaaaaaaaa" {
		t.Fatalf("%v %v", got, err)
	}
	exp := time.Now().Add(time.Hour)
	if err := r.PutSuppression(ctx, projID, connaudit.Suppression{FindingID: "aaaaaaaaaaaa", Reason: "motivo valido", ExpiresAt: &exp, CreatedBy: "u"}); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.Suppressions(ctx, projID); len(s) != 1 || s[0].ExpiresAt == nil {
		t.Fatalf("%v", s)
	}
	if err := r.DeleteSuppression(ctx, projID, "aaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.Suppressions(ctx, projID); len(s) != 0 {
		t.Fatal("not deleted")
	}
}
