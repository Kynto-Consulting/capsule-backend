//go:build dbtest

package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/recovery"
)

// Run with TEST_DATABASE_URL pointing at a throwaway Postgres: go test -tags dbtest ./internal/repository -run Recovery
func TestRecoveryRunJournalDB(t *testing.T) {
	pool := freshDB(t)
	ctx := context.Background()
	applyUpTo(t, pool, 1<<30)
	repo := NewRecoveryRepository(pool)

	mk := func(mode recovery.Mode, key string) *recovery.Run {
		return &recovery.Run{ID: uuid.New(), Mode: mode, Status: recovery.RunRunning, PlanID: "p", StartedAt: time.Now().UTC(),
			Request: recovery.Request{Mode: mode, All: true, Target: recovery.TargetEphemeral, Scopes: []recovery.Scope{recovery.ScopeGit}},
			Steps:   []recovery.StepState{{ID: "f0-preflight", Name: "F0", Phase: "F0", Status: recovery.StepPending}}, IdempotencyKey: key}
	}
	a := mk(recovery.ModeApply, "k1")
	if _, created, err := repo.Begin(ctx, a); err != nil || !created {
		t.Fatalf("begin: %v created=%v", err, created)
	}
	// one apply at a time
	if _, _, err := repo.Begin(ctx, mk(recovery.ModeApply, "k2")); !errors.Is(err, recovery.ErrActive) {
		t.Fatalf("second apply must be ErrActive, got %v", err)
	}
	// verify runs are not blocked
	if _, created, err := repo.Begin(ctx, mk(recovery.ModeVerify, "")); err != nil || !created {
		t.Fatalf("verify blocked: %v", err)
	}
	// same Idempotency-Key returns the first run, creates nothing
	ex, created, err := repo.Begin(ctx, mk(recovery.ModeApply, "k1"))
	if err != nil || created || ex == nil || ex.ID != a.ID {
		t.Fatalf("idempotency: %v created=%v ex=%+v", err, created, ex)
	}
	// journal round trip
	a.Steps[0].Status, a.Status = recovery.StepOK, recovery.RunSuccess
	fin := time.Now().UTC()
	a.FinishedAt = &fin
	if err := repo.Save(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(ctx, a.ID)
	if err != nil || got.Steps[0].Status != recovery.StepOK || got.Status != recovery.RunSuccess || got.Request.Target != recovery.TargetEphemeral {
		t.Fatalf("get: %v %+v", err, got)
	}
	// the slot is free again after the apply finished
	if _, created, err := repo.Begin(ctx, mk(recovery.ModeApply, "k3")); err != nil || !created {
		t.Fatalf("slot not released: %v", err)
	}
	if n, err := repo.FailOrphans(ctx); err != nil || n < 1 {
		t.Fatalf("orphans: %d %v", n, err)
	}
	if _, err := repo.Get(ctx, uuid.New()); !errors.Is(err, recovery.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestRecoveryCatalogQueriesDB(t *testing.T) {
	pool := sharedPool(t)
	repo := NewRecoveryRepository(pool)
	ctx := context.Background()
	if _, err := repo.Projects(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Snapshots(ctx); err != nil {
		t.Fatal(err)
	}
}
