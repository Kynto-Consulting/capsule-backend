package repository

import (
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/gitprotect"
)

// pgx fails every query at runtime when Scan gets a different number of destinations than the
// SELECT has columns; this guards the three scans of branch_protection_repo.go.
func TestBranchProtectionScansMatchColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanBranchProtection(row, &gitprotect.Rule{}); err != nil {
		t.Fatal(err)
	}
	if want := len(strings.Split(branchProtectionCols, ",")); row.n != want {
		t.Fatalf("scanBranchProtection scans %d destinations but branchProtectionCols selects %d", row.n, want)
	}
	row = &countingRow{}
	if err := scanBranchProtectionSync(row, &gitprotect.SyncState{}); err != nil {
		t.Fatal(err)
	}
	if want := len(strings.Split(branchProtectionSyncCols, ",")); row.n != want {
		t.Fatalf("scanBranchProtectionSync scans %d destinations but branchProtectionSyncCols selects %d", row.n, want)
	}
	row = &countingRow{}
	if err := scanBranchProtectionTarget(row, &gitprotect.Target{}); err != nil {
		t.Fatal(err)
	}
	if want := len(strings.Split(branchProtectionTargetCols, ",")); row.n != want {
		t.Fatalf("scanBranchProtectionTarget scans %d destinations but branchProtectionTargetCols selects %d", row.n, want)
	}
}
