package repository

import (
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/domain"
)

// Each scan helper must scan exactly as many destinations as its SELECT list has columns.
func TestScanAccessRuleMatchesColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanAccessRule(row, &domain.DatabaseAccessRule{}); err != nil {
		t.Fatal(err)
	}
	if cols := len(strings.Split(accessRuleCols, ",")); row.n != cols {
		t.Fatalf("scanAccessRule scans %d destinations but accessRuleCols selects %d", row.n, cols)
	}
}

func TestScanDesiredAccessMatchesColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanDesiredAccess(row, &domain.DesiredAccess{}); err != nil {
		t.Fatal(err)
	}
	if cols := len(strings.Split(desiredAccessCols, ",")); row.n != cols {
		t.Fatalf("scanDesiredAccess scans %d destinations but desiredAccessCols selects %d", row.n, cols)
	}
}

func TestScanIPAllowlistMatchesColumns(t *testing.T) {
	row := &countingRow{}
	var out []string
	if err := scanIPAllowlist(row, &out); err != nil {
		t.Fatal(err)
	}
	if cols := len(strings.Split(ipAllowlistCols, ",")); row.n != cols {
		t.Fatalf("scanIPAllowlist scans %d destinations but ipAllowlistCols selects %d", row.n, cols)
	}
}
