package repository

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
)

func TestScanProjectMemberMatchesColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanProjectMember(row, &authz.Member{}); err != nil {
		t.Fatal(err)
	}
	if cols := len(strings.Split(projectMemberCols, ",")); row.n != cols {
		t.Fatalf("scanProjectMember scans %d destinations but projectMemberCols selects %d", row.n, cols)
	}
}

func TestScanExplicitRoleMatchesColumns(t *testing.T) {
	row := &countingRow{}
	var id uuid.UUID
	var role string
	if err := scanExplicitRole(row, &id, &role); err != nil {
		t.Fatal(err)
	}
	if cols := len(strings.Split(explicitRoleCols, ",")); row.n != cols {
		t.Fatalf("scanExplicitRole scans %d destinations but explicitRoleCols selects %d", row.n, cols)
	}
}

func TestScanGrantMatchesColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanGrant(row, &authz.Grant{}); err != nil {
		t.Fatal(err)
	}
	// grantCols contains a COALESCE(x, '') whose comma is inside parentheses.
	cols := len(strings.Split(strings.Replace(grantCols, "COALESCE(pm.role, '')", "COALESCE(pm.role)", 1), ","))
	if row.n != cols {
		t.Fatalf("scanGrant scans %d destinations but grantCols selects %d", row.n, cols)
	}
}
