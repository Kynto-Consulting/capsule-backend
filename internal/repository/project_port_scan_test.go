package repository

import (
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/domain"
)

func TestScanProjectPortMatchesColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanProjectPort(row, &domain.ProjectPort{}); err != nil {
		t.Fatal(err)
	}
	if cols := len(strings.Split(projectPortCols, ",")); row.n != cols {
		t.Fatalf("scanProjectPort scans %d destinations but projectPortCols selects %d", row.n, cols)
	}
}

func TestScanPortRuleMatchesColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanPortRule(row, &domain.PortRule{}); err != nil {
		t.Fatal(err)
	}
	if cols := len(strings.Split(portRuleCols, ",")); row.n != cols {
		t.Fatalf("scanPortRule scans %d destinations but portRuleCols selects %d", row.n, cols)
	}
}

func TestScanDesiredPortRuleMatchesColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanDesiredPortRule(row, &domain.DesiredPortRule{}); err != nil {
		t.Fatal(err)
	}
	if cols := len(strings.Split(desiredPortRuleCols, ",")); row.n != cols {
		t.Fatalf("scanDesiredPortRule scans %d destinations but desiredPortRuleCols selects %d", row.n, cols)
	}
}

func TestScanUsedPortMatchesColumns(t *testing.T) {
	row := &countingRow{}
	var p int
	if err := scanUsedPort(row, &p); err != nil {
		t.Fatal(err)
	}
	if cols := len(strings.Split(usedPortCols, ",")); row.n != cols {
		t.Fatalf("scanUsedPort scans %d destinations but usedPortCols selects %d", row.n, cols)
	}
}
