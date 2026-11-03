package repository

import "testing"

// topLevelCols counts comma-separated columns outside parentheses (sub-selects).
func topLevelCols(s string) int {
	depth, cols := 0, 1
	for _, ch := range s {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				cols++
			}
		}
	}
	return cols
}

// Each scanner must scan exactly the columns its SELECT list names; a mismatch breaks every
// query at runtime ("number of field descriptions must equal number of destinations").
func TestBackupScansMatchColumns(t *testing.T) {
	cases := []struct {
		name string
		cols string
		scan func(r *countingRow) error
	}{
		{"settings", backupSettingsCols, func(r *countingRow) error { _, err := scanBackupSettings(r); return err }},
		{"run", backupRunCols, func(r *countingRow) error { _, err := scanBackupRun(r); return err }},
		{"snapshot", backupSnapCols, func(r *countingRow) error { _, err := scanBackupSnapshot(r); return err }},
		{"deploy", backupDeployCols, func(r *countingRow) error { _, err := scanBackupDeploy(r); return err }},
		{"candidate", backupCandidateCols, func(r *countingRow) error { _, err := scanBackupCandidate(r); return err }},
	}
	for _, c := range cases {
		row := &countingRow{}
		if err := c.scan(row); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if want := topLevelCols(c.cols); row.n != want {
			t.Errorf("%s: scans %d destinations but selects %d columns", c.name, row.n, want)
		}
	}
}
