package repository

import "testing"

// Each recovery scanner must scan exactly the columns its SELECT list names.
func TestRecoveryScansMatchColumns(t *testing.T) {
	cases := []struct {
		name string
		cols string
		scan func(r *countingRow) error
	}{
		{"run", recoveryRunCols, func(r *countingRow) error { _, err := scanRecoveryRun(r); return err }},
		{"project", recoveryProjCols, func(r *countingRow) error { _, err := scanRecoveryProject(r); return err }},
	}
	for _, c := range cases {
		row := &countingRow{}
		// the run scanner decodes JSON destinations, which a counting row leaves empty: that error is
		// fine, only the number of destinations matters here
		_ = c.scan(row)
		if want := topLevelCols(c.cols); row.n != want {
			t.Errorf("%s: scans %d destinations but selects %d columns", c.name, row.n, want)
		}
	}
}
