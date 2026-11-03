package repository

import (
	"regexp"
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/security"
)

// Every Scan must have exactly as many destinations as its column list selects, or each query
// fails at runtime ("number of field descriptions must equal number of destinations").
func TestSecurityScansMatchColumns(t *testing.T) {
	n := func(cols string) int { return len(strings.Split(cols, ",")) }
	cases := []struct {
		name string
		cols int
		scan func(r *countingRow) error
	}{
		{"security_alerts", n(securityAlertCols), func(r *countingRow) error { return scanSecurityAlert(r, &security.Alert{}, false) }},
		{"security_alerts + dismissing user", n(securityAlertSelect), func(r *countingRow) error { return scanSecurityAlert(r, &security.Alert{}, true) }},
		{"security_suppressions", n(securitySuppressionCols), func(r *countingRow) error { return scanSecuritySuppression(r, &security.Suppression{}, false) }},
		{"security_suppressions + creator", n(securitySuppressionSelect), func(r *countingRow) error { return scanSecuritySuppression(r, &security.Suppression{}, true) }},
		{"sarif_uploads", n(securityUploadCols), func(r *countingRow) error { return scanSecurityUpload(r, &security.Upload{}) }},
		{"sarif_uploads + findings (claim)", n(securityUploadCols) + 1, func(r *countingRow) error {
			var b []byte
			return scanSecurityUpload(r, &security.Upload{}, &b)
		}},
		{"security_check_runs", n(securityCheckCols), func(r *countingRow) error { return scanSecurityCheck(r, &security.CheckRun{}) }},
		{"renovate_state", n(securityRenovateCols), func(r *countingRow) error { return scanSecurityRenovate(r, &security.RenovateState{}) }},
		{"security_policies", n(securityPolicyCols), func(r *countingRow) error { return scanSecurityPolicy(r, &security.Policy{}) }},
	}
	for _, c := range cases {
		row := &countingRow{}
		if err := c.scan(row); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if row.n != c.cols {
			t.Errorf("%s scans %d destinations but its column list selects %d", c.name, row.n, c.cols)
		}
	}
}

// The INSERT of an alert must name one placeholder per column of the INSERT list, and the UPDATE
// must number its parameters without gaps.
func TestSecurityAlertSQLPlaceholders(t *testing.T) {
	cols := secN32(securityAlertCols)
	if got := strings.Count(securityInsertAlertSQL, "$"); got != cols {
		t.Errorf("insert has %d placeholders for %d columns", got, cols)
	}
	for i := 1; i <= 24; i++ {
		if !regexp.MustCompile(`\$` + secItoa(i) + `(\D|$)`).MatchString(securityUpdateAlertSQL) {
			t.Errorf("update lacks $%d", i)
		}
	}
	if strings.Contains(securityUpdateAlertSQL, "$25") {
		t.Error("update has more than 24 parameters")
	}
}

func secN32(cols string) int { return len(strings.Split(cols, ",")) }

func secItoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}
