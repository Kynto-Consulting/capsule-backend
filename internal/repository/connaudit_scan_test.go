package repository

import (
	"regexp"
	"strings"
	"testing"
)

func TestConnAuditScanDestinations(t *testing.T) {
	cases := []struct {
		name  string
		query string
		scan  func(*countingRow)
	}{
		{"suppressions", connSuppSelect, func(r *countingRow) { _, _ = scanConnSuppression(r) }},
		{"warnings", connWarnSelect, func(r *countingRow) { _, _, _ = scanConnWarnings(r) }},
	}
	for _, c := range cases {
		row := &countingRow{}
		c.scan(row)
		m := regexp.MustCompile(`(?is)SELECT\s+(.*?)\s+FROM`).FindStringSubmatch(c.query)
		if m == nil || len(strings.Split(m[1], ",")) != row.n {
			t.Errorf("%s: query columns do not match %d scan destinations", c.name, row.n)
		}
	}
}
