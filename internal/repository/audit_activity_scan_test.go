package repository

import (
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/gitaudit"
	"github.com/kynto/capsule/backend/internal/gitinsights"
)

// Every Scan must have exactly as many destinations as its column list selects.
func TestAuditActivityScansMatchColumns(t *testing.T) {
	cases := []struct {
		name string
		cols string
		scan func(r *countingRow) error
	}{
		{"audit_logs", auditCols, func(r *countingRow) error { return scanAudit(r, &gitaudit.Entry{}) }},
		{"git_activity", gitActivityCols, func(r *countingRow) error { return scanGitActivity(r, &gitinsights.Activity{}) }},
		{"pr timeline", prEventCols, func(r *countingRow) error { return scanPREvent(r, &gitinsights.PREvent{}) }},
		{"digest candidates", digestCandidateCols, func(r *countingRow) error { return scanDigestCandidate(r, &gitinsights.DigestCandidate{}) }},
	}
	for _, c := range cases {
		row := &countingRow{}
		if err := c.scan(row); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		// column lists contain commas inside COALESCE(...): count top-level commas only
		depth, n := 0, 1
		for _, ch := range c.cols {
			switch ch {
			case '(':
				depth++
			case ')':
				depth--
			case ',':
				if depth == 0 {
					n++
				}
			}
		}
		if row.n != n {
			t.Errorf("%s scans %d destinations but its column list selects %d (%s)", c.name, row.n, n, strings.TrimSpace(c.cols))
		}
	}
}
