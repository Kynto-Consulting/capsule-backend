package repository

import (
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/domain"
)

type countingRow struct{ n int }

func (c *countingRow) Scan(dest ...any) error { c.n = len(dest); return nil }

// scanToken must scan exactly the columns in tokenCols; a mismatch makes every
// token lookup fail at runtime ("number of field descriptions must equal number of destinations").
func TestScanTokenMatchesColumns(t *testing.T) {
	cols := len(strings.Split(tokenCols, ","))
	row := &countingRow{}
	if err := scanToken(row, &domain.APIToken{}); err != nil {
		t.Fatal(err)
	}
	if row.n != cols {
		t.Fatalf("scanToken scans %d destinations but tokenCols selects %d columns", row.n, cols)
	}
}
