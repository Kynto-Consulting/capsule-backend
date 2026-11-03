package repository

import (
	"strings"
	"testing"
)

// scanGit / scanPreview must scan exactly the selected columns; a mismatch
// breaks every query at runtime ("number of field descriptions must equal number of destinations").
func TestScanGitMatchesColumns(t *testing.T) {
	cols := len(strings.Split(gitCols, ","))
	row := &countingRow{}
	if _, err := (&GitRepository{}).scanGit(row); err != nil {
		t.Fatal(err)
	}
	if row.n != cols {
		t.Fatalf("scanGit scans %d destinations but gitCols selects %d columns", row.n, cols)
	}
}

func TestScanPreviewMatchesColumns(t *testing.T) {
	// previewCols contains two scalar sub-selects with commas inside parentheses: count top-level columns.
	depth, cols := 0, 1
	for _, ch := range previewCols {
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
	row := &countingRow{}
	if _, err := scanPreview(row); err != nil {
		t.Fatal(err)
	}
	if row.n != cols {
		t.Fatalf("scanPreview scans %d destinations but previewCols selects %d columns", row.n, cols)
	}
}
