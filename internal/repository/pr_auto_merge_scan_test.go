package repository

import (
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/gitreview"
)

// pgx fails every query at runtime when Scan gets a different number of destinations than the
// SELECT has columns.
func TestPRAutoMergeScanMatchesColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanPRAutoMerge(row, &gitreview.AutoMerge{}); err != nil {
		t.Fatal(err)
	}
	cols := strings.Split(strings.NewReplacer("\n", " ", "\t", " ").Replace(prAutoMergeCols), ",")
	if row.n != len(cols) {
		t.Fatalf("scanPRAutoMerge scans %d destinations but prAutoMergeCols selects %d", row.n, len(cols))
	}
}

func TestPRReviewDismissalScanMatchesColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanPRReviewDismissal(row, &gitreview.Dismissal{}); err != nil {
		t.Fatal(err)
	}
	if want := len(strings.Split(prReviewDismissalCols, ",")); row.n != want {
		t.Fatalf("scanPRReviewDismissal scans %d destinations but prReviewDismissalCols selects %d", row.n, want)
	}
}
