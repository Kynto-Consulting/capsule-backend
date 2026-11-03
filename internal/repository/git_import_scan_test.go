package repository

import (
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/gitimport"
)

// Every Scan must have exactly as many destinations as its column list selects.
func TestGitImportScansMatchColumns(t *testing.T) {
	cases := []struct {
		name string
		cols string
		scan func(r *countingRow) error
	}{
		{"git_imports", gitImportCols, func(r *countingRow) error { return scanGitImport(r, &gitimport.Import{}) }},
		{"git_import_repos", gitImportRepoCols, func(r *countingRow) error { return scanGitImportRepo(r, &gitimport.RepoState{}) }},
		{"git_mirrors", gitMirrorCols, func(r *countingRow) error { return scanGitMirror(r, &gitimport.Mirror{}) }},
	}
	for _, c := range cases {
		row := &countingRow{}
		if err := c.scan(row); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if want := len(strings.Split(c.cols, ",")); row.n != want {
			t.Errorf("%s scans %d destinations but its column list selects %d", c.name, row.n, want)
		}
	}
	// the mirror SELECT lists the same columns, in the same order, as gitMirrorCols (has_cred is computed)
	sel := strings.Join(strings.Fields(gitMirrorSelect), " ")
	pos := 0
	for _, col := range strings.Split(gitMirrorCols, ",") {
		col = strings.TrimSpace(col)
		i := strings.Index(sel[pos:], col)
		if i < 0 {
			t.Fatalf("gitMirrorSelect does not list %q in order", col)
		}
		pos += i + len(col)
	}
}
