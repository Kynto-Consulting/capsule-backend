package repository

import (
	"testing"

	"github.com/kynto/capsule/backend/internal/gittokens"
)

// scanGitToken and scanGitSSHKey must scan exactly the columns they SELECT; a mismatch makes every
// lookup fail at runtime ("number of field descriptions must equal number of destinations").
func TestScanGitTokenMatchesColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanGitToken(row, &gittokens.Token{}); err != nil {
		t.Fatal(err)
	}
	if row.n != len(gitTokenColumns) {
		t.Fatalf("scanGitToken scans %d destinations but gitTokenColumns selects %d", row.n, len(gitTokenColumns))
	}
}

func TestScanGitSSHKeyMatchesColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanGitSSHKey(row, &gittokens.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	if row.n != len(gitSSHKeyColumns) {
		t.Fatalf("scanGitSSHKey scans %d destinations but gitSSHKeyColumns selects %d", row.n, len(gitSSHKeyColumns))
	}
}

// Only the hash is ever stored: no column of the token table may carry a value.
func TestGitTokenColumnsNeverSelectAValue(t *testing.T) {
	for _, c := range gitTokenColumns {
		if c == "token" || c == "plain" || c == "value" {
			t.Fatalf("column %q must not exist: only the hash is stored", c)
		}
	}
}
