package repository

import (
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/gitsync"
)

func TestGitIdentityAndTeamStateScansMatchColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanGitIdentity(row, &gitsync.Identity{}); err != nil {
		t.Fatal(err)
	}
	if want := len(strings.Split(gitIdentityCols, ",")); row.n != want {
		t.Fatalf("scanGitIdentity scans %d destinations but gitIdentityCols selects %d", row.n, want)
	}
	row = &countingRow{}
	if err := scanGitTeamState(row, &gitsync.TeamState{}); err != nil {
		t.Fatal(err)
	}
	cols := strings.Split(strings.NewReplacer("\n", " ", "\t", " ").Replace(gitTeamStateCols), ",")
	if row.n != len(cols) {
		t.Fatalf("scanGitTeamState scans %d destinations but gitTeamStateCols selects %d", row.n, len(cols))
	}
}
