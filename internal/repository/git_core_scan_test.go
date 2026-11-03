package repository

import (
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/domain"
)

func TestGitCoreScansMatchColumns(t *testing.T) {
	row := &countingRow{}
	if err := scanGitCoreState(row, &domain.GitCoreState{}); err != nil {
		t.Fatal(err)
	}
	if want := len(strings.Split(gitCoreStateCols, ",")); row.n != want {
		t.Fatalf("scanGitCoreState scans %d destinations but gitCoreStateCols selects %d", row.n, want)
	}
	row = &countingRow{}
	if err := scanGitTeamSync(row, &domain.GitTeamSync{}); err != nil {
		t.Fatal(err)
	}
	if want := len(strings.Split(gitTeamSyncCols, ",")); row.n != want {
		t.Fatalf("scanGitTeamSync scans %d destinations but gitTeamSyncCols selects %d", row.n, want)
	}
}
