package repository

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/environments"
)

func ncols(s string) int { return len(strings.Split(s, ",")) }

// pgx fails every query at runtime when Scan gets a different number of destinations than the
// SELECT has columns; this guards each scan of environment_repo.go.
func TestEnvironmentScansMatchColumns(t *testing.T) {
	cases := []struct {
		name string
		scan func(*countingRow) error
		cols string
	}{
		{"environment", func(r *countingRow) error { return scanEnvironment(r, &environments.Environment{}) }, envCols},
		{"promotion", func(r *countingRow) error { return scanPromotion(r, &environments.Promotion{}) }, promoCols},
		{"env deployment", func(r *countingRow) error { return scanEnvDeployment(r, &environments.EnvDeployment{}) }, envDepCols},
		{"artifact", func(r *countingRow) error { return scanArtifact(r, &environments.Artifact{}) }, "id,source_key,git_sha,build_strategy,container_port"}, // artifactCols has commas inside COALESCE
		{"pending (promotion+environment)", func(r *countingRow) error { return scanPendingRow(r, &environments.PendingRow{}) }, promoCols + "," + envColsPrefixed},
		{"approval", func(r *countingRow) error {
			return scanApproval(r, new(uuid.UUID), &environments.Approval{})
		}, approvalCols},
	}
	for _, c := range cases {
		row := &countingRow{}
		// the scans decode JSON after Scan; countingRow leaves the buffers empty, so a decode error is expected
		_ = c.scan(row)
		if want := ncols(c.cols); row.n != want {
			t.Errorf("%s: scan has %d destinations but the SELECT lists %d columns", c.name, row.n, want)
		}
	}
}
