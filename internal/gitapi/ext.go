package gitapi

import (
	"context"
	"sort"
	"time"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// Optional capabilities. gitcore.Core (A1) does not expose them yet; the handlers look for them
// with a type assertion on the shared Core, so they light up the day A1 adds the methods and answer
// 501 NOT_SUPPORTED until then. Signatures are the contract A1 should implement.

// SecretInfo is a secret as listed: the value is never readable.
type SecretInfo struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SecretLister lists secret NAMES of a repository (r.Repo == "" for the organization).
type SecretLister interface {
	ListSecrets(ctx context.Context, r gitcore.RepoRef) ([]SecretInfo, error)
}

// Runner is an Actions runner.
type Runner struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Labels  []string `json:"labels"`
	Status  string   `json:"status"` // online|offline|busy
	Trusted bool     `json:"trusted"`
}

// RunnerLister lists the runners of an organization.
type RunnerLister interface {
	ListRunners(ctx context.Context, org string) ([]Runner, error)
}

// Artifact is a run artifact.
type Artifact struct {
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	DownloadURL string    `json:"download_url"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ArtifactLister lists the artifacts of a run.
type ArtifactLister interface {
	ListArtifacts(ctx context.Context, r gitcore.RepoRef, runID int64) ([]Artifact, error)
}

// RunRerunner re-runs a run (failedOnly: only its failed jobs) and returns the new run.
type RunRerunner interface {
	RerunRun(ctx context.Context, r gitcore.RepoRef, runID int64, failedOnly bool) (*gitcore.Run, error)
}

// Median of durations in seconds (0 for no data); even counts average the two middle values.
func MedianSeconds(d []time.Duration) int {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	n := len(s)
	if n%2 == 1 {
		return int(s[n/2].Seconds())
	}
	return int((s[n/2-1] + s[n/2]).Seconds() / 2)
}
