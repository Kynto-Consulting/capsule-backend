// Package recovery implements Git Capsule package C3: total recovery (docs/git-capsule/DR-BACKUP.md).
//
// `recover plan` is a PURE function of (Request, Catalog): same input, same Plan (and same PlanID).
// `recover apply` walks the plan phase by phase (F0..F9); every step is check -> apply -> verify and
// its result is written to a journal, so repeating a step, or resuming a run, never doubles an effect.
// `recover verify` runs only the verification half and changes nothing.
package recovery

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// Mode is the operation requested (matches RecoverRequest.mode in the API contract).
type Mode string

const (
	ModePlan   Mode = "plan"
	ModeApply  Mode = "apply"
	ModeVerify Mode = "verify"
)

// Target is where data is restored. Ephemeral never touches DNS, the elastic IP or production.
type Target string

const (
	TargetInPlace   Target = "in_place"
	TargetEphemeral Target = "ephemeral"
)

// Scope selects phases (RecoverRequest.scope).
type Scope string

const (
	ScopeNetwork   Scope = "network"
	ScopeCore      Scope = "core"
	ScopeGit       Scope = "git"
	ScopeDatabases Scope = "databases"
	ScopeVolumes   Scope = "volumes"
	ScopeProjects  Scope = "projects"
	ScopeDNS       Scope = "dns"
)

// scopeOrder is the canonical order (the order of the phases).
var scopeOrder = []Scope{ScopeNetwork, ScopeCore, ScopeGit, ScopeDatabases, ScopeVolumes, ScopeProjects, ScopeDNS}

var (
	platformScopes = append([]Scope(nil), scopeOrder...)
	projectScopes  = []Scope{ScopeDatabases, ScopeVolumes, ScopeProjects}
)

var (
	ErrInvalid       = errors.New("recovery: invalid request")
	ErrActive        = errors.New("recovery: another recovery is already running")
	ErrNotFound      = errors.New("recovery: not found")
	ErrManifest      = errors.New("recovery: manifest rejected")
	ErrChecksum      = errors.New("recovery: checksum mismatch")
	ErrNeedOverwrite = errors.New("recovery: destination holds different data; --force-overwrite is required")
)

// Request is the normalized input of plan/apply/verify.
type Request struct {
	Mode           Mode       `json:"mode"`
	ProjectID      *uuid.UUID `json:"project_id,omitempty"` // nil with All = platform recovery
	All            bool       `json:"all,omitempty"`
	SnapshotID     *uuid.UUID `json:"snapshot_id,omitempty"`
	At             *time.Time `json:"point_in_time,omitempty"`
	Target         Target     `json:"target"`
	Scopes         []Scope    `json:"scope"`
	ApplyInfra     bool       `json:"apply_infra,omitempty"`     // F1/F2 terraform apply and RDS restore need this explicit flag
	ForceOverwrite bool       `json:"force_overwrite,omitempty"` // destructive overwrite of existing data (a pre-restore copy is kept)
	ContinueOnErr  bool       `json:"continue_on_error,omitempty"`
}

// Normalize validates the request and returns it in canonical form (default target and scopes,
// scopes deduplicated and in phase order, times in UTC). It never mutates r.
func (r Request) Normalize() (Request, error) {
	switch r.Mode {
	case ModePlan, ModeApply, ModeVerify:
	default:
		return r, fmt.Errorf("%w: mode must be plan, apply or verify", ErrInvalid)
	}
	if r.All == (r.ProjectID != nil) {
		return r, fmt.Errorf("%w: choose exactly one of a project or --all", ErrInvalid)
	}
	if r.Target == "" {
		r.Target = TargetInPlace
	}
	if r.Target != TargetInPlace && r.Target != TargetEphemeral {
		return r, fmt.Errorf("%w: target must be in_place or ephemeral", ErrInvalid)
	}
	if r.SnapshotID != nil && r.At != nil {
		return r, fmt.Errorf("%w: --snapshot and --at are mutually exclusive", ErrInvalid)
	}
	if r.SnapshotID != nil && r.All {
		return r, fmt.Errorf("%w: --snapshot only applies to one project", ErrInvalid)
	}
	if r.At != nil {
		u := r.At.UTC()
		r.At = &u
	}
	allowed := projectScopes
	if r.All {
		allowed = platformScopes
	}
	want := r.Scopes
	if len(want) == 0 {
		want = allowed
	}
	set := map[Scope]bool{}
	for _, s := range want {
		if !containsScope(allowed, s) {
			return r, fmt.Errorf("%w: scope %q is not valid for this recovery", ErrInvalid, s)
		}
		set[s] = true
	}
	if r.Target == TargetEphemeral && set[ScopeDNS] {
		return r, fmt.Errorf("%w: an ephemeral recovery never touches DNS", ErrInvalid)
	}
	r.Scopes = nil
	for _, s := range scopeOrder {
		if set[s] {
			r.Scopes = append(r.Scopes, s)
		}
	}
	return r, nil
}

func containsScope(l []Scope, s Scope) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (r Request) hasScope(s Scope) bool { return containsScope(r.Scopes, s) }

// ---------------------------------------------------------------------------------------------
// Catalog: everything the planner may look at. Building it does the I/O; planning does none.
// ---------------------------------------------------------------------------------------------

// SnapshotRef is a backup object (a row of backup_snapshots, or one derived from the bucket layout).
type SnapshotRef struct {
	ID        uuid.UUID  `json:"id"`
	ProjectID *uuid.UUID `json:"project_id,omitempty"`
	Kind      string     `json:"kind"` // database | volume | manifest | platform
	Source    string     `json:"source"`
	SourceID  string     `json:"source_id,omitempty"`
	Engine    string     `json:"engine,omitempty"`
	ObjectKey string     `json:"object_key"`
	Size      int64      `json:"size_bytes"`
	Checksum  string     `json:"checksum,omitempty"` // sha256 of the plaintext; empty when the catalog came from the bucket only
	CreatedAt time.Time  `json:"created_at"`
}

// DumpRef is a `forgejo dump` object (encrypted with openssl, sidecar .sha256).
type DumpRef struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size_bytes"`
	LastModified time.Time `json:"last_modified"`
	Sha256       string    `json:"sha256,omitempty"` // from the sidecar; empty when the sidecar is missing
}

// ProjectEntry is one project and its backups.
type ProjectEntry struct {
	ID        uuid.UUID     `json:"id"`
	Slug      string        `json:"slug"`
	GitReady  bool          `json:"git_ready"`
	Snapshots []SnapshotRef `json:"snapshots"`
	// Manifest is the latest manifest that PASSED verification (nil when none or when rejected).
	Manifest    *ManifestSummary `json:"manifest,omitempty"`
	ManifestErr string           `json:"manifest_error,omitempty"` // why the newest manifest was rejected
}

// ManifestSummary is what the planner needs from a verified manifest (references only).
type ManifestSummary struct {
	SnapshotID uuid.UUID `json:"snapshot_id"`
	Databases  []string  `json:"databases"` // manifest databases[].id
	Volumes    []string  `json:"volumes"`   // manifest volumes[].name
	HasSource  bool      `json:"has_source"`
	Deployment string    `json:"deployment,omitempty"`
}

// Catalog is the planner's whole world. Now participates only in age-based risks.
type Catalog struct {
	Now          time.Time      `json:"now"`
	Projects     []ProjectEntry `json:"projects"`
	Platform     []SnapshotRef  `json:"platform"`
	ForgejoDumps []DumpRef      `json:"forgejo_dumps"`
	FromBucket   bool           `json:"from_bucket,omitempty"` // bootstrap catalog: no stored checksums
}

// ---------------------------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------------------------

// Kind identifies which executor runs a step.
type Kind string

const (
	KindPreflight Kind = "preflight"
	KindNetwork   Kind = "network"
	KindCore      Kind = "core"
	KindPlatform  Kind = "platform-files"
	KindGit       Kind = "git"
	KindDatabase  Kind = "database"
	KindVolume    Kind = "volume"
	KindProject   Kind = "project"
	KindDNS       Kind = "dns"
	KindSmoke     Kind = "smoke"
	KindReport    Kind = "report"
)

// Step is one entry of the plan.
type Step struct {
	ID              string       `json:"id"`
	Phase           string       `json:"phase"` // F0..F9
	Kind            Kind         `json:"kind"`
	Name            string       `json:"name"`
	ProjectID       *uuid.UUID   `json:"project_id,omitempty"`
	Snapshot        *SnapshotRef `json:"snapshot,omitempty"`
	Dump            *DumpRef     `json:"dump,omitempty"`
	DependsOn       []string     `json:"depends_on,omitempty"`
	Destructive     bool         `json:"destructive,omitempty"`
	NeedsInfraFlag  bool         `json:"needs_apply_infra,omitempty"`
	ContinueOnError bool         `json:"continue_on_error,omitempty"`
	EstimateSec     int          `json:"estimate_seconds"`
}

// Risk is something the plan found that the operator must know before applying.
type Risk struct {
	Code      string     `json:"code"`
	Severity  string     `json:"severity"` // error | warning
	Subject   string     `json:"subject"`
	ProjectID *uuid.UUID `json:"project_id,omitempty"`
	Message   string     `json:"message"`
}

// Plan is deterministic: its JSON never depends on the clock, map order or goroutines.
type Plan struct {
	PlanID  string  `json:"plan_id"` // sha256 of the canonical plan (request + steps + risks)
	Request Request `json:"request"`
	Steps   []Step  `json:"steps"`
	Risks   []Risk  `json:"risks"`
	// Ready is false when any risk has severity "error" (apply then needs ContinueOnErr).
	Ready          bool `json:"ready"`
	EstimateSecond int  `json:"estimate_seconds"`
}

// Blockers returns the error-severity risks.
func (p Plan) Blockers() []Risk {
	var out []Risk
	for _, r := range p.Risks {
		if r.Severity == "error" {
			out = append(out, r)
		}
	}
	return out
}

func sortRisks(rs []Risk) {
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.Severity != b.Severity {
			return a.Severity == "error"
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Subject < b.Subject
	})
}

// ---------------------------------------------------------------------------------------------
// Run journal
// ---------------------------------------------------------------------------------------------

type StepStatus string

const (
	StepPending StepStatus = "pending"
	StepRunning StepStatus = "running"
	StepOK      StepStatus = "ok"
	StepSkipped StepStatus = "skipped"
	StepFailed  StepStatus = "failed"
)

type RunStatus string

const (
	RunPlanned RunStatus = "planned"
	RunRunning RunStatus = "running"
	RunSuccess RunStatus = "success"
	RunFailed  RunStatus = "failed"
	RunPartial RunStatus = "partial"
)

// StepState is the journal entry of one step (the `steps` element of RecoverRun in the API).
type StepState struct {
	Name       string     `json:"name"`
	ID         string     `json:"id"`
	Phase      string     `json:"phase"`
	Status     StepStatus `json:"status"`
	Detail     string     `json:"detail"`
	Attempts   int        `json:"attempts,omitempty"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

// Run is a recovery run as stored in recovery_runs and returned by the API (RecoverRun).
type Run struct {
	ID             uuid.UUID   `json:"id"`
	Mode           Mode        `json:"mode"`
	Status         RunStatus   `json:"status"`
	Request        Request     `json:"request"`
	PlanID         string      `json:"plan_id"`
	Steps          []StepState `json:"steps"`
	ReportURL      string      `json:"report_url,omitempty"`
	Error          string      `json:"error,omitempty"`
	IdempotencyKey string      `json:"-"`
	RequestedBy    *uuid.UUID  `json:"-"`
	StartedAt      time.Time   `json:"started_at"`
	FinishedAt     *time.Time  `json:"finished_at,omitempty"`
}

func (r *Run) step(id string) *StepState {
	for i := range r.Steps {
		if r.Steps[i].ID == id {
			return &r.Steps[i]
		}
	}
	return nil
}
