package recovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/kynto/capsule/backend/internal/backup"
)

// Objectives (DR-BACKUP.md section 9). RTO is "not measured" until a real drill proves it.
const (
	RTOObjective      = 4 * time.Hour
	RPOGitObjective   = 6 * time.Hour
	DrillMaxAge       = 35 * 24 * time.Hour
	reportSchemaValue = 1
)

type PhaseTiming struct {
	Phase    string  `json:"phase"`
	Seconds  float64 `json:"seconds"`
	Steps    int     `json:"steps"`
	Failures int     `json:"failures"`
}

type SourceUsed struct {
	Step     string `json:"step"`
	Kind     string `json:"kind"`
	Source   string `json:"source"`
	Object   string `json:"object"`
	AgeHours int    `json:"age_hours"` // real RPO of this piece at the start of the run
}

// Report is the recovery/drill report (JSON written to S3 drills/ or recoveries/, rendered as Markdown).
type Report struct {
	Schema       int               `json:"schema"`
	RunID        string            `json:"run_id"`
	Mode         Mode              `json:"mode"`
	Target       Target            `json:"target"`
	PlanID       string            `json:"plan_id"`
	StartedAt    time.Time         `json:"started_at"`
	FinishedAt   time.Time         `json:"finished_at"`
	Status       RunStatus         `json:"status"`
	DurationSec  float64           `json:"duration_seconds"` // measured RTO of this run
	RTOObjective string            `json:"rto_objective"`
	Phases       []PhaseTiming     `json:"phases"`
	Used         []SourceUsed      `json:"used"`
	WorstRPOHrs  int               `json:"worst_rpo_hours"`
	Steps        []StepState       `json:"steps"`
	Risks        []Risk            `json:"risks"`
	Red          []string          `json:"red_conditions"` // empty = green
	Green        bool              `json:"green"`
	Tools        map[string]string `json:"tool_versions,omitempty"`
}

// BuildReport assembles the report from a finished (or running: F9 runs inside the run) journal.
// lastDrill is when the previous successful drill ended (zero = never).
func BuildReport(run *Run, plan Plan, now, lastDrill time.Time, tools map[string]string) Report {
	r := Report{Schema: reportSchemaValue, RunID: run.ID.String(), Mode: run.Mode, Target: plan.Request.Target, PlanID: plan.PlanID,
		StartedAt: run.StartedAt.UTC(), FinishedAt: now.UTC(), Status: run.Status, RTOObjective: RTOObjective.String(),
		Steps: run.Steps, Risks: plan.Risks, Tools: tools, Phases: []PhaseTiming{}, Used: []SourceUsed{}, Red: []string{}}
	r.DurationSec = now.Sub(run.StartedAt).Seconds()
	byPhase := map[string]*PhaseTiming{}
	for _, s := range run.Steps {
		pt := byPhase[s.Phase]
		if pt == nil {
			pt = &PhaseTiming{Phase: s.Phase}
			byPhase[s.Phase] = pt
		}
		pt.Steps++
		if s.Status == StepFailed {
			pt.Failures++
		}
		if s.StartedAt != nil && s.FinishedAt != nil {
			pt.Seconds += s.FinishedAt.Sub(*s.StartedAt).Seconds()
		}
	}
	for p := range byPhase {
		r.Phases = append(r.Phases, *byPhase[p])
	}
	sort.Slice(r.Phases, func(i, j int) bool { return r.Phases[i].Phase < r.Phases[j].Phase })
	for _, st := range plan.Steps {
		var obj, kind, src string
		var created time.Time
		switch {
		case st.Snapshot != nil:
			obj, kind, src, created = st.Snapshot.ObjectKey, st.Snapshot.Kind, st.Snapshot.Source, st.Snapshot.CreatedAt
		case st.Dump != nil:
			obj, kind, src, created = st.Dump.Key, "forgejo-dump", "forgejo", st.Dump.LastModified
		default:
			continue
		}
		age := int(run.StartedAt.Sub(created).Hours())
		if age > r.WorstRPOHrs {
			r.WorstRPOHrs = age
		}
		r.Used = append(r.Used, SourceUsed{Step: st.ID, Kind: kind, Source: src, Object: obj, AgeHours: age})
	}
	for _, s := range run.Steps {
		if s.Status == StepFailed {
			r.Red = append(r.Red, fmt.Sprintf("step %s failed: %s", s.ID, s.Detail))
		}
		if strings.Contains(s.Detail, "checksum mismatch") {
			r.Red = append(r.Red, "checksum mismatch in "+s.ID)
		}
	}
	for _, k := range plan.Blockers() {
		r.Red = append(r.Red, k.Code+": "+k.Subject)
	}
	if time.Duration(r.DurationSec*float64(time.Second)) > RTOObjective {
		r.Red = append(r.Red, "duration exceeds the RTO objective of "+RTOObjective.String())
	}
	if !lastDrill.IsZero() && now.Sub(lastDrill) > DrillMaxAge {
		r.Red = append(r.Red, "the previous drill is older than 35 days")
	}
	r.Green = len(r.Red) == 0 && run.Status == RunSuccess
	return r
}

// Markdown renders the report.
func (r Report) Markdown() string {
	var b bytes.Buffer
	state := "GREEN"
	if !r.Green {
		state = "RED"
	}
	fmt.Fprintf(&b, "# Recovery report %s (%s)\n\n", r.RunID, state)
	fmt.Fprintf(&b, "- mode: %s, target: %s, plan: %.12s\n- started: %s, finished: %s, status: %s\n",
		r.Mode, r.Target, r.PlanID, r.StartedAt.Format(time.RFC3339), r.FinishedAt.Format(time.RFC3339), r.Status)
	fmt.Fprintf(&b, "- measured duration: %.0f s (objective %s); worst real RPO: %d h\n\n", r.DurationSec, r.RTOObjective, r.WorstRPOHrs)
	b.WriteString("## Phases\n\n| Phase | Seconds | Steps | Failures |\n|---|---|---|---|\n")
	for _, p := range r.Phases {
		fmt.Fprintf(&b, "| %s | %.0f | %d | %d |\n", p.Phase, p.Seconds, p.Steps, p.Failures)
	}
	b.WriteString("\n## Backups used\n\n| Step | Kind | Source | Age (h) |\n|---|---|---|---|\n")
	for _, u := range r.Used {
		fmt.Fprintf(&b, "| %s | %s | %s | %d |\n", u.Step, u.Kind, u.Source, u.AgeHours)
	}
	b.WriteString("\n## Steps\n\n")
	for _, s := range r.Steps {
		fmt.Fprintf(&b, "- [%s] %s: %s\n", s.Status, s.Name, s.Detail)
	}
	if len(r.Red) > 0 {
		b.WriteString("\n## Red conditions\n\n")
		for _, x := range r.Red {
			fmt.Fprintf(&b, "- %s\n", x)
		}
	}
	return b.String()
}

// WriteReport uploads the JSON and Markdown report to prefix (drills/ or recoveries/) and returns the JSON key.
// The reports are not secret (no values, only names and sizes) but go through the same store.
func WriteReport(ctx context.Context, st backup.Store, prefix string, r Report) (string, error) {
	js, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	base := fmt.Sprintf("%s%s-%s", prefix, r.FinishedAt.Format("20060102T150405Z"), r.RunID)
	if _, err := st.Upload(ctx, base+".json", map[string]string{}, bytes.NewReader(js)); err != nil {
		return "", err
	}
	if _, err := st.Upload(ctx, base+".md", map[string]string{}, io.NopCloser(strings.NewReader(r.Markdown()))); err != nil {
		return "", err
	}
	return base + ".json", nil
}
