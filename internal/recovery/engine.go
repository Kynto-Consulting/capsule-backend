package recovery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// RunCtx is what an executor may know about the run.
type RunCtx struct {
	Request Request
	RunID   uuid.UUID
}

// Exec performs one kind of step. The engine calls Check first: when it reports done the step is
// not applied again (this is what makes a repeated step free of double effects), and Verify
// always runs afterwards. Verify must not change anything.
type Exec interface {
	Check(ctx context.Context, st Step, rc RunCtx) (done bool, detail string, err error)
	Apply(ctx context.Context, st Step, rc RunCtx) (detail string, err error)
	Verify(ctx context.Context, st Step, rc RunCtx) (detail string, err error)
}

// Engine runs a plan and journals every transition.
type Engine struct {
	Journal Journal
	Execs   map[Kind]Exec
	Now     func() time.Time
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

// InitSteps creates the pending journal entries of a plan.
func InitSteps(p Plan) []StepState {
	out := make([]StepState, len(p.Steps))
	for i, s := range p.Steps {
		out[i] = StepState{ID: s.ID, Name: s.Name, Phase: s.Phase, Status: StepPending}
	}
	return out
}

// Execute runs plan for run (which must already be stored by Journal.Begin). Steps already `ok`
// in run (resume) are skipped. In verify mode only Verify is called. It returns nil when the run
// ended success or partial; the final status is in run.Status.
func (e *Engine) Execute(ctx context.Context, plan Plan, run *Run) error {
	rc := RunCtx{Request: plan.Request, RunID: run.ID}
	if len(run.Steps) == 0 {
		run.Steps = InitSteps(plan)
	}
	run.Status = RunRunning
	run.PlanID = plan.PlanID
	if err := e.save(ctx, run); err != nil {
		return err
	}
	failed := map[string]bool{}
	aborted := false
	anyFail := false
	for _, st := range plan.Steps {
		ss := run.step(st.ID)
		if ss == nil {
			run.Steps = append(run.Steps, StepState{ID: st.ID, Name: st.Name, Phase: st.Phase, Status: StepPending})
			ss = run.step(st.ID)
		}
		if ss.Status == StepOK {
			continue // resume: completed steps are never re-run
		}
		barrier := st.Kind == KindSmoke || st.Kind == KindReport
		switch {
		case aborted && !barrier:
			e.mark(ss, StepSkipped, "aborted: an earlier step failed")
		case dependencyFailed(st, failed) && !barrier:
			e.mark(ss, StepSkipped, "a step this one depends on failed")
			failed[st.ID] = true
		case st.NeedsInfraFlag && !plan.Request.ApplyInfra && plan.Request.Mode == ModeApply:
			e.mark(ss, StepSkipped, "infrastructure change: pass --apply-infra to run it")
		default:
			ex := e.Execs[st.Kind]
			if ex == nil {
				e.mark(ss, StepSkipped, "not available in this mode (run it with the bootstrap procedure from an operator host)")
				break
			}
			ss.Attempts++
			t := e.now()
			ss.StartedAt, ss.FinishedAt, ss.Status, ss.Detail = &t, nil, StepRunning, ""
			_ = e.save(ctx, run)
			detail, err := e.runStep(ctx, ex, st, rc, plan.Request.Mode)
			if err != nil {
				e.mark(ss, StepFailed, trim(err.Error()))
				failed[st.ID], anyFail = true, true
				if !st.ContinueOnError && !plan.Request.ContinueOnErr {
					aborted = true
				}
			} else {
				e.mark(ss, StepOK, detail)
			}
		}
		_ = e.save(ctx, run)
	}
	fin := e.now()
	run.FinishedAt = &fin
	switch {
	case !anyFail:
		run.Status = RunSuccess
	case aborted || !anyOK(run):
		run.Status = RunFailed
	default:
		run.Status = RunPartial
	}
	return e.save(ctx, run)
}

func (e *Engine) runStep(ctx context.Context, ex Exec, st Step, rc RunCtx, mode Mode) (detail string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal error: %v", r)
		}
	}()
	if mode == ModeVerify {
		return ex.Verify(ctx, st, rc)
	}
	done, d, err := ex.Check(ctx, st, rc)
	if err != nil {
		return "", fmt.Errorf("check: %w", err)
	}
	if !done {
		if d, err = ex.Apply(ctx, st, rc); err != nil {
			return "", fmt.Errorf("apply: %w", err)
		}
	} else {
		d = "already done (check): " + d
	}
	v, err := ex.Verify(ctx, st, rc)
	if err != nil {
		return "", fmt.Errorf("verify: %w", err)
	}
	if v != "" {
		d += "; " + v
	}
	return d, nil
}

func dependencyFailed(st Step, failed map[string]bool) bool {
	for _, d := range st.DependsOn {
		if failed[d] {
			return true
		}
	}
	return false
}

func anyOK(r *Run) bool {
	for _, s := range r.Steps {
		if s.Status == StepOK {
			return true
		}
	}
	return false
}

func (e *Engine) mark(ss *StepState, s StepStatus, detail string) {
	t := e.now()
	ss.Status, ss.Detail, ss.FinishedAt = s, detail, &t
	if ss.StartedAt == nil {
		ss.StartedAt = &t
	}
}

func (e *Engine) save(ctx context.Context, run *Run) error {
	// Persist even when the request context was cancelled: the journal is the source of truth.
	return e.Journal.Save(context.WithoutCancel(ctx), run)
}

func trim(s string) string {
	if len(s) > 500 {
		return s[:500] + "..."
	}
	return s
}

// ErrBlocked is returned by Service when apply is requested on a plan with error risks.
var ErrBlocked = errors.New("recovery: the plan has blocking risks (see risks); fix them or pass --continue-on-error")

// ErrPlanChanged is returned when resuming a run whose plan would now be different (the catalog changed).
var ErrPlanChanged = errors.New("recovery: the catalog changed since this run was planned; start a new run")
