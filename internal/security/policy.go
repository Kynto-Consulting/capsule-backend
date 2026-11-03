package security

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

// PullRef identifies the pull request head the check is about.
type PullRef struct {
	Number  int
	Base    string // base branch
	Head    string // head branch
	HeadSHA string
}

// blocks reports whether the alert, being new in a pull request, blocks the merge under p.
func blocks(p Policy, a Alert) bool {
	switch a.Kind {
	case KindSecret:
		return p.BlockMergeOn.Secret == "any"
	case KindDependency:
		return meets(p.BlockMergeOn.Dependency, a.Severity)
	case KindCode:
		return meets(p.BlockMergeOn.Code, a.Severity)
	}
	return false
}

func meets(threshold string, s Severity) bool {
	if threshold == "" || threshold == "off" {
		return false
	}
	return s.Rank() >= Severity(threshold).Rank()
}

func globAny(patterns []string, branch string) bool {
	for _, p := range patterns {
		if p == branch {
			return true
		}
		if re, err := globToRegexp(p); err == nil && re.MatchString(branch) {
			return true
		}
	}
	return false
}

func capDescription(s string) string {
	s = plain(s, 400)
	if utf8.RuneCountInString(s) <= 250 {
		return s
	}
	r := []rune(s)
	return string(r[:249]) + "…"
}

func severitySummary(alerts []Alert) string {
	count := map[Severity]int{}
	for _, a := range alerts {
		count[a.Severity]++
	}
	var parts []string
	for _, sv := range []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo} {
		if n := count[sv]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sv))
		}
	}
	return strings.Join(parts, ", ")
}

// decision is the outcome of evaluating capsule/security for one head SHA.
type decision struct {
	state       string
	description string
	blocking    []Alert
}

// decide implements SPEC 5.8: only alerts NEW in the pull request (fingerprints absent from the
// base branch) at or above the policy threshold block; a required tool without results keeps the
// check pending and, after the timeout, fails it (closed).
func (s *Service) decide(ctx context.Context, p Policy, run CheckRun) (decision, error) {
	if len(p.AppliesToBranches) > 0 && run.BaseBranch != "" && !globAny(p.AppliesToBranches, run.BaseBranch) {
		return decision{state: "success", description: capDescription("La politica de seguridad no aplica a la rama " + run.BaseBranch)}, nil
	}
	alerts, err := s.store.OpenAlertsAtSHA(ctx, run.ProjectID, run.HeadSHA)
	if err != nil {
		return decision{}, err
	}
	known := map[string]bool{}
	if run.BaseBranch != "" {
		if known, err = s.store.KnownFingerprints(ctx, run.ProjectID, run.BaseBranch); err != nil {
			return decision{}, err
		}
	}
	var blocking []Alert
	for _, a := range alerts {
		if !known[a.Fingerprint] && blocks(p, a) {
			blocking = append(blocking, a)
		}
	}
	if len(blocking) > 0 {
		sort.Slice(blocking, func(i, j int) bool { return blocking[i].Severity.Rank() > blocking[j].Severity.Rank() })
		return decision{
			state: "failure", blocking: blocking,
			description: capDescription(fmt.Sprintf("%d alerta(s) nueva(s) bloquean el merge: %s (p. ej. %s)", len(blocking), severitySummary(blocking), blocking[0].RuleID)),
		}, nil
	}
	if len(p.RequiredTools) > 0 {
		have, err := s.store.ToolsUploadedAt(ctx, run.ProjectID, run.HeadSHA)
		if err != nil {
			return decision{}, err
		}
		var missing []string
		for _, rt := range p.RequiredTools {
			if !have[rt] {
				missing = append(missing, rt)
			}
		}
		if len(missing) > 0 {
			waited := s.now().Sub(run.FirstSeenAt)
			if waited >= s.cfg.CheckTimeout {
				return decision{state: "failure", description: capDescription(fmt.Sprintf(
					"Sin resultados de %s tras %d min: la politica falla cerrada", strings.Join(missing, ", "), int(s.cfg.CheckTimeout/time.Minute)))}, nil
			}
			return decision{state: "pending", description: capDescription("Esperando resultados de " + strings.Join(missing, ", "))}, nil
		}
	}
	return decision{state: "success", description: capDescription(fmt.Sprintf("Sin alertas nuevas que bloqueen (%d abiertas en este commit)", len(alerts)))}, nil
}

// EvaluatePull evaluates and publishes the capsule/security check of a pull request head.
func (s *Service) EvaluatePull(ctx context.Context, t Target, pr PullRef) (*CheckRun, error) {
	sha := strings.ToLower(strings.TrimSpace(pr.HeadSHA))
	if !reSHA.MatchString(sha) {
		return nil, validation("head_sha", "SHA no valido")
	}
	run, err := s.store.EnsureCheckRun(ctx, CheckRun{
		ProjectID: t.ProjectID, HeadSHA: sha, PR: pr.Number, BaseBranch: pr.Base, HeadBranch: pr.Head,
		State: "pending", FirstSeenAt: s.now(),
	})
	if err != nil {
		return nil, err
	}
	if (pr.Base != "" && run.BaseBranch != pr.Base) || (pr.Number != 0 && run.PR != pr.Number) {
		run.BaseBranch, run.PR, run.HeadBranch = pr.Base, pr.Number, pr.Head
	}
	return s.evaluateRun(ctx, t, run)
}

func (s *Service) evaluateRun(ctx context.Context, t Target, run *CheckRun) (*CheckRun, error) {
	p, err := s.GetPolicy(ctx, run.ProjectID)
	if err != nil {
		return nil, err
	}
	d, err := s.decide(ctx, *p, *run)
	if err != nil {
		return nil, err
	}
	prev := run.State
	changed := d.state != run.State || d.description != run.Description || run.LastEvalAt == nil
	run.State, run.Description = d.state, d.description
	now := s.now()
	published := !changed
	if changed && s.forge != nil && s.forge.Enabled() {
		_, perr := s.forge.SetCheck(ctx, repoRef(t), run.HeadSHA, gitcore.CheckInput{
			Context: CheckContext, State: gitcore.CheckState(d.state), Description: d.description,
		})
		if perr != nil {
			s.log.Warn("security: publishing capsule/security failed", "project_id", t.ProjectID, "sha", run.HeadSHA, "err", perr)
		} else {
			published = true
			run.LastEvalAt = &now
		}
	}
	run.Final = published && d.state != "pending"
	if err := s.store.SaveCheckRun(ctx, *run); err != nil {
		return nil, err
	}
	if d.state == "failure" && prev != "failure" && len(d.blocking) > 0 {
		s.publish(ctx, t, gitevents.SecurityPolicyBlock, "", run.HeadBranch, map[string]any{
			"scope": "merge", "pr": run.PR, "sha": run.HeadSHA, "alerts": len(d.blocking), "summary": severitySummary(d.blocking),
		})
	}
	return run, nil
}

// ReevaluateRecent re-evaluates the project's recent check runs (after a dismissal, a policy
// change, an upload on the base branch...). Best effort: failures are logged.
func (s *Service) ReevaluateRecent(ctx context.Context, t Target) {
	runs, err := s.store.RecentCheckRuns(ctx, t.ProjectID, s.now().Add(-14*24*time.Hour), 50)
	if err != nil {
		s.log.Warn("security: loading check runs failed", "project_id", t.ProjectID, "err", err)
		return
	}
	for i := range runs {
		if _, err := s.evaluateRun(ctx, t, &runs[i]); err != nil {
			s.log.Warn("security: evaluating check failed", "project_id", t.ProjectID, "sha", runs[i].HeadSHA, "err", err)
		}
	}
}

// Gate is the deploy decision of the policy.
type Gate struct {
	Blocked bool
	Reasons []string
}

// DeployGate says whether the policy lets sha be deployed (SPEC 5.8: the deploy policy looks at
// the open alerts at the SHA, not only the new ones). A6 (environments) calls it.
func (s *Service) DeployGate(ctx context.Context, t Target, sha string) (*Gate, error) {
	sha = strings.ToLower(strings.TrimSpace(sha))
	p, err := s.GetPolicy(ctx, t.ProjectID)
	if err != nil {
		return nil, err
	}
	g := &Gate{}
	if p.BlockDeployOn == "off" {
		return g, nil
	}
	alerts, err := s.store.OpenAlertsAtSHA(ctx, t.ProjectID, sha)
	if err != nil {
		return nil, err
	}
	var hit []Alert
	for _, a := range alerts {
		if meets(p.BlockDeployOn, a.Severity) {
			hit = append(hit, a)
		}
	}
	if len(hit) > 0 {
		g.Blocked = true
		g.Reasons = append(g.Reasons, capDescription(strconv.Itoa(len(hit))+" alerta(s) abiertas bloquean el despliegue: "+severitySummary(hit)))
	}
	if len(p.RequiredTools) > 0 {
		have, err := s.store.ToolsUploadedAt(ctx, t.ProjectID, sha)
		if err != nil {
			return nil, err
		}
		for _, rt := range p.RequiredTools {
			if !have[rt] {
				g.Blocked = true
				g.Reasons = append(g.Reasons, "falta el resultado de "+rt+" para este commit")
			}
		}
	}
	return g, nil
}
