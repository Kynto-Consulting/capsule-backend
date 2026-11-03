package gitprotect

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// Drift is one divergence found between Capsule's rules and Forgejo's.
type Drift struct {
	Pattern   string   `json:"pattern"`
	Kind      string   `json:"kind"` // missing | modified | unmanaged
	Fields    []string `json:"fields,omitempty"`
	Corrected bool     `json:"corrected"`
}

// Report is the outcome of reconciling one project.
type Report struct {
	Rules  int     `json:"rules"`
	Synced int     `json:"synced"` // rules that needed no change
	Fixed  int     `json:"fixed"`  // rules (re)applied to Forgejo
	Drifts []Drift `json:"drifts,omitempty"`
	Errors int     `json:"errors"`
}

const unmanagedAuditEvery = 24 * time.Hour

// ReconcileProject compares the desired state (Capsule rules) with Forgejo and corrects it:
// a missing rule is recreated, a modified one is overwritten, a rule that only exists in Forgejo
// is audited (and removed only with GITPROTECT_PRUNE_UNMANAGED=true, so a reconciliation never
// lowers protection by itself). Every divergence is audited as git.protection.drift.
// It is idempotent; running it twice in a row changes nothing the second time.
func (s *Service) ReconcileProject(ctx context.Context, t Target) (*Report, error) {
	if !s.forge.Enabled() {
		return nil, &gitcore.Error{Code: gitcore.CodeNotReady, Message: "la integración con Git no está activa", Retry: true}
	}
	defer s.lock(t.ProjectID)()

	rules, err := s.store.ListRules(ctx, t.ProjectID)
	if err != nil {
		return nil, err
	}
	syncs, err := s.store.ListSync(ctx, t.ProjectID)
	if err != nil {
		return nil, err
	}
	live, err := s.forge.ListProtections(ctx, s.ref(t))
	if err != nil {
		return nil, err
	}
	byName := map[string]gitcore.Protection{}
	for _, p := range live {
		byName[p.RuleName] = p
	}
	rep := &Report{Rules: len(rules)}
	managed := map[string]bool{}
	stale := map[string]bool{}

	for _, rule := range rules {
		managed[rule.Pattern] = true
		st := syncs[rule.ID]
		st.RuleID, st.ProjectID = rule.ID, t.ProjectID
		for _, n := range st.StaleRuleNames {
			stale[n] = true
		}
		want := BuildSpec(rule, t.ProjectSlug)
		cur, present := byName[rule.Pattern]
		var drift *Drift
		switch {
		case !present:
			if st.Status == SyncSynced {
				drift = &Drift{Pattern: rule.Pattern, Kind: "missing"}
			}
		default:
			if diff := DiffSpec(want, cur.ProtectionSpec); len(diff) > 0 {
				drift = &Drift{Pattern: rule.Pattern, Kind: "modified", Fields: diff}
			}
		}
		needs := drift != nil || !present || st.Status != SyncSynced || len(st.StaleRuleNames) > 0 || st.ForgejoRuleName != rule.Pattern
		if !needs {
			rep.Synced++
			continue
		}
		s.project(ctx, t, rule, &st)
		if st.Status == SyncSynced {
			rep.Fixed++
		} else {
			rep.Errors++
		}
		if drift != nil {
			drift.Corrected = st.Status == SyncSynced
			now := s.now()
			st.LastDriftAt, st.DriftCount = &now, st.DriftCount+1
			s.putSync(ctx, &st)
			rep.Drifts = append(rep.Drifts, *drift)
			nv := map[string]any{"pattern": rule.Pattern, "kind": drift.Kind, "fields": drift.Fields, "corrected": drift.Corrected}
			var ov map[string]any
			if drift.Kind == "modified" {
				ov = diffValues(want, cur.ProtectionSpec, drift.Fields)
			}
			s.audit(ctx, AuditEntry{OrgID: t.OrgID, Action: ActionProtectionDrift, ResourceType: ResourceProtection, ResourceID: rule.ID, OldValues: ov, NewValues: nv})
			s.log.Warn("gitprotect: drift corrected", "project", t.ProjectID, "pattern", rule.Pattern, "kind", drift.Kind, "fields", drift.Fields, "corrected", drift.Corrected)
		}
	}

	for name, p := range byName {
		if managed[name] || stale[name] {
			continue
		}
		d := Drift{Pattern: name, Kind: "unmanaged"}
		if s.cfg.PruneUnmanaged {
			if err := s.forge.DeleteProtection(ctx, s.ref(t), name); err == nil || errors.Is(err, gitcore.ErrNotFound) {
				d.Corrected = true
			} else {
				rep.Errors++
			}
		}
		rep.Drifts = append(rep.Drifts, d)
		if d.Corrected || s.firstSightRecently(t.ProjectID, name) {
			s.audit(ctx, AuditEntry{OrgID: t.OrgID, Action: ActionProtectionDrift, ResourceType: ResourceProtection, ResourceID: t.ProjectID,
				OldValues: map[string]any{"forgejo_rule": specFields(p.ProtectionSpec)},
				NewValues: map[string]any{"pattern": name, "kind": "unmanaged", "removed": d.Corrected}})
		}
	}

	if err := s.ProjectTags(ctx, t); err != nil {
		rep.Errors++
	}
	if err := s.applyRepoEffects(ctx, t, rules, Actor{}); err != nil {
		rep.Errors++
		s.log.Warn("gitprotect: repo settings reconcile failed", "project", t.ProjectID, "err", describe(err))
	}
	return rep, nil
}

// firstSightRecently reports true once per unmanagedAuditEvery for (project, rule), so a stray
// rule is audited but a 10-minute reconciler does not flood audit_logs.
func (s *Service) firstSightRecently(project uuid.UUID, name string) bool {
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	k := project.String() + "|" + name
	now := s.now()
	if t, ok := s.seen[k]; ok && now.Sub(t) < unmanagedAuditEvery {
		return false
	}
	if len(s.seen) > 4096 {
		s.seen = map[string]time.Time{}
	}
	s.seen[k] = now
	return true
}

// RunLoop reconciles every project with rules each cfg.ReconcileEvery until ctx ends.
// A first pass runs after a random delay (up to one minute) so replicas do not start in step.
func (s *Service) RunLoop(ctx context.Context) {
	if s.cfg.ReconcileEvery <= 0 {
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Duration(rand.Int63n(int64(time.Minute)))):
	}
	for {
		s.reconcileAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.ReconcileEvery):
		}
	}
}

func (s *Service) reconcileAll(ctx context.Context) {
	if !s.forge.Enabled() {
		return
	}
	targets, err := s.store.ProjectsWithRules(ctx)
	if err != nil {
		s.log.Error("gitprotect: listing projects failed", "err", err)
		return
	}
	for _, t := range targets {
		if ctx.Err() != nil {
			return
		}
		pctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		if _, err := s.ReconcileProject(pctx, t); err != nil {
			s.log.Warn("gitprotect: reconcile failed", "project", t.ProjectID, "err", describe(err))
		}
		cancel()
	}
}
