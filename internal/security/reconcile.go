package security

import (
	"regexp"
	"time"

	"github.com/google/uuid"
)

// compiledSupp is a suppression with its glob compiled once.
type compiledSupp struct {
	s  Suppression
	re *regexp.Regexp // nil when there is no path glob
}

// SuppressionSet matches alerts against the active, unexpired suppressions of one project.
type SuppressionSet struct{ items []compiledSupp }

// NewSuppressionSet keeps only suppressions that are active and not expired at now.
func NewSuppressionSet(supps []Suppression, now time.Time) *SuppressionSet {
	set := &SuppressionSet{}
	for _, s := range supps {
		if s.State != SuppActive || !s.ExpiresAt.After(now) {
			continue
		}
		c := compiledSupp{s: s}
		if s.Match.PathGlob != "" {
			re, err := globToRegexp(s.Match.PathGlob)
			if err != nil {
				continue // a glob that does not compile suppresses nothing
			}
			c.re = re
		}
		set.items = append(set.items, c)
	}
	return set
}

func (c *compiledSupp) matches(ruleID, fingerprint, path string, sev Severity) bool {
	m := c.s.Match
	if m.RuleID != "" && m.RuleID != ruleID {
		return false
	}
	if m.Fingerprint != "" && m.Fingerprint != fingerprint {
		return false
	}
	if c.re != nil && !c.re.MatchString(path) {
		return false
	}
	// A suppression created without security.admin (or that covered nothing critical/high when
	// it was created) never suppresses critical/high alerts that show up later.
	return c.s.CoversHigh || !sev.HighOrAbove()
}

// MatchAlert returns the first suppression that covers the alert (nil if none).
func (set *SuppressionSet) MatchAlert(a *Alert) *Suppression {
	return set.match(a.RuleID, a.Fingerprint, a.Path, a.Severity)
}

func (set *SuppressionSet) match(ruleID, fingerprint, path string, sev Severity) *Suppression {
	if set == nil {
		return nil
	}
	for i := range set.items {
		if set.items[i].matches(ruleID, fingerprint, path, sev) {
			s := set.items[i].s
			return &s
		}
	}
	return nil
}

// MatchesIgnoringSeverity reports whether the suppression selects the alert regardless of
// severity (used to compute the severity ceiling of a new suppression).
func MatchesIgnoringSeverity(s Suppression, a *Alert) bool {
	c := compiledSupp{s: s}
	if s.Match.PathGlob != "" {
		re, err := globToRegexp(s.Match.PathGlob)
		if err != nil {
			return false
		}
		c.re = re
	}
	c.s.CoversHigh = true
	return c.matches(a.RuleID, a.Fingerprint, a.Path, a.Severity)
}

// ReconcileInput is one scope (tool + branch) of one upload.
type ReconcileInput struct {
	ProjectID uuid.UUID
	Branch    string
	SHA       string
	UploadID  uuid.UUID
	Scope     Scope
	Findings  []Finding // only the findings of Scope
	Existing  []Alert   // every alert of (project, tool_name, branch), any state
	Supp      *SuppressionSet
	Now       time.Time
}

// ReconcilePlan is what the store writes in one transaction.
type ReconcilePlan struct {
	Insert  []Alert
	Update  []Alert // complete rows to write back
	Created []Alert // new or reopened alerts (for events); subset of Insert and Update
	Fixed   int
}

// Reconcile is the open -> fixed cycle of SPEC 5.8, pure so that every Store shares it:
//   - a finding present in the upload creates the alert or refreshes it; a fixed alert that
//     reappears is reopened; a dismissed alert whose dismissal expired is reopened;
//   - an open alert of the same tool and branch that the upload no longer contains becomes fixed;
//   - dismissed alerts stay dismissed while their suppression/dismissal is in force;
//   - active suppressions are applied to new, reopened alerts.
func Reconcile(in ReconcileInput) ReconcilePlan {
	var plan ReconcilePlan
	existing := make(map[string]*Alert, len(in.Existing))
	for i := range in.Existing {
		existing[in.Existing[i].Fingerprint] = &in.Existing[i]
	}
	seen := make(map[string]bool, len(in.Findings))
	for _, f := range in.Findings {
		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		e, ok := existing[f.Fingerprint]
		if !ok {
			a := Alert{
				ID: uuid.New(), ProjectID: in.ProjectID, Kind: f.Kind, Tool: f.Tool, ToolName: f.ToolName,
				RuleID: f.RuleID, Severity: f.Severity, State: StateOpen, Title: f.Title, Description: f.Description,
				Fingerprint: f.Fingerprint, Branch: in.Branch, Path: f.Path, StartLine: f.StartLine, EndLine: f.EndLine,
				Package: f.Package, Version: f.Version, FixedVersion: f.FixedVersion, Advisory: f.Advisory,
				Evidence: f.Evidence, Trace: f.Trace, FirstSeenSHA: in.SHA, LastSeenSHA: in.SHA, LastUploadID: in.UploadID,
				CreatedAt: in.Now, UpdatedAt: in.Now,
			}
			suppress(&a, in.Supp, in.Now)
			plan.Insert = append(plan.Insert, a)
			plan.Created = append(plan.Created, a)
			continue
		}
		a := *e
		a.Severity, a.Title, a.Description = f.Severity, f.Title, f.Description
		a.Path, a.StartLine, a.EndLine = f.Path, f.StartLine, f.EndLine
		a.Package, a.Version, a.FixedVersion, a.Advisory = f.Package, f.Version, f.FixedVersion, f.Advisory
		a.Evidence, a.Trace = f.Evidence, f.Trace
		a.LastSeenSHA, a.LastUploadID, a.UpdatedAt = in.SHA, in.UploadID, in.Now
		reopened := false
		switch {
		case a.State == StateFixed:
			reopened = true
		case a.State == StateDismissed && a.Dismissal != nil && !a.Dismissal.ExpiresAt.After(in.Now):
			reopened = true
		}
		if reopened {
			clearDismissal(&a)
			a.State, a.FixedAt = StateOpen, nil
			suppress(&a, in.Supp, in.Now)
			plan.Created = append(plan.Created, a)
		} else if a.State == StateOpen {
			suppress(&a, in.Supp, in.Now) // a suppression created after the alert was first seen
		}
		plan.Update = append(plan.Update, a)
	}
	for i := range in.Existing {
		e := in.Existing[i]
		if e.State == StateOpen && !seen[e.Fingerprint] {
			e.State = StateFixed
			t := in.Now
			e.FixedAt = &t
			e.UpdatedAt = in.Now
			plan.Update = append(plan.Update, e)
			plan.Fixed++
		}
	}
	return plan
}

func clearDismissal(a *Alert) {
	a.Dismissal = nil
	a.SuppressionID = uuid.Nil
}

// suppress dismisses a (open) alert when an active suppression covers it.
func suppress(a *Alert, set *SuppressionSet, now time.Time) {
	if a.State != StateOpen {
		return
	}
	s := set.MatchAlert(a)
	if s == nil {
		return
	}
	a.State = StateDismissed
	a.SuppressionID = s.ID
	a.Dismissal = &Dismissal{
		Reason: s.Reason, Justification: s.Justification, ByUserID: s.CreatedBy,
		ExpiresAt: s.ExpiresAt, At: now,
	}
}
