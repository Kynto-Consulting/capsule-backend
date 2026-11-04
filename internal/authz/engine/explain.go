package engine

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
)

// Cause is the exact reason of a decision.
type Cause string

const (
	CauseGranted            Cause = "granted"
	CauseNotMember          Cause = "not_member"
	CauseSuspended          Cause = "suspended"
	CauseTemplateUnresolved Cause = "template_unresolved"
	CauseHidden             Cause = "hidden"             // no project:view at the scope: the project is not visible
	CauseCeiling            Cause = "ceiling"            // something grants it but the template ceiling cuts it
	CauseMissing            Cause = "missing"            // nothing grants it
	CauseUnknownPermission  Cause = "unknown_permission" // not in the catalog
)

// Via names the mechanism that grants a permission.
type Via string

const (
	ViaOrgTemplate       Via = "org_template"       // permissions of the organization template (org scope)
	ViaFloor             Via = "floor"              // template floor: always held in every project
	ViaBase              Via = "base"               // template base, open policy and no own assignments
	ViaOrgAssignment     Via = "org_assignment"     // assignment to "all projects"
	ViaProjectAssignment Via = "project_assignment" // own assignment on the project
	ViaRepoAssignment    Via = "repo_assignment"
	ViaEnvAssignment     Via = "env_assignment" // includes environment approvers
)

// Grant is one place a permission comes from.
type Grant struct {
	Via             Via
	AssignmentID    uuid.UUID // zero for template-derived grants
	SubjectKind     SubjectKind
	SubjectID       uuid.UUID
	TemplateID      uuid.UUID
	TemplateSlug    string
	TemplateVersion int
	Source          string // assignment source (manual, temporary, approver, ...)
	ExpiresAt       time.Time
}

// Note codes of Decision.Notes (why something that looked relevant did not count).
const (
	NoteExpired      = "expired_assignment" // an assignment that would grant it has expired
	NoteReplaced     = "fallback_replaced"  // the org-wide assignment or base has it, but own assignments replace the fallback
	NoteBaseInactive = "base_inactive"      // the template base has it but the policy is restricted
	NoteCeilingCut   = "ceiling_cut"        // granted below, removed by the ceiling
)

// Note is a secondary finding.
type Note struct {
	Code   string
	Grants []Grant // the assignments or templates involved
}

// Decision is the explained outcome of one check. Allowed is exactly what Can returns for the same input
// and instant: both read the same compiled snapshot through the same function.
type Decision struct {
	Allowed bool
	Cause   Cause
	Perm    string
	Scope   Scope
	Access  Access
	Grants  []Grant // where the permission comes from (when Allowed) or would have come from (ceiling)
	Notes   []Note
	Strict  bool
}

// Explain answers "why can or can't user do perm here" with the exact cause.
func (e *Engine) Explain(ctx context.Context, user, org uuid.UUID, sc Scope, perm string) (Decision, error) {
	d := Decision{Perm: perm, Scope: sc, Cause: CauseUnknownPermission}
	bit, ok := catalog.Bit(perm)
	if !ok {
		return d, nil
	}
	d.Strict = sensitives[bit]
	s, err := e.snapshot(ctx, user, org, d.Strict)
	if err != nil {
		return Decision{}, err
	}
	set, own, hidden := s.scopeSet(sc)
	d.Access = s.access(sc, set, own, hidden)
	d.Allowed = set.HasBit(bit)
	switch {
	case d.Allowed:
		d.Cause = CauseGranted
		d.Grants = s.contributions(sc, bit, s.compiled)
	case s.closed:
		switch s.reason {
		case ReasonNotMember:
			d.Cause = CauseNotMember
		case ReasonSuspended:
			d.Cause = CauseSuspended
		default:
			d.Cause = CauseTemplateUnresolved
		}
	case hidden:
		d.Cause = CauseHidden
		d.Grants = s.contributions(sc, bit, s.compiled)
	default:
		d.Grants = s.contributions(sc, bit, s.compiled)
		if len(d.Grants) > 0 {
			d.Cause = CauseCeiling // something grants it and the set still lacks it: only the ceiling cuts
			d.Notes = append(d.Notes, Note{Code: NoteCeilingCut, Grants: d.Grants})
		} else {
			d.Cause = CauseMissing
			d.Grants = nil
		}
	}
	if d.Cause != CauseGranted && !s.closed && sc.Type != ScopeOrg {
		d.Notes = append(d.Notes, s.nearMisses(sc, bit)...)
	}
	return d, nil
}

func asg(via Via, a Assignment) Grant {
	return Grant{Via: via, AssignmentID: a.ID, SubjectKind: a.SubjectKind, SubjectID: a.SubjectID,
		TemplateID: a.TemplateID, TemplateSlug: a.TemplateSlug, TemplateVersion: a.TemplateVersion,
		Source: a.Source, ExpiresAt: a.ExpiresAt}
}

// contributions lists everything that puts bit into the set BEFORE the ceiling, following the same
// level rules as scopeSet. It does not look at the ceiling or at visibility.
func (s *snapshot) contributions(sc Scope, bit int, now time.Time) []Grant {
	var out []Grant
	if s.closed {
		return nil
	}
	if sc.Type == ScopeOrg {
		if s.perms.HasBit(bit) {
			out = append(out, Grant{Via: ViaOrgTemplate, TemplateID: s.tpl.ID, TemplateSlug: s.tpl.Slug, TemplateVersion: s.tpl.Version})
		}
		return out
	}
	if s.floor.HasBit(bit) {
		out = append(out, Grant{Via: ViaFloor, TemplateID: s.tpl.FloorID})
	}
	e := s.projects[sc.ProjectID]
	open := s.policyOpen
	switch e.override {
	case ovOpen:
		open = true
	case ovRestricted:
		open = false
	}
	if e.own {
		for _, a := range s.data.Assignments {
			if a.Scope == ScopeProject && a.ScopeID == sc.ProjectID && !expired(a, now) && a.Permissions.HasBit(bit) {
				out = append(out, asg(ViaProjectAssignment, a))
			}
		}
	} else {
		for _, a := range s.data.Assignments {
			if a.Scope == ScopeOrg && !expired(a, now) && a.Permissions.HasBit(bit) {
				out = append(out, asg(ViaOrgAssignment, a))
			}
		}
		if open && s.base.HasBit(bit) {
			out = append(out, Grant{Via: ViaBase, TemplateID: s.tpl.BaseID})
		}
	}
	if sc.Type == ScopeRepo || sc.Type == ScopeEnv {
		for _, a := range s.data.Assignments {
			if a.ScopeID == sc.ID && a.ProjectID == sc.ProjectID && !expired(a, now) && a.Permissions.HasBit(bit) {
				if sc.Type == ScopeRepo && a.Scope == ScopeRepo {
					out = append(out, asg(ViaRepoAssignment, a))
				}
				if sc.Type == ScopeEnv && a.Scope == ScopeEnv {
					out = append(out, asg(ViaEnvAssignment, a))
				}
			}
		}
	}
	return out
}

// nearMisses explains the grants that exist on paper but do not count.
func (s *snapshot) nearMisses(sc Scope, bit int) []Note {
	var notes []Note
	now := s.compiled
	var exp []Grant
	for _, a := range s.data.Assignments {
		if !expired(a, now) || !a.Permissions.HasBit(bit) {
			continue
		}
		switch a.Scope {
		case ScopeOrg:
			exp = append(exp, asg(ViaOrgAssignment, a))
		case ScopeProject:
			if a.ScopeID == sc.ProjectID {
				exp = append(exp, asg(ViaProjectAssignment, a))
			}
		case ScopeRepo:
			if sc.Type == ScopeRepo && a.ScopeID == sc.ID {
				exp = append(exp, asg(ViaRepoAssignment, a))
			}
		case ScopeEnv:
			if sc.Type == ScopeEnv && a.ScopeID == sc.ID {
				exp = append(exp, asg(ViaEnvAssignment, a))
			}
		}
	}
	if len(exp) > 0 {
		notes = append(notes, Note{Code: NoteExpired, Grants: exp})
	}
	e := s.projects[sc.ProjectID]
	open := s.policyOpen
	switch e.override {
	case ovOpen:
		open = true
	case ovRestricted:
		open = false
	}
	if e.own {
		var rep []Grant
		for _, a := range s.data.Assignments {
			if a.Scope == ScopeOrg && !expired(a, now) && a.Permissions.HasBit(bit) {
				rep = append(rep, asg(ViaOrgAssignment, a))
			}
		}
		if open && s.base.HasBit(bit) {
			rep = append(rep, Grant{Via: ViaBase, TemplateID: s.tpl.BaseID})
		}
		if len(rep) > 0 {
			notes = append(notes, Note{Code: NoteReplaced, Grants: rep})
		}
	} else if !open && s.base.HasBit(bit) {
		notes = append(notes, Note{Code: NoteBaseInactive, Grants: []Grant{{Via: ViaBase, TemplateID: s.tpl.BaseID}}})
	}
	return notes
}
