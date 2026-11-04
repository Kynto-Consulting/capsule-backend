package engine

import (
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
)

// ScopeType is the level at which a decision is taken.
type ScopeType uint8

const (
	ScopeOrg ScopeType = iota
	ScopeProject
	ScopeRepo
	ScopeEnv
)

func (t ScopeType) String() string {
	switch t {
	case ScopeOrg:
		return "org"
	case ScopeProject:
		return "project"
	case ScopeRepo:
		return "repo"
	case ScopeEnv:
		return "env"
	}
	return "unknown"
}

// Scope identifies where a decision is taken. For repo and env scopes ProjectID is the project that
// contains them (the caller has already verified that it belongs to the organization, as the handlers do
// today). Use the constructors.
type Scope struct {
	Type      ScopeType
	ID        uuid.UUID // project, repo or env id; unused for the organization
	ProjectID uuid.UUID
}

// OrgScope is the organization scope.
func OrgScope() Scope { return Scope{} }

// ProjectScope is the scope of a project.
func ProjectScope(project uuid.UUID) Scope { return Scope{ScopeProject, project, project} }

// RepoScope is the scope of the repository of a project.
func RepoScope(project, repo uuid.UUID) Scope { return Scope{ScopeRepo, repo, project} }

// EnvScope is the scope of a deployment environment of a project.
func EnvScope(project, env uuid.UUID) Scope { return Scope{ScopeEnv, env, project} }

// Source says where the effective access of a project comes from (SPEC 5.3 rule 6).
type Source string

const (
	SourceOrg       Source = "org"       // the template floor provides all of it
	SourceExplicit  Source = "explicit"  // own assignments
	SourceInherited Source = "inherited" // fallback: org-wide assignments and template base
)

// Reason explains an empty outcome.
type Reason string

const (
	ReasonNone               Reason = ""
	ReasonNotMember          Reason = "not_member"
	ReasonSuspended          Reason = "suspended"
	ReasonTemplateUnresolved Reason = "template_unresolved"
	ReasonHidden             Reason = "hidden" // organization member without project:view
)

// Access is the outcome of resolving a user against a scope (the equivalent of authz.Access).
type Access struct {
	Member bool // belongs to the organization (suspended included)
	Hidden bool // must not learn the project exists (404)
	Source Source
	Reason Reason
}

const (
	ovNone uint8 = iota
	ovOpen
	ovRestricted
)

type projEntry struct {
	set      Set
	own      bool
	override uint8
}

type scopedEntry struct {
	set     Set
	project uuid.UUID
}

var (
	bitView    = mustBit("project:view")
	sensitives = func() (m [catalog.MaxPerms]bool) {
		for _, p := range catalog.All() {
			m[p.Bit] = p.Sensitive
		}
		return
	}()
)

func mustBit(id string) int {
	b, ok := catalog.Bit(id)
	if !ok {
		panic("engine: permission missing from the catalog: " + id)
	}
	return b
}

// snapshot is the immutable compiled form of one (user, organization). It is never modified after
// compile: readers share it without locks.
type snapshot struct {
	user, org uuid.UUID
	epochs    Epochs
	compiled  time.Time
	// validUntil = min(compiled + TTL, next assignment expiry): after it the snapshot is recompiled.
	validUntil time.Time

	member bool
	// closed: no permission at all (not a member, suspended, template unresolved).
	closed bool
	reason Reason

	tpl                OrgTemplate
	perms, floor, base Set
	hasCeil            bool
	ceilOrg, ceilProj  Set
	policyOpen         bool
	orgWide            Set
	projects           map[uuid.UUID]projEntry
	repos, envs        map[uuid.UUID]scopedEntry
	data               *AccessData // kept for Explain
	bytes              int64       // estimate for the cache budget
}

func expired(a Assignment, now time.Time) bool {
	return !a.ExpiresAt.IsZero() && !a.ExpiresAt.After(now)
}

// compile builds the snapshot. It performs no I/O.
func compile(user, org uuid.UUID, d *AccessData, now time.Time, ttl time.Duration) *snapshot {
	s := &snapshot{user: user, org: org, epochs: d.Epochs, compiled: now, data: d,
		validUntil: now.Add(ttl), member: d.Member}
	s.bytes = 256
	switch {
	case !d.Member:
		s.closed, s.reason = true, ReasonNotMember
		return s
	case !d.UserActive || !d.MemberActive:
		s.closed, s.reason = true, ReasonSuspended
		return s
	case d.Template == nil:
		s.closed, s.reason = true, ReasonTemplateUnresolved
		return s
	}
	t := *d.Template
	s.tpl = t
	s.perms, s.floor, s.base = t.Permissions, t.Floor, t.Base
	s.hasCeil, s.ceilOrg, s.ceilProj = t.HasCeiling, t.Ceiling, t.CeilingProject
	s.policyOpen = d.Policy != "restricted"

	nProj := len(d.ProjectOverrides)
	for _, a := range d.Assignments {
		if a.Scope == ScopeProject {
			nProj++
		}
	}
	s.projects = make(map[uuid.UUID]projEntry, nProj)
	for pid, m := range d.ProjectOverrides {
		switch m {
		case "open":
			e := s.projects[pid]
			e.override = ovOpen
			s.projects[pid] = e
		case "restricted":
			e := s.projects[pid]
			e.override = ovRestricted
			s.projects[pid] = e
		}
	}
	for _, a := range d.Assignments {
		if expired(a, now) {
			continue
		}
		if !a.ExpiresAt.IsZero() && a.ExpiresAt.Before(s.validUntil) {
			s.validUntil = a.ExpiresAt
		}
		switch a.Scope {
		case ScopeOrg:
			s.orgWide = s.orgWide.Union(a.Permissions)
		case ScopeProject:
			e := s.projects[a.ScopeID]
			e.set, e.own = e.set.Union(a.Permissions), true
			s.projects[a.ScopeID] = e
		case ScopeRepo:
			if s.repos == nil {
				s.repos = map[uuid.UUID]scopedEntry{}
			}
			e := s.repos[a.ScopeID]
			e.set, e.project = e.set.Union(a.Permissions), a.ProjectID
			s.repos[a.ScopeID] = e
		case ScopeEnv:
			if s.envs == nil {
				s.envs = map[uuid.UUID]scopedEntry{}
			}
			e := s.envs[a.ScopeID]
			e.set, e.project = e.set.Union(a.Permissions), a.ProjectID
			s.envs[a.ScopeID] = e
		}
	}
	s.bytes += int64(len(s.projects))*72 + int64(len(s.repos)+len(s.envs))*88 +
		int64(len(d.Assignments))*160 + int64(len(d.ProjectOverrides))*48
	return s
}

// projectRaw is the project set before the ceiling and the visibility test: the closest level wins, the
// floor always adds. own reports whether the project has own assignments.
func (s *snapshot) projectRaw(pid uuid.UUID) (raw Set, own bool) {
	e := s.projects[pid]
	open := s.policyOpen
	switch e.override {
	case ovOpen:
		open = true
	case ovRestricted:
		open = false
	}
	if e.own {
		raw = e.set
	} else {
		raw = s.orgWide
		if open {
			raw = raw.Union(s.base)
		}
	}
	return raw.Union(s.floor), e.own
}

// scopeSet computes the effective set at a scope. hidden is true when a member must not learn the project
// exists. own reports own assignments at the scope or its project (for Source).
func (s *snapshot) scopeSet(sc Scope) (set Set, own, hidden bool) {
	if s.closed {
		return Set{}, false, s.member && sc.Type != ScopeOrg
	}
	if sc.Type == ScopeOrg {
		set = s.perms
		if s.hasCeil {
			set = set.Intersect(s.ceilOrg)
		}
		return set, false, false
	}
	set, own = s.projectRaw(sc.ProjectID)
	switch sc.Type {
	case ScopeRepo:
		if e, ok := s.repos[sc.ID]; ok && e.project == sc.ProjectID {
			set, own = set.Union(e.set), true
		}
	case ScopeEnv:
		if e, ok := s.envs[sc.ID]; ok && e.project == sc.ProjectID {
			set, own = set.Union(e.set), true
		}
	}
	if s.hasCeil {
		set = set.Intersect(s.ceilProj)
	}
	if !set.HasBit(bitView) {
		return Set{}, false, true
	}
	return set, own, false
}

// visible is the project-level visibility test used by listings.
func (s *snapshot) visible(pid uuid.UUID) bool {
	if s.closed {
		return false
	}
	raw, _ := s.projectRaw(pid)
	if s.hasCeil {
		raw = raw.Intersect(s.ceilProj)
	}
	return raw.HasBit(bitView)
}

func (s *snapshot) access(sc Scope, set Set, own, hidden bool) Access {
	a := Access{Member: s.member, Hidden: hidden}
	if s.closed {
		a.Reason = s.reason
		return a
	}
	if hidden {
		a.Reason = ReasonHidden
		return a
	}
	if sc.Type == ScopeOrg {
		return a
	}
	switch {
	case !s.floor.IsEmpty() && s.floor.ContainsAll(set):
		a.Source = SourceOrg
	case own:
		a.Source = SourceExplicit
	default:
		a.Source = SourceInherited
	}
	return a
}

func (s *snapshot) has(sc Scope, bit int) bool {
	set, _, _ := s.scopeSet(sc)
	return set.HasBit(bit)
}
