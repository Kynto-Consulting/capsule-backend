// Package v2adapter presents the engine with the shapes of package authz (authz.V2) and builds it over a legacy authz.Store. It imports
// neither the repository nor the middleware so that test binaries of any package can link it (authz/wire does import them).
package v2adapter

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
	"github.com/kynto/capsule/backend/internal/authz/systemtemplates"
	"github.com/kynto/capsule/backend/internal/domain"
)

// Adapter implements authz.V2 over an engine.Engine.
type Adapter struct{ E *engine.Engine }

var _ authz.V2 = (*Adapter)(nil)

func scopeOf(project uuid.UUID) engine.Scope {
	if project == uuid.Nil {
		return engine.OrgScope()
	}
	return engine.ProjectScope(project)
}

func strictNeeded(perms []string) bool {
	for _, p := range perms {
		if c, ok := catalog.Get(p); ok && c.Sensitive {
			return true
		}
	}
	return false
}

func legacyAccess(a engine.Access, set engine.Set) authz.Access {
	return authz.Access{Role: authz.Role(engine.LegacyRole(set)), Source: authz.Source(a.Source), Member: a.Member, Hidden: a.Hidden}
}

// Check implements authz.V2: one Effective call, then act is contained in the set (every atom of the expansion of an old action).
func (a *Adapter) Check(ctx context.Context, user, org, project uuid.UUID, act authz.Action) (authz.Outcome, error) {
	want := authz.Atoms(act)
	var acc engine.Access
	var set engine.Set
	var err error
	if strictNeeded(want) {
		acc, set, err = a.E.EffectiveStrict(ctx, user, org, scopeOf(project))
	} else {
		acc, set, err = a.E.Effective(ctx, user, org, scopeOf(project))
	}
	if err != nil {
		return authz.Outcome{}, err
	}
	la := legacyAccess(acc, set)
	ws, unknown := catalog.ParseSet(want)
	allowed := acc.Member && !acc.Hidden && len(want) > 0 && len(unknown) == 0 && set.ContainsAll(ws)
	return authz.Outcome{Access: la, Allowed: allowed}, nil
}

// Access implements authz.V2.
func (a *Adapter) Access(ctx context.Context, user, org, project uuid.UUID) (authz.Access, error) {
	acc, set, err := a.E.Effective(ctx, user, org, scopeOf(project))
	if err != nil {
		return authz.Access{}, err
	}
	return legacyAccess(acc, set), nil
}

// FilterProjects implements authz.V2.
func (a *Adapter) FilterProjects(ctx context.Context, user, org uuid.UUID, ps []*domain.Project) ([]*domain.Project, error) {
	return a.E.FilterProjects(ctx, user, org, ps)
}

// Visibility implements authz.V2.
func (a *Adapter) Visibility(ctx context.Context, user, org uuid.UUID) (func(uuid.UUID) bool, error) {
	return a.E.Visibility(ctx, user, org)
}

// Explain implements authz.V2: cause, grants and notes of the first atom of act, with template identifiers only.
func (a *Adapter) Explain(ctx context.Context, user, org, project uuid.UUID, act authz.Action) string {
	atoms := authz.Atoms(act)
	if len(atoms) == 0 {
		return "no atoms for action"
	}
	d, err := a.E.Explain(ctx, user, org, scopeOf(project), atoms[0])
	if err != nil {
		return "explain error: " + err.Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "perm=%s allowed=%t cause=%s strict=%t", d.Perm, d.Allowed, d.Cause, d.Strict)
	for _, g := range d.Grants {
		fmt.Fprintf(&b, " grant(%s tpl=%s@%d src=%s)", g.Via, g.TemplateSlug, g.TemplateVersion, g.Source)
	}
	for _, n := range d.Notes {
		fmt.Fprintf(&b, " note(%s)", n.Code)
	}
	return b.String()
}

// LegacyStore presents a legacy authz.Store (organization role, mode, explicit project roles) as an engine.Store built from the
// system templates: the org role is the organization template with that slug, an explicit project role is an assignment of the
// project template with that slug, the mode is the policy. It is what lets the OLD test suites run, unchanged, with the new engine
// deciding (MIGRATION 5.2), and it is the in-memory form of what the migration 000070 backfill does to the real tables. Every call
// reads the legacy store again (no caching), so tests that change their fakes between calls keep working.
type LegacyStore struct{ Old authz.Store }

var _ engine.Store = LegacyStore{}

// Epochs implements engine.Store (the legacy store has no epochs: every load is fresh).
func (LegacyStore) Epochs(context.Context, uuid.UUID, uuid.UUID) (engine.Epochs, error) {
	return engine.Epochs{}, nil
}

// LoadAccess implements engine.Store.
func (l LegacyStore) LoadAccess(ctx context.Context, user, org uuid.UUID) (*engine.AccessData, error) {
	oa, err := l.Old.LoadOrgAccess(ctx, org, user)
	if err != nil {
		return nil, err
	}
	d := &engine.AccessData{}
	if oa == nil {
		return d, nil
	}
	d.Member, d.UserActive, d.MemberActive = true, true, true
	d.Policy = oa.Mode
	if t, ok := systemtemplates.Org(oa.OrgRole); ok {
		d.Template = &engine.OrgTemplate{
			ID: t.ID, Slug: t.Slug, Version: t.Version, Permissions: t.Permissions,
			FloorID: t.FloorID, BaseID: t.BaseID, Floor: t.Floor, Base: t.Base,
			HasCeiling: t.HasCeiling, Ceiling: t.Ceiling, CeilingProject: t.CeilingProject,
		}
	}
	for pid, role := range oa.Explicit {
		if !authz.ValidProjectRole(role) {
			continue // legacy Resolve ignores an unknown explicit role
		}
		pt, ok := systemtemplates.Project(role)
		if !ok {
			continue
		}
		d.Assignments = append(d.Assignments, engine.Assignment{
			ID: uuid.New(), SubjectKind: engine.SubjectUser, SubjectID: user,
			Scope: engine.ScopeProject, ScopeID: pid, ProjectID: pid,
			TemplateID: pt.ID, TemplateSlug: pt.Slug, TemplateVersion: pt.Version, Permissions: pt.Permissions,
			Source: engine.AssignMigrated,
		})
	}
	return d, nil
}

// NewLegacyV2 returns the new engine over a legacy store (see LegacyStore).
func NewLegacyV2(old authz.Store) authz.V2 {
	// the clock advances on every read (Windows timers are coarse): a snapshot is never reused, the legacy fakes may change between calls
	var tick atomic.Int64
	now := func() time.Time { return time.Now().Add(time.Duration(tick.Add(1)) * time.Millisecond) }
	return &Adapter{E: engine.New(LegacyStore{Old: old}, engine.Options{TTL: time.Nanosecond, Now: now})}
}
