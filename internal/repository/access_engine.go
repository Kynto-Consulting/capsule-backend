package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
)

// EngineStore adapts an AccessSource (the Postgres read side of P2) to engine.Store (P1). It is only type mapping: the
// organization template of the member and the project templates of the assignments are resolved in one batched query, the
// floor and base templates of the organization template in a second one.
type EngineStore struct {
	src AccessSource
	// envProjects resolves the project of environment ids (assignments of scope env carry no project id). Nil = unsupported.
	envProjects func(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error)
}

// NewEngineStore returns the engine.Store backed by src.
func NewEngineStore(src AccessSource) *EngineStore {
	e := &EngineStore{src: src}
	if s, ok := src.(*AccessStore); ok {
		e.envProjects = s.EnvProjects
	}
	return e
}

// EngineStore returns the engine.Store of this AccessStore.
func (s *AccessStore) EngineStore() engine.Store { return NewEngineStore(s) }

var _ engine.Store = (*EngineStore)(nil)

// EnvProjects returns environment id -> project id for the given environments.
func (s *AccessStore) EnvProjects(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	out := make(map[uuid.UUID]uuid.UUID, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT id, project_id FROM environments WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, fmt.Errorf("loading environment projects: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, p uuid.UUID
		if err := rows.Scan(&id, &p); err != nil {
			return nil, err
		}
		out[id] = p
	}
	return out, rows.Err()
}

// Epochs implements engine.Store.
func (e *EngineStore) Epochs(ctx context.Context, user, org uuid.UUID) (engine.Epochs, error) {
	oe, ue, err := e.src.Epochs(ctx, org, user)
	return engine.Epochs{Org: oe, User: ue}, err
}

// LoadAccess implements engine.Store.
func (e *EngineStore) LoadAccess(ctx context.Context, user, org uuid.UUID) (*engine.AccessData, error) {
	// epochs first: a concurrent write can only make the snapshot look older than it is
	oe, ue, err := e.src.Epochs(ctx, org, user)
	if err != nil {
		return nil, err
	}
	d := &engine.AccessData{Epochs: engine.Epochs{Org: oe, User: ue}}
	m, err := e.src.LoadMembership(ctx, org, user)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return d, nil // not a member
	}
	d.Member = true
	d.UserActive = m.UserStatus == "active"
	d.MemberActive = m.Status == "active"
	pol, err := e.src.LoadOrgPolicy(ctx, org)
	if err != nil {
		return nil, err
	}
	d.Policy = pol.Mode
	if d.ProjectOverrides, err = e.src.LoadProjectOverrides(ctx, org); err != nil {
		return nil, err
	}
	asg, err := e.src.LoadUserAssignments(ctx, org, user)
	if err != nil {
		return nil, err
	}

	refs := make([]TemplateRef, 0, len(asg)+1)
	seen := map[TemplateRef]bool{}
	add := func(r TemplateRef) {
		if !seen[r] {
			seen[r] = true
			refs = append(refs, r)
		}
	}
	var orgRef TemplateRef
	if m.TemplateID != nil {
		orgRef = TemplateRef{ID: *m.TemplateID}
		if m.TemplateVersion != nil {
			orgRef.Version = *m.TemplateVersion
		}
		add(orgRef)
	}
	for _, a := range asg {
		r := TemplateRef{ID: a.TemplateID}
		if a.PinnedVersion != nil {
			r.Version = *a.PinnedVersion
		}
		add(r)
	}
	vers, err := e.src.LoadTemplateVersions(ctx, refs)
	if err != nil {
		return nil, err
	}

	if m.TemplateID != nil {
		if v := vers[orgRef]; v != nil && !v.Archived && v.Kind == "org" {
			t := &engine.OrgTemplate{ID: v.TemplateID, Slug: v.Slug, Version: v.Version, Permissions: catalog.NewSet(v.Permissions...)}
			var fb []TemplateRef
			if v.FloorTemplateID != nil {
				fb = append(fb, TemplateRef{ID: *v.FloorTemplateID})
			}
			if v.BaseTemplateID != nil {
				fb = append(fb, TemplateRef{ID: *v.BaseTemplateID})
			}
			fbv, err := e.src.LoadTemplateVersions(ctx, fb)
			if err != nil {
				return nil, err
			}
			if v.FloorTemplateID != nil {
				t.FloorID = *v.FloorTemplateID
				if f := fbv[TemplateRef{ID: t.FloorID}]; f != nil {
					t.Floor = catalog.NewSet(f.Permissions...)
				}
			}
			if v.BaseTemplateID != nil {
				t.BaseID = *v.BaseTemplateID
				if b := fbv[TemplateRef{ID: t.BaseID}]; b != nil {
					t.Base = catalog.NewSet(b.Permissions...)
				}
			}
			if v.Ceiling != nil {
				t.HasCeiling = true
				t.Ceiling = catalog.NewSet(v.Ceiling...)
				t.CeilingProject = t.Ceiling
				if v.CeilingProject != nil {
					t.CeilingProject = catalog.NewSet(v.CeilingProject...)
				}
			}
			d.Template = t
		}
	}

	var envIDs []uuid.UUID
	d.Assignments = make([]engine.Assignment, 0, len(asg))
	for _, a := range asg {
		r := TemplateRef{ID: a.TemplateID}
		if a.PinnedVersion != nil {
			r.Version = *a.PinnedVersion
		}
		tv := vers[r]
		if tv == nil {
			continue // the template does not resolve: the assignment grants nothing
		}
		ea := engine.Assignment{
			ID: a.ID, SubjectKind: engine.SubjectKind(a.SubjectType), SubjectID: a.SubjectID,
			TemplateID: a.TemplateID, TemplateSlug: tv.Slug, TemplateVersion: tv.Version,
			Permissions: catalog.NewSet(tv.Permissions...), Source: a.Source,
		}
		switch a.ScopeType {
		case "org":
			ea.Scope = engine.ScopeOrg
		case "project":
			ea.Scope, ea.ScopeID, ea.ProjectID = engine.ScopeProject, a.ScopeID, a.ScopeID
		case "repo": // a repository is 1:1 with its project and shares its id as scope (migration 000068)
			ea.Scope, ea.ScopeID, ea.ProjectID = engine.ScopeRepo, a.ScopeID, a.ScopeID
		case "env":
			ea.Scope, ea.ScopeID = engine.ScopeEnv, a.ScopeID
			envIDs = append(envIDs, a.ScopeID)
		default:
			continue
		}
		exp := a.ExpiresAt
		if a.GroupExpiresAt != nil && (exp == nil || a.GroupExpiresAt.Before(*exp)) {
			exp = a.GroupExpiresAt
		}
		if exp != nil {
			ea.ExpiresAt = *exp
		}
		d.Assignments = append(d.Assignments, ea)
	}
	if len(envIDs) > 0 {
		if e.envProjects == nil {
			return nil, fmt.Errorf("environment assignments need EnvProjects")
		}
		ep, err := e.envProjects(ctx, envIDs)
		if err != nil {
			return nil, err
		}
		out := d.Assignments[:0]
		for _, a := range d.Assignments {
			if a.Scope == engine.ScopeEnv {
				p, ok := ep[a.ScopeID]
				if !ok {
					continue
				}
				a.ProjectID = p
			}
			out = append(out, a)
		}
		d.Assignments = out
	}
	return d, nil
}
