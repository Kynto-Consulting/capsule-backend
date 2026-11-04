package access

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
)

// overlayStore wraps an engine.Store and edits what a member's snapshot would load: hypothetical assignments or a changed policy. It
// backs the simulator what_if and the WOULD_HIDE preview with the SAME evaluator that decides (a throw-away engine over the overlay).
type overlayStore struct {
	inner  engine.Store
	mutate func(d *engine.AccessData)
}

func (o overlayStore) LoadAccess(ctx context.Context, user, org uuid.UUID) (*engine.AccessData, error) {
	d, err := o.inner.LoadAccess(ctx, user, org)
	if err == nil && d != nil && d.Member && o.mutate != nil {
		o.mutate(d)
	}
	return d, err
}

func (o overlayStore) Epochs(ctx context.Context, user, org uuid.UUID) (engine.Epochs, error) {
	return o.inner.Epochs(ctx, user, org)
}

func (s *Service) overlayEngine(mutate func(d *engine.AccessData)) *engine.Engine {
	return engine.New(overlayStore{inner: s.store.EngineStore(), mutate: mutate}, engine.Options{})
}

// ---------------------------------------------------------------- decision DTO

// TemplateRef is a template and version in a trace step.
type TemplateRef struct {
	Slug    string `json:"slug"`
	Version int    `json:"version"`
}

// GroupRef names a group in a trace step.
type GroupRef struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
}

// TraceStep is one step of the ordered, stable trace of a decision (SPEC 11.4).
type TraceStep struct {
	Step         string       `json:"step"`
	Result       string       `json:"result"`
	Detail       string       `json:"detail,omitempty"`
	Permissions  []string     `json:"permissions,omitempty"`
	AssignmentID *uuid.UUID   `json:"assignment_id"`
	Template     *TemplateRef `json:"template,omitempty"`
	ViaGroup     *GroupRef    `json:"via_group"`
	ExpiresAt    *time.Time   `json:"expires_at"`
	GrantedBy    *UserRef     `json:"granted_by,omitempty"`
}

// WhatIfDiff is the permission difference caused by hypothetical assignments at the scope.
type WhatIfDiff struct {
	Gains []string `json:"gains"`
	Loses []string `json:"loses"`
}

// DecisionDTO is the Decision schema.
type DecisionDTO struct {
	Allowed       bool        `json:"allowed"`
	Reason        string      `json:"reason"`
	Permission    string      `json:"permission"`
	Scope         ScopeRef    `json:"scope"`
	Trace         []TraceStep `json:"trace"`
	WhatIfDiff    *WhatIfDiff `json:"what_if_diff,omitempty"`
	WhatIfAllowed *bool       `json:"what_if_allowed,omitempty"`
}

// SimulateInput is the body of POST .../access/simulate.
type SimulateInput struct {
	UserID     uuid.UUID  `json:"user_id"`
	Permission string     `json:"permission"`
	Scope      *ScopeRef  `json:"scope"`
	TokenID    *uuid.UUID `json:"token_id"`
	WhatIf     *struct {
		AddAssignments      []AssignmentInput `json:"add_assignments"`
		RemoveAssignmentIDs []uuid.UUID       `json:"remove_assignment_ids"`
	} `json:"what_if"`
}

func reasonOf(d engine.Decision) string {
	switch d.Cause {
	case engine.CauseGranted:
		return "granted"
	case engine.CauseNotMember:
		return "not_member"
	case engine.CauseHidden:
		return "hidden"
	case engine.CauseSuspended:
		return "suspended"
	case engine.CauseCeiling:
		return "ceiling"
	case engine.CauseUnknownPermission:
		return "unknown_permission"
	}
	for _, n := range d.Notes {
		if n.Code == engine.NoteExpired {
			return "expired"
		}
	}
	return "no_grant"
}

type tokenCap struct {
	perms     catalog.Set
	org       *uuid.UUID
	project   *uuid.UUID
	explicit  bool
	forbidden bool
}

func scopeRefOf(sc engine.Scope, org uuid.UUID) ScopeRef {
	switch sc.Type {
	case engine.ScopeProject:
		return ScopeRef{Type: "project", ID: sc.ProjectID}
	case engine.ScopeRepo:
		return ScopeRef{Type: "repo", ID: sc.ID}
	case engine.ScopeEnv:
		return ScopeRef{Type: "env", ID: sc.ID}
	}
	return ScopeRef{Type: "org", ID: org}
}

// decide builds the DecisionDTO of one check from Engine.Explain: the same compiled snapshot that Can reads.
func (s *Service) decide(ctx context.Context, org, target uuid.UUID, sc engine.Scope, perm string, tok *tokenCap) (*DecisionDTO, error) {
	d, err := s.eng.Explain(ctx, target, org, sc, perm)
	if err != nil {
		return nil, err
	}
	out := &DecisionDTO{Allowed: d.Allowed, Reason: reasonOf(d), Permission: perm, Scope: scopeRefOf(sc, org), Trace: []TraceStep{}}
	add := func(t TraceStep) { out.Trace = append(out.Trace, t) }

	// 1-3: account, membership, organization template
	acctStatus, memberStatus := "", ""
	var tid *uuid.UUID
	var tver *int
	_ = s.q().QueryRow(ctx, `SELECT u.status, om.status, om.template_id, om.template_version FROM org_members om JOIN users u ON u.id = om.user_id WHERE om.org_id = $1 AND om.user_id = $2`,
		org, target).Scan(&acctStatus, &memberStatus, &tid, &tver)
	switch {
	case d.Cause == engine.CauseNotMember:
		add(TraceStep{Step: "account", Result: "info"})
		add(TraceStep{Step: "membership", Result: "denies", Detail: "not a member of the organization"})
	case d.Cause == engine.CauseSuspended:
		add(TraceStep{Step: "account", Result: "denies", Detail: "account or membership suspended"})
	default:
		add(TraceStep{Step: "account", Result: "passes", Detail: "active"})
		add(TraceStep{Step: "membership", Result: "passes"})
	}
	if tid != nil && d.Cause != engine.CauseNotMember {
		v := 0
		if tver != nil {
			v = *tver
		}
		if h, err := loadHead(ctx, s.q(), org, *tid, false); err == nil {
			if ver, err := loadVer(ctx, s.q(), *tid, v); err == nil {
				res := "info"
				if d.Cause == engine.CauseTemplateUnresolved {
					res = "denies"
				}
				add(TraceStep{Step: "org_template", Result: res, Template: &TemplateRef{Slug: h.Slug, Version: ver.Version}})
			}
		}
	} else if d.Cause == engine.CauseTemplateUnresolved {
		add(TraceStep{Step: "org_template", Result: "denies", Detail: "the organization template does not resolve"})
	}

	// where the permission comes from (granted, or cut by the ceiling)
	ids := make([]uuid.UUID, 0, len(d.Grants))
	for _, g := range d.Grants {
		if g.AssignmentID != uuid.Nil {
			ids = append(ids, g.AssignmentID)
		}
	}
	details := map[uuid.UUID]repoAssignment{}
	if len(ids) > 0 {
		if m, err := s.assignmentDetails(ctx, org, ids); err == nil {
			details = m
		}
	}
	stepOf := func(g engine.Grant) string {
		switch g.Via {
		case engine.ViaFloor:
			return "floor"
		case engine.ViaBase:
			return "base"
		case engine.ViaOrgTemplate:
			return "org_template"
		case engine.ViaOrgAssignment:
			return "org_wide_assignment"
		case engine.ViaProjectAssignment:
			if g.SubjectKind == engine.SubjectGroup {
				return "group_assignment"
			}
			return "project_assignment"
		case engine.ViaRepoAssignment:
			return "repo_assignment"
		case engine.ViaEnvAssignment:
			if g.Source == "approver" {
				return "approver"
			}
			return "env_assignment"
		}
		return "policy"
	}
	grantStep := func(g engine.Grant, result, detail string) TraceStep {
		t := TraceStep{Step: stepOf(g), Result: result, Detail: detail, Permissions: []string{perm}}
		if g.TemplateSlug != "" {
			t.Template = &TemplateRef{Slug: g.TemplateSlug, Version: g.TemplateVersion}
		}
		if g.AssignmentID != uuid.Nil {
			id := g.AssignmentID
			t.AssignmentID = &id
			if dt, ok := details[id]; ok {
				t.GrantedBy = dt.GrantedBy
				if dt.GroupSlug != "" {
					t.ViaGroup = &GroupRef{ID: g.SubjectID, Slug: dt.GroupSlug}
				}
			}
		}
		if !g.ExpiresAt.IsZero() {
			e := g.ExpiresAt
			t.ExpiresAt = &e
		}
		return t
	}
	if d.Allowed {
		for _, g := range d.Grants {
			add(grantStep(g, "grants", ""))
		}
	}
	for _, n := range d.Notes {
		switch n.Code {
		case engine.NoteExpired:
			for _, g := range n.Grants {
				add(grantStep(g, "none", "expired"))
			}
		case engine.NoteReplaced:
			add(TraceStep{Step: "project_assignment", Result: "replaces", Detail: "own assignments on the project replace the fallback", Permissions: []string{perm}})
		case engine.NoteBaseInactive:
			add(TraceStep{Step: "policy", Result: "none", Detail: "the policy is restricted, so the template base does not apply", Permissions: []string{perm}})
		case engine.NoteCeilingCut:
			for _, g := range n.Grants {
				add(grantStep(g, "adds", "would grant it"))
			}
			add(TraceStep{Step: "ceiling", Result: "cuts", Detail: "the template ceiling removes it", Permissions: []string{perm}})
		}
	}
	if d.Cause == engine.CauseHidden {
		add(TraceStep{Step: "policy", Result: "denies", Detail: "the project is not visible to this person", Permissions: []string{"project:view"}})
	}

	// token ceiling
	if tok != nil {
		res, detail := "passes", ""
		switch {
		case tok.org != nil && *tok.org != org:
			res, detail = "denies", "the token belongs to another organization"
		case tok.project != nil && (sc.Type == engine.ScopeOrg || sc.ProjectID != *tok.project):
			res, detail = "denies", "the token is limited to another project"
		case !tok.perms.Has(perm):
			res, detail = "denies", "the token does not carry this permission"
		}
		add(TraceStep{Step: "token", Result: res, Detail: detail, Permissions: []string{perm}})
		if res == "denies" && out.Allowed {
			out.Allowed = false
			out.Reason = "token_scope"
		}
	}
	final := "denies"
	if out.Allowed {
		final = "grants"
	}
	add(TraceStep{Step: "final", Result: final, Detail: out.Reason, Permissions: []string{perm}})
	return out, nil
}

type repoAssignment struct {
	GrantedBy *UserRef
	GroupSlug string
}

// assignmentDetails loads who granted the assignments and the group they came through, for the trace.
func (s *Service) assignmentDetails(ctx context.Context, org uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]repoAssignment, error) {
	rows, err := s.q().Query(ctx, `
		SELECT a.id, u.id, u.email, u.name, COALESCE(g.slug, '')
		  FROM access_assignments a LEFT JOIN users u ON u.id = a.created_by
		  LEFT JOIN groups g ON a.subject_type = 'group' AND g.id = a.subject_id
		 WHERE a.org_id = $1 AND a.id = ANY($2)`, org, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]repoAssignment{}
	for rows.Next() {
		var id uuid.UUID
		var uid *uuid.UUID
		var email, name *string
		var slug string
		if err := rows.Scan(&id, &uid, &email, &name, &slug); err != nil {
			return nil, err
		}
		d := repoAssignment{GroupSlug: slug}
		if uid != nil {
			d.GrantedBy = &UserRef{ID: *uid, Email: deref(email), Name: deref(name)}
		}
		out[id] = d
	}
	return out, rows.Err()
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (s *Service) isMember(ctx context.Context, org, user uuid.UUID) (bool, error) {
	var ok bool
	err := s.q().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2)`, org, user).Scan(&ok)
	return ok, err
}

// ExplainSelf answers GET /me/permissions/explain: why the authenticated user has or lacks a permission. Organizations the user does not
// belong to, and projects they cannot see, are a 404.
func (s *Service) ExplainSelf(ctx context.Context, user uuid.UUID, orgRef, perm, scopeType, scopeID string) (*DecisionDTO, error) {
	org, err := s.ResolveOrg(ctx, user, orgRef)
	if err != nil {
		return nil, err
	}
	if org == uuid.Nil {
		return nil, notFound("organization not found")
	}
	if ok, err := s.isMember(ctx, org, user); err != nil {
		return nil, err
	} else if !ok {
		return nil, notFound("organization not found")
	}
	if perm == "" {
		return nil, validationField("permission", "required")
	}
	if scopeType == "" {
		scopeType = "org"
	}
	var id uuid.UUID
	if scopeID != "" {
		u, perr := uuid.Parse(scopeID)
		if perr != nil {
			return nil, validationField("scope_id", "must be a uuid")
		}
		id = u
	}
	actor := Actor{UserID: user}
	var sc engine.Scope
	if scopeType == "org" {
		sc = engine.OrgScope()
	} else {
		var e error
		sc, _, _, e = s.requireAt(ctx, actor, org, scopeType, id)
		if e != nil {
			return nil, e
		}
	}
	return s.decide(ctx, org, user, sc, perm, nil)
}

// Simulate answers POST .../access/simulate (assignment:read): can the person do perm at the scope, why, and optionally what changes
// with hypothetical assignments (what_if) or a token ceiling.
func (s *Service) Simulate(ctx context.Context, actor Actor, org uuid.UUID, in SimulateInput) (*DecisionDTO, error) {
	if _, err := s.require(ctx, actor, org, orgScope, "assignment:read"); err != nil {
		return nil, err
	}
	if in.UserID == uuid.Nil {
		return nil, validationField("user_id", "required")
	}
	if in.Permission == "" {
		return nil, validationField("permission", "required")
	}
	if !catalog.Has(in.Permission) {
		return nil, validationDetails("unknown permission", map[string]any{
			"fields": map[string]string{"permission": "unknown permission"}, "unknown_permissions": []string{in.Permission}})
	}
	scope := ScopeRef{Type: "org", ID: org}
	if in.Scope != nil {
		scope = *in.Scope
		if scope.Type == "" {
			scope.Type = "org"
		}
	}
	var sc engine.Scope
	if scope.Type == "org" {
		sc = engine.OrgScope()
	} else {
		var err error
		// the simulator only describes scopes the actor can see
		sc, _, _, err = s.requireAt(ctx, actor, org, scope.Type, scope.ID)
		if err != nil {
			return nil, err
		}
	}
	if ok, err := s.isMember(ctx, org, in.UserID); err != nil {
		return nil, err
	} else if !ok {
		return nil, notFound("user not found")
	}
	var tok *tokenCap
	if in.TokenID != nil {
		var perms []string
		var torg, tproj *uuid.UUID
		err := s.q().QueryRow(ctx, `SELECT permissions, org_id, project_id FROM api_tokens WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, *in.TokenID, in.UserID).Scan(&perms, &torg, &tproj)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, notFound("token not found")
		}
		if err != nil {
			return nil, err
		}
		if perms == nil {
			return nil, validationField("token_id", "the token uses legacy scopes; only tokens with explicit permissions can be simulated")
		}
		tok = &tokenCap{perms: catalog.NewSet(perms...), org: torg, project: tproj, explicit: true}
	}
	out, err := s.decide(ctx, org, in.UserID, sc, in.Permission, tok)
	if err != nil {
		return nil, err
	}
	if in.WhatIf != nil && (len(in.WhatIf.AddAssignments) > 0 || len(in.WhatIf.RemoveAssignmentIDs) > 0) {
		diff, allowed, err := s.whatIf(ctx, org, in, sc)
		if err != nil {
			return nil, err
		}
		out.WhatIfDiff = diff
		out.WhatIfAllowed = &allowed
	}
	return out, nil
}

// whatIf evaluates hypothetical assignments with a throw-away engine over an overlay of the real data.
func (s *Service) whatIf(ctx context.Context, org uuid.UUID, in SimulateInput, sc engine.Scope) (*WhatIfDiff, bool, error) {
	w := in.WhatIf
	if len(w.AddAssignments) > 20 || len(w.RemoveAssignmentIDs) > 20 {
		return nil, false, validationField("what_if", "at most 20 hypothetical changes of each kind")
	}
	var adds []engine.Assignment
	for i, a := range w.AddAssignments {
		field := fmt.Sprintf("what_if.add_assignments[%d]", i)
		if a.SubjectType != "user" && a.SubjectType != "group" {
			return nil, false, validationField(field+".subject_type", "must be user or group")
		}
		head, err := loadHead(ctx, s.q(), org, a.TemplateID, false)
		if err != nil {
			return nil, false, validationField(field+".template_id", "no such template")
		}
		if !kindFitsScope(head.Kind, a.Scope.Type) {
			return nil, false, validationField(field+".template_id", "that template cannot be assigned at this scope")
		}
		pin := 0
		if a.PinnedVersion != nil {
			pin = *a.PinnedVersion
		}
		ver, err := loadVer(ctx, s.q(), head.ID, pin)
		if err != nil {
			return nil, false, validationField(field+".pinned_version", "that version does not exist")
		}
		var asc engine.Scope
		var project uuid.UUID
		if a.Scope.Type == "org" {
			asc = engine.OrgScope()
		} else {
			asc, project, err = s.resolveScope(ctx, s.q(), org, a.Scope.Type, a.Scope.ID)
			if err != nil {
				return nil, false, validationField(field+".scope", "no such scope in this organization")
			}
		}
		// only assignments that reach the person count
		reaches := false
		if a.SubjectType == "user" {
			reaches = a.SubjectID == in.UserID
		} else {
			reaches, err = s.selfSubject(ctx, s.q(), Actor{UserID: in.UserID}, "group", a.SubjectID)
			if err != nil {
				return nil, false, err
			}
		}
		if !reaches {
			continue
		}
		ea := engine.Assignment{
			ID: uuid.New(), SubjectKind: engine.SubjectKind(a.SubjectType), SubjectID: a.SubjectID, TemplateID: head.ID, TemplateSlug: head.Slug,
			TemplateVersion: ver.Version, Permissions: catalog.NewSet(ver.Permissions...), Source: "manual",
		}
		switch asc.Type {
		case engine.ScopeOrg:
			ea.Scope = engine.ScopeOrg
		case engine.ScopeProject:
			ea.Scope, ea.ScopeID, ea.ProjectID = engine.ScopeProject, asc.ID, project
		case engine.ScopeRepo:
			ea.Scope, ea.ScopeID, ea.ProjectID = engine.ScopeRepo, asc.ID, project
		case engine.ScopeEnv:
			ea.Scope, ea.ScopeID, ea.ProjectID = engine.ScopeEnv, asc.ID, project
		}
		if a.ExpiresAt != nil {
			ea.ExpiresAt = *a.ExpiresAt
		}
		adds = append(adds, ea)
	}
	remove := map[uuid.UUID]bool{}
	for _, id := range w.RemoveAssignmentIDs {
		remove[id] = true
	}
	hyp := s.overlayEngine(func(d *engine.AccessData) {
		keep := d.Assignments[:0:0]
		for _, a := range d.Assignments {
			if !remove[a.ID] {
				keep = append(keep, a)
			}
		}
		d.Assignments = append(keep, adds...)
	})
	_, before, err := s.eng.Effective(ctx, in.UserID, org, sc)
	if err != nil {
		return nil, false, err
	}
	_, after, err := hyp.Effective(ctx, in.UserID, org, sc)
	if err != nil {
		return nil, false, err
	}
	return &WhatIfDiff{Gains: nonNilStrings(setDiff(after, before)), Loses: nonNilStrings(setDiff(before, after))}, after.Has(in.Permission), nil
}
