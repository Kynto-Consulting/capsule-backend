package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/repository"
)

var orgScope = engine.OrgScope()

// ScopeRef names a scope.
type ScopeRef struct {
	Type string    `json:"type"`
	ID   uuid.UUID `json:"id"`
}

// AssignmentInput is the body of POST .../assignments.
type AssignmentInput struct {
	SubjectType   string     `json:"subject_type"`
	SubjectID     uuid.UUID  `json:"subject_id"`
	Scope         ScopeRef   `json:"scope"`
	TemplateID    uuid.UUID  `json:"template_id"`
	PinnedVersion *int       `json:"pinned_version"`
	ExpiresAt     *time.Time `json:"expires_at"`
	Reason        string     `json:"reason"`
}

// PatchAssignmentInput is the body of PATCH .../assignments/{id}; only the fields present change.
type PatchAssignmentInput struct {
	ExpiresAtSet bool
	ExpiresAt    *time.Time
	ReasonSet    bool
	Reason       string
	PinnedSet    bool
	Pinned       *int
}

// UnmarshalJSON records which fields the body carries (null clears expiry and pin).
func (p *PatchAssignmentInput) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for k, v := range m {
		switch k {
		case "expires_at":
			p.ExpiresAtSet = true
			if err := json.Unmarshal(v, &p.ExpiresAt); err != nil {
				return err
			}
		case "reason":
			p.ReasonSet = true
			if err := json.Unmarshal(v, &p.Reason); err != nil {
				return err
			}
		case "pinned_version":
			p.PinnedSet = true
			if err := json.Unmarshal(v, &p.Pinned); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown field %q", k)
		}
	}
	return nil
}

// AssignmentDTO is the Assignment schema.
type AssignmentDTO struct {
	ID         uuid.UUID  `json:"id"`
	Subject    Subject    `json:"subject"`
	Scope      ScopeRef   `json:"scope"`
	ScopeLabel string     `json:"scope_label"`
	Template   TemplateR  `json:"template"`
	Source     string     `json:"source"`
	Reason     string     `json:"reason"`
	ExpiresAt  *time.Time `json:"expires_at"`
	Status     string     `json:"status"`
	CreatedBy  *UserRef   `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Subject is the person or group of an assignment.
type Subject struct {
	Type  string    `json:"type"`
	ID    uuid.UUID `json:"id"`
	Label string    `json:"label"`
}

// TemplateR is the template reference inside an assignment.
type TemplateR struct {
	ID      uuid.UUID `json:"id"`
	Slug    string    `json:"slug"`
	Kind    string    `json:"kind"`
	Version int       `json:"version"`
	Pinned  bool      `json:"pinned"`
}

// AssignmentPage is a page of assignments.
type AssignmentPage struct {
	Data       []AssignmentDTO `json:"data"`
	NextCursor *string         `json:"next_cursor"`
}

type assignmentFilter struct {
	ID             *uuid.UUID
	SubjectType    string
	SubjectID      *uuid.UUID
	ScopeType      string
	ScopeID        *uuid.UUID
	TemplateID     *uuid.UUID
	ExpiringWithin time.Duration
	IncludeRevoked bool
}

// ParseWithin parses "7d", "36h", "90m" (the expiring_within filter).
func ParseWithin(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	unit := s[len(s)-1]
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 || n > 3650 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	switch unit {
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'm':
		return time.Duration(n) * time.Minute, nil
	}
	return 0, fmt.Errorf("invalid duration %q", s)
}

const assignmentSelect = `
	SELECT a.id, a.subject_type, a.subject_id, COALESCE(u.email, g.slug, ''), a.scope_type, a.scope_id,
	       COALESCE(p.name, o.name, e.name, ''), t.id, t.slug, t.kind, COALESCE(a.pinned_version, t.current_version), a.pinned_version IS NOT NULL,
	       a.source, a.reason, a.expires_at, a.revoked_at, a.created_by, a.created_at
	  FROM access_assignments a
	  JOIN role_templates t ON t.id = a.template_id
	  LEFT JOIN users u ON a.subject_type = 'user' AND u.id = a.subject_id
	  LEFT JOIN groups g ON a.subject_type = 'group' AND g.id = a.subject_id
	  LEFT JOIN projects p ON a.scope_type IN ('project','repo') AND p.id = a.scope_id
	  LEFT JOIN organizations o ON a.scope_type = 'org' AND o.id = a.scope_id
	  LEFT JOIN environments e ON a.scope_type = 'env' AND e.id = a.scope_id`

func (s *Service) scanAssignments(ctx context.Context, q querier, rows pgx.Rows) ([]AssignmentDTO, error) {
	defer rows.Close()
	var out []AssignmentDTO
	var by []uuid.UUID
	byIdx := map[int]uuid.UUID{}
	now := s.now()
	for rows.Next() {
		var a AssignmentDTO
		var revoked *time.Time
		var createdBy *uuid.UUID
		if err := rows.Scan(&a.ID, &a.Subject.Type, &a.Subject.ID, &a.Subject.Label, &a.Scope.Type, &a.Scope.ID, &a.ScopeLabel,
			&a.Template.ID, &a.Template.Slug, &a.Template.Kind, &a.Template.Version, &a.Template.Pinned,
			&a.Source, &a.Reason, &a.ExpiresAt, &revoked, &createdBy, &a.CreatedAt); err != nil {
			return nil, err
		}
		switch {
		case revoked != nil:
			a.Status = "revoked"
		case a.ExpiresAt != nil && !a.ExpiresAt.After(now):
			a.Status = "expired"
		default:
			a.Status = "active"
		}
		if createdBy != nil {
			by = append(by, *createdBy)
			byIdx[len(out)] = *createdBy
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	refs, err := s.userRefs(ctx, q, by)
	if err != nil {
		return nil, err
	}
	for i, id := range byIdx {
		if u, ok := refs[id]; ok {
			c := u
			out[i].CreatedBy = &c
		}
	}
	return out, nil
}

func (s *Service) listAssignments(ctx context.Context, q querier, org uuid.UUID, f assignmentFilter, cursor string, limit int) (*AssignmentPage, error) {
	limit = clampLimit(limit)
	where := []string{"a.org_id = $1"}
	args := []any{org}
	add := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if !f.IncludeRevoked {
		where = append(where, "a.revoked_at IS NULL")
	}
	if f.ID != nil {
		where = append(where, "a.id = "+add(*f.ID))
	}
	if f.SubjectType != "" {
		where = append(where, "a.subject_type = "+add(f.SubjectType))
	}
	if f.SubjectID != nil {
		where = append(where, "a.subject_id = "+add(*f.SubjectID))
	}
	if f.ScopeType != "" {
		where = append(where, "a.scope_type = "+add(f.ScopeType))
	}
	if f.ScopeID != nil {
		where = append(where, "a.scope_id = "+add(*f.ScopeID))
	}
	if f.TemplateID != nil {
		where = append(where, "a.template_id = "+add(*f.TemplateID))
	}
	if f.ExpiringWithin > 0 {
		where = append(where, "a.expires_at IS NOT NULL AND a.expires_at > now() AND a.expires_at <= now() + "+add(f.ExpiringWithin)+"::interval")
	}
	if at, id, ok := decodeCursor(cursor); ok {
		t, err1 := time.Parse(time.RFC3339Nano, at)
		u, err2 := uuid.Parse(id)
		if err1 == nil && err2 == nil {
			where = append(where, fmt.Sprintf("(a.created_at, a.id) > (%s, %s)", add(t), add(u)))
		}
	}
	rows, err := q.Query(ctx, assignmentSelect+" WHERE "+strings.Join(where, " AND ")+" ORDER BY a.created_at, a.id LIMIT "+add(limit+1), args...)
	if err != nil {
		return nil, err
	}
	list, err := s.scanAssignments(ctx, q, rows)
	if err != nil {
		return nil, err
	}
	page := &AssignmentPage{Data: list}
	if page.Data == nil {
		page.Data = []AssignmentDTO{}
	}
	if len(page.Data) > limit {
		page.Data = page.Data[:limit]
		last := page.Data[limit-1]
		c := encodeCursor(last.CreatedAt.UTC().Format(time.RFC3339Nano), last.ID.String())
		page.NextCursor = &c
	}
	return page, nil
}

// AssignmentQuery is the query string of GET .../assignments.
type AssignmentQuery struct {
	SubjectType, SubjectID, ScopeType, ScopeID, TemplateID, ExpiringWithin, Cursor string
	Limit                                                                          int
}

func parseOptUUID(field, v string) (*uuid.UUID, error) {
	if v == "" {
		return nil, nil
	}
	u, err := uuid.Parse(v)
	if err != nil {
		return nil, validationField(field, "must be a uuid")
	}
	return &u, nil
}

// ListAssignments lists live assignments with filters (assignment:read).
func (s *Service) ListAssignments(ctx context.Context, actor Actor, org uuid.UUID, qy AssignmentQuery) (*AssignmentPage, error) {
	if _, err := s.require(ctx, actor, org, orgScope, "assignment:read"); err != nil {
		return nil, err
	}
	f := assignmentFilter{SubjectType: qy.SubjectType, ScopeType: qy.ScopeType}
	if f.SubjectType != "" && f.SubjectType != "user" && f.SubjectType != "group" {
		return nil, validationField("subject_type", "must be user or group")
	}
	switch f.ScopeType {
	case "", "org", "project", "repo", "env":
	default:
		return nil, validationField("scope_type", "must be org, project, repo or env")
	}
	var err error
	if f.SubjectID, err = parseOptUUID("subject_id", qy.SubjectID); err != nil {
		return nil, err
	}
	if f.ScopeID, err = parseOptUUID("scope_id", qy.ScopeID); err != nil {
		return nil, err
	}
	if f.TemplateID, err = parseOptUUID("template_id", qy.TemplateID); err != nil {
		return nil, err
	}
	if f.ExpiringWithin, err = ParseWithin(qy.ExpiringWithin); err != nil {
		return nil, validationField("expiring_within", "use a number and d, h or m (7d)")
	}
	// a listing of a project or repo scope must not reveal a project the actor cannot see
	if f.ScopeID != nil && (f.ScopeType == "project" || f.ScopeType == "repo") {
		if _, _, _, err := s.requireAt(ctx, actor, org, "project", *f.ScopeID, "assignment:read"); err != nil {
			return nil, err
		}
	}
	return s.listAssignments(ctx, s.q(), org, f, qy.Cursor, qy.Limit)
}

// GetAssignment returns one assignment of any status (assignment:read).
func (s *Service) GetAssignment(ctx context.Context, actor Actor, org, id uuid.UUID) (*AssignmentDTO, error) {
	if _, err := s.require(ctx, actor, org, orgScope, "assignment:read"); err != nil {
		return nil, err
	}
	p, err := s.listAssignments(ctx, s.q(), org, assignmentFilter{ID: &id, IncludeRevoked: true}, "", 1)
	if err != nil {
		return nil, err
	}
	if len(p.Data) == 0 {
		return nil, notFound("assignment not found")
	}
	a := p.Data[0]
	if a.Scope.Type == "project" || a.Scope.Type == "repo" || a.Scope.Type == "env" {
		// same answer as a missing assignment when the project is hidden from the actor
		typ := a.Scope.Type
		if _, _, _, err := s.requireAt(ctx, actor, org, typ, a.Scope.ID, "assignment:read"); err != nil {
			if e, ok := err.(*Error); ok && e.Status == 404 {
				return nil, notFound("assignment not found")
			}
			return nil, err
		}
	}
	return &a, nil
}

// requireAt resolves a scope of the organization and requires perms there. A scope that does not exist and one the actor cannot see
// do the same work and give the same 404; only members get any answer, non-members get "not a member" before anything is resolved.
func (s *Service) requireAt(ctx context.Context, actor Actor, org uuid.UUID, typ string, id uuid.UUID, perms ...string) (engine.Scope, uuid.UUID, engine.Set, error) {
	sc, project, rerr := s.resolveScope(ctx, s.q(), org, typ, id)
	var ve *Error
	if errors.As(rerr, &ve) && ve.Status == 422 {
		return engine.Scope{}, uuid.Nil, engine.Set{}, rerr
	}
	if rerr != nil && !errors.As(rerr, &ve) {
		return engine.Scope{}, uuid.Nil, engine.Set{}, rerr
	}
	probe := sc
	if rerr != nil {
		probe = engine.ProjectScope(id)
	}
	set, err := s.require(ctx, actor, org, probe, perms...)
	if rerr != nil {
		if e, ok := err.(*Error); ok && e.Status == 403 && e.Message == "not a member" {
			return engine.Scope{}, uuid.Nil, engine.Set{}, err
		}
		if err != nil && !isDomain(err) {
			return engine.Scope{}, uuid.Nil, engine.Set{}, err
		}
		return engine.Scope{}, uuid.Nil, engine.Set{}, notFound("project not found")
	}
	if err != nil {
		return engine.Scope{}, uuid.Nil, engine.Set{}, err
	}
	return sc, project, set, nil
}

func isDomain(err error) bool {
	var e *Error
	return errors.As(err, &e)
}

// containmentMissing returns the permissions of perms the actor does not hold at the scope an assignment applies to. For an
// organization-wide assignment (all projects) that is what the actor holds in every project.
func (s *Service) containmentMissing(ctx context.Context, actor Actor, org uuid.UUID, scopeType string, scopeID uuid.UUID, perms catalog.Set) (catalog.Set, error) {
	if scopeType == "org" {
		caps, err := s.projectCaps(ctx, actor.UserID, org)
		if err != nil {
			return catalog.Set{}, err
		}
		return perms.Minus(caps), nil
	}
	_, _, set, err := s.requireAt(ctx, actor, org, scopeType, scopeID)
	if err != nil {
		return catalog.Set{}, err
	}
	return perms.Minus(set), nil
}

type liveAssignment struct {
	ID        uuid.UUID
	ScopeType string
	ScopeID   uuid.UUID
	Perms     catalog.Set
}

// liveGroupAssignments returns the live, unexpired assignments of a group with their template permissions.
func (s *Service) liveGroupAssignments(ctx context.Context, q querier, org, group uuid.UUID) ([]liveAssignment, error) {
	rows, err := q.Query(ctx, `
		SELECT a.id, a.scope_type, a.scope_id, v.permissions
		  FROM access_assignments a JOIN role_templates t ON t.id = a.template_id
		  JOIN role_template_versions v ON v.template_id = t.id AND v.version = COALESCE(a.pinned_version, t.current_version)
		 WHERE a.org_id = $1 AND a.subject_type = 'group' AND a.subject_id = $2 AND a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())`, org, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []liveAssignment
	for rows.Next() {
		var a liveAssignment
		var perms []string
		if err := rows.Scan(&a.ID, &a.ScopeType, &a.ScopeID, &perms); err != nil {
			return nil, err
		}
		a.Perms = catalog.NewSet(perms...)
		out = append(out, a)
	}
	return out, rows.Err()
}

// outOfScope returns the permissions that cannot be granted at an assignment scope (SPEC 5.1).
func outOfScope(set catalog.Set, scopeType string) []string {
	if scopeType == "org" {
		scopeType = "project" // an organization-wide assignment carries project permissions to every project
	}
	want := permScope(scopeType)
	var out []string
	for _, id := range set.IDs() {
		if c, ok := catalog.Get(id); ok && !c.HasScope(want) {
			out = append(out, id)
		}
	}
	return out
}

func kindFitsScope(kind, scopeType string) bool {
	if scopeType == "repo" {
		return kind == "repo" || kind == "project"
	}
	return kind == "project"
}

func (s *Service) selfSubject(ctx context.Context, q querier, actor Actor, subjectType string, subject uuid.UUID) (bool, error) {
	if subjectType == "user" {
		return subject == actor.UserID, nil
	}
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2 AND (expires_at IS NULL OR expires_at > now()))`, subject, actor.UserID).Scan(&ok)
	return ok, err
}

// CreateAssignment grants a template to a person or group at a scope (assignment:grant at that scope; no-escalation SPEC 13.1).
func (s *Service) CreateAssignment(ctx context.Context, actor Actor, org uuid.UUID, in AssignmentInput, idem *Idem) (Reply[*AssignmentDTO], error) {
	fail := func(err error) (Reply[*AssignmentDTO], error) { return Reply[*AssignmentDTO]{}, err }
	if _, err := s.require(ctx, actor, org, orgScope); err != nil { // membership first: nothing else is revealed to outsiders
		return fail(err)
	}
	fields := map[string]string{}
	if in.SubjectType != "user" && in.SubjectType != "group" {
		fields["subject_type"] = "must be user or group"
	}
	if in.SubjectID == uuid.Nil {
		fields["subject_id"] = "required"
	}
	if in.TemplateID == uuid.Nil {
		fields["template_id"] = "required"
	}
	switch in.Scope.Type {
	case "org", "project", "repo", "env":
	default:
		fields["scope.type"] = "must be org, project, repo or env"
	}
	if len(in.Reason) > 500 {
		fields["reason"] = "at most 500 characters"
	}
	if len(fields) > 0 {
		return fail(validation(fields))
	}
	sc, project, _, err := s.requireAt(ctx, actor, org, in.Scope.Type, scopeIDOf(in.Scope, org), "assignment:grant")
	if err != nil {
		return fail(err)
	}
	_ = sc
	scopeID := scopeIDOf(in.Scope, org)

	head, err := loadHead(ctx, s.q(), org, in.TemplateID, false)
	if err != nil {
		return fail(validationField("template_id", "no such template"))
	}
	if head.ArchivedAt != nil {
		return fail(conflict("TEMPLATE_ARCHIVED", "template is archived", nil))
	}
	if !kindFitsScope(head.Kind, in.Scope.Type) {
		return fail(validationField("template_id", fmt.Sprintf("a %s template cannot be assigned at %s scope", head.Kind, in.Scope.Type)))
	}
	pin := 0
	if in.PinnedVersion != nil {
		pin = *in.PinnedVersion
		if pin < 1 || pin > head.Current {
			return fail(validationField("pinned_version", "that version does not exist"))
		}
	}
	ver, err := loadVer(ctx, s.q(), head.ID, pin)
	if err != nil {
		return fail(validationField("pinned_version", "that version does not exist"))
	}
	perms := catalog.NewSet(ver.Permissions...)
	if oos := outOfScope(perms, in.Scope.Type); len(oos) > 0 {
		return fail(validationDetails("the template carries permissions that cannot be granted at this scope", map[string]any{
			"fields": map[string]string{"template_id": "permissions outside the scope"}, "out_of_scope": oos}))
	}
	if err := s.checkSubject(ctx, s.q(), org, in.SubjectType, in.SubjectID); err != nil {
		return fail(err)
	}
	if err := s.checkExpiry(ctx, s.q(), org, "expires_at", in.ExpiresAt); err != nil {
		return fail(err)
	}
	owner, err := s.isOwner(ctx, s.q(), org, actor.UserID)
	if err != nil {
		return fail(err)
	}
	if !owner {
		self, err := s.selfSubject(ctx, s.q(), actor, in.SubjectType, in.SubjectID)
		if err != nil {
			return fail(err)
		}
		if self {
			return fail(escalation("you cannot grant or widen your own access", nil, "self_grant"))
		}
		missing, err := s.containmentMissing(ctx, actor, org, in.Scope.Type, scopeID, perms)
		if err != nil {
			return fail(err)
		}
		if !missing.IsEmpty() {
			return fail(escalation("the template carries permissions you do not hold at this scope", missing.IDs(), ""))
		}
	}
	var projID *uuid.UUID
	if in.Scope.Type != "org" {
		p := project
		projID = &p
	}
	return doWrite(ctx, s, org, actor, idem, 201, func(tx pgx.Tx) (*AssignmentDTO, error) {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM access_assignments WHERE org_id = $1 AND revoked_at IS NULL`, org).Scan(&n); err != nil {
			return nil, err
		}
		if n >= repository.MaxAssignmentsPerOrg {
			return nil, limitErr(fmt.Sprintf("an organization has at most %d assignments", repository.MaxAssignmentsPerOrg))
		}
		var id uuid.UUID
		var created bool
		var oldExp *time.Time
		var oldPin *int
		var oldReason string
		_ = tx.QueryRow(ctx, `SELECT expires_at, pinned_version, reason FROM access_assignments
			WHERE subject_type = $1 AND subject_id = $2 AND scope_type = $3 AND scope_id = $4 AND template_id = $5 AND revoked_at IS NULL`,
			in.SubjectType, in.SubjectID, in.Scope.Type, scopeID, in.TemplateID).Scan(&oldExp, &oldPin, &oldReason)
		err := tx.QueryRow(ctx, `
			INSERT INTO access_assignments (org_id, subject_type, subject_id, scope_type, scope_id, template_id, pinned_version, source, reason, expires_at, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT (subject_type, subject_id, scope_type, scope_id, template_id) WHERE revoked_at IS NULL
			DO UPDATE SET pinned_version = EXCLUDED.pinned_version, expires_at = EXCLUDED.expires_at, reason = EXCLUDED.reason
			RETURNING id, (xmax = 0)`,
			org, in.SubjectType, in.SubjectID, in.Scope.Type, scopeID, in.TemplateID, in.PinnedVersion, sourceFor(in), in.Reason, in.ExpiresAt, actor.UserID).Scan(&id, &created)
		if err != nil {
			return nil, mapPg(err)
		}
		impact := 1
		if in.SubjectType == "group" {
			_ = tx.QueryRow(ctx, `SELECT count(*) FROM group_members WHERE group_id = $1`, in.SubjectID).Scan(&impact)
		}
		nv := map[string]any{"subject_type": in.SubjectType, "subject_id": in.SubjectID.String(), "scope_type": in.Scope.Type, "scope_id": scopeID.String(),
			"template": head.Slug, "template_id": head.ID.String(), "version": ver.Version, "pinned": in.PinnedVersion != nil, "expires_at": in.ExpiresAt, "reason": in.Reason}
		action := "access.assignment.granted"
		var ov map[string]any
		if !created {
			action = "access.assignment.changed"
			ov = map[string]any{"subject_id": in.SubjectID.String(), "expires_at": oldExp, "pinned_version": oldPin, "reason": oldReason}
		}
		if err := s.audit(ctx, tx, org, actor, auditRow{Action: action, ResourceType: "assignment", ResourceID: id, ProjectID: projID, Old: ov, New: nv, Impact: impact}); err != nil {
			return nil, err
		}
		return s.loadAssignmentTx(ctx, tx, org, id)
	})
}

func sourceFor(in AssignmentInput) string {
	if in.ExpiresAt != nil {
		return "temporary"
	}
	return "manual"
}

func scopeIDOf(sc ScopeRef, org uuid.UUID) uuid.UUID {
	if sc.Type == "org" && sc.ID == uuid.Nil {
		return org
	}
	return sc.ID
}

func (s *Service) loadAssignmentTx(ctx context.Context, q querier, org, id uuid.UUID) (*AssignmentDTO, error) {
	p, err := s.listAssignments(ctx, q, org, assignmentFilter{ID: &id, IncludeRevoked: true}, "", 1)
	if err != nil {
		return nil, err
	}
	if len(p.Data) == 0 {
		return nil, domain.ErrNotFound
	}
	return &p.Data[0], nil
}

// checkSubject validates that the subject belongs to the organization. The same 422 is given for a person that does not exist and for
// one that belongs to another organization.
func (s *Service) checkSubject(ctx context.Context, q querier, org uuid.UUID, typ string, id uuid.UUID) error {
	var ok bool
	var err error
	if typ == "user" {
		err = q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2)`, org, id).Scan(&ok)
		if err == nil && !ok {
			return validationField("subject_id", "not a member of the organization")
		}
	} else {
		err = q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM groups WHERE org_id = $1 AND id = $2 AND archived_at IS NULL)`, org, id).Scan(&ok)
		if err == nil && !ok {
			return validationField("subject_id", "no such group")
		}
	}
	return err
}

type currentAssignment struct {
	ID         uuid.UUID
	SubjectTyp string
	SubjectID  uuid.UUID
	ScopeType  string
	ScopeID    uuid.UUID
	TemplateID uuid.UUID
	Pinned     *int
	ExpiresAt  *time.Time
	Reason     string
}

func (s *Service) loadLive(ctx context.Context, q querier, org, id uuid.UUID, lock bool) (*currentAssignment, error) {
	sql := `SELECT id, subject_type, subject_id, scope_type, scope_id, template_id, pinned_version, expires_at, reason FROM access_assignments
		WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`
	if lock {
		sql += ` FOR UPDATE`
	}
	var c currentAssignment
	if err := q.QueryRow(ctx, sql, id, org).Scan(&c.ID, &c.SubjectTyp, &c.SubjectID, &c.ScopeType, &c.ScopeID, &c.TemplateID, &c.Pinned, &c.ExpiresAt, &c.Reason); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

// authorizeExisting requires assignment:grant at the scope of an existing assignment. A missing assignment, or one in a project the
// actor cannot see, is the same 404.
func (s *Service) authorizeExisting(ctx context.Context, actor Actor, org, id uuid.UUID) (*currentAssignment, uuid.UUID, error) {
	cur, err := s.loadLive(ctx, s.q(), org, id, false)
	if errors.Is(err, domain.ErrNotFound) {
		if _, e := s.require(ctx, actor, org, orgScope, "assignment:grant"); e != nil {
			if x, ok := e.(*Error); ok && x.Status == 403 && x.Message == "not a member" {
				return nil, uuid.Nil, e
			}
		}
		return nil, uuid.Nil, notFound("assignment not found")
	}
	if err != nil {
		return nil, uuid.Nil, err
	}
	_, project, _, err := s.requireAt(ctx, actor, org, cur.ScopeType, cur.ScopeID, "assignment:grant")
	if err != nil {
		if e, ok := err.(*Error); ok && e.Status == 404 {
			return nil, uuid.Nil, notFound("assignment not found")
		}
		return nil, uuid.Nil, err
	}
	return cur, project, nil
}

// PatchAssignment changes expiry, reason or pinned version of a live assignment (assignment:grant at its scope). Widening (a later or no
// expiry, a pin that adds permissions) re-runs the no-escalation rule; nobody widens their own access but an owner.
func (s *Service) PatchAssignment(ctx context.Context, actor Actor, org, id uuid.UUID, in PatchAssignmentInput, idem *Idem) (Reply[*AssignmentDTO], error) {
	fail := func(err error) (Reply[*AssignmentDTO], error) { return Reply[*AssignmentDTO]{}, err }
	cur, project, err := s.authorizeExisting(ctx, actor, org, id)
	if err != nil {
		return fail(err)
	}
	if len(in.Reason) > 500 {
		return fail(validationField("reason", "at most 500 characters"))
	}
	newExp, newPin, newReason := cur.ExpiresAt, cur.Pinned, cur.Reason
	if in.ExpiresAtSet {
		newExp = in.ExpiresAt
	}
	if in.PinnedSet {
		newPin = in.Pinned
	}
	if in.ReasonSet {
		newReason = in.Reason
	}
	if in.ExpiresAtSet && in.ExpiresAt != nil && (cur.ExpiresAt == nil || !in.ExpiresAt.Equal(*cur.ExpiresAt)) {
		if err := s.checkExpiry(ctx, s.q(), org, "expires_at", in.ExpiresAt); err != nil {
			return fail(err)
		}
	}
	head, err := loadHead(ctx, s.q(), org, cur.TemplateID, false)
	if err != nil {
		return fail(Normalize(err))
	}
	pinV := 0
	if newPin != nil {
		pinV = *newPin
		if pinV < 1 || pinV > head.Current {
			return fail(validationField("pinned_version", "that version does not exist"))
		}
	}
	newVer, err := loadVer(ctx, s.q(), head.ID, pinV)
	if err != nil {
		return fail(validationField("pinned_version", "that version does not exist"))
	}
	oldPinV := 0
	if cur.Pinned != nil {
		oldPinV = *cur.Pinned
	}
	oldVer, err := loadVer(ctx, s.q(), head.ID, oldPinV)
	if err != nil {
		return fail(Normalize(err))
	}
	newPerms, oldPerms := catalog.NewSet(newVer.Permissions...), catalog.NewSet(oldVer.Permissions...)
	if oos := outOfScope(newPerms, cur.ScopeType); len(oos) > 0 {
		return fail(validationDetails("the version carries permissions that cannot be granted at this scope", map[string]any{
			"fields": map[string]string{"pinned_version": "permissions outside the scope"}, "out_of_scope": oos}))
	}
	owner, err := s.isOwner(ctx, s.q(), org, actor.UserID)
	if err != nil {
		return fail(err)
	}
	if !owner {
		widerExpiry := (cur.ExpiresAt != nil && (newExp == nil || newExp.After(*cur.ExpiresAt)))
		widerPerms := !oldPerms.ContainsAll(newPerms)
		if widerExpiry || widerPerms {
			self, err := s.selfSubject(ctx, s.q(), actor, cur.SubjectTyp, cur.SubjectID)
			if err != nil {
				return fail(err)
			}
			if self {
				return fail(escalation("you cannot widen your own access", nil, "self_grant"))
			}
		}
		if widerPerms {
			missing, err := s.containmentMissing(ctx, actor, org, cur.ScopeType, cur.ScopeID, newPerms.Minus(oldPerms))
			if err != nil {
				return fail(err)
			}
			if !missing.IsEmpty() {
				return fail(escalation("the version carries permissions you do not hold at this scope", missing.IDs(), ""))
			}
		}
	}
	var projID *uuid.UUID
	if cur.ScopeType != "org" {
		p := project
		projID = &p
	}
	return doWrite(ctx, s, org, actor, idem, 200, func(tx pgx.Tx) (*AssignmentDTO, error) {
		lc, err := s.loadLive(ctx, tx, org, id, true)
		if err != nil {
			return nil, err
		}
		src := "manual"
		if newExp != nil {
			src = "temporary"
		}
		if lc.ExpiresAt == nil && newExp == nil {
			src = "manual"
		}
		if _, err := tx.Exec(ctx, `UPDATE access_assignments SET expires_at = $3, reason = $4, pinned_version = $5, source = CASE WHEN source IN ('manual','temporary') THEN $6 ELSE source END
			WHERE id = $1 AND org_id = $2`, id, org, newExp, newReason, newPin, src); err != nil {
			return nil, mapPg(err)
		}
		if err := s.audit(ctx, tx, org, actor, auditRow{Action: "access.assignment.changed", ResourceType: "assignment", ResourceID: id, ProjectID: projID,
			Old: map[string]any{"subject_id": lc.SubjectID.String(), "expires_at": lc.ExpiresAt, "pinned_version": lc.Pinned, "reason": lc.Reason},
			New: map[string]any{"subject_id": lc.SubjectID.String(), "expires_at": newExp, "pinned_version": newPin, "reason": newReason}, Impact: 1}); err != nil {
			return nil, err
		}
		return s.loadAssignmentTx(ctx, tx, org, id)
	})
}

// RevokeAssignment revokes a live assignment (assignment:grant at its scope). The row stays for the audit trail.
func (s *Service) RevokeAssignment(ctx context.Context, actor Actor, org, id uuid.UUID, idem *Idem) (Reply[struct{}], error) {
	cur, project, err := s.authorizeExisting(ctx, actor, org, id)
	if err != nil {
		return Reply[struct{}]{}, err
	}
	var projID *uuid.UUID
	if cur.ScopeType != "org" {
		p := project
		projID = &p
	}
	return doWrite(ctx, s, org, actor, idem, 204, func(tx pgx.Tx) (struct{}, error) {
		lc, err := s.loadLive(ctx, tx, org, id, true)
		if err != nil {
			return struct{}{}, err
		}
		if _, err := tx.Exec(ctx, `UPDATE access_assignments SET revoked_at = now(), revoked_by = $3 WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL`, id, org, actor.UserID); err != nil {
			return struct{}{}, mapPg(err)
		}
		return struct{}{}, s.audit(ctx, tx, org, actor, auditRow{Action: "access.assignment.revoked", ResourceType: "assignment", ResourceID: id, ProjectID: projID,
			Old: map[string]any{"subject_type": lc.SubjectTyp, "subject_id": lc.SubjectID.String(), "scope_type": lc.ScopeType, "scope_id": lc.ScopeID.String(), "template_id": lc.TemplateID.String()}, Impact: 1})
	})
}

// ---------------------------------------------------------------- who has access to a project

// AccessVia is one reason a person has access to a project.
type AccessVia struct {
	Kind      string     `json:"kind"` // floor | base | direct | group | repo | env
	Label     string     `json:"label"`
	Template  string     `json:"template"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// AccessRow is one person with access to a project.
type AccessRow struct {
	User             UserRef     `json:"user"`
	OrgTemplate      string      `json:"org_template"`
	LegacyRole       string      `json:"legacy_role"`
	Source           string      `json:"source"`
	Via              []AccessVia `json:"via"`
	PermissionsCount int         `json:"permissions_count"`
}

// ProjectAccessPage is the answer of GET .../projects/{id}/access.
type ProjectAccessPage struct {
	Data       []AccessRow `json:"data"`
	Mode       string      `json:"mode"`
	NextCursor *string     `json:"next_cursor"`
}

// ProjectAccess lists who can see a project, with origin and effective permission count (assignment:read on the project).
func (s *Service) ProjectAccess(ctx context.Context, actor Actor, org, project uuid.UUID, cursor string, limit int) (*ProjectAccessPage, error) {
	if _, _, _, err := s.requireAt(ctx, actor, org, "project", project, "assignment:read"); err != nil {
		return nil, err
	}
	limit = clampLimit(limit)
	mode, err := s.effectiveMode(ctx, s.q(), org, project)
	if err != nil {
		return nil, err
	}
	page := &ProjectAccessPage{Data: []AccessRow{}, Mode: mode}
	afterEmail, afterID, hasCursor := decodeCursor(cursor)
	type member struct {
		ID                  uuid.UUID
		Email, Name, Templ  string
		FloorSlug, BaseSlug string
	}
	var lastEmail string
	var lastID uuid.UUID
	exhausted := false
	for len(page.Data) <= limit && !exhausted {
		chunk := 200
		rows, err := s.q().Query(ctx, `
			SELECT u.id, u.email, u.name, COALESCE(t.slug, ''), COALESCE(ft.slug, ''), COALESCE(bt.slug, '')
			  FROM org_members om JOIN users u ON u.id = om.user_id
			  LEFT JOIN role_templates t ON t.id = om.template_id
			  LEFT JOIN role_template_versions v ON v.template_id = t.id AND v.version = COALESCE(om.template_version, t.current_version)
			  LEFT JOIN role_templates ft ON ft.id = v.floor_template_id
			  LEFT JOIN role_templates bt ON bt.id = v.base_template_id
			 WHERE om.org_id = $1 AND (NOT $2 OR (u.email, u.id) > ($3, $4))
			 ORDER BY u.email, u.id LIMIT $5`, org, hasCursor, afterEmail, parseUUIDOrNil(afterID), chunk)
		if err != nil {
			return nil, err
		}
		var members []member
		for rows.Next() {
			var m member
			if err := rows.Scan(&m.ID, &m.Email, &m.Name, &m.Templ, &m.FloorSlug, &m.BaseSlug); err != nil {
				rows.Close()
				return nil, err
			}
			members = append(members, m)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if len(members) < chunk {
			exhausted = true
		}
		var visible []member
		type eff struct {
			acc engine.Access
			set engine.Set
		}
		effs := map[uuid.UUID]eff{}
		for _, m := range members {
			lastEmail, lastID = m.Email, m.ID
			acc, set, err := s.eng.Effective(ctx, m.ID, org, engine.ProjectScope(project))
			if err != nil {
				return nil, err
			}
			if !acc.Member || acc.Hidden || set.IsEmpty() {
				continue
			}
			visible = append(visible, m)
			effs[m.ID] = eff{acc, set}
			if len(page.Data)+len(visible) > limit {
				break
			}
		}
		afterEmail, hasCursor = lastEmail, true
		afterID = lastID.String()
		if len(visible) == 0 {
			continue
		}
		ids := make([]uuid.UUID, len(visible))
		for i, m := range visible {
			ids[i] = m.ID
		}
		vias, err := s.accessVias(ctx, org, project, ids)
		if err != nil {
			return nil, err
		}
		for _, m := range visible {
			e := effs[m.ID]
			via := vias[m.ID]
			if m.FloorSlug != "" {
				via = append([]AccessVia{{Kind: "floor", Label: m.FloorSlug, Template: m.FloorSlug}}, via...)
			}
			if m.BaseSlug != "" && mode == "open" && e.acc.Source == engine.SourceInherited {
				via = append(via, AccessVia{Kind: "base", Label: m.BaseSlug, Template: m.BaseSlug})
			}
			if via == nil {
				via = []AccessVia{}
			}
			page.Data = append(page.Data, AccessRow{
				User: UserRef{ID: m.ID, Email: m.Email, Name: m.Name}, OrgTemplate: m.Templ, LegacyRole: engine.LegacyRole(e.set),
				Source: string(e.acc.Source), Via: via, PermissionsCount: e.set.Len(),
			})
		}
	}
	if len(page.Data) > limit {
		page.Data = page.Data[:limit]
		last := page.Data[limit-1].User
		c := encodeCursor(last.Email, last.ID.String())
		page.NextCursor = &c
	}
	return page, nil
}

func parseUUIDOrNil(s string) uuid.UUID {
	u, _ := uuid.Parse(s)
	return u
}

func (s *Service) effectiveMode(ctx context.Context, q querier, org, project uuid.UUID) (string, error) {
	var mode string
	err := q.QueryRow(ctx, `SELECT COALESCE((SELECT access_override FROM projects WHERE id = $2 AND org_id = $1), o.project_access_mode) FROM organizations o WHERE o.id = $1`, org, project).Scan(&mode)
	return mode, err
}

// accessVias returns, for each user, the live assignments (own and through groups) that reach the project.
func (s *Service) accessVias(ctx context.Context, org, project uuid.UUID, users []uuid.UUID) (map[uuid.UUID][]AccessVia, error) {
	out := map[uuid.UUID][]AccessVia{}
	rows, err := s.q().Query(ctx, `
		SELECT a.subject_type, a.subject_id, a.scope_type, t.slug, a.expires_at
		  FROM access_assignments a JOIN role_templates t ON t.id = a.template_id
		 WHERE a.org_id = $1 AND a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())
		   AND ((a.scope_type IN ('project','repo') AND a.scope_id = $2) OR a.scope_type = 'org'
		        OR (a.scope_type = 'env' AND a.scope_id IN (SELECT id FROM environments WHERE project_id = $2)))
		 ORDER BY a.created_at, a.id`, org, project)
	if err != nil {
		return nil, err
	}
	type asg struct {
		scope, tpl string
		exp        *time.Time
	}
	direct := map[uuid.UUID][]asg{}
	group := map[uuid.UUID][]asg{}
	want := map[uuid.UUID]bool{}
	for _, u := range users {
		want[u] = true
	}
	for rows.Next() {
		var st, scope, tpl string
		var sid uuid.UUID
		var exp *time.Time
		if err := rows.Scan(&st, &sid, &scope, &tpl, &exp); err != nil {
			rows.Close()
			return nil, err
		}
		if st == "user" {
			if want[sid] {
				direct[sid] = append(direct[sid], asg{scope, tpl, exp})
			}
		} else {
			group[sid] = append(group[sid], asg{scope, tpl, exp})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	kind := func(scope string) string {
		switch scope {
		case "repo":
			return "repo"
		case "env":
			return "env"
		}
		return "direct"
	}
	for u, list := range direct {
		for _, a := range list {
			out[u] = append(out[u], AccessVia{Kind: kind(a.scope), Label: a.scope, Template: a.tpl, ExpiresAt: a.exp})
		}
	}
	if len(group) > 0 {
		gids := make([]uuid.UUID, 0, len(group))
		for g := range group {
			gids = append(gids, g)
		}
		r2, err := s.q().Query(ctx, `
			SELECT gm.user_id, g.id, g.slug, gm.expires_at FROM group_members gm JOIN groups g ON g.id = gm.group_id AND g.archived_at IS NULL
			 WHERE g.org_id = $1 AND g.id = ANY($2) AND gm.user_id = ANY($3) AND (gm.expires_at IS NULL OR gm.expires_at > now())`, org, gids, users)
		if err != nil {
			return nil, err
		}
		for r2.Next() {
			var u, g uuid.UUID
			var slug string
			var gexp *time.Time
			if err := r2.Scan(&u, &g, &slug, &gexp); err != nil {
				r2.Close()
				return nil, err
			}
			for _, a := range group[g] {
				exp := a.exp
				if gexp != nil && (exp == nil || gexp.Before(*exp)) {
					exp = gexp
				}
				out[u] = append(out[u], AccessVia{Kind: "group", Label: slug, Template: a.tpl, ExpiresAt: exp})
			}
		}
		r2.Close()
		if err := r2.Err(); err != nil {
			return nil, err
		}
	}
	for u := range out {
		sort.SliceStable(out[u], func(i, j int) bool { return out[u][i].Kind < out[u][j].Kind })
	}
	return out, nil
}
