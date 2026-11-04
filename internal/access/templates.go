package access

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/repository"
)

// TemplateInput is the body of POST (create or clone) and PUT (publish a version) of a template.
type TemplateInput struct {
	Kind          string     `json:"kind"`
	Slug          string     `json:"slug"`
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	Permissions   []string   `json:"permissions"`
	Ceiling       *[]string  `json:"ceiling"`
	FloorTemplate *string    `json:"floor_template"`
	BaseTemplate  *string    `json:"base_template"`
	ClonedFrom    *uuid.UUID `json:"cloned_from"`
	Note          string     `json:"note"`
}

// Usage counts where a template is used (organization scope only).
type Usage struct {
	Users    int `json:"users"`
	Groups   int `json:"groups"`
	Projects int `json:"projects"`
}

// TemplateDTO is the Template schema of API.openapi.yaml.
type TemplateDTO struct {
	ID                 uuid.UUID  `json:"id"`
	Kind               string     `json:"kind"`
	Slug               string     `json:"slug"`
	Name               string     `json:"name"`
	Description        string     `json:"description"`
	System             bool       `json:"system"`
	ClonedFrom         *uuid.UUID `json:"cloned_from"`
	CurrentVersion     int        `json:"current_version"`
	Archived           bool       `json:"archived"`
	Permissions        []string   `json:"permissions"`
	Ceiling            []string   `json:"ceiling"`
	FloorTemplate      *string    `json:"floor_template"`
	BaseTemplate       *string    `json:"base_template"`
	UnknownPermissions []string   `json:"unknown_permissions"`
	Usage              Usage      `json:"usage"`
}

// TemplateVersionDTO is one entry of the version history.
type TemplateVersionDTO struct {
	Version     int       `json:"version"`
	Permissions []string  `json:"permissions"`
	Note        string    `json:"note"`
	CreatedBy   *UserRef  `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// Impact is what publishing a version would change (SPEC 4.3 propagation): people, groups and projects that follow the latest version
// of the template, and the permissions they gain and lose. AffectedUsers is a sample (at most 20).
type Impact struct {
	Users          int       `json:"users"`
	Groups         int       `json:"groups"`
	Projects       int       `json:"projects"`
	Gains          []string  `json:"gains"`
	Loses          []string  `json:"loses"`
	CeilingChanged bool      `json:"ceiling_changed"`
	AffectedUsers  []UserRef `json:"affected_users"`
}

// PublishResult is the answer of PUT .../templates/{id}.
type PublishResult struct {
	Published bool         `json:"published"`
	Template  *TemplateDTO `json:"template"`
	Impact    Impact       `json:"impact"`
}

type templateHead struct {
	ID          uuid.UUID
	OrgID       *uuid.UUID
	Kind        string
	Slug        string
	Name        string
	Description string
	System      bool
	ClonedFrom  *uuid.UUID
	Current     int
	ArchivedAt  *time.Time
}

type templateVer struct {
	Version        int
	Permissions    []string
	Ceiling        []string
	CeilingProject []string
	FloorID        *uuid.UUID
	BaseID         *uuid.UUID
	Note           string
	CreatedBy      *uuid.UUID
	CreatedAt      time.Time
}

const headCols = `t.id, t.org_id, t.kind, t.slug, t.name, t.description, t.system, t.cloned_from, t.current_version, t.archived_at`
const verCols = `v.version, v.permissions, v.ceiling, v.ceiling_project, v.floor_template_id, v.base_template_id, v.note, v.created_by, v.created_at`

func scanHead(row interface{ Scan(...any) error }, h *templateHead) error {
	return row.Scan(&h.ID, &h.OrgID, &h.Kind, &h.Slug, &h.Name, &h.Description, &h.System, &h.ClonedFrom, &h.Current, &h.ArchivedAt)
}

func scanVer(row interface{ Scan(...any) error }, v *templateVer) error {
	return row.Scan(&v.Version, &v.Permissions, &v.Ceiling, &v.CeilingProject, &v.FloorID, &v.BaseID, &v.Note, &v.CreatedBy, &v.CreatedAt)
}

// loadHead returns a template visible to the organization (its own or a system one); ErrNotFound otherwise, which is the same answer
// for a template that does not exist and for one of another organization.
func loadHead(ctx context.Context, q querier, org, id uuid.UUID, lock bool) (*templateHead, error) {
	sql := `SELECT ` + headCols + ` FROM role_templates t WHERE t.id = $1 AND (t.org_id = $2 OR t.system)`
	if lock {
		sql += ` FOR UPDATE`
	}
	var h templateHead
	if err := scanHead(q.QueryRow(ctx, sql, id, org), &h); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return &h, nil
}

// loadVer returns a version of a template (0 = current).
func loadVer(ctx context.Context, q querier, id uuid.UUID, version int) (*templateVer, error) {
	var v templateVer
	err := scanVer(q.QueryRow(ctx, `
		SELECT `+verCols+` FROM role_template_versions v JOIN role_templates t ON t.id = v.template_id
		 WHERE v.template_id = $1 AND v.version = CASE WHEN $2 = 0 THEN t.current_version ELSE $2 END`, id, version), &v)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *Service) templateSlugs(ctx context.Context, q querier, ids ...*uuid.UUID) (map[uuid.UUID]string, error) {
	var list []uuid.UUID
	for _, p := range ids {
		if p != nil {
			list = append(list, *p)
		}
	}
	out := map[uuid.UUID]string{}
	if len(list) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT id, slug FROM role_templates WHERE id = ANY($1)`, list)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var slug string
		if err := rows.Scan(&id, &slug); err != nil {
			return nil, err
		}
		out[id] = slug
	}
	return out, rows.Err()
}

func (s *Service) templateUsage(ctx context.Context, q querier, org uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]Usage, error) {
	out := make(map[uuid.UUID]Usage, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `
		SELECT t.id,
		  (SELECT count(DISTINCT a.subject_id) FROM access_assignments a WHERE a.org_id = $1 AND a.template_id = t.id AND a.revoked_at IS NULL AND a.subject_type = 'user')
		   + (SELECT count(*) FROM org_members om WHERE om.org_id = $1 AND om.template_id = t.id),
		  (SELECT count(DISTINCT a.subject_id) FROM access_assignments a WHERE a.org_id = $1 AND a.template_id = t.id AND a.revoked_at IS NULL AND a.subject_type = 'group'),
		  (SELECT count(DISTINCT a.scope_id) FROM access_assignments a WHERE a.org_id = $1 AND a.template_id = t.id AND a.revoked_at IS NULL AND a.scope_type IN ('project','repo'))
		FROM role_templates t WHERE t.id = ANY($2)`, org, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var u Usage
		if err := rows.Scan(&id, &u.Users, &u.Groups, &u.Projects); err != nil {
			return nil, err
		}
		out[id] = u
	}
	return out, rows.Err()
}

func (s *Service) templateDTO(ctx context.Context, q querier, org uuid.UUID, h *templateHead, v *templateVer, usage Usage, slugs map[uuid.UUID]string) *TemplateDTO {
	_, unknown := catalog.ParseSet(v.Permissions)
	perms := v.Permissions
	if perms == nil {
		perms = []string{}
	}
	d := &TemplateDTO{
		ID: h.ID, Kind: h.Kind, Slug: h.Slug, Name: h.Name, Description: h.Description, System: h.System, ClonedFrom: h.ClonedFrom,
		CurrentVersion: v.Version, Archived: h.ArchivedAt != nil, Permissions: perms, Ceiling: v.Ceiling,
		UnknownPermissions: append([]string{}, unknown...), Usage: usage,
	}
	if v.FloorID != nil {
		if sl, ok := slugs[*v.FloorID]; ok {
			d.FloorTemplate = &sl
		}
	}
	if v.BaseID != nil {
		if sl, ok := slugs[*v.BaseID]; ok {
			d.BaseTemplate = &sl
		}
	}
	return d
}

func (s *Service) buildDTO(ctx context.Context, q querier, org uuid.UUID, h *templateHead, v *templateVer) (*TemplateDTO, error) {
	slugs, err := s.templateSlugs(ctx, q, v.FloorID, v.BaseID)
	if err != nil {
		return nil, err
	}
	us, err := s.templateUsage(ctx, q, org, []uuid.UUID{h.ID})
	if err != nil {
		return nil, err
	}
	return s.templateDTO(ctx, q, org, h, v, us[h.ID], slugs), nil
}

// ListTemplates returns the system templates and the organization's own (template:read).
func (s *Service) ListTemplates(ctx context.Context, actor Actor, org uuid.UUID, kind string, includeArchived bool) ([]*TemplateDTO, error) {
	if _, err := s.require(ctx, actor, org, orgScope, "template:read"); err != nil {
		return nil, err
	}
	if kind != "" && kind != "org" && kind != "project" && kind != "repo" {
		return nil, validationField("kind", "must be org, project or repo")
	}
	rows, err := s.q().Query(ctx, `
		SELECT `+headCols+`, `+verCols+`
		  FROM role_templates t JOIN role_template_versions v ON v.template_id = t.id AND v.version = t.current_version
		 WHERE (t.org_id = $1 OR t.system) AND ($2 = '' OR t.kind = $2) AND ($3 OR t.archived_at IS NULL)
		 ORDER BY t.system DESC, t.kind, t.slug`, org, kind, includeArchived)
	if err != nil {
		return nil, err
	}
	type pair struct {
		h templateHead
		v templateVer
	}
	var all []pair
	for rows.Next() {
		var p pair
		dst := []any{&p.h.ID, &p.h.OrgID, &p.h.Kind, &p.h.Slug, &p.h.Name, &p.h.Description, &p.h.System, &p.h.ClonedFrom, &p.h.Current, &p.h.ArchivedAt,
			&p.v.Version, &p.v.Permissions, &p.v.Ceiling, &p.v.CeilingProject, &p.v.FloorID, &p.v.BaseID, &p.v.Note, &p.v.CreatedBy, &p.v.CreatedAt}
		if err := rows.Scan(dst...); err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, len(all))
	var refs []*uuid.UUID
	for i := range all {
		ids[i] = all[i].h.ID
		refs = append(refs, all[i].v.FloorID, all[i].v.BaseID)
	}
	usage, err := s.templateUsage(ctx, s.q(), org, ids)
	if err != nil {
		return nil, err
	}
	slugs, err := s.templateSlugs(ctx, s.q(), refs...)
	if err != nil {
		return nil, err
	}
	out := make([]*TemplateDTO, 0, len(all))
	for i := range all {
		out = append(out, s.templateDTO(ctx, s.q(), org, &all[i].h, &all[i].v, usage[all[i].h.ID], slugs))
	}
	return out, nil
}

// GetTemplate returns a template with its latest version and usage (template:read).
func (s *Service) GetTemplate(ctx context.Context, actor Actor, org, id uuid.UUID) (*TemplateDTO, error) {
	if _, err := s.require(ctx, actor, org, orgScope, "template:read"); err != nil {
		return nil, err
	}
	h, err := loadHead(ctx, s.q(), org, id, false)
	if err != nil {
		return nil, Normalize(err)
	}
	v, err := loadVer(ctx, s.q(), id, 0)
	if err != nil {
		return nil, Normalize(err)
	}
	return s.buildDTO(ctx, s.q(), org, h, v)
}

// ListTemplateVersions returns the version history, newest first (template:read).
func (s *Service) ListTemplateVersions(ctx context.Context, actor Actor, org, id uuid.UUID) ([]TemplateVersionDTO, error) {
	if _, err := s.require(ctx, actor, org, orgScope, "template:read"); err != nil {
		return nil, err
	}
	if _, err := loadHead(ctx, s.q(), org, id, false); err != nil {
		return nil, Normalize(err)
	}
	rows, err := s.q().Query(ctx, `SELECT `+verCols+` FROM role_template_versions v WHERE v.template_id = $1 ORDER BY v.version DESC`, id)
	if err != nil {
		return nil, err
	}
	var vers []templateVer
	for rows.Next() {
		var v templateVer
		if err := scanVer(rows, &v); err != nil {
			rows.Close()
			return nil, err
		}
		vers = append(vers, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var by []uuid.UUID
	for _, v := range vers {
		if v.CreatedBy != nil {
			by = append(by, *v.CreatedBy)
		}
	}
	refs, err := s.userRefs(ctx, s.q(), by)
	if err != nil {
		return nil, err
	}
	out := make([]TemplateVersionDTO, 0, len(vers))
	for _, v := range vers {
		d := TemplateVersionDTO{Version: v.Version, Permissions: append([]string{}, v.Permissions...), Note: v.Note, CreatedAt: v.CreatedAt}
		if v.CreatedBy != nil {
			if u, ok := refs[*v.CreatedBy]; ok {
				d.CreatedBy = &u
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// TemplateDiff is the answer of .../versions/{from}/diff/{to}.
type TemplateDiff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// DiffTemplateVersions returns the permissions added and removed between two versions (template:read).
func (s *Service) DiffTemplateVersions(ctx context.Context, actor Actor, org, id uuid.UUID, from, to int) (*TemplateDiff, error) {
	if _, err := s.require(ctx, actor, org, orgScope, "template:read"); err != nil {
		return nil, err
	}
	if _, err := loadHead(ctx, s.q(), org, id, false); err != nil {
		return nil, Normalize(err)
	}
	if from < 1 || to < 1 {
		return nil, notFound("version not found")
	}
	a, err := loadVer(ctx, s.q(), id, from)
	if err != nil {
		return nil, notFound("version not found")
	}
	b, err := loadVer(ctx, s.q(), id, to)
	if err != nil {
		return nil, notFound("version not found")
	}
	sa, sb := catalog.NewSet(a.Permissions...), catalog.NewSet(b.Permissions...)
	return &TemplateDiff{Added: nonNilStrings(setDiff(sb, sa)), Removed: nonNilStrings(setDiff(sa, sb))}, nil
}

func nonNilStrings(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// ---------------------------------------------------------------- write: validation shared by create and publish

type preparedTemplate struct {
	Perms          catalog.Set
	PermIDs        []string
	Ceiling        []string // nil = none
	FloorID        *uuid.UUID
	BaseID         *uuid.UUID
	FloorSet       catalog.Set
	BaseSet        catalog.Set
	Name           string
	Description    string
	Note           string
	baselinePerms  catalog.Set // what the save does not ADD (the clone source or the current version)
	baselineFloor  catalog.Set
	baselineBase   catalog.Set
	baselineFloorI *uuid.UUID
	baselineBaseI  *uuid.UUID
}

func (s *Service) prepareTemplate(ctx context.Context, q querier, org uuid.UUID, kind string, in TemplateInput, base *templateVer) (*preparedTemplate, error) {
	fields := map[string]string{}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 80 {
		fields["name"] = "required, at most 80 characters"
	}
	if len(in.Description) > 500 {
		fields["description"] = "at most 500 characters"
	}
	if len(in.Note) > 300 {
		fields["note"] = "at most 300 characters"
	}
	if len(in.Permissions) > repository.MaxPermsPerTemplate {
		return nil, limitErr(fmt.Sprintf("a template has at most %d permissions", repository.MaxPermsPerTemplate))
	}
	if len(fields) > 0 {
		return nil, validation(fields)
	}
	p := &preparedTemplate{Name: name, Description: in.Description, Note: in.Note}
	perms := in.Permissions
	if len(perms) == 0 {
		if base == nil {
			return nil, validationField("permissions", "at least one permission is required")
		}
		perms = base.Permissions // clone without edits: copy of the source
	}
	set, ids, verr := ValidatePermissions("permissions", kind, perms)
	if verr != nil {
		return nil, verr
	}
	p.Perms, p.PermIDs = set, ids
	if in.Ceiling != nil {
		if kind != "org" {
			return nil, validationField("ceiling", "only organization templates have a ceiling")
		}
		_, cids, cerr := validateCeiling(*in.Ceiling)
		if cerr != nil {
			return nil, cerr
		}
		p.Ceiling = cids
		if p.Ceiling == nil {
			p.Ceiling = []string{}
		}
	}
	// floor and base are project templates (visible, not archived) of an organization template
	resolve := func(field string, slug *string) (*uuid.UUID, catalog.Set, error) {
		if slug == nil || *slug == "" {
			return nil, catalog.Set{}, nil
		}
		if kind != "org" {
			return nil, catalog.Set{}, validationField(field, "only organization templates have a floor and a base")
		}
		var id uuid.UUID
		var archived bool
		err := q.QueryRow(ctx, `SELECT t.id, t.archived_at IS NOT NULL FROM role_templates t WHERE t.kind = 'project' AND t.slug = $2 AND (t.org_id = $1 OR t.system) ORDER BY t.system LIMIT 1`, org, *slug).Scan(&id, &archived)
		if errors.Is(err, pgx.ErrNoRows) || archived {
			return nil, catalog.Set{}, validationField(field, "no such project template")
		}
		if err != nil {
			return nil, catalog.Set{}, err
		}
		v, err := loadVer(ctx, q, id, 0)
		if err != nil {
			return nil, catalog.Set{}, err
		}
		return &id, catalog.NewSet(v.Permissions...), nil
	}
	var err error
	if p.FloorID, p.FloorSet, err = resolve("floor_template", in.FloorTemplate); err != nil {
		return nil, err
	}
	if p.BaseID, p.BaseSet, err = resolve("base_template", in.BaseTemplate); err != nil {
		return nil, err
	}
	if base != nil {
		p.baselinePerms = catalog.NewSet(base.Permissions...)
		p.baselineFloorI, p.baselineBaseI = base.FloorID, base.BaseID
		if base.FloorID != nil {
			if v, err := loadVer(ctx, q, *base.FloorID, 0); err == nil {
				p.baselineFloor = catalog.NewSet(v.Permissions...)
			}
		}
		if base.BaseID != nil {
			if v, err := loadVer(ctx, q, *base.BaseID, 0); err == nil {
				p.baselineBase = catalog.NewSet(v.Permissions...)
			}
		}
	}
	return p, nil
}

func validateCeiling(list []string) (catalog.Set, []string, *Error) {
	var set catalog.Set
	var unknown []string
	for _, p := range list {
		if strings.Contains(p, "*") {
			return set, nil, validationField("ceiling", "wildcards are only allowed in system templates")
		}
		if !catalog.Has(p) {
			unknown = append(unknown, p)
			continue
		}
		set = set.Add(p)
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return set, nil, validationDetails("invalid ceiling", map[string]any{"fields": map[string]string{"ceiling": "unknown permissions"}, "unknown_permissions": unknown})
	}
	return set, set.IDs(), nil
}

// checkNoEscalation implements the rule of SPEC 4.3 and 13.1: a save may only ADD permissions the actor holds. kind org templates are
// checked against the actor's organization set, project and repo templates against what the actor holds in every project; the floor
// and base of an organization template count as project permissions. An active owner is exempt. Removing is always free.
func (s *Service) checkNoEscalation(ctx context.Context, actor Actor, org uuid.UUID, kind string, orgSet catalog.Set, p *preparedTemplate) error {
	owner, err := s.isOwner(ctx, s.q(), org, actor.UserID)
	if err != nil {
		return err
	}
	if owner {
		return nil
	}
	added := p.Perms.Minus(p.baselinePerms)
	var projAdded catalog.Set
	if p.FloorID != nil && (p.baselineFloorI == nil || *p.baselineFloorI != *p.FloorID) {
		projAdded = projAdded.Union(p.FloorSet.Minus(p.baselineFloor))
	}
	if p.BaseID != nil && (p.baselineBaseI == nil || *p.baselineBaseI != *p.BaseID) {
		projAdded = projAdded.Union(p.BaseSet.Minus(p.baselineBase))
	}
	var missing catalog.Set
	if kind == "org" {
		missing = added.Minus(orgSet)
	} else {
		projAdded = projAdded.Union(added)
		added = catalog.Set{}
	}
	if !projAdded.IsEmpty() {
		caps, err := s.projectCaps(ctx, actor.UserID, org)
		if err != nil {
			return err
		}
		missing = missing.Union(projAdded.Minus(caps))
	}
	if missing.IsEmpty() {
		return nil
	}
	return escalation("a template save can only add permissions you hold yourself", missing.IDs(), "")
}

// ---------------------------------------------------------------- create / clone

// CreateTemplate creates a custom template (version 1) or, with cloned_from, a copy of any visible template (template:manage).
func (s *Service) CreateTemplate(ctx context.Context, actor Actor, org uuid.UUID, in TemplateInput, idem *Idem) (Reply[*TemplateDTO], error) {
	orgSet, err := s.require(ctx, actor, org, orgScope, "template:manage")
	if err != nil {
		return Reply[*TemplateDTO]{}, err
	}
	fields := map[string]string{}
	if in.Kind != "org" && in.Kind != "project" && in.Kind != "repo" {
		fields["kind"] = "must be org, project or repo"
	}
	if !slugRE.MatchString(in.Slug) {
		fields["slug"] = "lowercase letters, digits and hyphens, 1 to 40 characters"
	}
	if len(fields) > 0 {
		return Reply[*TemplateDTO]{}, validation(fields)
	}
	var base *templateVer
	if in.ClonedFrom != nil {
		sh, err := loadHead(ctx, s.q(), org, *in.ClonedFrom, false)
		if err != nil {
			return Reply[*TemplateDTO]{}, validationField("cloned_from", "no such template")
		}
		if sh.Kind != in.Kind {
			return Reply[*TemplateDTO]{}, validationField("kind", "a clone has the kind of its source ("+sh.Kind+")")
		}
		if base, err = loadVer(ctx, s.q(), sh.ID, 0); err != nil {
			return Reply[*TemplateDTO]{}, validationField("cloned_from", "no such template")
		}
		// a clone without explicit floor, base or ceiling inherits the source's
		if in.FloorTemplate == nil && base.FloorID != nil {
			sl, _ := s.templateSlugs(ctx, s.q(), base.FloorID)
			v := sl[*base.FloorID]
			in.FloorTemplate = &v
		}
		if in.BaseTemplate == nil && base.BaseID != nil {
			sl, _ := s.templateSlugs(ctx, s.q(), base.BaseID)
			v := sl[*base.BaseID]
			in.BaseTemplate = &v
		}
		if in.Ceiling == nil && base.Ceiling != nil {
			c := append([]string{}, base.Ceiling...)
			in.Ceiling = &c
		}
	}
	p, err := s.prepareTemplate(ctx, s.q(), org, in.Kind, in, base)
	if err != nil {
		return Reply[*TemplateDTO]{}, err
	}
	if err := s.checkNoEscalation(ctx, actor, org, in.Kind, orgSet, p); err != nil {
		return Reply[*TemplateDTO]{}, err
	}
	return doWrite(ctx, s, org, actor, idem, 201, func(tx pgx.Tx) (*TemplateDTO, error) {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM role_templates WHERE org_id = $1`, org).Scan(&n); err != nil {
			return nil, err
		}
		if n >= repository.MaxTemplatesPerOrg {
			return nil, limitErr(fmt.Sprintf("an organization has at most %d templates", repository.MaxTemplatesPerOrg))
		}
		var reserved bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM role_templates WHERE system AND kind = $1 AND slug = $2)`, in.Kind, in.Slug).Scan(&reserved); err != nil {
			return nil, err
		}
		if reserved {
			return nil, validationField("slug", "slug is reserved by a system template")
		}
		var h templateHead
		if err := scanHead(tx.QueryRow(ctx, `
			INSERT INTO role_templates (org_id, kind, slug, name, description, system, cloned_from, created_by)
			VALUES ($1,$2,$3,$4,$5,false,$6,$7)
			RETURNING id, org_id, kind, slug, name, description, system, cloned_from, current_version, archived_at`,
			org, in.Kind, in.Slug, p.Name, p.Description, in.ClonedFrom, actor.UserID), &h); err != nil {
			if e := mapPg(err); errors.Is(e, repository.ErrAccessConflict) {
				return nil, conflict("DUPLICATE", "a template with that slug already exists", nil)
			} else {
				return nil, e
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO role_template_versions (template_id, version, permissions, ceiling, floor_template_id, base_template_id, note, created_by)
			VALUES ($1, 1, $2, $3, $4, $5, $6, $7)`, h.ID, nonNilStrings(p.PermIDs), p.Ceiling, p.FloorID, p.BaseID, p.Note, actor.UserID); err != nil {
			return nil, mapPg(err)
		}
		action := "access.template.created"
		if in.ClonedFrom != nil {
			action = "access.template.cloned"
		}
		nv := map[string]any{"kind": in.Kind, "slug": in.Slug, "name": p.Name, "version": 1, "permissions": nonNilStrings(p.PermIDs)}
		if in.ClonedFrom != nil {
			nv["cloned_from"] = in.ClonedFrom.String()
		}
		if err := s.audit(ctx, tx, org, actor, auditRow{Action: action, ResourceType: "template", ResourceID: h.ID, New: nv}); err != nil {
			return nil, err
		}
		v, err := loadVer(ctx, tx, h.ID, 0)
		if err != nil {
			return nil, err
		}
		return s.buildDTO(ctx, tx, org, &h, v)
	})
}

// ---------------------------------------------------------------- impact

// impactOf computes who follows the latest version of a template and what they would gain and lose.
func (s *Service) impactOf(ctx context.Context, q querier, org uuid.UUID, h *templateHead, cur *templateVer, p *preparedTemplate) (Impact, error) {
	imp := Impact{Gains: []string{}, Loses: []string{}, AffectedUsers: []UserRef{}}
	oldSet := catalog.NewSet(cur.Permissions...)
	newSet := p.Perms
	oldAll, newAll := oldSet, newSet
	if cur.FloorID != nil {
		if v, err := loadVer(ctx, q, *cur.FloorID, 0); err == nil {
			oldAll = oldAll.Union(catalog.NewSet(v.Permissions...))
		}
	}
	if cur.BaseID != nil {
		if v, err := loadVer(ctx, q, *cur.BaseID, 0); err == nil {
			oldAll = oldAll.Union(catalog.NewSet(v.Permissions...))
		}
	}
	newAll = newAll.Union(p.FloorSet).Union(p.BaseSet)
	imp.Gains, imp.Loses = nonNilStrings(setDiff(newAll, oldAll)), nonNilStrings(setDiff(oldAll, newAll))
	imp.CeilingChanged = !sameStrings(cur.Ceiling, p.Ceiling) || (cur.Ceiling == nil) != (p.Ceiling == nil)

	const live = `a.org_id = $1 AND a.template_id = $2 AND a.revoked_at IS NULL AND a.pinned_version IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())`
	rows, err := q.Query(ctx, `
		SELECT a.subject_id FROM access_assignments a
		  JOIN org_members om ON om.org_id = a.org_id AND om.user_id = a.subject_id AND om.status = 'active'
		 WHERE `+live+` AND a.subject_type = 'user'
		UNION
		SELECT gm.user_id FROM access_assignments a
		  JOIN groups g ON g.id = a.subject_id AND g.archived_at IS NULL
		  JOIN group_members gm ON gm.group_id = g.id AND (gm.expires_at IS NULL OR gm.expires_at > now())
		  JOIN org_members om ON om.org_id = a.org_id AND om.user_id = gm.user_id AND om.status = 'active'
		 WHERE `+live+` AND a.subject_type = 'group'
		UNION
		SELECT om.user_id FROM org_members om WHERE om.org_id = $1 AND om.template_id = $2 AND om.template_version IS NULL AND om.status = 'active'`, org, h.ID)
	if err != nil {
		return imp, err
	}
	var users []uuid.UUID
	for rows.Next() {
		var u uuid.UUID
		if err := rows.Scan(&u); err != nil {
			rows.Close()
			return imp, err
		}
		users = append(users, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return imp, err
	}
	imp.Users = len(users)
	if err := q.QueryRow(ctx, `SELECT count(DISTINCT a.subject_id) FROM access_assignments a JOIN groups g ON g.id = a.subject_id AND g.archived_at IS NULL
		 WHERE `+live+` AND a.subject_type = 'group'`, org, h.ID).Scan(&imp.Groups); err != nil {
		return imp, err
	}
	if h.Kind == "org" {
		// the floor and base of an organization template apply to every project
		if imp.Users > 0 {
			if err := q.QueryRow(ctx, `SELECT count(*) FROM projects WHERE org_id = $1 AND deleted_at IS NULL`, org).Scan(&imp.Projects); err != nil {
				return imp, err
			}
		}
	} else if err := q.QueryRow(ctx, `
		SELECT count(*) FROM (
		  SELECT a.scope_id AS p FROM access_assignments a WHERE `+live+` AND a.scope_type IN ('project','repo')
		  UNION SELECT e.project_id FROM access_assignments a JOIN environments e ON e.id = a.scope_id WHERE `+live+` AND a.scope_type = 'env'
		  UNION SELECT pr.id FROM projects pr WHERE pr.org_id = $1 AND pr.deleted_at IS NULL
		        AND EXISTS (SELECT 1 FROM access_assignments a WHERE `+live+` AND a.scope_type = 'org')
		) x`, org, h.ID).Scan(&imp.Projects); err != nil {
		return imp, err
	}
	if len(users) > 0 {
		r2, err := q.Query(ctx, `SELECT id, email, name FROM users WHERE id = ANY($1) ORDER BY email, id LIMIT 20`, users)
		if err != nil {
			return imp, err
		}
		for r2.Next() {
			var u UserRef
			if err := r2.Scan(&u.ID, &u.Email, &u.Name); err != nil {
				r2.Close()
				return imp, err
			}
			imp.AffectedUsers = append(imp.AffectedUsers, u)
		}
		r2.Close()
		if err := r2.Err(); err != nil {
			return imp, err
		}
	}
	return imp, nil
}

// FollowerIDs returns the people who follow the latest version of a template (for tests and impact checks).
func (s *Service) followerIDs(ctx context.Context, org, template uuid.UUID) ([]uuid.UUID, error) {
	const live = `a.org_id = $1 AND a.template_id = $2 AND a.revoked_at IS NULL AND a.pinned_version IS NULL AND (a.expires_at IS NULL OR a.expires_at > now())`
	rows, err := s.q().Query(ctx, `
		SELECT a.subject_id FROM access_assignments a JOIN org_members om ON om.org_id = a.org_id AND om.user_id = a.subject_id AND om.status = 'active'
		 WHERE `+live+` AND a.subject_type = 'user'
		UNION
		SELECT gm.user_id FROM access_assignments a JOIN groups g ON g.id = a.subject_id AND g.archived_at IS NULL
		  JOIN group_members gm ON gm.group_id = g.id AND (gm.expires_at IS NULL OR gm.expires_at > now())
		  JOIN org_members om ON om.org_id = a.org_id AND om.user_id = gm.user_id AND om.status = 'active'
		 WHERE `+live+` AND a.subject_type = 'group'
		UNION
		SELECT om.user_id FROM org_members om WHERE om.org_id = $1 AND om.template_id = $2 AND om.template_version IS NULL AND om.status = 'active'`, org, template)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var u uuid.UUID
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- publish

// PublishTemplate publishes version n+1 of a custom template, or with dryRun answers what it would change without saving
// (template:manage). System templates answer 409 SYSTEM_TEMPLATE; an archived template 409; the no-escalation rule applies.
func (s *Service) PublishTemplate(ctx context.Context, actor Actor, org, id uuid.UUID, in TemplateInput, dryRun bool, idem *Idem) (Reply[*PublishResult], error) {
	orgSet, err := s.require(ctx, actor, org, orgScope, "template:manage")
	if err != nil {
		return Reply[*PublishResult]{}, err
	}
	h, err := loadHead(ctx, s.q(), org, id, false)
	if err != nil {
		return Reply[*PublishResult]{}, Normalize(err)
	}
	if h.System {
		return Reply[*PublishResult]{}, conflict("SYSTEM_TEMPLATE", "system templates are immutable; clone it instead", nil)
	}
	if h.ArchivedAt != nil {
		return Reply[*PublishResult]{}, conflict("TEMPLATE_ARCHIVED", "template is archived", nil)
	}
	if in.Kind != "" && in.Kind != h.Kind {
		return Reply[*PublishResult]{}, validationField("kind", "the kind of a template cannot change")
	}
	if in.Slug != "" && in.Slug != h.Slug {
		return Reply[*PublishResult]{}, validationField("slug", "the slug of a template cannot change")
	}
	if in.Name == "" {
		in.Name = h.Name
	}
	cur, err := loadVer(ctx, s.q(), id, 0)
	if err != nil {
		return Reply[*PublishResult]{}, Normalize(err)
	}
	// PUT replaces the content: the body carries the whole template, so an absent or null ceiling means no ceiling.
	p, err := s.prepareTemplate(ctx, s.q(), org, h.Kind, in, cur)
	if err != nil {
		return Reply[*PublishResult]{}, err
	}
	if err := s.checkNoEscalation(ctx, actor, org, h.Kind, orgSet, p); err != nil {
		return Reply[*PublishResult]{}, err
	}
	same := func(c *templateVer, p *preparedTemplate) bool {
		return catalog.NewSet(c.Permissions...) == p.Perms && sameStrings(c.Ceiling, p.Ceiling) && (c.Ceiling == nil) == (p.Ceiling == nil) &&
			ptrEq(c.FloorID, p.FloorID) && ptrEq(c.BaseID, p.BaseID)
	}
	if dryRun {
		imp, err := s.impactOf(ctx, s.q(), org, h, cur, p)
		if err != nil {
			return Reply[*PublishResult]{}, err
		}
		if err := s.checkLastGranter(ctx, s.q(), org, h, p); err != nil {
			return Reply[*PublishResult]{}, err
		}
		proposed := &TemplateDTO{
			ID: h.ID, Kind: h.Kind, Slug: h.Slug, Name: p.Name, Description: p.Description, System: false, ClonedFrom: h.ClonedFrom,
			CurrentVersion: cur.Version + 1, Permissions: nonNilStrings(p.PermIDs), Ceiling: p.Ceiling, UnknownPermissions: []string{},
		}
		if same(cur, p) {
			proposed.CurrentVersion = cur.Version
		}
		return Reply[*PublishResult]{Value: &PublishResult{Published: false, Template: proposed, Impact: imp}, Status: 200}, nil
	}
	return doWrite(ctx, s, org, actor, idem, 200, func(tx pgx.Tx) (*PublishResult, error) {
		hh, err := loadHead(ctx, tx, org, id, true) // lock: two publishers serialize
		if err != nil {
			return nil, err
		}
		if hh.ArchivedAt != nil {
			return nil, conflict("TEMPLATE_ARCHIVED", "template is archived", nil)
		}
		cc, err := loadVer(ctx, tx, id, 0)
		if err != nil {
			return nil, err
		}
		if cc.Version != cur.Version {
			// someone published while we validated: re-run the checks against the new baseline
			return nil, conflict("STALE_VERSION", "the template changed; reload it and retry", map[string]any{"current_version": cc.Version})
		}
		imp, err := s.impactOf(ctx, tx, org, hh, cc, p)
		if err != nil {
			return nil, err
		}
		if err := s.checkLastGranter(ctx, tx, org, hh, p); err != nil {
			return nil, err
		}
		if same(cc, p) {
			if p.Name == hh.Name && p.Description == hh.Description {
				dto, err := s.buildDTO(ctx, tx, org, hh, cc)
				return &PublishResult{Published: false, Template: dto, Impact: Impact{Gains: []string{}, Loses: []string{}, AffectedUsers: []UserRef{}}}, err
			}
			if _, err := tx.Exec(ctx, `UPDATE role_templates SET name = $2, description = $3, updated_at = now() WHERE id = $1`, id, p.Name, p.Description); err != nil {
				return nil, mapPg(err)
			}
			if err := s.audit(ctx, tx, org, actor, auditRow{Action: "access.template.updated", ResourceType: "template", ResourceID: id,
				Old: map[string]any{"name": hh.Name, "description": hh.Description}, New: map[string]any{"name": p.Name, "description": p.Description}}); err != nil {
				return nil, err
			}
			hh.Name, hh.Description = p.Name, p.Description
			dto, err := s.buildDTO(ctx, tx, org, hh, cc)
			return &PublishResult{Published: false, Template: dto, Impact: Impact{Gains: []string{}, Loses: []string{}, AffectedUsers: []UserRef{}}}, err
		}
		next := cc.Version + 1
		if _, err := tx.Exec(ctx, `
			INSERT INTO role_template_versions (template_id, version, permissions, ceiling, floor_template_id, base_template_id, note, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, id, next, nonNilStrings(p.PermIDs), p.Ceiling, p.FloorID, p.BaseID, p.Note, actor.UserID); err != nil {
			return nil, mapPg(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE role_templates SET current_version = $2, name = $3, description = $4, updated_at = now() WHERE id = $1`, id, next, p.Name, p.Description); err != nil {
			return nil, mapPg(err)
		}
		if err := s.audit(ctx, tx, org, actor, auditRow{
			Action: "access.template.published", ResourceType: "template", ResourceID: id, Impact: imp.Users,
			Old:   map[string]any{"version": cc.Version, "permissions": nonNilStrings(cc.Permissions)},
			New:   map[string]any{"version": next, "permissions": nonNilStrings(p.PermIDs), "gains": imp.Gains, "loses": imp.Loses},
			Extra: map[string]any{"impact_users": imp.Users, "impact_groups": imp.Groups, "impact_projects": imp.Projects},
		}); err != nil {
			return nil, err
		}
		hh.Name, hh.Description, hh.Current = p.Name, p.Description, next
		nv, err := loadVer(ctx, tx, id, 0)
		if err != nil {
			return nil, err
		}
		dto, err := s.buildDTO(ctx, tx, org, hh, nv)
		return &PublishResult{Published: true, Template: dto, Impact: imp}, err
	})
}

func ptrEq(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// checkLastGranter keeps at least one active member able to grant access (SPEC 13.1.4): an organization template save that drops
// assignment:grant is refused when no other active member's organization template carries it.
func (s *Service) checkLastGranter(ctx context.Context, q querier, org uuid.UUID, h *templateHead, p *preparedTemplate) error {
	if h.Kind != "org" || p.Perms.Has("assignment:grant") {
		return nil
	}
	var others int
	if err := q.QueryRow(ctx, `
		SELECT count(*) FROM org_members om
		  JOIN users u ON u.id = om.user_id AND u.status = 'active'
		  JOIN role_templates t ON t.id = om.template_id
		  JOIN role_template_versions v ON v.template_id = t.id AND v.version = COALESCE(om.template_version, t.current_version)
		 WHERE om.org_id = $1 AND om.status = 'active' AND om.template_id <> $2 AND 'assignment:grant' = ANY(v.permissions)`, org, h.ID).Scan(&others); err != nil {
		return err
	}
	if others > 0 {
		return nil
	}
	return conflict("LAST_GRANTER", "this change would leave the organization without anyone able to grant access", nil)
}

// ---------------------------------------------------------------- archive / delete

// DeleteTemplate archives a template that is in use or deletes one nothing references (template:manage). System templates: 409.
func (s *Service) DeleteTemplate(ctx context.Context, actor Actor, org, id uuid.UUID, idem *Idem) (Reply[struct{}], error) {
	if _, err := s.require(ctx, actor, org, orgScope, "template:manage"); err != nil {
		return Reply[struct{}]{}, err
	}
	h, err := loadHead(ctx, s.q(), org, id, false)
	if err != nil {
		return Reply[struct{}]{}, Normalize(err)
	}
	if h.System {
		return Reply[struct{}]{}, conflict("SYSTEM_TEMPLATE", "system templates are immutable", nil)
	}
	return doWrite(ctx, s, org, actor, idem, 204, func(tx pgx.Tx) (struct{}, error) {
		hh, err := loadHead(ctx, tx, org, id, true)
		if err != nil {
			return struct{}{}, err
		}
		var used bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM access_assignments WHERE template_id = $1)
			    OR EXISTS (SELECT 1 FROM org_members WHERE template_id = $1)
			    OR EXISTS (SELECT 1 FROM invitations WHERE template_id = $1)
			    OR EXISTS (SELECT 1 FROM role_template_versions WHERE (floor_template_id = $1 OR base_template_id = $1) AND template_id <> $1)`, id).Scan(&used); err != nil {
			return struct{}{}, err
		}
		if used {
			if hh.ArchivedAt == nil {
				if _, err := tx.Exec(ctx, `UPDATE role_templates SET archived_at = now(), updated_at = now() WHERE id = $1`, id); err != nil {
					return struct{}{}, mapPg(err)
				}
				if err := s.audit(ctx, tx, org, actor, auditRow{Action: "access.template.archived", ResourceType: "template", ResourceID: id,
					Old: map[string]any{"slug": hh.Slug, "archived": false}, New: map[string]any{"slug": hh.Slug, "archived": true}}); err != nil {
					return struct{}{}, err
				}
			}
			return struct{}{}, nil
		}
		if _, err := tx.Exec(ctx, `DELETE FROM role_templates WHERE id = $1`, id); err != nil {
			return struct{}{}, mapPg(err)
		}
		return struct{}{}, s.audit(ctx, tx, org, actor, auditRow{Action: "access.template.deleted", ResourceType: "template", ResourceID: id,
			Old: map[string]any{"slug": hh.Slug, "kind": hh.Kind}})
	})
}
