package repository

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kynto/capsule/backend/internal/domain"
)

var (
	templateSlugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	permFormatRE   = regexp.MustCompile(`^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$`)
)

const templateCols = `id, org_id, kind, slug, name, description, system, cloned_from, current_version, archived_at, created_by, created_at, updated_at`

func scanTemplate(row rowScanner, t *AccessTemplate) error {
	return row.Scan(&t.ID, &t.OrgID, &t.Kind, &t.Slug, &t.Name, &t.Description, &t.System, &t.ClonedFrom, &t.CurrentVersion,
		&t.ArchivedAt, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
}

// NewTemplate is the input of CreateTemplate (version 1). Permission ids are checked for FORMAT and wildcards here; whether each id
// exists in the catalog and whether dependencies are satisfied is the service's job (P4, it owns the catalog).
type NewTemplate struct {
	Kind            string // org | project | repo
	Slug            string
	Name            string
	Description     string
	Permissions     []string
	Ceiling         []string // org templates only; nil = none
	CeilingProject  []string
	FloorTemplateID *uuid.UUID
	BaseTemplateID  *uuid.UUID
	ClonedFrom      *uuid.UUID
	Note            string
	CreatedBy       *uuid.UUID
}

// NewTemplateVersion is the input of PublishVersion.
type NewTemplateVersion struct {
	Permissions     []string
	Ceiling         []string
	CeilingProject  []string
	FloorTemplateID *uuid.UUID
	BaseTemplateID  *uuid.UUID
	Note            string
	CreatedBy       *uuid.UUID
}

func checkCustomPerms(kind string, lists ...[]string) error {
	_ = kind
	for _, l := range lists {
		if len(l) > MaxPermsPerTemplate {
			return fmt.Errorf("%w: more than %d permissions", ErrAccessLimit, MaxPermsPerTemplate)
		}
		seen := map[string]bool{}
		for _, p := range l {
			if !permFormatRE.MatchString(p) {
				return fmt.Errorf("%w: permission %q (wildcards are only for system templates)", ErrAccessInvalid, p)
			}
			if seen[p] {
				return fmt.Errorf("%w: permission %q repeated", ErrAccessInvalid, p)
			}
			seen[p] = true
		}
	}
	return nil
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// CreateTemplate creates a custom template of the organization with version 1. Slug must be unique per (org, kind) and not
// reserved by a system template of the same kind; at most MaxTemplatesPerOrg templates per organization.
func (s *AccessStore) CreateTemplate(ctx context.Context, orgID uuid.UUID, in NewTemplate) (*AccessTemplate, error) {
	if in.Kind != "org" && in.Kind != "project" && in.Kind != "repo" {
		return nil, fmt.Errorf("%w: kind %q", ErrAccessInvalid, in.Kind)
	}
	if !templateSlugRE.MatchString(in.Slug) || strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("%w: slug or name", ErrAccessInvalid)
	}
	if err := checkCustomPerms(in.Kind, in.Permissions, in.Ceiling, in.CeilingProject); err != nil {
		return nil, err
	}
	var out AccessTemplate
	err := s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM role_templates WHERE org_id = $1`, orgID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxTemplatesPerOrg {
			return fmt.Errorf("%w: %d templates per organization", ErrAccessLimit, MaxTemplatesPerOrg)
		}
		var reserved bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM role_templates WHERE system AND kind = $1 AND slug = $2)`, in.Kind, in.Slug).Scan(&reserved); err != nil {
			return err
		}
		if reserved {
			return ErrReservedSlug
		}
		if err := scanTemplate(tx.QueryRow(ctx, `
			INSERT INTO role_templates (org_id, kind, slug, name, description, system, cloned_from, created_by)
			VALUES ($1,$2,$3,$4,$5,false,$6,$7) RETURNING `+templateCols,
			orgID, in.Kind, in.Slug, in.Name, in.Description, in.ClonedFrom, in.CreatedBy), &out); err != nil {
			return mapAccessErr(err)
		}
		return mapAccessErr(insertVersion(ctx, tx, out.ID, 1, NewTemplateVersion{
			Permissions: in.Permissions, Ceiling: in.Ceiling, CeilingProject: in.CeilingProject,
			FloorTemplateID: in.FloorTemplateID, BaseTemplateID: in.BaseTemplateID, Note: in.Note, CreatedBy: in.CreatedBy,
		}))
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func insertVersion(ctx context.Context, tx pgx.Tx, templateID uuid.UUID, version int, v NewTemplateVersion) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO role_template_versions (template_id, version, permissions, ceiling, ceiling_project, floor_template_id, base_template_id, note, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		templateID, version, nonNil(v.Permissions), v.Ceiling, v.CeilingProject, v.FloorTemplateID, v.BaseTemplateID, v.Note, v.CreatedBy)
	return err
}

// lockTemplate locks a template of the organization (never a system one: those are ErrSystemTemplate).
func lockTemplate(ctx context.Context, tx pgx.Tx, orgID, templateID uuid.UUID) (*AccessTemplate, error) {
	var t AccessTemplate
	err := scanTemplate(tx.QueryRow(ctx, `SELECT `+templateCols+` FROM role_templates WHERE id = $1 AND (org_id = $2 OR system) FOR UPDATE`, templateID, orgID), &t)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if t.System {
		return nil, ErrSystemTemplate
	}
	return &t, nil
}

// PublishVersion appends version n+1 to a custom template (versions are immutable) and makes it current. Archived templates cannot
// be published. Returns the new version number.
func (s *AccessStore) PublishVersion(ctx context.Context, orgID, templateID uuid.UUID, v NewTemplateVersion) (int, error) {
	var kind string
	if err := s.pool.QueryRow(ctx, `SELECT kind FROM role_templates WHERE id = $1`, templateID).Scan(&kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, domain.ErrNotFound
		}
		return 0, err
	}
	if err := checkCustomPerms(kind, v.Permissions, v.Ceiling, v.CeilingProject); err != nil {
		return 0, err
	}
	var next int
	err := s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		t, err := lockTemplate(ctx, tx, orgID, templateID)
		if err != nil {
			return err
		}
		if t.ArchivedAt != nil {
			return ErrTemplateArchived
		}
		next = t.CurrentVersion + 1
		if err := insertVersion(ctx, tx, templateID, next, v); err != nil {
			return mapAccessErr(err)
		}
		_, err = tx.Exec(ctx, `UPDATE role_templates SET current_version = $2, updated_at = now() WHERE id = $1`, templateID, next)
		return err
	})
	return next, err
}

// ArchiveTemplate makes a custom template non-assignable; live assignments keep working.
func (s *AccessStore) ArchiveTemplate(ctx context.Context, orgID, templateID uuid.UUID) error {
	return s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		if _, err := lockTemplate(ctx, tx, orgID, templateID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE role_templates SET archived_at = coalesce(archived_at, now()), updated_at = now() WHERE id = $1`, templateID)
		return err
	})
}

// DeleteTemplate deletes a custom template that nothing references (no assignment, member, invitation or other template's floor/base).
func (s *AccessStore) DeleteTemplate(ctx context.Context, orgID, templateID uuid.UUID) error {
	return s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		if _, err := lockTemplate(ctx, tx, orgID, templateID); err != nil {
			return err
		}
		var used bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM access_assignments WHERE template_id = $1)
			    OR EXISTS (SELECT 1 FROM org_members WHERE template_id = $1)
			    OR EXISTS (SELECT 1 FROM invitations WHERE template_id = $1)
			    OR EXISTS (SELECT 1 FROM role_template_versions WHERE (floor_template_id = $1 OR base_template_id = $1) AND template_id <> $1)`,
			templateID).Scan(&used); err != nil {
			return err
		}
		if used {
			return ErrTemplateInUse
		}
		_, err := tx.Exec(ctx, `DELETE FROM role_templates WHERE id = $1`, templateID)
		return mapAccessErr(err)
	})
}

// GetTemplate returns a template visible to the organization (its own or a system one).
func (s *AccessStore) GetTemplate(ctx context.Context, orgID, templateID uuid.UUID) (*AccessTemplate, error) {
	var t AccessTemplate
	err := scanTemplate(s.pool.QueryRow(ctx, `SELECT `+templateCols+` FROM role_templates WHERE id = $1 AND (org_id = $2 OR system)`, templateID, orgID), &t)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting template: %w", err)
	}
	return &t, nil
}

// ListTemplates returns the system templates and the organization's own, system first.
func (s *AccessStore) ListTemplates(ctx context.Context, orgID uuid.UUID) ([]AccessTemplate, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+templateCols+` FROM role_templates WHERE org_id = $1 OR system ORDER BY system DESC, kind, slug`, orgID)
	if err != nil {
		return nil, fmt.Errorf("listing templates: %w", err)
	}
	defer rows.Close()
	var out []AccessTemplate
	for rows.Next() {
		var t AccessTemplate
		if err := scanTemplate(rows, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetOrgTemplate sets the organization template of a member (their "organization role"). legacyRole is the label stored in
// org_members.role (owner|admin|member|readonly; engine.LegacyRole of the template); for a system template the trigger derives it
// from the slug, so it is only authoritative for custom templates. version nil follows the latest version.
func (s *AccessStore) SetOrgTemplate(ctx context.Context, orgID, userID, templateID uuid.UUID, version *int, legacyRole string) error {
	switch legacyRole {
	case "owner", "admin", "member", "readonly":
	default:
		return fmt.Errorf("%w: legacy role %q", ErrAccessInvalid, legacyRole)
	}
	return s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		var archived bool
		var kind string
		err := tx.QueryRow(ctx, `SELECT kind, archived_at IS NOT NULL FROM role_templates WHERE id = $1 AND (org_id = $2 OR system)`, templateID, orgID).Scan(&kind, &archived)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		if err != nil {
			return err
		}
		if kind != "org" {
			return fmt.Errorf("%w: template kind %s is not an organization template", ErrAccessInvalid, kind)
		}
		if archived {
			return ErrTemplateArchived
		}
		tag, err := tx.Exec(ctx, `UPDATE org_members SET template_id = $3, template_version = $4, role = $5 WHERE org_id = $1 AND user_id = $2`,
			orgID, userID, templateID, version, legacyRole)
		if err != nil {
			return mapAccessErr(err)
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}
