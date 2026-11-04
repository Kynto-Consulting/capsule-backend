package repository

import (
	"context"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/authz/systemtemplates"
)

// SystemTemplateID is the deterministic id of a system template: uuid v5(Namespace, "kind/slug"). Migration 000070 computes the
// same value in SQL (access_system_template_id) for the template headers; TestSystemTemplateIDsMatchSQL keeps them equal.
func SystemTemplateID(kind, slug string) uuid.UUID {
	return systemtemplates.ID(systemtemplates.Kind(kind), slug)
}

// SeedSystemTemplates writes the CONTENT of the system templates from authz/systemtemplates.json: headers (already inserted by
// migration 000070; inserted here if missing) and the version rows (permissions, floor, base, ceilings). It is idempotent
// (ON CONFLICT DO NOTHING) and fail-closed: if a version row already exists with different content the file and the database
// disagree about an immutable version and the seed returns an error instead of overwriting. A template version newer than the
// header's current_version advances it (a new version of a system template is published by shipping it in the JSON).
//
// Call it after RunMigrations (P3 wires it at server start; the same function is used by the tests). inserted counts new version rows.
func SeedSystemTemplates(ctx context.Context, pool *pgxpool.Pool) (inserted int, err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	inserted, err = SeedSystemTemplatesTx(ctx, tx)
	if err != nil {
		return 0, err
	}
	return inserted, tx.Commit(ctx)
}

// SeedSystemTemplatesTx is SeedSystemTemplates inside the caller's transaction.
func SeedSystemTemplatesTx(ctx context.Context, tx pgx.Tx) (int, error) {
	all := systemtemplates.All()
	// Postgres serializes concurrent seeders; the second one finds everything in place.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('capsule.access.seed'))`); err != nil {
		return 0, err
	}
	for _, t := range all {
		if _, err := tx.Exec(ctx, `
			INSERT INTO role_templates (id, org_id, kind, slug, name, description, system, current_version)
			VALUES ($1, NULL, $2, $3, $4, $5, true, 1) ON CONFLICT DO NOTHING`,
			t.ID, string(t.Kind), t.Slug, t.Name, t.Description.ES); err != nil {
			return 0, fmt.Errorf("seeding template header %s/%s: %w", t.Kind, t.Slug, err)
		}
	}
	inserted := 0
	for _, t := range all {
		var floor, base *uuid.UUID
		if t.FloorID != uuid.Nil {
			f := t.FloorID
			floor = &f
		}
		if t.BaseID != uuid.Nil {
			b := t.BaseID
			base = &b
		}
		var ceiling, ceilingProject []string
		if t.HasCeiling {
			ceiling, ceilingProject = nonNil(t.CeilingIDs), nonNil(t.CeilingProjIDs)
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO role_template_versions (template_id, version, permissions, ceiling, ceiling_project, floor_template_id, base_template_id, note)
			VALUES ($1,$2,$3,$4,$5,$6,$7,'system seed') ON CONFLICT (template_id, version) DO NOTHING`,
			t.ID, t.Version, nonNil(t.PermissionIDs), ceiling, ceilingProject, floor, base)
		if err != nil {
			return 0, fmt.Errorf("seeding template version %s/%s v%d: %w", t.Kind, t.Slug, t.Version, err)
		}
		if tag.RowsAffected() == 0 {
			var perms, c, cp []string
			var f, b *uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT permissions, ceiling, ceiling_project, floor_template_id, base_template_id
				FROM role_template_versions WHERE template_id = $1 AND version = $2`, t.ID, t.Version).Scan(&perms, &c, &cp, &f, &b); err != nil {
				return 0, err
			}
			if !sameSet(perms, t.PermissionIDs) || !sameSet(c, ceiling) || (c == nil) != (ceiling == nil) ||
				!sameSet(cp, ceilingProject) || !sameUUID(f, floor) || !sameUUID(b, base) {
				return 0, fmt.Errorf("seeding %s/%s v%d: stored version differs from systemtemplates.json (immutable)", t.Kind, t.Slug, t.Version)
			}
		} else {
			inserted += int(tag.RowsAffected())
		}
		if _, err := tx.Exec(ctx, `UPDATE role_templates SET current_version = $2, updated_at = now() WHERE id = $1 AND current_version < $2`, t.ID, t.Version); err != nil {
			return 0, fmt.Errorf("advancing %s/%s: %w", t.Kind, t.Slug, err)
		}
	}
	return inserted, nil
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func sameUUID(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
