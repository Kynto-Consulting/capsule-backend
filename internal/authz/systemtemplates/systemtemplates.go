// Package systemtemplates loads the system role templates of the permission engine
// (docs/permissions/SPEC.md section 4.2) from backend/internal/authz/systemtemplates.json.
//
// # File schema (schema_version 1, stable: consumers such as the repository seed rely on it)
//
//	{
//	  "schema_version": 1,
//	  "catalog_version": 1,                  // catalog.Version the file was written against
//	  "namespace": "<uuid>",                 // uuid v5 of "urn:capsule:permissions:system-templates" in the URL namespace
//	  "templates": [
//	    {
//	      "id": "<uuid>",                    // uuid v5(namespace, kind + "/" + slug): deterministic, equal in every environment
//	      "kind": "org" | "project" | "repo",
//	      "slug": "owner",                   // unique per kind; "admin" exists as org and as project
//	      "name": "Owner",                   // visible name (kept from today's roles)
//	      "description": {"es": "...", "en": "..."},
//	      "version": 1,                      // template version; content of a version never changes
//	      "legacy_role": "owner",            // org_members.role / project_members.role it replaces (absent for repo templates)
//	      "permissions": ["org:read", ...],  // explicit catalog ids in catalog order; NO wildcards in v1
//	      "floor_template_id": "<uuid>|null",// org templates: project template always held in every project
//	      "base_template_id": "<uuid>|null", // org templates: project template held where there is no own assignment (open policy)
//	      "ceiling": ["..."] | null,         // org templates: absolute cap, applied at organization scope
//	      "ceiling_project": ["..."] | null  // org templates: the cap applied at project, repo and env scope
//	    }
//	  ]
//	}
//
// Mapping to the SQL sketch of SPEC 14: role_templates(id, kind, slug, name, system=true, org_id=NULL,
// current_version=version); role_template_versions(template_id, version, permissions, ceiling,
// floor_template_id, base_template_id). "ceiling_project" has no column in that sketch: see
// docs/permissions/P0-NOTES.md (discrepancy D1) for why it exists and what the repository must store.
//
// Wildcards are materialised on purpose: SPEC 4.2 says system templates only gain permissions in a NEW
// template version, so a new catalog entry must never be granted by surprise.
//
// Import direction: this package imports authz (for the embedded bytes) and catalog. authz and catalog
// must never import it.
package systemtemplates

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/authz/catalog"
)

// SchemaVersion is the schema_version this loader understands.
const SchemaVersion = 1

// NamespaceName is the name hashed (uuid v5, URL namespace) into Namespace.
const NamespaceName = "urn:capsule:permissions:system-templates"

// Namespace is the uuid v5 namespace of the template ids.
var Namespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte(NamespaceName))

// Kind is the template kind.
type Kind string

const (
	KindOrg     Kind = "org"
	KindProject Kind = "project"
	KindRepo    Kind = "repo"
)

// ID returns the deterministic uuid of the system template (kind, slug): uuid v5(Namespace, "kind/slug").
// In SQL: uuid_generate_v5('<Namespace>', 'org/owner').
func ID(kind Kind, slug string) uuid.UUID {
	return uuid.NewSHA1(Namespace, []byte(string(kind)+"/"+slug))
}

// Text is a bilingual text.
type Text struct {
	ES string `json:"es"`
	EN string `json:"en"`
}

// Template is a loaded system template.
type Template struct {
	ID          uuid.UUID
	Kind        Kind
	Slug        string
	Name        string
	Description Text
	Version     int
	LegacyRole  string

	Permissions   catalog.Set
	PermissionIDs []string // as in the file, catalog order

	// Organization templates only. The zero uuid means "none".
	FloorID, BaseID uuid.UUID
	Floor, Base     catalog.Set // permissions of the floor/base project template

	HasCeiling     bool
	Ceiling        catalog.Set // cap at organization scope
	CeilingProject catalog.Set // cap at project, repo and env scope (valid when HasCeiling)
	CeilingIDs     []string
	CeilingProjIDs []string
}

type fileTemplate struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	Slug           string   `json:"slug"`
	Name           string   `json:"name"`
	Description    Text     `json:"description"`
	Version        int      `json:"version"`
	LegacyRole     string   `json:"legacy_role"`
	Permissions    []string `json:"permissions"`
	FloorTemplate  *string  `json:"floor_template_id"`
	BaseTemplate   *string  `json:"base_template_id"`
	Ceiling        []string `json:"ceiling"`
	CeilingProject []string `json:"ceiling_project"`
}

type fileDoc struct {
	SchemaVersion  int            `json:"schema_version"`
	CatalogVersion int            `json:"catalog_version"`
	Namespace      string         `json:"namespace"`
	Templates      []fileTemplate `json:"templates"`
}

// Parse validates and loads a systemtemplates.json document. It fails closed: an unknown permission, a
// wrong id, a dependency that is not satisfied or a permission outside the scope of its kind is an error.
func Parse(data []byte) ([]Template, error) {
	var doc fileDoc
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("systemtemplates: %w", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("systemtemplates: schema_version %d, want %d", doc.SchemaVersion, SchemaVersion)
	}
	if doc.CatalogVersion > catalog.Version {
		return nil, fmt.Errorf("systemtemplates: written for catalog %d, this build has %d", doc.CatalogVersion, catalog.Version)
	}
	if doc.Namespace != Namespace.String() {
		return nil, fmt.Errorf("systemtemplates: namespace %s, want %s", doc.Namespace, Namespace)
	}
	out := make([]Template, 0, len(doc.Templates))
	byID := map[uuid.UUID]int{}
	type key struct{ k, s string }
	seen := map[key]bool{}
	for _, ft := range doc.Templates {
		k := Kind(ft.Kind)
		if k != KindOrg && k != KindProject && k != KindRepo {
			return nil, fmt.Errorf("systemtemplates: %s/%s: bad kind", ft.Kind, ft.Slug)
		}
		if seen[key{ft.Kind, ft.Slug}] || ft.Slug == "" || ft.Version < 1 {
			return nil, fmt.Errorf("systemtemplates: %s/%s: duplicate, empty slug or bad version", ft.Kind, ft.Slug)
		}
		seen[key{ft.Kind, ft.Slug}] = true
		id, err := uuid.Parse(ft.ID)
		if err != nil || id != ID(k, ft.Slug) {
			return nil, fmt.Errorf("systemtemplates: %s/%s: id %q is not uuid v5(namespace, kind/slug)", ft.Kind, ft.Slug, ft.ID)
		}
		set, unknown := catalog.ParseSet(ft.Permissions)
		if len(unknown) > 0 || set.Len() != len(ft.Permissions) {
			return nil, fmt.Errorf("systemtemplates: %s/%s: unknown or repeated permissions %v", ft.Kind, ft.Slug, unknown)
		}
		t := Template{
			ID: id, Kind: k, Slug: ft.Slug, Name: ft.Name, Description: ft.Description, Version: ft.Version,
			LegacyRole: ft.LegacyRole, Permissions: set, PermissionIDs: set.IDs(),
		}
		if err := checkScopes(t); err != nil {
			return nil, err
		}
		if err := checkRequires(t); err != nil {
			return nil, err
		}
		byID[id] = len(out)
		out = append(out, t)
	}
	// second pass: floor, base, ceiling (need the project templates)
	for i, ft := range doc.Templates {
		t := &out[i]
		resolve := func(ref *string, what string) (uuid.UUID, catalog.Set, error) {
			if ref == nil {
				return uuid.Nil, catalog.Set{}, nil
			}
			rid, err := uuid.Parse(*ref)
			j, ok := byID[rid]
			if err != nil || !ok || out[j].Kind != KindProject {
				return uuid.Nil, catalog.Set{}, fmt.Errorf("systemtemplates: %s/%s: %s must reference a project template", t.Kind, t.Slug, what)
			}
			return rid, out[j].Permissions, nil
		}
		var err error
		if t.FloorID, t.Floor, err = resolve(ft.FloorTemplate, "floor_template_id"); err != nil {
			return nil, err
		}
		if t.BaseID, t.Base, err = resolve(ft.BaseTemplate, "base_template_id"); err != nil {
			return nil, err
		}
		if (t.FloorID != uuid.Nil || t.BaseID != uuid.Nil || ft.Ceiling != nil || ft.CeilingProject != nil) && t.Kind != KindOrg {
			return nil, fmt.Errorf("systemtemplates: %s/%s: floor, base and ceiling belong to org templates", t.Kind, t.Slug)
		}
		if (ft.Ceiling == nil) != (ft.CeilingProject == nil) {
			return nil, fmt.Errorf("systemtemplates: %s/%s: ceiling and ceiling_project go together", t.Kind, t.Slug)
		}
		if ft.Ceiling != nil {
			c, u1 := catalog.ParseSet(ft.Ceiling)
			cp, u2 := catalog.ParseSet(ft.CeilingProject)
			if len(u1)+len(u2) > 0 {
				return nil, fmt.Errorf("systemtemplates: %s/%s: unknown ceiling permissions %v %v", t.Kind, t.Slug, u1, u2)
			}
			if !c.ContainsAll(t.Permissions) {
				return nil, fmt.Errorf("systemtemplates: %s/%s: ceiling must contain the template permissions", t.Kind, t.Slug)
			}
			if !c.ContainsAll(cp) {
				return nil, fmt.Errorf("systemtemplates: %s/%s: ceiling_project must be inside ceiling", t.Kind, t.Slug)
			}
			t.HasCeiling, t.Ceiling, t.CeilingProject = true, c, cp
			t.CeilingIDs, t.CeilingProjIDs = c.IDs(), cp.IDs()
		}
	}
	return out, nil
}

func checkScopes(t Template) error {
	for _, id := range t.PermissionIDs {
		p, _ := catalog.Get(id)
		ok := false
		switch t.Kind {
		case KindOrg:
			ok = p.HasScope(catalog.ScopeOrg)
		case KindProject:
			ok = p.HasScope(catalog.ScopeProject) || p.HasScope(catalog.ScopeRepo) || p.HasScope(catalog.ScopeEnv)
		case KindRepo:
			ok = p.HasScope(catalog.ScopeRepo)
		}
		if !ok {
			return fmt.Errorf("systemtemplates: %s/%s: %s cannot be granted at the scope of this kind", t.Kind, t.Slug, id)
		}
	}
	return nil
}

func checkRequires(t Template) error {
	for _, id := range t.PermissionIDs {
		p, _ := catalog.Get(id)
		for _, r := range p.Requires {
			if !t.Permissions.Has(r) {
				return fmt.Errorf("systemtemplates: %s/%s: %s requires %s", t.Kind, t.Slug, id, r)
			}
		}
	}
	return nil
}

var (
	once    sync.Once
	loaded  []Template
	loadErr error
)

func load() {
	once.Do(func() { loaded, loadErr = Parse(authz.SystemTemplatesJSON) })
	if loadErr != nil {
		panic(loadErr) // the embedded file is checked by tests; a corrupt build must not serve decisions
	}
}

// All returns every system template, in file order. The slice is a copy.
func All() []Template {
	load()
	return append([]Template(nil), loaded...)
}

func get(kind Kind, slug string) (Template, bool) {
	load()
	for _, t := range loaded {
		if t.Kind == kind && t.Slug == slug {
			return t, true
		}
	}
	return Template{}, false
}

// Org returns the system organization template with the slug (owner, admin, member, readonly).
func Org(slug string) (Template, bool) { return get(KindOrg, slug) }

// Project returns the system project template with the slug (viewer, deployer, admin).
func Project(slug string) (Template, bool) { return get(KindProject, slug) }

// Repo returns the system repo template with the slug (repo-read, repo-write).
func Repo(slug string) (Template, bool) { return get(KindRepo, slug) }

// ByID returns the system template with the id.
func ByID(id uuid.UUID) (Template, bool) {
	load()
	for _, t := range loaded {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}
