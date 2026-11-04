package access

import (
	"regexp"
	"sort"
	"strings"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
)

var (
	permFormatRE = regexp.MustCompile(`^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$`)
	slugRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
)

// permScope maps a template or assignment scope to the catalog scope a permission must allow.
func permScope(kindOrScope string) catalog.Scope {
	switch kindOrScope {
	case "org":
		return catalog.ScopeOrg
	case "repo":
		return catalog.ScopeRepo
	case "env":
		return catalog.ScopeEnv
	}
	return catalog.ScopeProject
}

// ValidatePermissions validates the permission list of a custom template of the given kind (org | project | repo) or of the
// permissions an assignment carries at a scope (typ org | project | repo | env, as an assignment scope: pass the scope type and
// asScope=true). Rules (SPEC 3.0, 3.4, 4.3, 5.1): format, no wildcards, existing in the catalog, allowed at the scope, and every
// dependency present. It returns the normalized set in catalog order. The error is an *Error 422 with the details of
// API.openapi.yaml (unknown_permissions, out_of_scope, missing_dependencies, fields).
func ValidatePermissions(field, kindOrScope string, perms []string) (catalog.Set, []string, *Error) {
	var (
		fields  = map[string]string{}
		unknown []string
		outOf   []string
		set     catalog.Set
	)
	want := permScope(kindOrScope)
	seen := map[string]bool{}
	for _, p := range perms {
		if seen[p] {
			continue
		}
		seen[p] = true
		if strings.Contains(p, "*") {
			fields[field] = "wildcards are only allowed in system templates"
			continue
		}
		if !permFormatRE.MatchString(p) {
			fields[field] = "permission ids look like resource:action"
			unknown = append(unknown, p)
			continue
		}
		c, ok := catalog.Get(p)
		if !ok {
			unknown = append(unknown, p)
			continue
		}
		if !c.HasScope(want) {
			outOf = append(outOf, p)
			continue
		}
		set = set.Add(p)
	}
	missing := missingDependencies(set)
	if len(fields) == 0 && len(unknown) == 0 && len(outOf) == 0 && len(missing) == 0 {
		return set, set.IDs(), nil
	}
	d := map[string]any{}
	if len(fields) > 0 {
		d["fields"] = fields
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		d["unknown_permissions"] = unknown
		if _, ok := fields[field]; !ok {
			fields[field] = "unknown permissions"
			d["fields"] = fields
		}
	}
	if len(outOf) > 0 {
		sort.Strings(outOf)
		d["out_of_scope"] = outOf
		if _, ok := fields[field]; !ok {
			fields[field] = "permissions not allowed at this scope"
			d["fields"] = fields
		}
	}
	if len(missing) > 0 {
		d["missing_dependencies"] = missing
		if _, ok := fields[field]; !ok {
			fields[field] = "dependencies are missing"
			d["fields"] = fields
		}
	}
	return catalog.Set{}, nil, validationDetails("invalid permissions", d)
}

// missingDependencies lists the permissions the set needs (SPEC 3.4) and does not contain.
func missingDependencies(set catalog.Set) []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range set.IDs() {
		c, _ := catalog.Get(id)
		for _, r := range c.Requires {
			if !set.Has(r) && !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	sort.Strings(out)
	return out
}

// setDiff returns the ids in a and not in b, in catalog order.
func setDiff(a, b catalog.Set) []string { return a.Minus(b).IDs() }
