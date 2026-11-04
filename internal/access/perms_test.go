package access

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/systemtemplates"
)

func TestValidatePermissionsRules(t *testing.T) {
	cases := []struct {
		name  string
		kind  string
		perms []string
		field string // key expected in details ("" = valid)
	}{
		{"valid project template", "project", []string{"project:view", "deployment:read", "log:read"}, ""},
		{"wildcard", "project", []string{"*"}, "fields"},
		{"resource wildcard", "project", []string{"deployment:*"}, "fields"},
		{"unknown", "project", []string{"project:view", "nope:nada"}, "unknown_permissions"},
		{"bad format", "project", []string{"Project View"}, "unknown_permissions"},
		{"missing dependency", "project", []string{"deployment:create"}, "missing_dependencies"},
		{"project permission in an org template", "org", []string{"org:read", "deployment:read", "project:view"}, "out_of_scope"},
		{"org permission in a project template", "project", []string{"project:view", "org:update"}, "out_of_scope"},
		{"platform permission", "project", []string{"project:view", "platform-user:read"}, "out_of_scope"},
		{"env permission in a repo template", "repo", []string{"project:view", "git:read", "promotion:approve"}, "out_of_scope"},
	}
	for _, c := range cases {
		set, ids, err := ValidatePermissions("permissions", c.kind, c.perms)
		if c.field == "" {
			if err != nil || set.IsEmpty() || len(ids) != len(c.perms) {
				t.Errorf("%s: %v %v", c.name, ids, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if err.Status != 422 || err.Details[c.field] == nil {
			t.Errorf("%s: want detail %q, got %v", c.name, c.field, err.Details)
		}
	}
	// duplicates collapse
	_, ids, err := ValidatePermissions("permissions", "project", []string{"project:view", "project:view"})
	if err != nil || len(ids) != 1 {
		t.Errorf("duplicates: %v %v", ids, err)
	}
}

// Everything a clone copies must validate: every system template passes the rules of custom templates of its kind.
func TestSystemTemplatesValidateAsCustom(t *testing.T) {
	for _, tpl := range systemtemplates.All() {
		if _, _, err := ValidatePermissions("permissions", string(tpl.Kind), tpl.Permissions.IDs()); err != nil {
			t.Errorf("%s/%s does not validate as a custom template: %v", tpl.Kind, tpl.Slug, err.Details)
		}
	}
}

func TestCatalogDocument(t *testing.T) {
	body, tag := CatalogJSON()
	var doc CatalogDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.CatalogVersion != catalog.Version || len(doc.Permissions) != catalog.Len() || catalog.Len() != 99 || len(doc.Groups) == 0 {
		t.Fatalf("catalog doc: version %d, %d permissions", doc.CatalogVersion, len(doc.Permissions))
	}
	body2, tag2 := CatalogJSON()
	if tag != tag2 || string(body) != string(body2) {
		t.Fatal("catalog ETag is not stable")
	}
	for _, e := range doc.Permissions {
		if e.ID == "" || len(e.Scopes) == 0 || e.Label["es"] == "" || e.Label["en"] == "" {
			t.Fatalf("incomplete entry %+v", e)
		}
	}
}

func TestParseWithinAndCursor(t *testing.T) {
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "36h": 36 * time.Hour, "90m": 90 * time.Minute, "": 0} {
		got, err := ParseWithin(in)
		if err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"7", "d", "0d", "-1d", "7x", "99999d"} {
		if _, err := ParseWithin(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	id := uuid.New().String()
	c := encodeCursor("2026-01-01T00:00:00Z", id)
	a, b, ok := decodeCursor(c)
	if !ok || a != "2026-01-01T00:00:00Z" || b != id {
		t.Errorf("cursor round trip: %q %q %v", a, b, ok)
	}
	if _, _, ok := decodeCursor("%%%"); ok {
		t.Error("garbage cursor accepted")
	}
	for in, want := range map[int]int{0: 50, -3: 50, 7: 7, 500: 200} {
		if clampLimit(in) != want {
			t.Errorf("clampLimit(%d) = %d", in, clampLimit(in))
		}
	}
}

func TestHashRequestBindsMethodPathAndBody(t *testing.T) {
	a := HashRequest("POST", "/x", []byte("{}"))
	if a != HashRequest("POST", "/x", []byte("{}")) || len(a) != 64 {
		t.Fatal("hash not deterministic or not 64 hex characters")
	}
	for _, o := range []string{HashRequest("PUT", "/x", []byte("{}")), HashRequest("POST", "/y", []byte("{}")), HashRequest("POST", "/x", []byte("[]"))} {
		if o == a {
			t.Fatal("hash ignores method, path or body")
		}
	}
}

func TestErrorShapes(t *testing.T) {
	e := escalation("m", []string{"a:b"}, "")
	if e.Status != 403 || e.DetailCode() != "ESCALATION" || fmt.Sprint(e.Details["missing"]) != "[a:b]" {
		t.Errorf("escalation: %+v", e)
	}
	if d := denied("x:y", []string{"x:y"}, "no_grant"); d.Status != 403 || d.DetailCode() != "PERMISSION_DENIED" || d.Details["permission"] != "x:y" {
		t.Errorf("denied: %+v", d)
	}
	if c := conflict("LAST_OWNER", "m", nil); c.Status != 409 || c.DetailCode() != "LAST_OWNER" {
		t.Errorf("conflict: %+v", c)
	}
	if l := limitErr("m"); l.Status != 422 || l.DetailCode() != "LIMIT_EXCEEDED" {
		t.Errorf("limit: %+v", l)
	}
}
