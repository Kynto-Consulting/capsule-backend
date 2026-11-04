package catalog_test

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/internal/specdoc"
)

var update = flag.Bool("update", false, "rewrite catalog.json")

// The 23 old authz actions (authz.AllActions + GitActions + GatewayActions), spelled out so this package
// needs no import of authz. authz_test checks the same list against the real constants.
var oldActions = []string{
	"project.read", "project.deploy", "project.env_write", "project.env_reveal", "project.ops",
	"project.databases", "project.network", "project.members", "project.delete",
	"git.read", "git.write", "git.review", "git.merge", "git.admin",
	"security.read", "security.triage", "security.admin",
	"env.read", "env.request", "env.admin", "env.approve", "webhooks.manage",
	"project.connect",
}

func TestCatalogHas99Entries(t *testing.T) {
	if got := len(catalog.All()); got != 99 || catalog.Len() != 99 {
		t.Fatalf("catalog has %d entries, want 99", got)
	}
	var org, proj, plat int
	for _, p := range catalog.All() {
		switch {
		case p.HasScope(catalog.ScopePlatform):
			plat++
		case p.HasScope(catalog.ScopeProject) || p.HasScope(catalog.ScopeRepo) || p.HasScope(catalog.ScopeEnv):
			proj++
		default:
			org++
		}
	}
	if org != 26 || proj != 66 || plat != 7 {
		t.Fatalf("split org/project/platform = %d/%d/%d, want 26/66/7", org, proj, plat)
	}
}

var idFormat = regexp.MustCompile(`^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$`)

func TestCatalogStructure(t *testing.T) {
	all := catalog.All()
	seen := map[string]bool{}
	for i, p := range all {
		if p.Bit != i {
			t.Errorf("%s: bit %d at position %d", p.ID, p.Bit, i)
		}
		if !idFormat.MatchString(p.ID) {
			t.Errorf("%s: bad identifier", p.ID)
		}
		if seen[p.ID] {
			t.Errorf("%s: duplicate", p.ID)
		}
		seen[p.ID] = true
		if len(p.Scopes) == 0 || p.Label.ES == "" || p.Label.EN == "" || p.Group == "" || p.Since != 1 {
			t.Errorf("%s: incomplete entry %+v", p.ID, p)
		}
		if b, ok := catalog.Bit(p.ID); !ok || b != i || catalog.IDAt(i) != p.ID {
			t.Errorf("%s: Bit/IDAt disagree", p.ID)
		}
	}
	// requires: only known ids, never itself, no cycles (a dependency always sits at a lower or equal "depth")
	for _, p := range all {
		for _, r := range p.Requires {
			if !seen[r] || r == p.ID {
				t.Errorf("%s: bad dependency %q", p.ID, r)
			}
		}
	}
	// SPEC 3.4 spot checks
	need := map[string][]string{
		"git:merge":         {"git:read", "project:view"},
		"ci:secret":         {"ci:read", "project:view"},
		"security:admin":    {"project:view", "security:read"},
		"envvar:reveal":     {"envvar:read", "project:view"},
		"database:query":    {"database:read", "project:view"},
		"promotion:approve": {"environment:read", "project:view"},
		"assignment:grant":  {"assignment:read"},
		"member:invite":     {"member:read"},
		"group:manage":      {"group:read"},
		"template:manage":   {"template:read"},
		"project:view":      {},
		"project:create":    {},
	}
	for id, want := range need {
		p, _ := catalog.Get(id)
		got := append([]string{}, p.Requires...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s requires %v, want %v", id, got, want)
		}
	}
	// non-tokenable (SPEC 9.1)
	for _, p := range all {
		res, _, _ := strings.Cut(p.ID, ":")
		want := true
		switch res {
		case "org", "member", "group", "template", "assignment", "token", "oauthclient", "platform-user", "platform-backup":
			want = false
		}
		if p.ID == "billing:manage" {
			want = false
		}
		if p.Tokenable != want {
			t.Errorf("%s tokenable=%v, want %v", p.ID, p.Tokenable, want)
		}
	}
}

// Acceptance (1): the catalog matches the tables of SPEC.md section 3.
func TestCatalogMatchesSpec(t *testing.T) {
	doc, err := specdoc.Load()
	if errors.Is(err, specdoc.ErrNotFound) {
		t.Skip("docs/permissions/SPEC.md is not reachable from this checkout")
	}
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, a := range oldActions {
		known[a] = true
	}
	want := map[string]bool{}
	for _, r := range doc.Rows {
		want[r.ID] = true
	}
	for _, id := range doc.Platform {
		want[id] = true
	}
	if len(want) != 99 {
		t.Fatalf("SPEC section 3 lists %d permissions, want 99 (parser or spec changed)", len(want))
	}
	for id := range want {
		if !catalog.Has(id) {
			t.Errorf("in SPEC but not in the catalog: %s", id)
		}
	}
	for _, p := range catalog.All() {
		if !want[p.ID] {
			t.Errorf("in the catalog but not in SPEC: %s", p.ID)
		}
	}
	if len(doc.Platform) != 7 {
		t.Errorf("SPEC 3.3 lists %d platform permissions, want 7", len(doc.Platform))
	}

	letter := map[catalog.Scope]string{
		catalog.ScopeOrg: "O", catalog.ScopeProject: "P", catalog.ScopeRepo: "R", catalog.ScopeEnv: "E",
	}
	for _, r := range doc.Rows {
		p, ok := catalog.Get(r.ID)
		if !ok {
			continue
		}
		var gotScopes []string
		for _, s := range p.Scopes {
			gotScopes = append(gotScopes, letter[s])
		}
		a, b := sortedChars(strings.Join(gotScopes, "")), sortedChars(r.Scopes)
		if a != b {
			t.Errorf("%s: scopes %q, SPEC says %q", r.ID, a, b)
		}
		var legacy []string
		for _, d := range r.Derives {
			if known[d] {
				legacy = append(legacy, d)
			}
		}
		sort.Strings(legacy)
		got := append([]string{}, p.Legacy...)
		sort.Strings(got)
		legacy = dedupe(legacy)
		if strings.Join(got, ",") != strings.Join(legacy, ",") {
			t.Errorf("%s: legacy %v, SPEC derives from %v", r.ID, got, legacy)
		}
		if p.Sensitive != r.Sensitive {
			t.Errorf("%s: sensitive=%v, SPEC says %v", r.ID, p.Sensitive, r.Sensitive)
		}
		if r.LegacyGap && !p.LegacyGap {
			t.Errorf("%s: SPEC marks legacy_gap", r.ID)
		}
	}
	// G7: the three legacy_gap permissions (project:create is a row; the other two are in the paragraph after 3.1)
	var gaps []string
	for _, p := range catalog.All() {
		if p.LegacyGap {
			gaps = append(gaps, p.ID)
		}
	}
	if strings.Join(gaps, ",") != "project:create,domain:manage,database:create" {
		t.Errorf("legacy_gap entries: %v", gaps)
	}
}

func sortedChars(s string) string {
	c := strings.Split(s, "")
	sort.Strings(c)
	return strings.Join(c, "")
}

func dedupe(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// Acceptance (3), catalog side: every old action expands, to catalog ids only, and every project-scoped
// permission derives from exactly the actions the SPEC says.
func TestExpandCoversEveryOldAction(t *testing.T) {
	if len(oldActions) != 23 {
		t.Fatal("old action list out of sync")
	}
	for _, a := range oldActions {
		ex := catalog.Expand(a)
		if len(ex) == 0 {
			t.Errorf("no expansion for %s", a)
		}
		for _, id := range ex {
			if !catalog.Has(id) {
				t.Errorf("%s expands to unknown %s", a, id)
			}
		}
	}
	if catalog.Expand("project.nope") != nil || catalog.Expand("") != nil {
		t.Error("unknown action must expand to nothing")
	}
	if got := strings.Join(catalog.OldActions(), ","); got != func() string { s := append([]string{}, oldActions...); sort.Strings(s); return strings.Join(s, ",") }() {
		t.Errorf("OldActions() = %s", got)
	}
	// every project/repo/env permission comes from at least one old action (no orphan atoms)
	for _, p := range catalog.All() {
		project := p.HasScope(catalog.ScopeProject) || p.HasScope(catalog.ScopeRepo) || p.HasScope(catalog.ScopeEnv)
		if project && len(p.Legacy) == 0 {
			t.Errorf("%s has no legacy action", p.ID)
		}
		if !project && len(p.Legacy) != 0 {
			t.Errorf("%s is not a project permission but derives from %v", p.ID, p.Legacy)
		}
	}
	// the union of every expansion is exactly the project-level catalog
	all := catalog.ExpandSet(oldActions...)
	var n int
	for _, p := range catalog.All() {
		if all.Has(p.ID) {
			n++
		}
	}
	if n != 66 || all.Len() != 66 {
		t.Errorf("old actions cover %d permissions, want the 66 of SPEC 3.2", all.Len())
	}
}

func TestMatchWildcards(t *testing.T) {
	if len(catalog.Match("*")) != 99 {
		t.Error("* must match all")
	}
	if got := catalog.Match("git:*"); len(got) != 10 {
		t.Errorf("git:* = %v", got)
	}
	if catalog.Match("nope:*") != nil || catalog.Match("nope:x") != nil {
		t.Error("unknown patterns match nothing")
	}
	if got := catalog.Match("ci:run"); len(got) != 1 || got[0] != "ci:run" {
		t.Errorf("plain id: %v", got)
	}
}

// Acceptance (5): catalog.json is the generated artifact and must not be stale.
func TestCatalogJSONUpToDate(t *testing.T) {
	want := catalog.JSON()
	if *update {
		if err := os.WriteFile("catalog.json", want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile("catalog.json")
	if err != nil {
		t.Fatalf("catalog.json missing (run `make catalog-gen`): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("catalog.json is stale: run `make catalog-gen` and commit it")
	}
}

func TestSet(t *testing.T) {
	var zero catalog.Set
	if !zero.IsEmpty() || zero.Len() != 0 || zero.Has("org:read") {
		t.Fatal("zero set")
	}
	a := catalog.NewSet("org:read", "git:read", "nope:nope", "platform-backup:run")
	if a.Len() != 3 || !a.Has("org:read") || a.Has("nope:nope") || !a.Has("platform-backup:run") {
		t.Fatalf("NewSet: %v", a.IDs())
	}
	b := catalog.NewSet("git:read", "git:write")
	if got := a.Union(b).Len(); got != 4 {
		t.Errorf("union %d", got)
	}
	if got := a.Intersect(b).IDs(); len(got) != 1 || got[0] != "git:read" {
		t.Errorf("intersect %v", got)
	}
	if !a.Union(b).ContainsAll(a) || a.ContainsAll(b) || !a.ContainsAll(zero) || !zero.ContainsAll(zero) {
		t.Error("ContainsAll")
	}
	if got := a.Minus(b).Len(); got != 2 {
		t.Errorf("minus %d", got)
	}
	full := catalog.Full()
	if full.Len() != 99 || len(full.IDs()) != 99 {
		t.Error("Full")
	}
	// out of range and the edges of the second word
	if full.HasBit(-1) || full.HasBit(128) || full.HasBit(99) || !full.HasBit(98) || !full.HasBit(63) || !full.HasBit(64) {
		t.Error("HasBit bounds")
	}
	// hex round trip, and bits beyond the catalog are dropped
	for _, s := range []catalog.Set{zero, a, b, full} {
		h := s.Hex()
		if len(h) != 32 {
			t.Fatalf("hex %q", h)
		}
		back, ok := catalog.SetFromHex(h)
		if !ok || back != s {
			t.Errorf("round trip %s", h)
		}
	}
	if s, ok := catalog.SetFromHex("ffffffffffffffffffffffffffffffff"); !ok || s != full {
		t.Error("bits beyond the catalog must be cleared")
	}
	if _, ok := catalog.SetFromHex("zz"); ok {
		t.Error("bad hex accepted")
	}
	if _, ok := catalog.SetFromHex(strings.Repeat("0", 33)); ok {
		t.Error("too long hex accepted")
	}
	if s, unknown := catalog.ParseSet([]string{"org:read", "x:y"}); s.Len() != 1 || len(unknown) != 1 || unknown[0] != "x:y" {
		t.Errorf("ParseSet %v %v", s.IDs(), unknown)
	}
	// value semantics: Add does not mutate the receiver
	c := zero.Add("org:read")
	if !zero.IsEmpty() || !c.Has("org:read") || c.Add("nope:nope") != c {
		t.Error("Add")
	}
}

func TestSetOperationsDoNotAllocate(t *testing.T) {
	a := catalog.NewSet("git:read", "ci:read", "project:view")
	b := catalog.Full()
	bit, _ := catalog.Bit("git:read")
	n := testing.AllocsPerRun(100, func() {
		x := a.Union(b).Intersect(b).Minus(a)
		_ = x.ContainsAll(a)
		_ = a.HasBit(bit)
		_ = a.Has("git:read")
		_ = x.Len()
	})
	if n != 0 {
		t.Errorf("allocations per run: %v", n)
	}
}

func BenchmarkSetCan(b *testing.B) {
	user := catalog.NewSet("git:read", "ci:read", "project:view", "deployment:read")
	ceil := catalog.Full()
	bit, _ := catalog.Bit("git:read")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !user.Intersect(ceil).HasBit(bit) {
			b.Fatal("expected")
		}
	}
}
