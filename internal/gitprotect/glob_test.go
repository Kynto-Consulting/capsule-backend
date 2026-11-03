package gitprotect

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		// plain names are exact
		{"main", "main", true},
		{"main", "main2", false},
		{"main", "Main", false},
		{"main", "release/main", false},
		// '*' does not cross '/'
		{"release/*", "release/1.0", true},
		{"release/*", "release/1.0/hotfix", false},
		{"release/*", "release/", true}, // gobwas: * may be empty (a branch "release/" cannot exist, so harmless)
		{"release/*", "release", false},
		{"*", "main", true},
		{"*", "feat/x", false},
		{"feat*", "feature", true},
		{"feat*", "feat/x", false},
		{"*-hotfix", "a-hotfix", true},
		{"*-hotfix", "a/b-hotfix", false},
		// '**' crosses '/'
		{"**", "main", true},
		{"**", "a/b/c", true},
		{"release/**", "release/1/2/3", true},
		{"release/**", "release/x", true},
		{"**/stable", "a/b/stable", true},
		{"**/stable", "stable", false}, // like gobwas: the '/' is literal
		{"a/**/b", "a/x/y/b", true},
		{"a/**/b", "a/b", false},
		// '?'
		{"v?", "v1", true},
		{"v?", "v10", false},
		{"v?", "v/", false},
		{"a?b", "a/b", false},
		// classes
		{"v[0-9]", "v7", true},
		{"v[0-9]", "va", false},
		{"v[!0-9]", "va", true},
		{"v[!0-9]", "v7", false},
		{"v[!0-9]", "v/", false}, // negated class never matches '/'
		{"[abc]x", "bx", true},
		{"[abc]x", "dx", false},
		{`[\]]x`, "]x", true},
		// alternatives
		{"{main,develop}", "main", true},
		{"{main,develop}", "develop", true},
		{"{main,develop}", "dev", false},
		{"release/{1,2}.*", "release/1.5", true},
		{"release/{1,2}.*", "release/3.5", false},
		{"{a,{b,c}}x", "cx", true},
		{"a,b", "a,b", true}, // comma outside braces is literal
		// escapes and regexp metacharacters are literal
		{`a\*b`, "a*b", true},
		{`a\*b`, "axb", false},
		{"a.b", "a.b", true},
		{"a.b", "axb", false},
		{"a+b(c)", "a+b(c)", true},
		{"a|b", "a|b", true},
		{"a|b", "a", false},
		{"^main$", "^main$", true},
		{"^main$", "main", false},
		// unicode
		{"rama-é", "rama-é", true},
		{"rama-?", "rama-é", true},
	}
	for _, c := range cases {
		g, err := CompileGlob(c.pattern)
		if err != nil {
			t.Errorf("CompileGlob(%q): %v", c.pattern, err)
			continue
		}
		if got := g.Match(c.name); got != c.want {
			t.Errorf("%q ~ %q = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestGlobInvalid(t *testing.T) {
	for _, p := range []string{"", "a[", "a[]", "a[b", "{a,b", `a\`, "[z-a]", "{{{{{{{a}}}}}}}"} {
		if _, err := CompileGlob(p); err == nil {
			t.Errorf("CompileGlob(%q) should fail", p)
		}
	}
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := CompileGlob(string(long)); err == nil {
		t.Error("a pattern over 255 bytes should fail")
	}
}

func TestIsPlain(t *testing.T) {
	for p, want := range map[string]bool{"main": true, "release/1.0": true, "a-b_c": true, "release/*": false, "a?": false, "[a]": false, "{a,b}": false, `a\b`: false, "**": false} {
		if got := IsPlain(p); got != want {
			t.Errorf("IsPlain(%q) = %v, want %v", p, got, want)
		}
	}
}

func rule(pattern string, age int) Rule {
	return Rule{ID: uuid.New(), Pattern: pattern, CreatedAt: time.Date(2026, 11, 1, 0, 0, age, 0, time.UTC)}
}

// Precedence: a rule without glob beats any glob rule; among globs the oldest wins.
func TestRankPrecedence(t *testing.T) {
	// created newest-first on purpose so ordering cannot come from slice order
	rules := []Rule{rule("main", 5), rule("**", 4), rule("m*", 3), rule("{main,dev}", 1), rule("release/*", 2)}
	patterns := func(rs []Ranked) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.Rule.Pattern)
		}
		return out
	}
	cases := []struct {
		branch string
		want   []string
	}{
		{"main", []string{"main", "{main,dev}", "m*", "**"}}, // plain first, then globs oldest first
		{"dev", []string{"{main,dev}", "**"}},
		{"release/1", []string{"release/*", "**"}}, // '**' is the newest glob that matches
		{"release/1/2", []string{"**"}},            // '*' does not cross '/'
		{"misc", []string{"m*", "**"}},
		{"nothing/x", []string{"**"}},
	}
	for _, c := range cases {
		got := patterns(Rank(rules, c.branch))
		if len(got) != len(c.want) {
			t.Errorf("Rank(%q) = %v, want %v", c.branch, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("Rank(%q) = %v, want %v", c.branch, got, c.want)
				break
			}
		}
	}
	if len(Rank([]Rule{rule("release/*", 1)}, "main")) != 0 {
		t.Error("no rule should match main")
	}
	// an invalid pattern never matches (and never panics)
	if len(Rank([]Rule{rule("a[", 1)}, "a[")) != 0 {
		t.Error("invalid pattern must not match")
	}
}
