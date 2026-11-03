package gitreview

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestParseAndOwnersOf(t *testing.T) {
	src := "# comment\r\n" +
		`.*\.go$ @alice @acme/web-deployer` + "\n" +
		`^docs/ @bob # trailing comment` + "\n" +
		`!.*\.md$ @carol` + "\n" +
		"\n"
	f := Parse("CODEOWNERS", []byte(src))
	if len(f.Warnings) != 0 || len(f.Rules) != 3 {
		t.Fatalf("rules %d warnings %v", len(f.Rules), f.Warnings)
	}
	cases := []struct {
		path string
		want []string
	}{
		{"main.go", []string{"@acme/web-deployer", "@alice", "@carol"}}, // negative applies to non-md
		{"docs/a.md", []string{"@bob"}},                                 // md: negative rule does not apply
		{"docs/x.txt", []string{"@bob", "@carol"}},
		{"README.md", nil},
	}
	for _, c := range cases {
		got := f.OwnersOf(c.path)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v want %v", c.path, got, c.want)
		}
	}
}

func TestParseWarnings(t *testing.T) {
	cases := []struct{ name, line, want string }{
		{"invalid regex glob", `*.js @alice`, "expresion regular invalida"},
		{"glob hint", `*.js @alice`, `[^/]*\.js`},
		{"leading slash", `/docs/ @alice`, "empieza con '/'"},
		{"double star", `src/**/*.go @alice`, "equivalente"},
		{"no owners", `.*\.go$`, "no tiene propietarios"},
		{"email owner", `.*\.go$ dev@example.com`, "propietario"},
		{"section", `[Docs]`, "secciones"},
		{"empty negation", `! @alice`, ""},
	}
	for _, c := range cases {
		f := Parse("CODEOWNERS", []byte(c.line))
		joined := strings.Join(f.Warnings, "|")
		if c.want == "" {
			continue
		}
		if !strings.Contains(joined, c.want) {
			t.Errorf("%s: warnings %q lack %q", c.name, joined, c.want)
		}
	}
	// invalid regex rules are dropped, valid ones kept
	f := Parse("CODEOWNERS", []byte("*.js @a\n.*\\.go$ @b"))
	if len(f.Rules) != 1 || f.Rules[0].Owners[0] != "@b" {
		t.Fatalf("rules: %+v", f.Rules)
	}
	if len(f.Warnings) == 0 {
		t.Fatal("want a warning for the invalid rule")
	}
}

func TestGlobToRegexMatchesLikeGitHub(t *testing.T) {
	cases := []struct {
		glob  string
		path  string
		match bool
	}{
		{"*.js", "a.js", true},
		{"*.js", "src/deep/a.js", true},
		{"*.js", "a.jsx", false},
		{"/docs/", "docs/a.md", true},
		{"/docs/", "x/docs/a.md", false},
		{"docs/", "x/docs/a.md", true},
		{"/src/**", "src/a/b.go", true},
		{"src/**/test.go", "src/test.go", true},
		{"src/**/test.go", "src/a/b/test.go", true},
		{"/build/output", "build/output", true},
		{"/build/output", "build/output/x", true},
		{"/build/output", "build/outputs", false},
		{"a?c", "abc", true},
		{"a?c", "a/c", false},
	}
	for _, c := range cases {
		re := regexp.MustCompile(GlobToRegex(c.glob))
		if re.MatchString(c.path) != c.match {
			t.Errorf("glob %q path %q: regex %s match=%v want %v", c.glob, c.path, re, !c.match, c.match)
		}
	}
	if GlobToRegex("!x") != "" || GlobToRegex("") != "" {
		t.Fatal("negation and empty are not convertible")
	}
}

func TestConvertGitHub(t *testing.T) {
	in := "# owners\n*.go @alice\n/docs/ @bob @acme/docs dev@x.io\n!secret @eve\nlonely\n"
	out, warns := ConvertGitHub(in)
	f := Parse("CODEOWNERS", []byte(out))
	if len(f.Warnings) != 0 {
		t.Fatalf("converted file still warns: %v\n%s", f.Warnings, out)
	}
	if !reflect.DeepEqual(f.OwnersOf("x/y.go"), []string{"@alice"}) {
		t.Fatalf("owners of go file: %v", f.OwnersOf("x/y.go"))
	}
	if !reflect.DeepEqual(f.OwnersOf("docs/a.md"), []string{"@acme/docs", "@bob"}) {
		t.Fatalf("owners of docs: %v", f.OwnersOf("docs/a.md"))
	}
	w := strings.Join(warns, "|")
	for _, want := range []string{"'!'", "sin propietarios", "dev@x.io", "ultima regla"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings %q lack %q", w, want)
		}
	}
}
