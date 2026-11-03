package gitimport_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/gitimport"
)

// matches evaluates a converted rule the way Forgejo does: the expression is wrapped in ^...$ and
// matched against the changed path without a leading slash.
func matches(t *testing.T, rule, path string) bool {
	t.Helper()
	pat, _, _ := strings.Cut(rule, " ")
	re, err := regexp.Compile("^" + pat + "$")
	if err != nil {
		t.Fatalf("converted rule %q is not a Go regexp: %v", pat, err)
	}
	return re.MatchString(path)
}

func TestConvertCodeOwnersPatterns(t *testing.T) {
	cases := []struct {
		pattern string
		yes, no []string
	}{
		{"*", []string{"a.go", "x/y/z.txt"}, nil},
		{"*.js", []string{"a.js", "src/deep/a.js"}, []string{"a.jsx", "ajs"}},
		{"/build/logs/", []string{"build/logs/a.log", "build/logs/x/y.log"}, []string{"build/logs", "src/build/logs/a.log", "build/log/a"}},
		{"docs/*", []string{"docs/a.md"}, []string{"docs/sub/a.md", "x/docs/a.md"}},
		{"docs/", []string{"docs/a.md", "src/docs/a.md", "src/docs/x/y.md"}, []string{"docsx/a.md", "docs"}},
		{"/docs", []string{"docs", "docs/a.md"}, []string{"x/docs", "docs2"}},
		{"apps/", []string{"apps/a", "x/apps/b"}, []string{"app/a"}},
		{"/src/**/test.go", []string{"src/test.go", "src/a/test.go", "src/a/b/test.go"}, []string{"lib/test.go", "src/a/test.gox"}},
		{"/src/**", []string{"src/a", "src/a/b/c"}, []string{"lib/src/a"}},
		{"**/vendor/", []string{"vendor/a", "a/b/vendor/c"}, []string{"vendorx/a"}},
		{"file?.txt", []string{"file1.txt", "d/fileA.txt"}, []string{"file12.txt", "file/.txt"}},
		{"a.b+c", []string{"a.b+c"}, []string{"aXb+c", "a.bbc"}},
		{`\#hash`, []string{"#hash"}, []string{"hash"}},
	}
	for _, c := range cases {
		rep := gitimport.ConvertCodeOwners(c.pattern+" @alice\n", "acme")
		line := strings.TrimSpace(rep.Converted)
		if !strings.HasSuffix(line, " @alice") {
			t.Errorf("%s: converted %q (warnings %v)", c.pattern, rep.Converted, rep.Warnings)
			continue
		}
		for _, p := range c.yes {
			if !matches(t, line, p) {
				t.Errorf("%s -> %q should match %q", c.pattern, line, p)
			}
		}
		for _, p := range c.no {
			if p != "" && matches(t, line, p) {
				t.Errorf("%s -> %q must NOT match %q", c.pattern, line, p)
			}
		}
	}
}

func TestConvertCodeOwnersWarningsAndDrops(t *testing.T) {
	src := strings.Join([]string{
		"# header comment",
		"",
		"*.go @alice @bob",
		"/docs/ @acme/writers",    // team: dropped, rule skipped (no owner left)
		"/web/ @carol @acme/team", // team dropped, carol kept
		"[a-z].txt @dave",         // unsupported
		"!secret.txt @erin",       // unsupported
		"/solo/",                  // no owners
		"/mail/ dev@example.org",  // e-mail: dropped, rule skipped
		"/odd/ plainword",         // not an owner
	}, "\n")
	rep := gitimport.ConvertCodeOwners(src, "acme")
	if !strings.Contains(rep.Converted, "# header comment") {
		t.Errorf("comments are kept: %q", rep.Converted)
	}
	for _, want := range []string{"@alice @bob", "web/.* @carol"} {
		if !strings.Contains(rep.Converted, want) {
			t.Errorf("converted misses %q:\n%s", want, rep.Converted)
		}
	}
	for _, gone := range []string{"writers", "acme/team", "dave", "erin", "solo", "plainword", "mail/"} {
		if strings.Contains(rep.Converted, gone) {
			t.Errorf("converted must not contain %q:\n%s", gone, rep.Converted)
		}
	}
	w := strings.Join(rep.Warnings, "\n")
	for _, want := range []string{"team @acme/writers has no equivalent", "character ranges", "negation", "without owners was skipped", "e-mail owner dev@example.org dropped", "neither @user", "UNITES the owners", "GitHub login"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings miss %q:\n%s", want, w)
		}
	}
}

func TestConvertCodeOwnersCapsRulesAndHandlesCRLF(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 5100; i++ {
		b.WriteString("/d/ @a\r\n")
	}
	rep := gitimport.ConvertCodeOwners(b.String(), "acme")
	if !strings.Contains(strings.Join(rep.Warnings, "\n"), "more than 5000 rules") {
		t.Fatalf("cap warning missing: %v", rep.Warnings)
	}
	if strings.Contains(rep.Converted, "\r") {
		t.Fatal("CRLF must be normalized")
	}
	if n := strings.Count(rep.Converted, "\n"); n != 5000 {
		t.Fatalf("lines: %d", n)
	}
}
