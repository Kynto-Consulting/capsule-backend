package security

import (
	"regexp"
	"strings"
)

// globToRegexp compiles a path glob: "*" and "?" stay inside one path segment, "**" crosses
// segments ("a/**/b" also matches "a/b"). Matching is on the whole path.
func globToRegexp(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString(`^`)
	for i := 0; i < len(glob); {
		c := glob[i]
		switch {
		case c == '*' && i+1 < len(glob) && glob[i+1] == '*':
			// "**/" = any number of directories (including none); trailing "**" = anything
			if i+2 < len(glob) && glob[i+2] == '/' {
				b.WriteString(`(?:.*/)?`)
				i += 3
			} else {
				b.WriteString(`.*`)
				i += 2
			}
		case c == '*':
			b.WriteString(`[^/]*`)
			i++
		case c == '?':
			b.WriteString(`[^/]`)
			i++
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
			i++
		}
	}
	b.WriteString(`$`)
	return regexp.Compile(b.String())
}

// globMatchesEverything is true for globs that would suppress the whole repository ("**", "*",
// "**/*", "/**"...): everything made only of "*" and "/" is refused (SPEC 5.8).
func globMatchesEverything(glob string) bool {
	return strings.TrimSpace(strings.NewReplacer("*", "", "/", "").Replace(glob)) == ""
}
