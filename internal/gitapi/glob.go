// Package gitapi holds the pure logic behind the Git Capsule API (package B1): pull request
// mergeability, DTO mapping, branch-rule globs, log redaction, idempotency and workflow parsing.
// It never talks HTTP; the handlers (server/handlers/gitapi_*.go) wire it to gitcore and authz.
package gitapi

import (
	"regexp"
	"strings"
	"sync"
)

var (
	globMu    sync.Mutex
	globCache = map[string]*regexp.Regexp{}
)

// MatchGlob reports whether name matches pattern with Forgejo's rule semantics: "/" is the
// separator, "*" matches within a segment, "**" matches across segments, "?" one character,
// "[...]" a class and "{a,b}" alternatives. A pattern without wildcards is an exact match.
func MatchGlob(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if !strings.ContainsAny(pattern, "*?[{") {
		return false
	}
	globMu.Lock()
	re, ok := globCache[pattern]
	if !ok {
		re = compileGlob(pattern)
		if len(globCache) > 1024 {
			globCache = map[string]*regexp.Regexp{}
		}
		globCache[pattern] = re
	}
	globMu.Unlock()
	return re != nil && re.MatchString(name)
}

func compileGlob(p string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	depth := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch c {
		case '*':
			if i+1 < len(p) && p[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '[':
			j := strings.IndexByte(p[i:], ']')
			if j < 0 {
				b.WriteString(`\[`)
				continue
			}
			cls := p[i+1 : i+j]
			if strings.HasPrefix(cls, "!") {
				cls = "^" + cls[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(cls, `\`, `\`) + "]")
			i += j
		case '{':
			depth++
			b.WriteString("(?:")
		case '}':
			if depth > 0 {
				depth--
				b.WriteString(")")
			} else {
				b.WriteString(`\}`)
			}
		case ',':
			if depth > 0 {
				b.WriteString("|")
			} else {
				b.WriteString(",")
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	for ; depth > 0; depth-- {
		b.WriteString(")")
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}
