package gitprotect

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Glob follows the semantics Forgejo uses for branch rule names (gobwas/glob with '/' as
// separator): '*' matches any run of characters except '/', '**' matches anything including '/',
// '?' one character except '/', [abc] [a-z] [!abc] character classes, {a,b} alternatives and
// '\' escapes the next character. The whole branch name must match (anchored).
//
// The doc statement "/ separates, ** crosses" is verified in Forgejo's documentation; the rest
// of the dialect (classes, alternatives, escape, negated class never matching '/') is taken from
// the library's documented syntax and covered by this package's table tests, NOT diffed against
// Forgejo's binary.
type Glob struct {
	src string
	re  *regexp.Regexp
}

const (
	maxPatternLen = 255
	maxBraceDepth = 6
)

// IsPlain reports whether the pattern has no glob metacharacters (Forgejo gives plain names
// precedence over globs).
func IsPlain(pattern string) bool { return !strings.ContainsAny(pattern, `*?[]{}\`) }

// CompileGlob validates and compiles a pattern.
func CompileGlob(pattern string) (*Glob, error) {
	if pattern == "" {
		return nil, errors.New("empty pattern")
	}
	if len(pattern) > maxPatternLen {
		return nil, errors.New("pattern too long")
	}
	if !utf8.ValidString(pattern) {
		return nil, errors.New("pattern is not valid UTF-8")
	}
	var b strings.Builder
	b.WriteString(`^(?s:`)
	rs := []rune(pattern)
	depth := 0
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch c {
		case '\\':
			if i+1 >= len(rs) {
				return nil, errors.New("trailing backslash")
			}
			i++
			b.WriteString(regexp.QuoteMeta(string(rs[i])))
		case '*':
			j := i
			for j+1 < len(rs) && rs[j+1] == '*' {
				j++
			}
			if j > i {
				b.WriteString(`.*`)
			} else {
				b.WriteString(`[^/]*`)
			}
			i = j
		case '?':
			b.WriteString(`[^/]`)
		case '[':
			cls, next, err := parseClass(rs, i)
			if err != nil {
				return nil, err
			}
			b.WriteString(cls)
			i = next
		case '{':
			depth++
			if depth > maxBraceDepth {
				return nil, errors.New("alternatives nested too deeply")
			}
			b.WriteString(`(?:`)
		case '}':
			if depth == 0 {
				b.WriteString(regexp.QuoteMeta("}"))
			} else {
				depth--
				b.WriteString(`)`)
			}
		case ',':
			if depth > 0 {
				b.WriteString(`|`)
			} else {
				b.WriteString(`,`)
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	if depth != 0 {
		return nil, errors.New("unclosed '{'")
	}
	b.WriteString(`)$`)
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %v", err)
	}
	return &Glob{src: pattern, re: re}, nil
}

// parseClass parses [..] starting at rs[start]=='[' and returns the regexp class and the index of ']'.
func parseClass(rs []rune, start int) (string, int, error) {
	i := start + 1
	neg := false
	if i < len(rs) && (rs[i] == '!' || rs[i] == '^') {
		neg = true
		i++
	}
	var items strings.Builder
	n := 0
	for ; i < len(rs); i++ {
		c := rs[i]
		if c == ']' && n > 0 {
			cls := "[" + items.String() + "]"
			if neg {
				cls = "[^/" + items.String() + "]"
			}
			return cls, i, nil
		}
		if c == '\\' {
			if i+1 >= len(rs) {
				return "", 0, errors.New("unclosed '['")
			}
			i++
			c = rs[i]
		} else if i+2 < len(rs) && rs[i+1] == '-' && rs[i+2] != ']' {
			lo, hi := c, rs[i+2]
			if lo > hi {
				return "", 0, errors.New("invalid range in '[...]'")
			}
			items.WriteString(classEsc(lo) + "-" + classEsc(hi))
			i += 2
			n++
			continue
		}
		items.WriteString(classEsc(c))
		n++
	}
	return "", 0, errors.New("unclosed '['")
}

func classEsc(r rune) string {
	switch r {
	case '\\', ']', '[', '^', '-':
		return `\` + string(r)
	}
	return string(r)
}

// Match reports whether name matches the whole pattern.
func (g *Glob) Match(name string) bool { return g.re.MatchString(name) }

// Source returns the original pattern.
func (g *Glob) Source() string { return g.src }

// Ranked is a rule that matches a branch with its place in the precedence order.
type Ranked struct {
	Rule  Rule
	Plain bool
}

// Rank returns the rules that match branch ordered by Forgejo's precedence: rules without glob
// first (they win, verified in Forgejo docs), then glob rules by creation time and id (the
// creation-order tie-break is from Forgejo's source as remembered, marked (?) in the report).
// The first element is the rule Forgejo applies. Rules with an invalid pattern never match.
func Rank(rules []Rule, branch string) []Ranked {
	var out []Ranked
	for _, r := range rules {
		g, err := CompileGlob(r.Pattern)
		if err != nil || !g.Match(branch) {
			continue
		}
		out = append(out, Ranked{Rule: r, Plain: IsPlain(r.Pattern)})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Plain != b.Plain {
			return a.Plain
		}
		if !a.Rule.CreatedAt.Equal(b.Rule.CreatedAt) {
			return a.Rule.CreatedAt.Before(b.Rule.CreatedAt)
		}
		return a.Rule.ID.String() < b.Rule.ID.String()
	})
	return out
}
