package gitimport

import (
	"fmt"
	"regexp"
	"strings"
)

// GitHub looks for CODEOWNERS here, first match wins (the order GitHub documents).
var GitHubCodeOwnersPaths = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

// maxCodeOwnersRules bounds the work done for one file.
const maxCodeOwnersRules = 5000

// ConvertCodeOwners converts a GitHub CODEOWNERS file (gitignore-like globs) to Forgejo's syntax: one
// Go regular expression per line followed by its owners (Forgejo wraps the expression in ^...$ and
// matches it against the changed path without a leading slash; verified with Forgejo 15.0.11, which also
// reads CODEOWNERS only from the root, docs/, .gitea/ and .forgejo/, never from .github/).
//
// Everything with no equivalent is dropped and reported in Warnings, never guessed:
//   - patterns using [..] or a leading ! (GitHub does not support them either);
//   - owners that are teams (@org/team): Git Capsule derives its only teams from project roles;
//   - e-mail owners;
//   - rules left without owners.
//
// Owners that are users keep their GitHub login (they only count if a Forgejo user has that login);
// e-mail owners are dropped (Forgejo 15.0.11 requests no reviewer for them). orgSlug is only used in the
// messages.
func ConvertCodeOwners(src, orgSlug string) CodeOwnersReport {
	var out []string
	var warns []string
	seenWarn := map[string]bool{}
	warn := func(format string, a ...any) {
		w := fmt.Sprintf(format, a...)
		if !seenWarn[w] {
			seenWarn[w] = true
			warns = append(warns, w)
		}
	}
	rules, keptUsers, converted := 0, false, 0
	for i, line := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		n := i + 1
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			out = append(out, trim)
			continue
		}
		rules++
		if rules > maxCodeOwnersRules {
			warn("more than %d rules: the rest was not converted", maxCodeOwnersRules)
			break
		}
		pat, owners, ok := splitRule(trim)
		if !ok {
			warn("line %d: rule without owners was skipped", n)
			continue
		}
		re, why := globToRegexp(pat)
		if why != "" {
			warn("line %d: pattern %q skipped: %s", n, pat, why)
			continue
		}
		var keep []string
		for _, o := range owners {
			switch {
			case strings.HasPrefix(o, "@") && strings.Contains(o, "/"):
				warn("line %d: team %s has no equivalent (Git Capsule teams come from project roles); owner dropped", n, o)
			case strings.HasPrefix(o, "@"):
				keep = append(keep, o)
				keptUsers = true
			case strings.Contains(o, "@"):
				warn("line %d: e-mail owner %s dropped: Forgejo does not accept e-mail owners (verified on 15.0.11)", n, o)
			default:
				warn("line %d: owner %q is neither @user, @org/team nor an e-mail; dropped", n, o)
			}
		}
		if len(keep) == 0 {
			warn("line %d: rule for %q has no usable owner and was skipped", n, pat)
			continue
		}
		out = append(out, re+" "+strings.Join(keep, " "))
		converted++
	}
	if rules > 1 {
		warn("GitHub applies the LAST matching rule; Forgejo UNITES the owners of every matching rule (verified on 15.0.11): review overlapping rules")
	}
	if keptUsers {
		warn("owners keep their GitHub login: map them to the logins of the Git Capsule users before relying on required reviews (org %s)", orgSlug)
	}
	return CodeOwnersReport{Converted: strings.TrimSpace(strings.Join(out, "\n")) + "\n", Warnings: warns}
}

// splitRule splits "pattern owner owner" on unescaped whitespace.
func splitRule(line string) (string, []string, bool) {
	var toks []string
	var cur strings.Builder
	esc := false
	for _, r := range line {
		switch {
		case esc:
			cur.WriteRune('\\')
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ' ' || r == '\t':
			if cur.Len() > 0 {
				toks = append(toks, cur.String())
				cur.Reset()
			}
		case r == '#' && cur.Len() == 0:
			// trailing comment
			if cur.Len() > 0 {
				toks = append(toks, cur.String())
			}
			goto done
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		toks = append(toks, cur.String())
	}
done:
	if len(toks) < 2 {
		return "", nil, false
	}
	return toks[0], toks[1:], true
}

// globToRegexp converts one CODEOWNERS pattern. The second result is non-empty when the pattern
// cannot be converted.
func globToRegexp(p string) (string, string) {
	if strings.HasPrefix(p, "!") {
		return "", "negation (!) is not supported by GitHub CODEOWNERS"
	}
	if strings.Contains(p, "[") {
		return "", "character ranges ([ ]) are not supported by GitHub CODEOWNERS"
	}
	anchored := strings.HasPrefix(p, "/")
	core := strings.TrimPrefix(p, "/")
	dirOnly := strings.HasSuffix(core, "/")
	core = strings.TrimSuffix(core, "/")
	if core == "" {
		return "", "empty pattern"
	}
	floating := !anchored && !strings.Contains(core, "/")

	var b strings.Builder
	for i := 0; i < len(core); {
		switch {
		case strings.HasPrefix(core[i:], "**/") && (i == 0 || core[i-1] == '/'):
			b.WriteString(`(?:.*/)?`)
			i += 3
		case strings.HasPrefix(core[i:], "**"):
			b.WriteString(`.*`)
			i += 2
			for i < len(core) && core[i] == '*' {
				i++
			}
		case core[i] == '*':
			b.WriteString(`[^/]*`)
			i++
		case core[i] == '?':
			b.WriteString(`[^/]`)
			i++
		case core[i] == '\\' && i+1 < len(core):
			b.WriteString(regexp.QuoteMeta(string(core[i+1])))
			i += 2
		default:
			b.WriteString(regexp.QuoteMeta(string(core[i])))
			i++
		}
	}
	body := b.String()
	last := core
	if j := strings.LastIndex(core, "/"); j >= 0 {
		last = core[j+1:]
	}
	re := body
	if floating {
		re = `(?:.*/)?` + re
	}
	switch {
	case dirOnly:
		re += `/.*`
	case strings.ContainsAny(last, "*?") || strings.HasSuffix(core, "**"):
		// a glob in the last segment names files/dirs directly, GitHub does not descend ("docs/*")
	default:
		re += `(?:/.*)?` // a literal name may be a directory: its contents belong to it
	}
	if _, err := regexp.Compile("^" + re + "$"); err != nil {
		return "", "the converted expression is not a valid regular expression"
	}
	return re, ""
}
