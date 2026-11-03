package gitreview

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// CODEOWNERS as Forgejo reads it (same model as Gitea, (?) not probed against v15.0.11):
//   - one rule per line: <go-regexp> <owner> [<owner>...]; owners are @user or @org/team;
//   - the pattern is an UNANCHORED Go regexp tested against the path without leading slash;
//   - a leading "!" negates the rule: it applies to the files that do NOT match;
//   - the owners of EVERY applicable rule are united (GitHub keeps only the last match);
//   - the first file found among OwnersFiles is the one used, read from the base branch.

// OwnersFiles are the paths looked up, in order.
var OwnersFiles = []string{"CODEOWNERS", "docs/CODEOWNERS", ".gitea/CODEOWNERS", ".forgejo/CODEOWNERS"}

// Rule is one parsed CODEOWNERS line.
type Rule struct {
	Line     int
	Pattern  string // without the "!"
	Negative bool
	Owners   []string // as written: "@alice", "@org/team"
	re       *regexp.Regexp
}

// File is a parsed CODEOWNERS.
type File struct {
	Path     string
	Rules    []Rule
	Warnings []string
}

// Parse never fails: invalid lines become warnings and are skipped.
func Parse(path string, content []byte) *File {
	f := &File{Path: path}
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	for i, raw := range strings.Split(text, "\n") {
		n := i + 1
		line := strings.TrimSpace(stripComment(raw))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			f.warn(n, "las secciones [..] no existen en Forgejo; la linea se ignora")
			continue
		}
		toks := strings.Fields(line)
		pat := toks[0]
		neg := strings.HasPrefix(pat, "!")
		pat = strings.TrimPrefix(pat, "!")
		if pat == "" {
			f.warn(n, "regla vacia despues de '!'")
			continue
		}
		var owners []string
		for _, t := range toks[1:] {
			if !validOwner(t) {
				f.warn(n, fmt.Sprintf("propietario %q ignorado: se espera @usuario o @org/equipo", t))
				continue
			}
			owners = append(owners, t)
		}
		if len(owners) == 0 {
			f.warn(n, "la regla no tiene propietarios validos; Forgejo no admite 'sin propietario' como GitHub")
			continue
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			msg := fmt.Sprintf("expresion regular invalida %q (Forgejo usa regex de Go, no globs)", pat)
			if hint := GlobToRegex(pat); hint != "" && hint != pat {
				msg += "; equivalente: " + hint
			}
			f.warn(n, msg)
			continue
		}
		if g := globWarning(pat); g != "" {
			f.warn(n, g)
		}
		f.Rules = append(f.Rules, Rule{Line: n, Pattern: pat, Negative: neg, Owners: owners, re: re})
	}
	return f
}

func (f *File) warn(line int, msg string) {
	f.Warnings = append(f.Warnings, fmt.Sprintf("linea %d: %s", line, msg))
}

var ownerRe = regexp.MustCompile(`^@[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)?$`)

func validOwner(s string) bool { return ownerRe.MatchString(s) }

// stripComment removes a "#" comment: at line start or after whitespace (\# is literal).
func stripComment(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return s[:i]
		}
	}
	return s
}

// globWarning flags GitHub-style patterns that compile as regex but do not mean what they look like.
func globWarning(p string) string {
	switch {
	case strings.HasPrefix(p, "/"):
		return fmt.Sprintf("el patron %q empieza con '/': las rutas no llevan barra inicial, nunca coincidira; usa ^ruta", p)
	case strings.Contains(p, "**"):
		return fmt.Sprintf("el patron %q parece un glob de GitHub; equivalente: %s", p, GlobToRegex(p))
	case strings.HasSuffix(p, "/") && !strings.ContainsAny(p, `^$.*+?()[]{}|\`):
		return fmt.Sprintf("el patron %q es una subcadena sin anclar, no un directorio; equivalente: %s", p, GlobToRegex(p))
	}
	return ""
}

// OwnersOf returns the united raw owners that apply to one path (sorted, unique).
func (f *File) OwnersOf(path string) []string {
	set := map[string]bool{}
	for _, r := range f.Rules {
		if r.re.MatchString(path) != r.Negative {
			for _, o := range r.Owners {
				set[o] = true
			}
		}
	}
	return sortedKeys(set)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// GlobToRegex translates one GitHub CODEOWNERS (gitignore-style) glob to a Forgejo regex.
// "" means the glob cannot be expressed.
func GlobToRegex(g string) string {
	g = strings.TrimSpace(g)
	if g == "" || strings.HasPrefix(g, "!") {
		return ""
	}
	dirOnly := strings.HasSuffix(g, "/")
	g = strings.TrimSuffix(g, "/")
	anchored := strings.HasPrefix(g, "/") || strings.Contains(strings.TrimPrefix(g, "/"), "/")
	g = strings.TrimPrefix(g, "/")
	var b strings.Builder
	for i := 0; i < len(g); i++ {
		switch c := g[i]; {
		case c == '*' && i+1 < len(g) && g[i+1] == '*':
			i++
			if i+1 < len(g) && g[i+1] == '/' {
				i++
				b.WriteString(`(?:.*/)?`)
			} else {
				b.WriteString(`.*`)
			}
		case c == '*':
			b.WriteString(`[^/]*`)
		case c == '?':
			b.WriteString(`[^/]`)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	prefix := `(?:^|/)`
	if anchored {
		prefix = `^`
	}
	suffix := `(?:/|$)`
	if dirOnly {
		suffix = `/`
	}
	return prefix + b.String() + suffix
}

// ConvertGitHub converts a GitHub CODEOWNERS to Forgejo syntax (used by the importer, C1). Lines
// that cannot be converted are dropped and reported.
func ConvertGitHub(content string) (string, []string) {
	var out, warns []string
	rules := 0
	for i, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		n := i + 1
		trim := strings.TrimSpace(raw)
		if trim == "" || strings.HasPrefix(trim, "#") {
			out = append(out, raw)
			continue
		}
		toks := strings.Fields(stripComment(trim))
		if len(toks) < 2 {
			warns = append(warns, fmt.Sprintf("linea %d: regla sin propietarios (en GitHub deja la ruta sin dueno); omitida", n))
			continue
		}
		if strings.HasPrefix(toks[0], "!") {
			warns = append(warns, fmt.Sprintf("linea %d: GitHub no admite '!'; omitida", n))
			continue
		}
		var owners []string
		for _, t := range toks[1:] {
			if validOwner(t) {
				owners = append(owners, t)
			} else {
				warns = append(warns, fmt.Sprintf("linea %d: propietario %q omitido (correo o formato no soportado)", n, t))
			}
		}
		if len(owners) == 0 {
			continue
		}
		re := GlobToRegex(toks[0])
		if re == "" {
			warns = append(warns, fmt.Sprintf("linea %d: patron %q no convertible; omitida", n, toks[0]))
			continue
		}
		out = append(out, re+" "+strings.Join(owners, " "))
		rules++
	}
	if rules > 1 {
		warns = append(warns, "GitHub aplica solo la ultima regla que coincide; Forgejo une los propietarios de todas las reglas que coinciden: revisa los solapes")
	}
	return strings.Join(out, "\n"), warns
}
