package security

import (
	"html"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Texts coming from SARIF are untrusted: they are never rendered as HTML. They are stored after
// sanitize (control characters out, valid UTF-8, bounded) and escape (HTML entities, Markdown
// punctuation), so rendering them as Markdown or HTML cannot inject markup, links or images.

// sanitize removes control characters (keeps \n and \t), fixes invalid UTF-8 and cuts to max runes.
func sanitize(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			break
		}
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			n++
			continue
		}
		if r == '\r' {
			continue
		}
		if unicode.IsControl(r) || r == ' ' || r == ' ' || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			continue // controls and bidi overrides
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

var mdReplacer = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", `*`, `\*`, `_`, `\_`, `[`, `\[`, `]`, `\]`, `(`, `\(`, `)`, `\)`,
	`!`, `\!`, `#`, `\#`, `|`, `\|`, `~`, `\~`,
)

// escape neutralizes Markdown punctuation and then HTML-escapes (in this order, so the entities
// produced by the HTML step, which contain "#" and ";", are not touched again).
func escape(s string) string { return html.EscapeString(mdReplacer.Replace(s)) }

// clean = sanitize + escape, for free text (title, description, evidence, trace messages).
func clean(s string, max int) string { return escape(sanitize(s, max)) }

// plain sanitizes identifiers (rule ids, package names, versions, paths): no escaping, they are
// compared and displayed as plain text, but they cannot carry controls or exceed max.
func plain(s string, max int) string {
	s = sanitize(s, max)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.TrimSpace(s)
}

var whitespace = regexp.MustCompile(`\s+`)

// normalizeSpace collapses whitespace for hashing.
func normalizeSpace(s string) string { return strings.TrimSpace(whitespace.ReplaceAllString(s, " ")) }

// cleanPath normalizes an artifact URI to a repo-relative path: strips file:// and leading ./ and
// slashes, converts backslashes, refuses parent traversal (the path is only ever displayed and
// matched, never opened).
func cleanPath(uri string) string {
	p := plain(uri, 1024)
	p = strings.TrimPrefix(p, "file://")
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	p = strings.TrimLeft(p, "/")
	segs := strings.Split(p, "/")
	out := segs[:0]
	for _, s := range segs {
		if s == ".." {
			continue
		}
		out = append(out, s)
	}
	return strings.Join(out, "/")
}
