package gitevents

import (
	"html"
	"strings"
)

// oneLine removes control characters (header injection) and collapses whitespace.
func oneLine(in string) string {
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, in)), " ")
}

// RenderEmail renders the fixed email template of a summary: subject, plain text and HTML. All
// user-controlled text is escaped in the HTML and stripped of control characters in the subject.
func RenderEmail(sum Summary) (subject, text, htmlBody string) {
	subject = "[Git Capsule] " + trunc(oneLine(sum.Title), 200)
	var t strings.Builder
	t.WriteString(oneLine(sum.Title))
	t.WriteString("\n")
	if sum.Body != "" {
		t.WriteString("\n" + strings.TrimSpace(sum.Body) + "\n")
	}
	if sum.URL != "" {
		t.WriteString("\nVer en Git Capsule: " + sum.URL + "\n")
	}
	t.WriteString("\nRecibes este correo por tus preferencias de notificaciones de Git Capsule.\n")
	text = t.String()

	var h strings.Builder
	h.WriteString("<div style=\"font-family:system-ui,sans-serif;font-size:14px;color:#111\">")
	h.WriteString("<p style=\"font-size:16px;font-weight:600\">" + html.EscapeString(oneLine(sum.Title)) + "</p>")
	if sum.Body != "" {
		h.WriteString("<p style=\"white-space:pre-wrap\">" + html.EscapeString(strings.TrimSpace(sum.Body)) + "</p>")
	}
	if sum.URL != "" {
		h.WriteString("<p><a href=\"" + html.EscapeString(sum.URL) + "\">Ver en Git Capsule</a></p>")
	}
	h.WriteString("<p style=\"color:#666;font-size:12px\">Recibes este correo por tus preferencias de notificaciones de Git Capsule.</p></div>")
	return subject, text, h.String()
}
