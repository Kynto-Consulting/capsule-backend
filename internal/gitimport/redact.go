package gitimport

import (
	"regexp"
	"strings"
)

// tokenShapes matches GitHub token formats (classic, fine-grained, OAuth, app) so that even a token
// that was not the one of the request never reaches an error message or a log line.
var tokenShapes = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`)

// Redact removes every given secret and every GitHub-token-shaped string from s.
func Redact(s string, secrets ...string) string {
	for _, sec := range secrets {
		if len(sec) >= 4 {
			s = strings.ReplaceAll(s, sec, "***")
		}
	}
	return tokenShapes.ReplaceAllString(s, "***")
}

// clip bounds a message stored in the database or shown to the caller.
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
