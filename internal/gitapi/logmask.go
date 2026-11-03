package gitapi

import (
	"regexp"
	"strings"
	"sync"
)

// Log redaction for job logs. Forgejo's runner already masks the secrets of the job, but the API is
// the last door before a browser or CLI, so the logs are redacted again here (defence in depth):
//   - values announced with the runner's "::add-mask::VALUE" workflow command (the whole log is
//     scrubbed of VALUE, including lines that came before the announcement),
//   - well known credential formats (Capsule/Forgejo/GitHub tokens, AWS keys, JWTs, private keys,
//     "Authorization: Bearer ...", URLs with embedded passwords),
//   - key=value pairs whose key says secret/token/password.
//
// Package B6 may replace the redactor with a richer one through SetLogRedactor.

const redacted = "***"

var (
	addMaskRe = regexp.MustCompile(`(?m)^(?:[0-9T:.\-Z ]*)?::add-mask::(.+?)\s*$`)

	credentialRes = []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`),
		regexp.MustCompile(`\bcg[tp]_[A-Za-z0-9_\-]{16,}`),
		regexp.MustCompile(`\bcap_[A-Za-z0-9_\-]{16,}`),
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),
		regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`),
		regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9\-]{10,}`),
		regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic|token)\s+)[^\s"']+`),
		regexp.MustCompile(`(?i)(https?://[^/\s:@]+:)[^/\s@]+(@)`),
	}
	// (key)(separator)(value)
	kvRe = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.\-]*(?:secret|token|passw(?:or)?d|api[_\-]?key|private[_\-]?key|access[_\-]?key)[A-Za-z0-9_.\-]*)(\s*[=:]\s*)("[^"\n]*"|'[^'\n]*'|[^\s"',;]+)`)
)

var (
	redMu    sync.RWMutex
	redactor = DefaultRedactor
)

// SetLogRedactor replaces the process-wide redactor (nil restores the default).
func SetLogRedactor(f func(content string, extra ...string) string) {
	redMu.Lock()
	defer redMu.Unlock()
	if f == nil {
		f = DefaultRedactor
	}
	redactor = f
}

// RedactLog applies the active redactor. extra are values known to be secret by the caller.
func RedactLog(content string, extra ...string) string {
	redMu.RLock()
	f := redactor
	redMu.RUnlock()
	return f(content, extra...)
}

// DefaultRedactor is the built-in redactor.
func DefaultRedactor(content string, extra ...string) string {
	if content == "" {
		return content
	}
	values := append([]string(nil), extra...)
	for _, m := range addMaskRe.FindAllStringSubmatch(content, -1) {
		values = append(values, strings.TrimSpace(m[1]))
	}
	// Longest first so a value that contains another one is replaced whole.
	for i := 0; i < len(values); i++ {
		for j := i + 1; j < len(values); j++ {
			if len(values[j]) > len(values[i]) {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
	for _, v := range values {
		if len(v) >= 3 { // masking one or two characters would shred the log
			content = strings.ReplaceAll(content, v, redacted)
		}
	}
	content = addMaskRe.ReplaceAllString(content, "::add-mask::"+redacted)
	for i, re := range credentialRes {
		switch i {
		case 8:
			content = re.ReplaceAllString(content, "${1}"+redacted)
		case 9:
			content = re.ReplaceAllString(content, "${1}"+redacted+"${2}")
		default:
			content = re.ReplaceAllString(content, redacted)
		}
	}
	content = kvRe.ReplaceAllStringFunc(content, func(s string) string {
		m := kvRe.FindStringSubmatch(s)
		if m[3] == redacted || strings.Trim(m[3], `"'`) == redacted || isReference(m[3]) {
			return s
		}
		return m[1] + m[2] + redacted
	})
	return content
}

// isReference keeps values that are only a reference to a secret (${{ secrets.X }}, $VAR, ***) so
// the log stays readable.
func isReference(v string) bool {
	v = strings.Trim(v, `"'`)
	return strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "***")
}
