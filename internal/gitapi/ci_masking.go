package gitapi

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// CI log re-masking (WORKBREAKDOWN B6, SPEC 5.6 / T4).
//
// The Forgejo runner masks job secrets on a best-effort basis: it does not catch a secret that was
// transformed (base64, URL-encoded, JSON-escaped), nor each line of a multi-line secret printed
// separately. CIRedactor extends the built-in redactor (logmask.go) by expanding every known secret
// value (the ones the caller passes plus the ones announced with ::add-mask::) into its common
// encodings before scrubbing, then runs DefaultRedactor for the credential formats.
//
// It is installed as the process-wide redactor at init; SetLogRedactor(nil) restores the default.

// minMaskLen: shorter values would shred the log (same floor as DefaultRedactor).
const minMaskLen = 3

func init() { SetLogRedactor(CIRedactor) }

// CIRedactor scrubs known secret values and their encodings, then applies DefaultRedactor.
func CIRedactor(content string, extra ...string) string {
	if content == "" {
		return content
	}
	seeds := append([]string(nil), extra...)
	for _, m := range addMaskRe.FindAllStringSubmatch(content, -1) {
		seeds = append(seeds, strings.TrimSpace(m[1]))
	}
	values := MaskVariants(seeds)
	// Longest first so a value that contains another is replaced whole.
	sort.SliceStable(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, v := range values {
		content = strings.ReplaceAll(content, v, redacted)
	}
	return DefaultRedactor(content, extra...)
}

// MaskVariants returns the secrets plus the encodings a job can print them in: each non-empty line
// of a multi-line value, base64 (std/url, padded or not), percent-encoding and JSON escaping.
// Values shorter than minMaskLen are dropped. The result has no duplicates.
func MaskVariants(secrets []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if len(s) >= minMaskLen && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range secrets {
		s = strings.TrimRight(s, "\r\n")
		if len(s) < minMaskLen {
			continue
		}
		add(s)
		for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
			add(strings.TrimSpace(line))
		}
		b := []byte(s)
		add(base64.StdEncoding.EncodeToString(b))
		add(base64.RawStdEncoding.EncodeToString(b))
		add(base64.URLEncoding.EncodeToString(b))
		add(base64.RawURLEncoding.EncodeToString(b))
		add(url.QueryEscape(s))
		add(url.PathEscape(s))
		if j, err := json.Marshal(s); err == nil && len(j) > 2 {
			add(string(j[1 : len(j)-1]))
		}
	}
	return out
}
