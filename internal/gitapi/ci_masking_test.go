package gitapi

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestCIRedactorKnownValues(t *testing.T) {
	secret := "s3cr3t/value+with=chars&more"
	multi := "line-one-secret\nline-two-secret"
	in := strings.Join([]string{
		"plain: " + secret,
		"b64: " + base64.StdEncoding.EncodeToString([]byte(secret)),
		"b64raw: " + base64.RawURLEncoding.EncodeToString([]byte(secret)),
		"url: " + url.QueryEscape(secret),
		`json: {"k":"` + `s3cr3t/value+with=chars&more` + `"}`,
		"only the second line: line-two-secret",
		"a harmless build line",
		"::add-mask::announced-value-123",
		"later announced-value-123 appears",
	}, "\n")
	out := CIRedactor(in, secret, multi)
	for _, leak := range []string{secret, base64.StdEncoding.EncodeToString([]byte(secret)),
		base64.RawURLEncoding.EncodeToString([]byte(secret)), url.QueryEscape(secret),
		"line-one-secret", "line-two-secret", "announced-value-123"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q in:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "a harmless build line") {
		t.Errorf("over-redacted:\n%s", out)
	}
}

func TestCIRedactorShortAndEmpty(t *testing.T) {
	if CIRedactor("") != "" {
		t.Error("empty stays empty")
	}
	if got := CIRedactor("ab abc", "ab"); got != "ab abc" {
		t.Errorf("values under the floor must not shred the log: %q", got)
	}
}

func TestCIRedactorIsInstalled(t *testing.T) {
	SetLogRedactor(nil)
	SetLogRedactor(CIRedactor)
	if got := RedactLog("x hunter2-secret-val y", "hunter2-secret-val"); strings.Contains(got, "hunter2-secret-val") {
		t.Errorf("leak: %s", got)
	}
}

// Line captured from a REAL forgejo-runner v13.2.1 job (B6 real-runner test): the runner masked the plain
// value after ::add-mask:: but let the base64 form through. CIRedactor, given the known secret, closes it.
func TestCIRedactorRealRunnerLog(t *testing.T) {
	log := "imprimo: ***\nen base64: dmFsb3Itc2VjcmV0by1iNi0xMjM0NQ==\n"
	out := CIRedactor(log, "valor-secreto-b6-12345")
	if strings.Contains(out, "dmFsb3Itc2VjcmV0by1iNi0xMjM0NQ") {
		t.Errorf("base64 form leaked: %s", out)
	}
	if !strings.Contains(out, "en base64: ***") {
		t.Errorf("unexpected output: %s", out)
	}
}
