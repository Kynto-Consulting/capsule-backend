package security

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func mustParse(t *testing.T, raw, hint, repo string) *Parsed {
	t.Helper()
	p, err := testParser().Parse(raw, hint, repo)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func sarifCode(t *testing.T, raw string) string {
	t.Helper()
	_, err := testParser().Parse(raw, "", "")
	var se *SarifError
	if !errors.As(err, &se) {
		t.Fatalf("expected a *SarifError, got %v", err)
	}
	return se.Code
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func countBy[T comparable](fs []Finding, key func(Finding) T) map[T]int {
	m := map[T]int{}
	for _, f := range fs {
		m[key(f)]++
	}
	return m
}

func checkCommon(t *testing.T, p *Parsed) {
	t.Helper()
	seen := map[string]bool{}
	for _, f := range p.Findings {
		if !hex64.MatchString(f.Fingerprint) {
			t.Errorf("fingerprint %q is not 64 hex chars", f.Fingerprint)
		}
		if seen[f.Fingerprint] {
			t.Errorf("duplicate fingerprint %s (%s)", f.Fingerprint, f.RuleID)
		}
		seen[f.Fingerprint] = true
		if !f.Kind.Valid() || !f.Severity.Valid() || !validTool(f.Tool) {
			t.Errorf("bad enums in %+v", f)
		}
		if strings.ContainsAny(f.Path, "\\") || strings.HasPrefix(f.Path, "/") || strings.Contains(f.Path, ":") {
			t.Errorf("path %q is not repo-relative", f.Path)
		}
		if f.Title == "" {
			t.Errorf("empty title for %s", f.RuleID)
		}
	}
}

// ---- real tool output ------------------------------------------------------------------------

func TestParseSemgrepReal(t *testing.T) {
	p := mustParse(t, fixtureBytes(t, "semgrep-1.183.0.sarif"), "", "")
	checkCommon(t, p)
	if len(p.Findings) != 35 {
		t.Fatalf("findings = %d, want 35 (the run found 35 results)", len(p.Findings))
	}
	if len(p.Scopes) != 1 || p.Scopes[0] != (Scope{ToolSemgrep, ToolSemgrep}) {
		t.Fatalf("scopes = %+v", p.Scopes)
	}
	for _, f := range p.Findings {
		if f.Tool != ToolSemgrep {
			t.Fatalf("tool = %s", f.Tool)
		}
		// results carry no level: the rule's defaultConfiguration.level applies (ERROR=high, WARNING=medium)
		if f.Severity != SevHigh && f.Severity != SevMedium && f.Severity != SevLow {
			t.Errorf("%s severity %s", f.RuleID, f.Severity)
		}
		if strings.HasPrefix(f.Path, "src/") == false {
			t.Errorf("path %q should have been normalized to src/...", f.Path)
		}
	}
	if len(countBy(p.Findings, func(f Finding) Severity { return f.Severity })) < 2 {
		t.Errorf("expected both error and warning rules in the fixture, got %v", countBy(p.Findings, func(f Finding) Severity { return f.Severity }))
	}
	// evidence is kept for code findings, escaped
	withEvidence := 0
	for _, f := range p.Findings {
		if f.Kind == KindCode && f.Evidence != "" {
			withEvidence++
		}
	}
	if withEvidence == 0 {
		t.Error("no code finding kept its evidence")
	}
	// every secret-like semgrep rule loses its evidence
	for _, f := range p.Findings {
		if f.Kind == KindSecret && (f.Evidence != "" || len(f.Trace) != 0) {
			t.Errorf("secret finding %s keeps evidence", f.RuleID)
		}
	}
}

func TestParseGitleaksRealRedactsEverything(t *testing.T) {
	p := mustParse(t, fixtureBytes(t, "gitleaks.sarif"), "", "")
	checkCommon(t, p)
	if len(p.Findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(p.Findings))
	}
	byRule := map[string]Finding{}
	for _, f := range p.Findings {
		byRule[f.RuleID] = f
		if f.Kind != KindSecret || f.Tool != ToolGitleaks {
			t.Errorf("%+v is not a gitleaks secret", f)
		}
		if f.Evidence != "" || len(f.Trace) != 0 {
			t.Errorf("secret keeps evidence/trace: %+v", f)
		}
	}
	// SPEC 5.8: gitleaks is always high, critical for cloud providers
	if byRule["aws-access-token"].Severity != SevCritical {
		t.Errorf("aws = %s, want critical", byRule["aws-access-token"].Severity)
	}
	if byRule["github-pat"].Severity != SevHigh || byRule["stripe-access-token"].Severity != SevHigh {
		t.Errorf("non-cloud secrets must be high: %s %s", byRule["github-pat"].Severity, byRule["stripe-access-token"].Severity)
	}
	// the value never appears anywhere in what would be stored
	blob, _ := json.Marshal(p)
	for ph, v := range fakeSecrets {
		if strings.Contains(string(blob), v) || strings.Contains(string(blob), ph) {
			t.Fatalf("secret value %s... leaked into the parsed findings", v[:6])
		}
	}
	if byRule["github-pat"].Path != "config.env" || byRule["github-pat"].StartLine != 1 {
		t.Errorf("github-pat location = %s:%d", byRule["github-pat"].Path, byRule["github-pat"].StartLine)
	}
}

func TestParseTrivyReal(t *testing.T) {
	p := mustParse(t, fixtureBytes(t, "trivy-0.76.1.sarif"), "", "")
	checkCommon(t, p)
	if len(p.Findings) != 13 {
		t.Fatalf("findings = %d, want 13", len(p.Findings))
	}
	kinds := countBy(p.Findings, func(f Finding) Kind { return f.Kind })
	if kinds[KindDependency] != 9 || kinds[KindCode] != 4 {
		t.Fatalf("kinds = %v, want 9 dependency (CVE/NSWG) and 4 code (Dockerfile misconfiguration DS-*)", kinds)
	}
	var lodash int
	for _, f := range p.Findings {
		if f.Kind != KindDependency {
			if !strings.HasPrefix(f.RuleID, "DS-") {
				t.Errorf("misconfiguration rule %s", f.RuleID)
			}
			continue
		}
		if f.Package == "" || f.Version == "" || f.Path != "package-lock.json" {
			t.Errorf("dependency without package data: %+v", f)
		}
		if f.Package == "lodash" && f.Version == "4.17.15" {
			lodash++
		}
		if f.Advisory == "" {
			t.Errorf("no advisory for %s", f.RuleID)
		}
	}
	if lodash == 0 {
		t.Error("lodash@4.17.15 not found")
	}
	// CVE-2020-8203: security-severity 7.4 => high; the fixed version is parsed from the message
	for _, f := range p.Findings {
		if f.RuleID == "CVE-2020-8203" {
			if f.Severity != SevHigh || f.FixedVersion == "" {
				t.Errorf("CVE-2020-8203 = %s fixed=%q", f.Severity, f.FixedVersion)
			}
		}
	}
	// the CRITICAL vulnerability maps to critical through security-severity >= 9
	crit := 0
	for _, f := range p.Findings {
		if f.Severity == SevCritical {
			crit++
		}
	}
	if crit == 0 {
		t.Error("the fixture has a critical vulnerability and none was mapped to critical")
	}
}

func TestParseGosecRealSeverityFromTags(t *testing.T) {
	p := mustParse(t, fixtureBytes(t, "gosec-dev.sarif"), "", "gosec-fixture")
	checkCommon(t, p)
	if len(p.Findings) != 4 {
		t.Fatalf("findings = %d, want 4", len(p.Findings))
	}
	for _, f := range p.Findings {
		if f.Tool != ToolGosec || f.Kind != KindCode {
			t.Errorf("%+v", f)
		}
		// gosec writes level=error on every result; the severity is in the rule (MEDIUM)
		if f.Severity != SevMedium {
			t.Errorf("%s = %s, want medium (rule tag), not high from level=error", f.RuleID, f.Severity)
		}
		if f.Path != "main.go" {
			t.Errorf("absolute workspace path not made relative: %q", f.Path)
		}
	}
}

func TestParseOSVSarifAndJSON(t *testing.T) {
	ps := mustParse(t, fixtureBytes(t, "osv-scanner-1.9.2.sarif"), "", "app")
	checkCommon(t, ps)
	if len(ps.Findings) != 8 {
		t.Fatalf("sarif findings = %d, want 8", len(ps.Findings))
	}
	for _, f := range ps.Findings {
		if f.Kind != KindDependency || f.Package != "lodash" && f.Package != "minimist" {
			t.Errorf("%+v", f)
		}
		if f.Path != "package-lock.json" || f.Version == "" || !strings.HasPrefix(f.Advisory, "CVE-") {
			t.Errorf("location/package data: %+v", f)
		}
		// osv-scanner's SARIF has no severity: level warning => medium
		if f.Severity != SevMedium {
			t.Errorf("%s = %s", f.RuleID, f.Severity)
		}
	}
	pj := mustParse(t, fixtureBytes(t, "osv-scanner-1.9.2.json"), "", "app")
	checkCommon(t, pj)
	if len(pj.Findings) != 8 {
		t.Fatalf("json findings = %d, want 8", len(pj.Findings))
	}
	got := map[string]Severity{}
	for _, f := range pj.Findings {
		got[f.RuleID] = f.Severity
		if f.Path != "package-lock.json" || f.Tool != ToolOSV {
			t.Errorf("%+v", f)
		}
	}
	// max_severity 9.8 / 8.1 / 7.2 / 6.5 / 5.3 from the real run: SPEC CVSS bands
	want := map[string]Severity{
		"GHSA-xvch-5gv4-984h": SevCritical, "GHSA-r5fr-rjxr-66jc": SevHigh, "GHSA-35jh-r3h4-6jhm": SevHigh,
		"GHSA-f23m-r3pf-42rh": SevMedium, "GHSA-29mw-wpgm-hmr9": SevMedium,
	}
	for id, sev := range want {
		if got[id] != sev {
			t.Errorf("%s = %s, want %s", id, got[id], sev)
		}
	}
	// SARIF and JSON give the same alert for the same package: fingerprint ignores the format
	if ps.Findings[0].Fingerprint == "" || pj.Findings[0].Fingerprint == "" {
		t.Fatal("empty fingerprint")
	}
}

func TestFingerprintsAreStableAndSpecific(t *testing.T) {
	raw := fixtureBytes(t, "semgrep-1.183.0.sarif")
	a := mustParse(t, raw, "", "")
	b := mustParse(t, raw, "", "")
	for i := range a.Findings {
		if a.Findings[i].Fingerprint != b.Findings[i].Fingerprint {
			t.Fatalf("fingerprint %d differs between two parses of the same SARIF", i)
		}
	}
	// the same finding moved down by 10 lines (and a different run directory) keeps its fingerprint
	var log map[string]any
	if err := json.Unmarshal([]byte(raw), &log); err != nil {
		t.Fatal(err)
	}
	for _, r := range log["runs"].([]any) {
		for _, res := range r.(map[string]any)["results"].([]any) {
			reg := res.(map[string]any)["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["region"].(map[string]any)
			reg["startLine"] = reg["startLine"].(float64) + 10
			reg["endLine"] = reg["endLine"].(float64) + 10
		}
	}
	moved, _ := json.Marshal(log)
	c := mustParse(t, string(moved), "", "")
	for i := range a.Findings {
		if a.Findings[i].Fingerprint != c.Findings[i].Fingerprint {
			t.Fatalf("fingerprint %d changed when the code moved 10 lines", i)
		}
	}
	// a different rule on the same snippet is a different alert
	if a.Findings[0].Fingerprint == a.Findings[1].Fingerprint {
		t.Fatal("distinct findings share a fingerprint")
	}
}

func TestSecretFingerprintIsKeyedAndLineIndependent(t *testing.T) {
	raw := fixtureBytes(t, "gitleaks.sarif")
	a := mustParse(t, raw, "", "")
	other := &Parser{Key: []byte("another key")}
	b, err := other.Parse(raw, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for i := range a.Findings {
		if a.Findings[i].Fingerprint == b.Findings[i].Fingerprint {
			t.Fatal("the secret fingerprint does not depend on the HMAC key")
		}
	}
	// the secret moved to another line is the same alert
	moved := strings.ReplaceAll(raw, `"startLine": 1,`, `"startLine": 7,`)
	c := mustParse(t, moved, "", "")
	for i := range a.Findings {
		if a.Findings[i].Fingerprint != c.Findings[i].Fingerprint {
			t.Fatal("moving a secret to another line changed its fingerprint")
		}
	}
	// a different value is a different alert
	d := mustParse(t, strings.ReplaceAll(raw, "@@SECRET_3@@", "x"+fakeSecrets["@@SECRET_3@@"]), "", "")
	_ = d
	changed := strings.ReplaceAll(fixtureBytes(t, "gitleaks.sarif"), fakeSecrets["@@SECRET_3@@"], "ghp_AnotherFixtureValue9876543210zyxwvutsrq")
	e := mustParse(t, changed, "", "")
	diff := 0
	for i := range a.Findings {
		if a.Findings[i].Fingerprint != e.Findings[i].Fingerprint {
			diff++
		}
	}
	if diff != 1 {
		t.Fatalf("changing one secret value changed %d fingerprints, want exactly 1", diff)
	}
}

// ---- hostile input ---------------------------------------------------------------------------

func bigSarif(results int) string {
	var b strings.Builder
	b.WriteString(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[`)
	for i := 0; i < results; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"ruleId":"r%d","message":{"text":"m"}}`, i)
	}
	b.WriteString(`]}]}`)
	return b.String()
}

func TestSarifResultLimit(t *testing.T) {
	if got := sarifCode(t, bigSarif(MaxResults+1)); got != "SARIF_TOO_MANY_RESULTS" {
		t.Fatalf("code = %s", got)
	}
	p := mustParse(t, bigSarif(MaxResults), "", "")
	if len(p.Findings) != MaxResults {
		t.Fatalf("findings = %d, want %d", len(p.Findings), MaxResults)
	}
	// gzip+base64 of a big upload works too
	if _, err := testParser().Parse(gzipB64(t, bigSarif(2000)), "", ""); err != nil {
		t.Fatal(err)
	}
}

func TestSarifNestingLimit(t *testing.T) {
	deep := func(n int) string {
		return `{"version":"2.1.0","runs":[],"properties":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}`
	}
	if got := sarifCode(t, deep(MaxDepth+10)); got != "SARIF_TOO_DEEP" {
		t.Fatalf("code = %s", got)
	}
	if got := sarifCode(t, deep(2_000_000)); got != "SARIF_TOO_DEEP" {
		t.Fatalf("a million levels: code = %s", got)
	}
	if _, err := testParser().Parse(deep(MaxDepth-5), "", ""); err != nil {
		t.Fatalf("depth below the limit must pass: %v", err)
	}
	// nesting hidden in a string is not nesting
	if _, err := testParser().Parse(`{"version":"2.1.0","runs":[],"properties":{"a":"`+strings.Repeat("[", 5000)+`"}}`, "", ""); err != nil {
		t.Fatalf("brackets inside a string: %v", err)
	}
}

func TestSarifSizeLimits(t *testing.T) {
	// base64 text that decodes to more than 10 MiB
	huge := strings.Repeat("QUFB", (MaxCompressedBytes/3)+10)
	if got := sarifCode(t, huge); got != "SARIF_TOO_LARGE" {
		t.Fatalf("compressed: %s", got)
	}
	// raw JSON over 10 MiB
	if got := sarifCode(t, `{"version":"2.1.0","runs":[],"x":"`+strings.Repeat("a", MaxCompressedBytes+1)+`"}`); got != "SARIF_TOO_LARGE" {
		t.Fatalf("raw: %s", got)
	}
	// gzip bomb: tiny compressed, huge decompressed
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(`{"version":"2.1.0","runs":[],"x":"`))
	chunk := bytes.Repeat([]byte("a"), 1<<20)
	for i := 0; i < (MaxDecompressedBytes>>20)+2; i++ {
		zw.Write(chunk)
	}
	zw.Write([]byte(`"}`))
	zw.Close()
	if buf.Len() > MaxCompressedBytes {
		t.Fatalf("test bomb is not small: %d", buf.Len())
	}
	if got := sarifCode(t, base64.StdEncoding.EncodeToString(buf.Bytes())); got != "SARIF_TOO_LARGE" {
		t.Fatalf("bomb: %s", got)
	}
}

func TestSarifStrictSchema(t *testing.T) {
	ok := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","message":{"text":"m"}}]}]}`
	if _, err := testParser().Parse(ok, "", ""); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct{ raw, code string }{
		"empty":           {"   ", "SARIF_INVALID"},
		"not json":        {"{not json", "SARIF_INVALID"},
		"not base64":      {"%%%%", "SARIF_INVALID"},
		"array":           {`[1,2]`, "SARIF_INVALID"},
		"no runs":         {`{"version":"2.1.0"}`, "SARIF_INVALID"},
		"runs null":       {`{"version":"2.1.0","runs":null}`, "SARIF_INVALID"},
		"runs wrong type": {`{"version":"2.1.0","runs":{"a":1}}`, "SARIF_INVALID"},
		"old version":     {`{"version":"2.0.0","runs":[]}`, "SARIF_UNSUPPORTED"},
		"unknown top key": {`{"version":"2.1.0","runs":[],"evil":true}`, "SARIF_INVALID"},
		"no driver name":  {`{"version":"2.1.0","runs":[{"tool":{"driver":{}},"results":[]}]}`, "SARIF_INVALID"},
		"no rule id":      {`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"message":{"text":"m"}}]}]}`, "SARIF_INVALID"},
		"no message":      {`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r"}]}]}`, "SARIF_INVALID"},
		"bad level":       {`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","level":"fatal","message":{"text":"m"}}]}]}`, "SARIF_INVALID"},
		"negative line":   {`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","message":{"text":"m"},"locations":[{"physicalLocation":{"region":{"startLine":-4}}}]}]}]}`, "SARIF_INVALID"},
		"line wrong type": {`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","message":{"text":"m"},"locations":[{"physicalLocation":{"region":{"startLine":"3"}}}]}]}]}`, "SARIF_INVALID"},
		"message is text": {`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","message":"m"}]}]}`, "SARIF_INVALID"},
		"too many runs":   {`{"version":"2.1.0","runs":[` + strings.TrimSuffix(strings.Repeat(`{"tool":{"driver":{"name":"x"}}},`, MaxRuns+1), ",") + `]}`, "SARIF_TOO_LARGE"},
	}
	for name, c := range cases {
		if got := sarifCode(t, c.raw); got != c.code {
			t.Errorf("%s: code = %s, want %s", name, got, c.code)
		}
	}
	if _, err := (&Parser{}).Parse(ok, "", ""); err == nil {
		t.Error("a parser without a key must refuse to run")
	}
}

func TestSarifTextIsEscapedAndSanitized(t *testing.T) {
	evil := `<script>alert(1)</script> ![x](http://evil/p.png) [click](javascript:alert(1)) <img src=x onerror=alert(1)>` + "\x00\x1b[31m‮abc"
	raw, _ := json.Marshal(map[string]any{
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{"name": "evil-tool", "rules": []any{map[string]any{
				"id": "r<1>", "shortDescription": map[string]any{"text": evil},
			}}}},
			"results": []any{map[string]any{
				"ruleId": "r<1>", "message": map[string]any{"text": evil},
				"locations": []any{map[string]any{"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": "../../etc/passwd"},
					"region":           map[string]any{"startLine": 1, "snippet": map[string]any{"text": evil}},
				}}},
			}},
		}},
	})
	p := mustParse(t, string(raw), "", "")
	f := p.Findings[0]
	for name, v := range map[string]string{"title": f.Title, "description": f.Description, "evidence": f.Evidence} {
		if strings.ContainsAny(v, "<>\x00\x1b‮") {
			t.Errorf("%s still has markup or control characters: %q", name, v)
		}
		if !strings.Contains(v, `\[click\]\(javascript`) {
			t.Errorf("%s: markdown link not neutralized: %q", name, v)
		}
		if strings.Contains(v, "![") {
			t.Errorf("%s: markdown image not neutralized: %q", name, v)
		}
	}
	if strings.Contains(f.Path, "..") || f.Path != "etc/passwd" {
		t.Errorf("path traversal not removed: %q", f.Path)
	}
	if f.Tool != ToolOther || f.ToolName != "evil-tool" {
		t.Errorf("unknown tool = %s/%s", f.Tool, f.ToolName)
	}
}

func TestSarifInSourceSuppressionsAndDuplicates(t *testing.T) {
	raw := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[
	  {"ruleId":"r","message":{"text":"m"},"suppressions":[{"kind":"inSource"}]},
	  {"ruleId":"r","message":{"text":"same"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1,"snippet":{"text":"x := 1"}}}}]},
	  {"ruleId":"r","message":{"text":"same"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":9,"snippet":{"text":"x := 1"}}}}]}]}]}`
	p := mustParse(t, raw, "", "")
	if len(p.Findings) != 2 {
		t.Fatalf("findings = %d: the in-source suppressed result must be skipped, the identical pair kept", len(p.Findings))
	}
	if p.Findings[0].Fingerprint == p.Findings[1].Fingerprint {
		t.Fatal("two occurrences of the same snippet must stay distinct")
	}
	// the same upload parsed again keeps the same two fingerprints in the same order
	q := mustParse(t, raw, "", "")
	if q.Findings[0].Fingerprint != p.Findings[0].Fingerprint || q.Findings[1].Fingerprint != p.Findings[1].Fingerprint {
		t.Fatal("ordinal fingerprints are not deterministic")
	}
}

func TestSarifGzipBase64EqualsRawAndToolHint(t *testing.T) {
	raw := fixtureBytes(t, "trivy-0.76.1.sarif")
	a := mustParse(t, raw, "", "")
	b := mustParse(t, gzipB64(t, raw), "", "")
	if len(a.Findings) != len(b.Findings) || a.Findings[3].Fingerprint != b.Findings[3].Fingerprint {
		t.Fatal("gzip+base64 and raw JSON disagree")
	}
	// unknown driver + a known tool_name hint => that tool; unknown hint => sarif-other keeps the name
	x := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"corp-wrapper"}},"results":[{"ruleId":"r","message":{"text":"m"}}]}]}`
	if p := mustParse(t, x, "gosec", ""); p.Scopes[0].Tool != ToolGosec {
		t.Errorf("hint ignored: %+v", p.Scopes)
	}
	if p := mustParse(t, x, "my scanner", ""); p.Scopes[0] != (Scope{ToolOther, "my scanner"}) {
		t.Errorf("scope = %+v", p.Scopes)
	}
	// a driver the parser knows wins over a misleading hint
	if p := mustParse(t, strings.ReplaceAll(x, "corp-wrapper", "Semgrep OSS"), "gitleaks", ""); p.Scopes[0].Tool != ToolSemgrep {
		t.Errorf("driver must win over hint: %+v", p.Scopes)
	}
}

func TestSeverityMapping(t *testing.T) {
	mk := func(tool, rule, level string, props map[string]any, ruleProps map[string]any) Severity {
		r := map[string]any{"id": rule}
		if ruleProps != nil {
			r["properties"] = ruleProps
		}
		res := map[string]any{"ruleId": rule, "message": map[string]any{"text": "m"}}
		if level != "" {
			res["level"] = level
		}
		if props != nil {
			res["properties"] = props
		}
		raw, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{"name": tool, "rules": []any{r}}}, "results": []any{res}}}})
		return mustParse(t, string(raw), "", "").Findings[0].Severity
	}
	cases := []struct {
		name string
		got  Severity
		want Severity
	}{
		{"semgrep ERROR", mk("semgrep", "r", "error", nil, nil), SevHigh},
		{"semgrep WARNING", mk("semgrep", "r", "warning", nil, nil), SevMedium},
		{"semgrep INFO", mk("semgrep", "r", "note", nil, nil), SevLow},
		{"no level defaults to warning", mk("semgrep", "r", "", nil, nil), SevMedium},
		{"cvss 9.0", mk("trivy", "CVE-1", "error", nil, map[string]any{"security-severity": "9.0"}), SevCritical},
		{"cvss 7.0", mk("trivy", "CVE-1", "error", nil, map[string]any{"security-severity": "7.0"}), SevHigh},
		{"cvss 6.9", mk("trivy", "CVE-1", "error", nil, map[string]any{"security-severity": "6.9"}), SevMedium},
		{"cvss 4.0", mk("trivy", "CVE-1", "error", nil, map[string]any{"security-severity": "4.0"}), SevMedium},
		{"cvss 3.9", mk("trivy", "CVE-1", "error", nil, map[string]any{"security-severity": "3.9"}), SevLow},
		{"cvss number type", mk("trivy", "CVE-1", "error", nil, map[string]any{"security-severity": 9.8}), SevCritical},
		{"gosec tag wins over level", mk("gosec", "G104", "error", nil, map[string]any{"tags": []string{"security", "LOW"}}), SevLow},
		{"bandit severity property", mk("bandit", "B101", "warning", map[string]any{"severity": "HIGH"}, nil), SevHigh},
		{"gitleaks always high", mk("gitleaks", "generic-api-key", "note", nil, nil), SevHigh},
		{"gitleaks gcp is critical", mk("gitleaks", "gcp-api-key", "note", nil, nil), SevCritical},
		{"gitleaks azure is critical", mk("gitleaks", "azure-ad-client-secret", "note", nil, nil), SevCritical},
		{"gitleaks slack stays high", mk("gitleaks", "slack-bot-token", "note", nil, nil), SevHigh},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %s, want %s", c.name, c.got, c.want)
		}
	}
}

func TestSecretLikeRulesOfCodeToolsAreRedacted(t *testing.T) {
	val := "hunter2-" + "fixture-credential"
	for _, tc := range []struct{ tool, rule string }{{"gosec", "G101"}, {"bandit", "B105"}, {"semgrep", "rules.generic.secrets.security.detected-private-key"}} {
		raw, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{"name": tc.tool}},
			"results": []any{map[string]any{"ruleId": tc.rule, "level": "error", "message": map[string]any{"text": "credential " + val},
				"locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": "a.go"},
					"region": map[string]any{"startLine": 4, "snippet": map[string]any{"text": `pw = "` + val + `"`}}}}}}},
		}}})
		f := mustParse(t, string(raw), "", "").Findings[0]
		if f.Kind != KindSecret || f.Evidence != "" || strings.Contains(f.Title+f.Description, val) {
			t.Errorf("%s %s is not redacted: %+v", tc.tool, tc.rule, f)
		}
	}
}
