package security

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Limits applied to every SARIF upload (T10 of SPEC 6.1).
const (
	MaxCompressedBytes   = 10 << 20 // gzip+base64 payload decoded size, or raw JSON size
	MaxDecompressedBytes = 48 << 20 // gzip bomb guard
	MaxDepth             = 64       // JSON nesting
	MaxResults           = 10000    // results per upload, all runs together
	MaxRuns              = 20
	maxTraceSteps        = 25
	maxEvidenceRunes     = 2000
	maxDescriptionRunes  = 4000
)

// Parser turns SARIF 2.1.0 into Findings. Key is the HMAC key of secret fingerprints (a secret's
// value is never stored, but a plain hash of a low-entropy value could be guessed offline).
type Parser struct{ Key []byte }

// Parsed is the sanitized content of a SARIF log.
type Parsed struct {
	Scopes       []Scope
	Findings     []Finding
	ResultsTotal int
}

// ---- wire types (only what Capsule reads; everything else is ignored) -----------------------

type sMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type sSnippet struct {
	Text string `json:"text"`
}

type sRegion struct {
	StartLine   int      `json:"startLine"`
	EndLine     int      `json:"endLine"`
	StartColumn int      `json:"startColumn"`
	EndColumn   int      `json:"endColumn"`
	Snippet     sSnippet `json:"snippet"`
}

type sArtifactLocation struct {
	URI string `json:"uri"`
}

type sPhysical struct {
	ArtifactLocation sArtifactLocation `json:"artifactLocation"`
	Region           sRegion           `json:"region"`
	ContextRegion    sRegion           `json:"contextRegion"`
}

type sLocation struct {
	PhysicalLocation sPhysical `json:"physicalLocation"`
	Message          sMessage  `json:"message"`
}

type sThreadFlowLoc struct {
	Location sLocation `json:"location"`
}

type sThreadFlow struct {
	Locations []sThreadFlowLoc `json:"locations"`
}

type sCodeFlow struct {
	ThreadFlows []sThreadFlow `json:"threadFlows"`
}

type sSuppression struct {
	Kind string `json:"kind"`
}

type sRuleRef struct {
	ID    string `json:"id"`
	Index *int   `json:"index"`
}

type sResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           *int              `json:"ruleIndex"`
	Rule                sRuleRef          `json:"rule"`
	Level               string            `json:"level"`
	Message             sMessage          `json:"message"`
	Locations           []sLocation       `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Fingerprints        map[string]string `json:"fingerprints"`
	CodeFlows           []sCodeFlow       `json:"codeFlows"`
	Suppressions        []sSuppression    `json:"suppressions"`
	Properties          map[string]any    `json:"properties"`
}

type sRuleProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity any      `json:"security-severity"`
	Severity         any      `json:"severity"`
}

type sRule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	ShortDescription sMessage   `json:"shortDescription"`
	FullDescription  sMessage   `json:"fullDescription"`
	Help             sMessage   `json:"help"`
	HelpURI          string     `json:"helpUri"`
	Properties       sRuleProps `json:"properties"`
	DefaultConfig    struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
}

type sDriver struct {
	Name  string  `json:"name"`
	Rules []sRule `json:"rules"`
}

type sRun struct {
	Tool struct {
		Driver sDriver `json:"driver"`
	} `json:"tool"`
	Results []sResult `json:"results"`
}

type sLog struct {
	Version string `json:"version"`
	Runs    []sRun `json:"runs"`
}

var allowedTopLevel = map[string]bool{"$schema": true, "version": true, "runs": true, "inlineExternalProperties": true, "properties": true}

// Parse decodes (gzip+base64 or raw JSON), validates and normalizes a SARIF upload. toolHint is
// the optional tool_name of the request. Errors are *SarifError.
func (p *Parser) Parse(raw, toolHint, repoHint string) (*Parsed, error) {
	if len(p.Key) == 0 {
		return nil, fmt.Errorf("security: parser has no fingerprint key")
	}
	data, err := decodeBytes(raw)
	if err != nil {
		return nil, err
	}
	if d := jsonDepth(data); d > MaxDepth {
		return nil, sarifErr("SARIF_TOO_DEEP", "el JSON anida %d niveles (maximo %d)", d, MaxDepth)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, sarifErr("SARIF_INVALID", "no es JSON valido: %s", jsonErrText(err))
	}
	if _, hasRuns := top["runs"]; !hasRuns {
		if _, hasResults := top["results"]; hasResults {
			return p.parseOSVJSON(data, repoHint)
		}
	}
	for k := range top {
		if !allowedTopLevel[k] {
			return nil, sarifErr("SARIF_INVALID", "campo %q no existe en un SARIF 2.1.0", sanitize(k, 40))
		}
	}
	if _, ok := top["runs"]; !ok {
		return nil, sarifErr("SARIF_INVALID", "falta el campo runs")
	}
	var log sLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, sarifErr("SARIF_INVALID", "estructura invalida: %s", jsonErrText(err))
	}
	if log.Version != "2.1.0" {
		return nil, sarifErr("SARIF_UNSUPPORTED", "version %q no soportada: se requiere 2.1.0", sanitize(log.Version, 20))
	}
	if log.Runs == nil {
		return nil, sarifErr("SARIF_INVALID", "runs debe ser un arreglo")
	}
	if len(log.Runs) > MaxRuns {
		return nil, sarifErr("SARIF_TOO_LARGE", "%d runs (maximo %d)", len(log.Runs), MaxRuns)
	}
	total := 0
	for _, r := range log.Runs {
		total += len(r.Results)
	}
	if total > MaxResults {
		return nil, sarifErr("SARIF_TOO_MANY_RESULTS", "%d resultados (maximo %d por subida): divide el analisis", total, MaxResults)
	}

	out := &Parsed{ResultsTotal: total}
	seenScope := map[Scope]bool{}
	occurrences := map[string]int{}
	for ri, run := range log.Runs {
		name := strings.TrimSpace(run.Tool.Driver.Name)
		if name == "" {
			return nil, sarifErr("SARIF_INVALID", "runs[%d].tool.driver.name es obligatorio", ri)
		}
		tool, toolName := detectTool(name, toolHint)
		sc := Scope{Tool: tool, ToolName: toolName}
		paths := newPathMapper(repoHint, run.Results)
		if !seenScope[sc] {
			seenScope[sc] = true
			out.Scopes = append(out.Scopes, sc)
		}
		for i := range run.Results {
			res := &run.Results[i]
			if err := validateResult(res, ri, i); err != nil {
				return nil, err
			}
			if len(res.Suppressions) > 0 {
				continue // suppressed in source by the tool itself (e.g. nosemgrep): not an alert
			}
			rule := lookupRule(run.Tool.Driver.Rules, res)
			f := p.normalize(tool, toolName, res, rule, paths)
			// identical findings (same fingerprint inside one upload) stay distinct: ordinal suffix
			key := toolName + "\x00" + f.Fingerprint
			n := occurrences[key]
			occurrences[key] = n + 1
			if n > 0 {
				f.Fingerprint = hashHex("dup", f.Fingerprint, strconv.Itoa(n))
			}
			out.Findings = append(out.Findings, f)
		}
	}
	return out, nil
}

func validateResult(r *sResult, run, idx int) error {
	if r.ruleID() == "" && r.RuleIndex == nil {
		return sarifErr("SARIF_INVALID", "runs[%d].results[%d] no tiene ruleId", run, idx)
	}
	if strings.TrimSpace(r.Message.Text) == "" && strings.TrimSpace(r.Message.Markdown) == "" {
		return sarifErr("SARIF_INVALID", "runs[%d].results[%d].message es obligatorio", run, idx)
	}
	switch r.Level {
	case "", "none", "note", "warning", "error":
	default:
		return sarifErr("SARIF_INVALID", "runs[%d].results[%d].level %q no es valido", run, idx, sanitize(r.Level, 20))
	}
	for li, l := range r.Locations {
		rg := l.PhysicalLocation.Region
		if rg.StartLine < 0 || rg.EndLine < 0 || rg.StartColumn < 0 || rg.EndColumn < 0 {
			return sarifErr("SARIF_INVALID", "runs[%d].results[%d].locations[%d]: region con valores negativos", run, idx, li)
		}
	}
	return nil
}

func (r *sResult) ruleID() string {
	if r.RuleID != "" {
		return r.RuleID
	}
	return r.Rule.ID
}

func lookupRule(rules []sRule, r *sResult) *sRule {
	idx := -1
	switch {
	case r.RuleIndex != nil:
		idx = *r.RuleIndex
	case r.Rule.Index != nil:
		idx = *r.Rule.Index
	}
	if idx >= 0 && idx < len(rules) && (r.ruleID() == "" || rules[idx].ID == r.ruleID()) {
		return &rules[idx]
	}
	if id := r.ruleID(); id != "" {
		for i := range rules {
			if rules[i].ID == id {
				return &rules[i]
			}
		}
	}
	return nil
}

// ---- decoding helpers -----------------------------------------------------------------------

func decodeBytes(raw string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, sarifErr("SARIF_INVALID", "el campo sarif esta vacio")
	}
	var data []byte
	if s[0] == '{' {
		if len(s) > MaxCompressedBytes {
			return nil, sarifErr("SARIF_TOO_LARGE", "el SARIF supera %d MiB", MaxCompressedBytes>>20)
		}
		data = []byte(s)
	} else {
		clean := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, s)
		if len(clean)/4*3 > MaxCompressedBytes+3 {
			return nil, sarifErr("SARIF_TOO_LARGE", "el SARIF comprimido supera %d MiB", MaxCompressedBytes>>20)
		}
		var err error
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if data, err = enc.DecodeString(clean); err == nil {
				break
			}
		}
		if err != nil {
			return nil, sarifErr("SARIF_INVALID", "el campo sarif no es base64 ni JSON")
		}
		if len(data) > MaxCompressedBytes {
			return nil, sarifErr("SARIF_TOO_LARGE", "el SARIF comprimido supera %d MiB", MaxCompressedBytes>>20)
		}
	}
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, sarifErr("SARIF_INVALID", "gzip invalido")
		}
		defer zr.Close()
		lr := io.LimitReader(zr, MaxDecompressedBytes+1)
		out, err := io.ReadAll(lr)
		if err != nil {
			return nil, sarifErr("SARIF_INVALID", "gzip corrupto")
		}
		if len(out) > MaxDecompressedBytes {
			return nil, sarifErr("SARIF_TOO_LARGE", "el SARIF descomprimido supera %d MiB", MaxDecompressedBytes>>20)
		}
		data = out
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return nil, sarifErr("SARIF_INVALID", "el contenido no es un objeto JSON")
	}
	return data, nil
}

// jsonDepth returns the maximum nesting of arrays/objects without decoding anything (strings are
// skipped), so a document nested a million levels deep is refused before any recursive decoder
// sees it.
func jsonDepth(b []byte) int {
	depth, max := 0, 0
	inStr, esc := false, false
	for _, c := range b {
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			depth++
			if depth > max {
				max = depth
			}
		case '}', ']':
			depth--
		}
	}
	return max
}

func jsonErrText(err error) string {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se):
		return "error de sintaxis"
	case errors.As(err, &te):
		return "el campo " + sanitize(te.Field, 80) + " tiene un tipo incorrecto"
	}
	return "contenido ilegible"
}

// ---- tool detection --------------------------------------------------------------------------

func detectTool(driverName, hint string) (tool, toolName string) {
	n := strings.ToLower(driverName)
	switch {
	case strings.Contains(n, "semgrep"):
		return ToolSemgrep, ToolSemgrep
	case strings.Contains(n, "gosec"):
		return ToolGosec, ToolGosec
	case strings.Contains(n, "bandit"):
		return ToolBandit, ToolBandit
	case strings.Contains(n, "gitleaks"):
		return ToolGitleaks, ToolGitleaks
	case strings.Contains(n, "trivy"):
		return ToolTrivy, ToolTrivy
	case strings.Contains(n, "osv"):
		return ToolOSV, ToolOSV
	case strings.Contains(n, "eslint"):
		return ToolESLint, ToolESLint
	case strings.Contains(n, "renovate"):
		return ToolRenovate, ToolRenovate
	}
	h := strings.ToLower(strings.TrimSpace(hint))
	if validTool(h) && h != ToolOther {
		return h, h
	}
	name := plain(hint, 64)
	if name == "" {
		name = plain(driverName, 64)
	}
	if name == "" {
		name = "unknown"
	}
	return ToolOther, name
}

// ---- normalization ---------------------------------------------------------------------------

var (
	reDepPackage   = regexp.MustCompile(`(?m)^\s*Package:\s*(.+?)\s*$`)
	reDepInstalled = regexp.MustCompile(`(?m)^\s*Installed Version:\s*(.+?)\s*$`)
	reDepFixed     = regexp.MustCompile(`(?m)^\s*Fixed Version:\s*(.+?)\s*$`)
	reOSVPackage   = regexp.MustCompile(`[Pp]ackage '([^']+)'`)
	reHelpSeverity = regexp.MustCompile(`(?mi)^\s*Severity:\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*$`)
	reVulnID       = regexp.MustCompile(`\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|OSV-\d{4}-\d+|GO-\d{4}-\d+|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+)\b`)
)

func (p *Parser) normalize(tool, toolName string, res *sResult, rule *sRule, paths *pathMapper) Finding {
	ruleID := plain(res.ruleID(), 255)
	if ruleID == "" && rule != nil {
		ruleID = plain(rule.ID, 255)
	}
	var tags []string
	if rule != nil {
		tags = rule.Properties.Tags
	}
	kind := classify(tool, ruleID, tags)

	f := Finding{Kind: kind, Tool: tool, ToolName: toolName, RuleID: ruleID}
	if len(res.Locations) > 0 {
		pl := res.Locations[0].PhysicalLocation
		f.Path = paths.rel(pl.ArtifactLocation.URI)
		f.StartLine, f.EndLine = pl.Region.StartLine, pl.Region.EndLine
		if f.EndLine < f.StartLine {
			f.EndLine = f.StartLine
		}
	}
	f.Severity = severityOf(tool, kind, res, rule, ruleID)
	msg := res.Message.Text
	if strings.TrimSpace(msg) == "" {
		msg = res.Message.Markdown
	}

	if kind == KindSecret {
		// The message, the snippet and the fingerprints of the tool can all carry the secret:
		// none of them is read into the Finding. Only the rule, path and line survive.
		f.Title = clean("Secreto detectado: "+ruleID, 300)
		f.Description = clean(fmt.Sprintf("La regla %s detecto un posible secreto en %s linea %d. El valor no se almacena: rotalo y quitalo del historial.", ruleID, orDash(f.Path), f.StartLine), maxDescriptionRunes)
		f.Fingerprint = p.secretFingerprint(toolName, ruleID, f.Path, res)
		return f
	}

	// title
	title := ""
	if rule != nil {
		title = firstNonEmpty(rule.ShortDescription.Text, rule.Name, rule.FullDescription.Text)
	}
	if title == "" {
		title = firstLine(msg)
	}
	f.Title = clean(title, 300)
	f.Description = clean(msg, maxDescriptionRunes)
	if len(res.Locations) > 0 {
		pl := res.Locations[0].PhysicalLocation
		ev := firstNonEmpty(pl.ContextRegion.Snippet.Text, pl.Region.Snippet.Text)
		f.Evidence = clean(ev, maxEvidenceRunes)
	}
	f.Trace = trace(res, paths)

	if kind == KindDependency {
		fillDependency(&f, msg, rule, ruleID)
		f.Fingerprint = hashHex("dep", toolName, f.RuleID, f.Package, f.Version, f.Path)
		return f
	}
	f.Fingerprint = codeFingerprint(toolName, ruleID, f.Path, res, msg)
	return f
}

func orDash(s string) string {
	if s == "" {
		return "(sin ruta)"
	}
	return s
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func fillDependency(f *Finding, msg string, rule *sRule, ruleID string) {
	if m := reDepPackage.FindStringSubmatch(msg); m != nil {
		f.Package = plain(m[1], 255)
	}
	if m := reDepInstalled.FindStringSubmatch(msg); m != nil {
		f.Version = plain(m[1], 128)
	}
	if m := reDepFixed.FindStringSubmatch(msg); m != nil {
		f.FixedVersion = plain(m[1], 128)
	}
	if f.Package == "" {
		if m := reOSVPackage.FindStringSubmatch(msg); m != nil {
			pkg := m[1]
			if i := strings.LastIndexByte(pkg, '@'); i > 0 {
				f.Package, f.Version = plain(pkg[:i], 255), plain(pkg[i+1:], 128)
			} else {
				f.Package = plain(pkg, 255)
			}
		}
	}
	adv := reVulnID.FindString(ruleID)
	if adv == "" {
		adv = reVulnID.FindString(msg)
	}
	if adv == "" && rule != nil {
		adv = reVulnID.FindString(rule.Name + " " + rule.ShortDescription.Text)
	}
	if adv == "" {
		adv = ruleID
	}
	f.Advisory = plain(adv, 255)
}

func trace(res *sResult, paths *pathMapper) []TraceStep {
	if len(res.CodeFlows) == 0 || len(res.CodeFlows[0].ThreadFlows) == 0 {
		return nil
	}
	var out []TraceStep
	for _, l := range res.CodeFlows[0].ThreadFlows[0].Locations {
		if len(out) >= maxTraceSteps {
			break
		}
		pl := l.Location.PhysicalLocation
		out = append(out, TraceStep{
			Path:    paths.rel(pl.ArtifactLocation.URI),
			Line:    pl.Region.StartLine,
			Message: clean(l.Location.Message.Text, 300),
		})
	}
	return out
}

// ---- classification --------------------------------------------------------------------------

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(strings.TrimSpace(t), want) {
			return true
		}
	}
	return false
}

// classify decides the kind. Rules that detect hard-coded credentials count as secrets even when
// the tool is a code scanner, because their snippet IS the credential and secrets are redacted.
func classify(tool, ruleID string, tags []string) Kind {
	id := strings.ToLower(ruleID)
	switch tool {
	case ToolGitleaks:
		return KindSecret
	case ToolOSV, ToolRenovate:
		return KindDependency
	case ToolGosec:
		if id == "g101" { // hardcoded credentials
			return KindSecret
		}
	case ToolBandit:
		if id == "b105" || id == "b106" || id == "b107" { // hardcoded password string / funcarg / default
			return KindSecret
		}
	case ToolTrivy:
		switch {
		case hasTag(tags, "secret"):
			return KindSecret
		case hasTag(tags, "vulnerability") || reVulnID.MatchString(ruleID) || strings.HasPrefix(strings.ToUpper(ruleID), "DLA-") || strings.HasPrefix(strings.ToUpper(ruleID), "RHSA-"):
			return KindDependency
		}
		return KindCode // misconfiguration / IaC
	}
	if hasTag(tags, "secret") || hasTag(tags, "secrets") || strings.Contains(id, ".secrets.") || strings.Contains(id, "hardcoded-secret") || strings.Contains(id, "hardcoded-credential") || strings.Contains(id, "hardcoded-password") {
		return KindSecret
	}
	return KindCode
}

var cloudTokens = map[string]bool{
	"aws": true, "gcp": true, "azure": true, "alibaba": true, "digitalocean": true,
	"ibm": true, "oracle": true, "linode": true, "scaleway": true, "hetzner": true,
}

func isCloudRule(ruleID string) bool {
	for _, tok := range strings.FieldsFunc(strings.ToLower(ruleID), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	}) {
		if cloudTokens[tok] {
			return true
		}
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	}
	return 0, false
}

func cvssBand(score float64) Severity {
	switch {
	case score >= 9:
		return SevCritical
	case score >= 7:
		return SevHigh
	case score >= 4:
		return SevMedium
	case score > 0:
		return SevLow
	}
	return SevInfo
}

func wordSeverity(s string) (Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SevCritical, true
	case "HIGH", "ERROR":
		return SevHigh, true
	case "MEDIUM", "MODERATE", "WARNING":
		return SevMedium, true
	case "LOW", "NOTE":
		return SevLow, true
	case "INFO", "INFORMATIONAL", "UNKNOWN":
		return SevInfo, true
	}
	return "", false
}

// severityOf implements the SPEC 5.8 mapping: gitleaks is always high (critical for cloud
// providers); a CVSS "security-severity" maps 9/7/4; trivy tags and gosec/Bandit "severity"
// properties map by word; otherwise the SARIF level (error=high, warning=medium, note=low).
func severityOf(tool string, kind Kind, res *sResult, rule *sRule, ruleID string) Severity {
	if tool == ToolGitleaks {
		if isCloudRule(ruleID) {
			return SevCritical
		}
		return SevHigh
	}
	if kind == KindSecret {
		if isCloudRule(ruleID) {
			return SevCritical
		}
		return SevHigh
	}
	if rule != nil {
		if f, ok := toFloat(rule.Properties.SecuritySeverity); ok {
			return cvssBand(f)
		}
	}
	if f, ok := toFloat(res.Properties["security-severity"]); ok {
		return cvssBand(f)
	}
	if s, ok := res.Properties["severity"].(string); ok {
		if v, ok := wordSeverity(s); ok {
			return v
		}
	}
	if rule != nil {
		if s, ok := rule.Properties.Severity.(string); ok {
			if v, ok := wordSeverity(s); ok {
				return v
			}
		}
		// trivy puts the severity in the tags; gosec in the tags and in the help text
		// ("Severity: MEDIUM") and sets level=error on every result; Bandit as gosec.
		if tool == ToolTrivy || tool == ToolGosec || tool == ToolBandit {
			for _, w := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
				if hasTag(rule.Properties.Tags, w) {
					v, _ := wordSeverity(w)
					return v
				}
			}
			if m := reHelpSeverity.FindStringSubmatch(rule.Help.Text); m != nil {
				if v, ok := wordSeverity(m[1]); ok {
					return v
				}
			}
		}
	}
	level := res.Level
	if level == "" && rule != nil {
		level = rule.DefaultConfig.Level
	}
	switch level {
	case "error":
		return SevHigh
	case "note":
		return SevLow
	case "none":
		return SevInfo
	}
	return SevMedium // "warning" and the SARIF default
}

// ---- fingerprints ----------------------------------------------------------------------------

func hashHex(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// codeFingerprint prefers the tool's own partialFingerprints (stable across line shifts by
// design), then rule + path + the hash of the code context, then rule + path + message.
func codeFingerprint(toolName, ruleID, path string, res *sResult, msg string) string {
	if len(res.PartialFingerprints) > 0 {
		keys := make([]string, 0, len(res.PartialFingerprints))
		for k := range res.PartialFingerprints {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := []string{"pf", toolName, ruleID}
		for _, k := range keys {
			parts = append(parts, k+"="+res.PartialFingerprints[k])
		}
		return hashHex(parts...)
	}
	ctx := ""
	if len(res.Locations) > 0 {
		pl := res.Locations[0].PhysicalLocation
		ctx = normalizeSpace(firstNonEmpty(pl.ContextRegion.Snippet.Text, pl.Region.Snippet.Text))
	}
	if ctx == "" {
		ctx = "msg:" + normalizeSpace(msg)
	}
	return hashHex("ctx", toolName, ruleID, path, hashHex(ctx))
}

// secretFingerprint is an HMAC so that the (hash of the) value cannot be brute-forced from the
// database: rule + path + snippet + commit (when the tool reports it).
func (p *Parser) secretFingerprint(toolName, ruleID, path string, res *sResult) string {
	snippet := ""
	if len(res.Locations) > 0 {
		pl := res.Locations[0].PhysicalLocation
		snippet = normalizeSpace(firstNonEmpty(pl.Region.Snippet.Text, pl.ContextRegion.Snippet.Text))
	}
	commit := res.PartialFingerprints["commitSha"]
	line := ""
	if snippet == "" {
		// no snippet: the line is the only anchor left
		if len(res.Locations) > 0 {
			line = strconv.Itoa(res.Locations[0].PhysicalLocation.Region.StartLine)
		}
	}
	m := hmac.New(sha256.New, p.Key)
	for _, s := range []string{"secret", toolName, ruleID, path, snippet, commit, line} {
		m.Write([]byte(s))
		m.Write([]byte{0})
	}
	return hex.EncodeToString(m.Sum(nil))
}
