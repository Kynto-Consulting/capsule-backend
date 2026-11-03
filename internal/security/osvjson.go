package security

import (
	"encoding/json"
	"strconv"
	"strings"
)

// osv-scanner's SARIF carries no severity at all (level is "warning" for every vulnerability), so
// the CVSS mapping of SPEC 5.8 (>= 9 critical, >= 7 high, >= 4 medium, < 4 low) needs its native
// JSON output (--format json), which has max_severity per vulnerability group. The upload accepts
// both; this parses the JSON form.

type osvPackage struct {
	Package struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Groups []struct {
		IDs         []string `json:"ids"`
		Aliases     []string `json:"aliases"`
		MaxSeverity string   `json:"max_severity"`
	} `json:"groups"`
	Vulnerabilities []struct {
		ID      string `json:"id"`
		Summary string `json:"summary"`
	} `json:"vulnerabilities"`
}

type osvResult struct {
	Source struct {
		Path string `json:"path"`
	} `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvDoc struct {
	Results []osvResult `json:"results"`
}

func (p *Parser) parseOSVJSON(data []byte, repoHint string) (*Parsed, error) {
	var doc osvDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, sarifErr("SARIF_INVALID", "estructura invalida: %s", jsonErrText(err))
	}
	total := 0
	for _, r := range doc.Results {
		for _, pk := range r.Packages {
			total += len(pk.Groups)
		}
	}
	if total > MaxResults {
		return nil, sarifErr("SARIF_TOO_MANY_RESULTS", "%d resultados (maximo %d por subida): divide el analisis", total, MaxResults)
	}
	out := &Parsed{ResultsTotal: total, Scopes: []Scope{{Tool: ToolOSV, ToolName: ToolOSV}}}
	fake := make([]sResult, 0, len(doc.Results))
	for _, r := range doc.Results {
		var l sLocation
		l.PhysicalLocation.ArtifactLocation.URI = r.Source.Path
		fake = append(fake, sResult{Locations: []sLocation{l}})
	}
	paths := newPathMapper(repoHint, fake)
	for _, r := range doc.Results {
		path := paths.rel(r.Source.Path)
		for _, pk := range r.Packages {
			summaries := map[string]string{}
			for _, v := range pk.Vulnerabilities {
				summaries[v.ID] = v.Summary
			}
			for _, g := range pk.Groups {
				if len(g.IDs) == 0 {
					continue
				}
				rule := plain(g.IDs[0], 255)
				adv := rule
				for _, id := range append(append([]string{}, g.IDs...), g.Aliases...) {
					if strings.HasPrefix(id, "CVE-") {
						adv = plain(id, 255)
						break
					}
				}
				sev := SevMedium
				if f, err := strconv.ParseFloat(strings.TrimSpace(g.MaxSeverity), 64); err == nil {
					sev = cvssBand(f)
				}
				title := summaries[g.IDs[0]]
				if title == "" {
					title = rule + " en " + pk.Package.Name
				}
				f := Finding{
					Kind: KindDependency, Tool: ToolOSV, ToolName: ToolOSV, RuleID: rule, Severity: sev,
					Title: clean(title, 300), Path: path, Package: plain(pk.Package.Name, 255), Version: plain(pk.Package.Version, 128),
					Advisory:    adv,
					Description: clean("El paquete "+pk.Package.Name+"@"+pk.Package.Version+" ("+pk.Package.Ecosystem+") es vulnerable a "+strings.Join(g.IDs, ", ")+".", maxDescriptionRunes),
				}
				f.Fingerprint = hashHex("dep", ToolOSV, f.RuleID, f.Package, f.Version, f.Path)
				out.Findings = append(out.Findings, f)
			}
		}
	}
	return out, nil
}
