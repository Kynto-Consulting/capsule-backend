package gitimport

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	maxWorkflowFiles = 20
	maxWorkflowBytes = 256 << 10
)

// usesRe finds `uses: <ref>` in a workflow (single-line values only; enough to flag actions).
var usesRe = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*['"]?([^\s'"#]+)`)

// inspect reads CODEOWNERS and .github/workflows from GitHub (best effort: any failure only drops the
// note) and returns the CODEOWNERS report plus repository warnings. Nothing is written anywhere.
func (s *Service) inspect(ctx context.Context, token, owner, name, ref, orgSlug string) (*CodeOwnersReport, []string) {
	var warns []string
	var report *CodeOwnersReport
	for _, p := range GitHubCodeOwnersPaths {
		data, found, err := s.d.GitHub.File(ctx, token, owner, name, ref, p)
		if err != nil {
			warns = append(warns, "CODEOWNERS could not be read from GitHub: "+clip(err.Error(), 150))
			break
		}
		if !found {
			continue
		}
		r := ConvertCodeOwners(string(data), orgSlug)
		r.Path = p
		report = &r
		warns = append(warns, fmt.Sprintf("%s was converted to Forgejo syntax and is reported, not committed: review it and add it as CODEOWNERS at the repository root (%d note(s))", p, len(r.Warnings)))
		if p != "CODEOWNERS" && p != "docs/CODEOWNERS" {
			warns = append(warns, "Forgejo does not read "+p+": the converted file must be committed to the root or to docs/")
		} else {
			warns = append(warns, "the original "+p+" uses GitHub glob syntax, which Forgejo reads as regular expressions: replace its content with the converted one")
		}
		break
	}

	names, err := s.d.GitHub.Dir(ctx, token, owner, name, ref, ".github/workflows")
	if err != nil {
		warns = append(warns, "workflows could not be listed: "+clip(err.Error(), 150))
		return report, warns
	}
	var files []string
	for _, n := range names {
		if strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") {
			files = append(files, n)
		}
	}
	if len(files) == 0 {
		return report, warns
	}
	sort.Strings(files)
	if len(files) > maxWorkflowFiles {
		files = files[:maxWorkflowFiles]
		warns = append(warns, fmt.Sprintf("only the first %d workflows were inspected", maxWorkflowFiles))
	}
	external := map[string]bool{}
	for _, f := range files {
		data, found, err := s.d.GitHub.File(ctx, token, owner, name, ref, ".github/workflows/"+f)
		if err != nil || !found || len(data) > maxWorkflowBytes {
			continue
		}
		for _, m := range usesRe.FindAllStringSubmatch(string(data), -1) {
			if u := m[1]; !strings.HasPrefix(u, "./") {
				external[u] = true
			}
		}
	}
	warns = append(warns, fmt.Sprintf(".github/workflows (%d file(s)) was kept: the runner executes it", len(files)))
	if len(external) > 0 {
		list := make([]string, 0, len(external))
		for u := range external {
			list = append(list, u)
		}
		sort.Strings(list)
		if len(list) > 15 {
			list = append(list[:15], "...")
		}
		warns = append(warns, "workflows use external actions that the runner resolves at run time and that may not exist in its action source: "+strings.Join(list, ", "))
	}
	return report, warns
}
