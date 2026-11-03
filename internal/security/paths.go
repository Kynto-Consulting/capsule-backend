package security

import "strings"

// pathMapper turns the artifact URIs of one SARIF run into repo-relative paths. Tools such as
// gosec and osv-scanner report absolute paths of the CI workspace; those differ between runners
// and would break fingerprints, so they are cut at the repository directory (the project slug) or,
// failing that, at the longest directory prefix the run's absolute paths share.
type pathMapper struct {
	repo   string
	prefix []string // directory segments shared by every absolute path of the run
}

// absSegments splits a URI/path into segments and reports whether it was absolute (leading "/",
// a drive letter, or a file:// URI).
func absSegments(uri string) (segs []string, abs bool) {
	p := plain(uri, 1024)
	if strings.HasPrefix(p, "file://") {
		p, abs = strings.TrimPrefix(p, "file://"), true
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if len(p) >= 2 && p[1] == ':' && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) {
		abs = true
	}
	if strings.HasPrefix(p, "/") {
		abs = true
	}
	for _, s := range strings.Split(p, "/") {
		if s != "" && s != "." {
			segs = append(segs, s)
		}
	}
	return segs, abs
}

func newPathMapper(repo string, results []sResult) *pathMapper {
	m := &pathMapper{repo: repo}
	var common []string
	first := true
	for i := range results {
		if len(results[i].Locations) == 0 {
			continue
		}
		segs, abs := absSegments(results[i].Locations[0].PhysicalLocation.ArtifactLocation.URI)
		if !abs || len(segs) == 0 {
			continue
		}
		dir := segs[:len(segs)-1]
		if first {
			common, first = append([]string(nil), dir...), false
			continue
		}
		n := 0
		for n < len(common) && n < len(dir) && common[n] == dir[n] {
			n++
		}
		common = common[:n]
	}
	m.prefix = common
	return m
}

func (m *pathMapper) rel(uri string) string {
	segs, abs := absSegments(uri)
	if !abs {
		return cleanPath(strings.Join(segs, "/"))
	}
	if m.repo != "" && len(segs) > 1 {
		for i, s := range segs[:len(segs)-1] {
			if s == m.repo {
				return cleanPath(strings.Join(segs[i+1:], "/"))
			}
		}
	}
	if n := len(m.prefix); n > 0 && n < len(segs) {
		same := true
		for i := 0; i < n; i++ {
			if segs[i] != m.prefix[i] {
				same = false
				break
			}
		}
		if same {
			return cleanPath(strings.Join(segs[n:], "/"))
		}
	}
	return cleanPath(strings.Join(segs, "/"))
}
