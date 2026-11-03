package connaudit

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// ScanLimits bound the work done on untrusted source trees. Zero fields take
// the defaults.
type ScanLimits struct {
	MaxEntries   int           // directory entries visited (default 20000)
	MaxFiles     int           // files read (default 1500)
	MaxFileBytes int64         // per file (default 256 KiB)
	MaxTotal     int64         // bytes read overall (default 16 MiB)
	MaxDepth     int           // directory depth (default 12)
	MaxLine      int           // longer lines (minified code) are skipped (default 4096)
	MaxFindings  int           // default 200
	Timeout      time.Duration // default 10s
}

func (l ScanLimits) withDefaults() ScanLimits {
	if l.MaxEntries <= 0 {
		l.MaxEntries = 20000
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = 1500
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = 256 << 10
	}
	if l.MaxTotal <= 0 {
		l.MaxTotal = 16 << 20
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = 12
	}
	if l.MaxLine <= 0 {
		l.MaxLine = 4096
	}
	if l.MaxFindings <= 0 {
		l.MaxFindings = 200
	}
	if l.Timeout <= 0 {
		l.Timeout = 10 * time.Second
	}
	return l
}

// ScanStats tells what the scan did (for logs; no content).
type ScanStats struct {
	Entries, Files int
	Bytes          int64
	Truncated      bool // a limit stopped the scan
}

var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true, ".hg": true, ".svn": true, ".next": true,
	"dist": true, "build": true, "target": true, "__pycache__": true, ".venv": true, "venv": true,
	"site-packages": true, ".idea": true, ".vscode": true, ".gradle": true, ".terraform": true,
	"test": true, "tests": true, "__tests__": true, "spec": true, "e2e": true, "fixtures": true,
	"__mocks__": true, "testdata": true, "examples": true, "example": true,
}

var scanExts = map[string]bool{
	".json": true, ".yml": true, ".yaml": true, ".toml": true, ".ini": true, ".properties": true, ".cfg": true, ".conf": true,
	".ts": true, ".tsx": true, ".js": true, ".jsx": true, ".mjs": true, ".cjs": true, ".py": true, ".go": true,
	".java": true, ".kt": true, ".rb": true, ".php": true, ".prisma": true, ".cs": true, ".rs": true,
}

// fileKind: "" = skip, "env" = KEY=VALUE file, "text" = generic.
func fileKind(rel string) string {
	base := strings.ToLower(path.Base(rel))
	for _, suf := range []string{".example", ".sample", ".template", ".dist", ".tpl"} {
		if strings.HasSuffix(base, suf) {
			return ""
		}
	}
	if strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") || strings.HasSuffix(base, "_test.go") ||
		strings.HasSuffix(base, ".min.js") || strings.HasSuffix(base, ".lock") || base == "package-lock.json" {
		return ""
	}
	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") {
		return "env"
	}
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") ||
		strings.HasPrefix(base, "docker-compose") || strings.HasPrefix(base, "compose.") {
		return "text"
	}
	if scanExts[path.Ext(base)] {
		return "text"
	}
	return ""
}

// ScanDir reads a source tree already extracted in dir and reports non-routed
// endpoints. It never executes anything, never follows symlinks, never leaves
// dir and stops at the limits. The returned paths are relative to dir.
func ScanDir(ctx context.Context, dir string, c *Classifier, lim ScanLimits) ([]Finding, ScanStats) {
	lim = lim.withDefaults()
	if c == nil {
		c = &Classifier{}
	}
	ctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()
	ign := loadGitignore(dir)
	var st ScanStats
	var out []Finding
	seen := map[string]bool{}
	stop := func() bool {
		if ctx.Err() != nil || len(out) >= lim.MaxFindings || st.Files >= lim.MaxFiles || st.Bytes >= lim.MaxTotal || st.Entries >= lim.MaxEntries {
			st.Truncated = true
			return true
		}
		return false
	}
	root := filepath.Clean(dir)
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if p == root {
			return nil
		}
		st.Entries++
		if stop() {
			return filepath.SkipAll
		}
		relOS, rerr := filepath.Rel(root, p)
		if rerr != nil || relOS == ".." || strings.HasPrefix(relOS, ".."+string(filepath.Separator)) {
			return filepath.SkipDir
		}
		rel := filepath.ToSlash(relOS)
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // never followed, never read
		}
		if d.IsDir() {
			name := d.Name()
			if skipDirs[strings.ToLower(name)] || strings.Count(rel, "/")+1 > lim.MaxDepth || ign.match(rel, true) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || ign.match(rel, false) {
			return nil
		}
		kind := fileKind(rel)
		if kind == "" {
			return nil
		}
		data, ok := readSmall(p, lim.MaxFileBytes)
		if !ok {
			return nil
		}
		st.Files++
		st.Bytes += int64(len(data))
		for _, f := range scanContent(data, rel, kind, c, lim.MaxLine) {
			if !seen[f.ID] {
				seen[f.ID] = true
				out = append(out, f)
				if len(out) >= lim.MaxFindings {
					break
				}
			}
		}
		return nil
	})
	return out, st
}

// readSmall reads a regular file of at most max bytes; binaries and larger
// files are skipped. The file is opened without following a final symlink race:
// it is re-checked as regular after open.
func readSmall(p string, max int64) ([]byte, bool) {
	f, err := os.Open(p)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, false
	}
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return nil, false // binary
	}
	return data, true
}

func scanContent(data []byte, rel, kind string, c *Classifier, maxLine int) []Finding {
	text := string(data)
	lines := strings.Split(text, "\n")
	safeRel := cleanSourcePath(rel)
	var out []Finding
	if kind == "env" {
		kv := map[string]string{}
		type row struct {
			k, v string
			n    int
		}
		var rows []row
		for i, ln := range lines {
			ln = strings.TrimSpace(strings.TrimSuffix(ln, "\r"))
			if ln == "" || strings.HasPrefix(ln, "#") || len(ln) > maxLine {
				continue
			}
			ln = strings.TrimPrefix(ln, "export ")
			eq := strings.IndexByte(ln, '=')
			if eq <= 0 {
				continue
			}
			k, v := strings.TrimSpace(ln[:eq]), strings.Trim(strings.TrimSpace(ln[eq+1:]), `"'`)
			kv[k] = v
			rows = append(rows, row{k, v, i + 1})
		}
		for _, r := range rows {
			src := "file:" + safeRel + ":" + itoa(r.n)
			out = append(out, analyzeKV(r.k, r.v, func(prefix string) int { return portOf(kv, prefix) }, src, c)...)
		}
		return out
	}
	for i, ln := range lines {
		ln = strings.TrimSuffix(ln, "\r")
		if len(ln) > maxLine || len(strings.TrimSpace(ln)) == 0 {
			continue
		}
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "--") {
			continue // comments
		}
		out = append(out, analyzeLine(ln, text, "file:"+safeRel+":"+itoa(i+1), c)...)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// cleanSourcePath keeps the path printable and free of ':' so file:path:line parses.
func cleanSourcePath(rel string) string {
	var b strings.Builder
	for _, r := range rel {
		switch {
		case r < 0x20 || r == 0x7f:
			b.WriteByte('?')
		case r == ':':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ---- .gitignore (root file only, the common subset) ----

type ignRule struct {
	pat      string
	neg      bool
	dirOnly  bool
	anchored bool
}

type gitignore struct{ rules []ignRule }

func loadGitignore(dir string) *gitignore {
	g := &gitignore{}
	data, ok := readSmall(filepath.Join(dir, ".gitignore"), 64<<10)
	if !ok {
		return g
	}
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimSpace(strings.TrimSuffix(ln, "\r"))
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		r := ignRule{}
		if strings.HasPrefix(ln, "!") {
			r.neg, ln = true, ln[1:]
		}
		if strings.HasSuffix(ln, "/") {
			r.dirOnly, ln = true, strings.TrimSuffix(ln, "/")
		}
		if strings.HasPrefix(ln, "/") || strings.Contains(ln, "/") {
			r.anchored, ln = true, strings.TrimPrefix(ln, "/")
		}
		ln = strings.TrimPrefix(ln, "**/")
		if ln == "" {
			continue
		}
		r.pat = ln
		g.rules = append(g.rules, r)
	}
	return g
}

func (g *gitignore) match(rel string, isDir bool) bool {
	ignored := false
	for _, r := range g.rules {
		if r.dirOnly && !isDir {
			continue
		}
		var hit bool
		if r.anchored {
			hit, _ = path.Match(r.pat, rel)
		} else {
			hit, _ = path.Match(r.pat, path.Base(rel))
		}
		if hit {
			ignored = !r.neg
		}
	}
	return ignored
}
