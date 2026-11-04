// Package specdoc parses the permission tables of docs/permissions/SPEC.md (section 3) so tests can
// compare the code against the written specification. It is test support: nothing in the server imports it.
package specdoc

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrNotFound is returned when SPEC.md is not reachable (for instance a checkout of the backend alone,
// which is a submodule of the capsule repository).
var ErrNotFound = errors.New("docs/permissions/SPEC.md not found")

// Row is one permission row of SPEC section 3.1 or 3.2. A permission listed in both (assignment:read and
// assignment:grant) is merged into a single Row.
type Row struct {
	ID        string
	Scopes    string          // letters among O P R E (organization, project, repo, environment)
	Derives   []string        // backticked tokens of the "Deriva de" column that look like old actions
	Sensitive bool            // the notes say "sensible"
	LegacyGap bool            // the notes say legacy_gap
	Cols      map[string]bool // org template columns O A M R (3.1) and project template columns V D P (3.2)
}

// Doc is the parsed section 3.
type Doc struct {
	Rows     []Row
	Platform []string // section 3.3
}

var (
	idRe       = regexp.MustCompile("^`([a-z][a-z0-9-]*:[a-z][a-z0-9-]*)`$")
	tickRe     = regexp.MustCompile("`([^`]+)`")
	actionRe   = regexp.MustCompile(`^[a-z]+\.[a-z_]+$`)
	platformRe = regexp.MustCompile("`(platform-[a-z-]+:[a-z-]+)`")
)

// Find locates SPEC.md by walking up from dir.
func Find(dir string) (string, error) {
	d, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(d, "docs", "permissions", "SPEC.md")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", ErrNotFound
		}
		d = parent
	}
}

// Load parses SPEC.md found from the current directory upwards.
func Load() (*Doc, error) {
	p, err := Find(".")
	if err != nil {
		return nil, err
	}
	return Parse(p)
}

// Parse parses the SPEC.md at path.
func Parse(path string) (*Doc, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	doc := &Doc{}
	pos := map[string]int{}
	section := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "## 4."):
			return doc, nil
		case strings.HasPrefix(line, "### 3.1"):
			section = "3.1"
			continue
		case strings.HasPrefix(line, "### 3.2"):
			section = "3.2"
			continue
		case strings.HasPrefix(line, "### 3.3"):
			section = "3.3"
			continue
		case strings.HasPrefix(line, "### 3.4"):
			section = "3.4"
			continue
		}
		if section == "3.3" {
			for _, m := range platformRe.FindAllStringSubmatch(line, -1) {
				doc.Platform = append(doc.Platform, m[1])
			}
			continue
		}
		if (section != "3.1" && section != "3.2") || !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := splitRow(line)
		m := idRe.FindStringSubmatch(cells[0])
		if m == nil {
			continue
		}
		r := Row{ID: m[1], Cols: map[string]bool{}}
		var derive, notes string
		var cols []string
		if section == "3.1" { // Permiso | Deriva de | O | A | M | R | Notas
			if len(cells) < 7 {
				continue
			}
			r.Scopes = "O"
			derive, cols, notes = cells[1], cells[2:6], cells[6]
			for i, k := range []string{"O", "A", "M", "R"} {
				r.Cols[k] = strings.TrimSpace(cols[i]) == "x"
			}
		} else { // Permiso | Alc. | Deriva de | V | D | P | Qué cubre
			if len(cells) < 7 {
				continue
			}
			for _, c := range strings.ToUpper(cells[1]) {
				if strings.ContainsRune("PREO", c) && !strings.ContainsRune(r.Scopes, c) {
					r.Scopes += string(c)
				}
			}
			derive, cols, notes = cells[2], cells[3:6], cells[6]
			for i, k := range []string{"V", "D", "P"} {
				r.Cols[k] = strings.TrimSpace(cols[i]) == "x"
			}
		}
		for _, t := range tickRe.FindAllStringSubmatch(derive, -1) {
			if actionRe.MatchString(t[1]) {
				r.Derives = append(r.Derives, t[1])
			}
		}
		r.Sensitive = strings.Contains(notes, "sensible")
		r.LegacyGap = strings.Contains(notes, "legacy_gap")

		if i, dup := pos[r.ID]; dup {
			o := &doc.Rows[i]
			for _, c := range r.Scopes {
				if !strings.ContainsRune(o.Scopes, c) {
					o.Scopes += string(c)
				}
			}
			o.Derives = append(o.Derives, r.Derives...)
			o.Sensitive = o.Sensitive || r.Sensitive
			o.LegacyGap = o.LegacyGap || r.LegacyGap
			for k, v := range r.Cols {
				if v {
					o.Cols[k] = true
				} else if _, ok := o.Cols[k]; !ok {
					o.Cols[k] = false
				}
			}
			continue
		}
		pos[r.ID] = len(doc.Rows)
		doc.Rows = append(doc.Rows, r)
	}
	return doc, sc.Err()
}

func splitRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
