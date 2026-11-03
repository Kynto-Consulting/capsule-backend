package gitapi

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// WorkflowDirs are the directories Forgejo Actions reads workflows from, in precedence order.
var WorkflowDirs = []string{".forgejo/workflows", ".gitea/workflows", ".github/workflows"}

const maxWorkflows = 50

// WorkflowOut is the API schema Workflow.
type WorkflowOut struct {
	ID       string   `json:"id"` // file name: what Forgejo's dispatch endpoint takes
	Name     string   `json:"name"`
	Path     string   `json:"path"`
	State    string   `json:"state"`
	Triggers []string `json:"triggers"`
}

var workflowFileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.ya?ml$`)

// ValidWorkflowID reports whether id is a plain workflow file name (no path, no traversal).
func ValidWorkflowID(id string) bool { return workflowFileRe.MatchString(id) }

// ListWorkflows reads the workflow files of ref from the repository. The first directory that has
// a file named X wins over the same name in later directories.
func ListWorkflows(ctx context.Context, core gitcore.Content, ref gitcore.RepoRef, branch string) ([]WorkflowOut, error) {
	seen := map[string]bool{}
	var out []WorkflowOut
	for _, dir := range WorkflowDirs {
		list, err := core.ListTree(ctx, ref, branch, dir, gitcore.Page{Limit: gitcore.MaxLimit})
		if err != nil {
			if e, ok := gitcore.AsError(err); ok && e.Code == gitcore.CodeNotFound {
				continue
			}
			return nil, err
		}
		for _, e := range list.Items {
			if e.Type != "file" || !ValidWorkflowID(e.Name) || seen[e.Name] {
				continue
			}
			if len(out) >= maxWorkflows {
				break
			}
			seen[e.Name] = true
			w := WorkflowOut{ID: e.Name, Name: e.Name, Path: e.Path, State: "active", Triggers: []string{}}
			if b, err := core.GetFile(ctx, ref, branch, e.Path); err == nil && b != nil && !b.Binary && !b.Truncated && b.Encoding != "base64" {
				name, triggers := ParseWorkflow(b.Content)
				if name != "" {
					w.Name = name
				}
				if len(triggers) > 0 {
					w.Triggers = triggers
				}
			}
			out = append(out, w)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if out == nil {
		out = []WorkflowOut{}
	}
	return out, nil
}

func indentOf(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }

func stripComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '#':
			if !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
				return s[:i]
			}
		}
	}
	return s
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// ParseWorkflow extracts the display name and the trigger events from a workflow file without a
// YAML dependency: it understands the three spellings of "on" (scalar, flow list, block map/list).
func ParseWorkflow(src string) (name string, triggers []string) {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := stripComment(lines[i])
		if strings.TrimSpace(line) == "" || indentOf(line) != 0 {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = unquote(key)
		val = strings.TrimSpace(val)
		switch key {
		case "name":
			if name == "" {
				name = unquote(val)
			}
		case "on", "true":
			switch {
			case strings.HasPrefix(val, "["):
				inner := strings.Trim(val, "[] ")
				for _, t := range strings.Split(inner, ",") {
					if t = unquote(t); t != "" {
						triggers = append(triggers, t)
					}
				}
			case val != "" && !strings.HasPrefix(val, "{"):
				triggers = append(triggers, unquote(val))
			default:
				base := -1
				for j := i + 1; j < len(lines); j++ {
					l := stripComment(lines[j])
					if strings.TrimSpace(l) == "" {
						continue
					}
					ind := indentOf(l)
					if ind == 0 {
						break
					}
					if base < 0 {
						base = ind
					}
					if ind != base {
						continue
					}
					t := strings.TrimSpace(l)
					if strings.HasPrefix(t, "- ") {
						triggers = append(triggers, unquote(strings.TrimPrefix(t, "- ")))
					} else if k, _, ok := strings.Cut(t, ":"); ok {
						triggers = append(triggers, unquote(k))
					}
				}
			}
		}
	}
	return name, triggers
}
