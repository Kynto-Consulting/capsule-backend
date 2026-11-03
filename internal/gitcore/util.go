package gitcore

import (
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func itoa(n int) string { return strconv.Itoa(n) }

func jsonInto(b []byte, v any) error { return json.Unmarshal(b, v) }

func sortTree(t []TreeEntry) {
	sort.SliceStable(t, func(i, j int) bool {
		di, dj := t[i].Type == "dir", t[j].Type == "dir"
		if di != dj {
			return di
		}
		return strings.ToLower(t[i].Name) < strings.ToLower(t[j].Name)
	})
}

// pageSlice pages an in-memory slice with offset cursors (cursor.Page-1 = offset).
func pageSlice[T any](all []T, p Page) (List[T], error) {
	c, err := decodeOffsetCursor(p.Cursor)
	if err != nil {
		return List[T]{}, err
	}
	limit := clampLimit(p.Limit)
	if c > len(all) {
		c = len(all)
	}
	end := c + limit
	out := List[T]{Items: all[c:min(end, len(all))]}
	if out.Items == nil {
		out.Items = []T{}
	}
	if end < len(all) {
		out.NextCursor = encodeCursor(cursor{Page: end + 1})
	}
	return out, nil
}

func decodeOffsetCursor(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	c, err := decodeCursorRaw(s)
	if err != nil {
		return 0, err
	}
	return c.Page - 1, nil
}

// parseDiff splits a unified diff (git format) per file and bounds the total patch size.
func parseDiff(raw string, maxBytes int) Diff {
	d := Diff{Files: []FileDiff{}, Bytes: 0}
	if raw == "" {
		return d
	}
	chunks := strings.Split("\n"+raw, "\ndiff --git ")
	budget := maxBytes
	for _, ch := range chunks[1:] {
		nl := strings.IndexByte(ch, '\n')
		head, rest := ch, ""
		if nl >= 0 {
			head, rest = ch[:nl], ch[nl+1:]
		}
		f := FileDiff{Status: "modified"}
		f.Path = diffHeaderPath(head)
		patchStart := -1
		inHunk := false
		pos := 0
		for _, line := range strings.SplitAfter(rest, "\n") {
			t := strings.TrimRight(line, "\r\n")
			switch {
			case !inHunk && strings.HasPrefix(t, "new file mode"):
				f.Status = "added"
			case !inHunk && strings.HasPrefix(t, "deleted file mode"):
				f.Status = "removed"
			case !inHunk && strings.HasPrefix(t, "rename from "):
				f.Status, f.OldPath = "renamed", strings.TrimPrefix(t, "rename from ")
			case !inHunk && strings.HasPrefix(t, "rename to "):
				f.Path = strings.TrimPrefix(t, "rename to ")
			case !inHunk && strings.HasPrefix(t, "--- ") && f.Status == "modified" && f.OldPath == "":
				// path stays from the header
			case strings.HasPrefix(t, "@@"):
				if !inHunk {
					inHunk, patchStart = true, pos
				}
			case inHunk && strings.HasPrefix(t, "+") && !strings.HasPrefix(t, "+++ "):
				f.Additions++
			case inHunk && strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--- "):
				f.Deletions++
			case strings.HasPrefix(t, "Binary files") || strings.HasPrefix(t, "GIT binary patch"):
				f.Truncated = true // binary: there is no textual patch to show
			}
			pos += len(line)
		}
		if patchStart >= 0 {
			patch := rest[patchStart:]
			if len(patch) <= budget {
				f.Patch = patch
				budget -= len(patch)
				d.Bytes += len(patch)
			} else {
				f.Truncated, d.Truncated = true, true
				budget = 0
			}
		}
		d.Files = append(d.Files, f)
	}
	return d
}

// diffHeaderPath extracts the path from "a/<p> b/<p>" (equal halves) or the text after " b/".
func diffHeaderPath(h string) string {
	if strings.HasPrefix(h, "a/") {
		if n := len(h) - 5; n > 0 && n%2 == 0 {
			p := h[2 : 2+n/2]
			if h == "a/"+p+" b/"+p {
				return p
			}
		}
	}
	if i := strings.LastIndex(h, " b/"); i >= 0 {
		return h[i+3:]
	}
	return h
}

func cloneQuery(q url.Values) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	return out
}
