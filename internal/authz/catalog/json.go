package catalog

import (
	"bytes"
	"encoding/json"
)

// File is the document published as catalog.json and by GET /permissions/catalog.
type File struct {
	CatalogVersion int    `json:"catalog_version"`
	Count          int    `json:"count"`
	Permissions    []Perm `json:"permissions"`
}

// JSON returns the canonical catalog.json bytes (two-space indent, trailing newline). The file checked
// in next to this package must equal it; regenerate with `make catalog-gen`.
func JSON() []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(File{CatalogVersion: Version, Count: len(perms), Permissions: All()}); err != nil {
		panic(err) // the document only holds strings, ints and bools
	}
	return buf.Bytes()
}
