package authz

import _ "embed"

// SystemTemplatesJSON is the embedded systemtemplates.json: the system role templates of the permission
// engine (docs/permissions/SPEC.md section 4.2) as data. It is read-only data; the typed loader and the
// documented schema are in package authz/systemtemplates. Embedding it here (and not there) is only
// because go:embed cannot reach a file in a parent directory. Nothing in the server reads it yet.
//
//go:embed systemtemplates.json
var SystemTemplatesJSON []byte
