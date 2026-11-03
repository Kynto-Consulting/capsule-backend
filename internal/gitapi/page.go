package gitapi

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// OffsetCursor encodes an offset as an opaque cursor (used where the upstream has no cursor and the
// API slices an already bounded list: PR files, activity).
func OffsetCursor(n int) string {
	return base64.RawURLEncoding.EncodeToString([]byte("o:" + strconv.Itoa(n)))
}

// ParseOffset decodes OffsetCursor ("" = 0). Malformed cursors are INVALID_ARGUMENT errors.
func ParseOffset(c string) (int, error) {
	if c == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil || !strings.HasPrefix(string(raw), "o:") {
		return 0, &gitcore.Error{Code: gitcore.CodeInvalid, Message: "invalid cursor"}
	}
	n, err := strconv.Atoi(string(raw)[2:])
	if err != nil || n < 0 {
		return 0, &gitcore.Error{Code: gitcore.CodeInvalid, Message: "invalid cursor"}
	}
	return n, nil
}

// SliceByCursor returns the page of all selected by the cursor and the next cursor ("" at the end).
func SliceByCursor[T any](all []T, p gitcore.Page) ([]T, string, error) {
	off, err := ParseOffset(p.Cursor)
	if err != nil {
		return nil, "", err
	}
	limit := p.Limit
	if limit <= 0 {
		limit = gitcore.DefaultLimit
	}
	if limit > gitcore.MaxLimit {
		limit = gitcore.MaxLimit
	}
	if off > len(all) {
		off = len(all)
	}
	end := off + limit
	next := ""
	if end < len(all) {
		next = OffsetCursor(end)
	} else {
		end = len(all)
	}
	return all[off:end], next, nil
}
