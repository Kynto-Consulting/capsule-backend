package access

import (
	"encoding/base64"
	"strings"
)

// Opaque pagination cursors: two strings joined by a separator and base64url-encoded.
func encodeCursor(a, b string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(a + "\x1f" + b))
}

func decodeCursor(c string) (a, b string, ok bool) {
	if c == "" {
		return "", "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(raw), "\x1f", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// clampLimit applies the API convention: 1-200, 50 by default.
func clampLimit(n int) int {
	switch {
	case n <= 0:
		return 50
	case n > 200:
		return 200
	}
	return n
}
