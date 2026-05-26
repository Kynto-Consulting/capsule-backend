package handlers

import (
	"encoding/json"
	"io"
)

func encodeJSON(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}
