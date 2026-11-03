package security

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinels.
var (
	ErrNotFound   = errors.New("security: not found")
	ErrNoPolicy   = errors.New("security: no stored policy")
	ErrRateLimit  = errors.New("security: rate limited")
	ErrNotReady   = errors.New("security: not configured")
	ErrNoTopicAPI = errors.New("security: the Git core cannot set repository topics")
)

// FieldError is one validation problem.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError groups field errors (422 VALIDATION_ERROR).
type ValidationError struct{ Fields []FieldError }

func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		parts = append(parts, f.Field+": "+f.Message)
	}
	return "validation failed: " + strings.Join(parts, "; ")
}

func validation(field, msg string) *ValidationError {
	return &ValidationError{Fields: []FieldError{{Field: field, Message: msg}}}
}

// SarifError is a rejected upload (422 with a stable code).
type SarifError struct {
	Code    string // SARIF_INVALID | SARIF_TOO_LARGE | SARIF_TOO_DEEP | SARIF_TOO_MANY_RESULTS | SARIF_UNSUPPORTED
	Message string
}

func (e *SarifError) Error() string { return e.Code + ": " + e.Message }

func sarifErr(code, format string, a ...any) *SarifError {
	return &SarifError{Code: code, Message: fmt.Sprintf(format, a...)}
}

// ForbiddenError is a 403 with a business code (e.g. ADMIN_REQUIRED).
type ForbiddenError struct{ Code, Message string }

func (e *ForbiddenError) Error() string { return e.Code + ": " + e.Message }

// ConflictError is a 409 (e.g. ALERT_STATE_CONFLICT).
type ConflictError struct{ Code, Message string }

func (e *ConflictError) Error() string { return e.Code + ": " + e.Message }
