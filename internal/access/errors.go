// Package access is the domain service behind the permission-management API of docs/permissions/API.openapi.yaml: templates,
// groups, assignments, effective permissions, the simulator and the audit trail. It has no HTTP: handlers translate *Error to
// {"error":{"code","message","details"}} and call the methods with an Actor.
//
// Every write runs through AccessStore.InTx (organization row lock, access_epoch bump and NOTIFY in the same transaction) and
// writes its audit_logs row and its Idempotency-Key row inside that transaction too, so a failing audit rolls the change back.
package access

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/repository"
)

// Error is a domain error with the HTTP shape of the rest of the API.
type Error struct {
	Status  int
	Code    string // FORBIDDEN, NOT_FOUND, VALIDATION_ERROR, CONFLICT, ...
	Message string
	Details map[string]any // details.code is the specific code of API.openapi.yaml (ESCALATION, LAST_OWNER, ...)
}

func (e *Error) Error() string { return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Message) }

// DetailCode returns details.code ("" when absent).
func (e *Error) DetailCode() string {
	c, _ := e.Details["code"].(string)
	return c
}

func notFound(msg string) *Error {
	return &Error{Status: http.StatusNotFound, Code: "NOT_FOUND", Message: msg}
}

func forbidden(msg string) *Error {
	return &Error{Status: http.StatusForbidden, Code: "FORBIDDEN", Message: msg}
}

// denied is the visible-resource 403 of SPEC 11.2.
func denied(perm string, missing []string, reason string) *Error {
	d := map[string]any{"code": "PERMISSION_DENIED", "permission": perm}
	if len(missing) > 0 {
		d["missing"] = missing
	}
	if reason != "" {
		d["reason"] = reason
	}
	return &Error{Status: http.StatusForbidden, Code: "FORBIDDEN", Message: "your role does not allow this action", Details: d}
}

// escalation is the no-escalation rule of SPEC 13.1: 403 with details.code ESCALATION.
func escalation(msg string, missing []string, reason string) *Error {
	d := map[string]any{"code": "ESCALATION"}
	if len(missing) > 0 {
		d["missing"] = missing
	}
	if reason != "" {
		d["reason"] = reason
	}
	return &Error{Status: http.StatusForbidden, Code: "FORBIDDEN", Message: msg, Details: d}
}

func validation(fields map[string]string) *Error {
	return &Error{Status: http.StatusUnprocessableEntity, Code: "VALIDATION_ERROR", Message: "validation failed", Details: map[string]any{"fields": fields}}
}

func validationField(field, msg string) *Error { return validation(map[string]string{field: msg}) }

func validationDetails(msg string, details map[string]any) *Error {
	return &Error{Status: http.StatusUnprocessableEntity, Code: "VALIDATION_ERROR", Message: msg, Details: details}
}

func conflict(detailCode, msg string, extra map[string]any) *Error {
	d := map[string]any{"code": detailCode}
	for k, v := range extra {
		d[k] = v
	}
	return &Error{Status: http.StatusConflict, Code: "CONFLICT", Message: msg, Details: d}
}

func limitErr(msg string) *Error {
	return &Error{Status: http.StatusUnprocessableEntity, Code: "VALIDATION_ERROR", Message: msg, Details: map[string]any{"code": "LIMIT_EXCEEDED"}}
}

// mapPg turns constraint and trigger violations of the SQL this package runs inside transactions into the repository errors.
func mapPg(err error) error {
	if err == nil {
		return nil
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "23505":
			return fmt.Errorf("%w: %s", repository.ErrAccessConflict, pe.ConstraintName)
		case "23514", "23503", "22P02":
			return fmt.Errorf("%w: %s", repository.ErrAccessInvalid, pe.Message)
		case "23001":
			return fmt.Errorf("%w: %s", repository.ErrSystemTemplate, pe.Message)
		}
	}
	return err
}

// asError converts any error into an *Error; unknown errors stay internal (nil second result means "not a domain error").
func asError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return notFound("resource not found"), true
	case errors.Is(err, repository.ErrSystemTemplate):
		return conflict("SYSTEM_TEMPLATE", "system templates are immutable; clone it instead", nil), true
	case errors.Is(err, repository.ErrTemplateArchived):
		return conflict("TEMPLATE_ARCHIVED", "template is archived", nil), true
	case errors.Is(err, repository.ErrTemplateInUse):
		return conflict("TEMPLATE_IN_USE", "template is in use", nil), true
	case errors.Is(err, repository.ErrReservedSlug):
		return validationField("slug", "slug is reserved by a system template"), true
	case errors.Is(err, repository.ErrAccessLimit):
		return limitErr(err.Error()), true
	case errors.Is(err, repository.ErrAccessConflict):
		return conflict("DUPLICATE", "a record with that identity already exists", nil), true
	case errors.Is(err, repository.ErrAccessInvalid):
		return validationDetails(err.Error(), map[string]any{"code": "INVALID"}), true
	}
	return nil, false
}

// Normalize returns err as *Error when it is a domain error, else err unchanged (handlers answer 500).
func Normalize(err error) error {
	if err == nil {
		return nil
	}
	if e, ok := asError(err); ok {
		return e
	}
	return err
}
