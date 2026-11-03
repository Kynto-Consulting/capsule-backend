package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/kynto/capsule/backend/internal/environments"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

func TestEnvironmentsRoutesAnswer501WithoutService(t *testing.T) {
	r := chi.NewRouter()
	MountEnvironments(r, nil, nil, nil) // environments.Shared() is nil in this process
	for _, c := range []struct{ method, path string }{
		{"GET", "/orgs/o/projects/p/environments"},
		{"POST", "/orgs/o/projects/p/promotions"},
		{"POST", "/orgs/o/projects/p/promotions/x/approve"},
	} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s %s: %d", c.method, c.path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/orgs/o/approvals", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("approvals: %d", rec.Code)
	}
}

func TestEnvironmentsErrorMapping(t *testing.T) {
	h := &EnvironmentsHandler{}
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{&environments.ValidationError{Fields: []environments.FieldError{{Field: "name", Message: "bad"}}}, 422, "VALIDATION_ERROR"},
		{&environments.PolicyError{Code: "POLICY_BLOCKED", Message: "x"}, 422, "POLICY_BLOCKED"},
		{&environments.ConflictError{Code: "CHECKS_REQUIRED", Message: "x"}, 409, "CHECKS_REQUIRED"},
		{&environments.ConflictError{Code: "IDEMPOTENCY_CONFLICT", Message: "x"}, 409, "IDEMPOTENCY_CONFLICT"},
		{&environments.ForbiddenError{Code: "SELF_APPROVAL_FORBIDDEN", Message: "x"}, 403, "SELF_APPROVAL_FORBIDDEN"},
		{&environments.ForbiddenError{Code: "NOT_AN_APPROVER", Message: "x"}, 403, "NOT_AN_APPROVER"},
		{environments.ErrNotFound, 404, "NOT_FOUND"},
		{environments.ErrDuplicate, 409, "ENV_EXISTS"},
		{environments.ErrInvalidState, 409, "INVALID_STATE"},
		{&gitcore.Error{Code: gitcore.CodeUpstream, Message: "down"}, 502, "UPSTREAM_GIT_ERROR"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.fail(rec, c.err)
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), `"code":"`+c.code+`"`) {
			t.Errorf("%T: %d %s", c.err, rec.Code, rec.Body.String())
		}
	}
}

func TestEnvironmentsBodyRejectsUnknownFields(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/x", strings.NewReader(`{"name":"qa","kind":"other","require_approvals":2}`))
	var b envBody
	if envDecode(rec, req, &b) || rec.Code != http.StatusBadRequest {
		t.Fatalf("typo in a field must be refused: %d", rec.Code)
	}
	// a GET response echoed back on PUT must be accepted
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("PUT", "/x", strings.NewReader(`{"id":"1","current":null,"created_at":"2026-01-01T00:00:00Z","name":"qa","kind":"other"}`))
	if !envDecode(rec, req, &b) {
		t.Fatalf("echoed fields must be accepted: %s", rec.Body.String())
	}
}
