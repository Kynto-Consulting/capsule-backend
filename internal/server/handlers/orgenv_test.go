package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type fakeOrgRepo struct {
	domain.OrganizationRepository
	role string
}

func (f fakeOrgRepo) GetMemberRole(context.Context, uuid.UUID, uuid.UUID) (string, error) {
	if f.role == "" {
		return "", domain.ErrNotFound
	}
	return f.role, nil
}

type fakeOrgEnv struct{ vars []*domain.OrgEnvVar }

func (f *fakeOrgEnv) Upsert(_ context.Context, e *domain.OrgEnvVar) (*domain.OrgEnvVar, error) {
	e.ID = uuid.New()
	return e, nil
}
func (f *fakeOrgEnv) ListByOrg(context.Context, uuid.UUID) ([]*domain.OrgEnvVar, error) {
	return f.vars, nil
}
func (f *fakeOrgEnv) Delete(context.Context, uuid.UUID, string) error { return nil }

func TestOrgEnvMaskingAndPermissions(t *testing.T) {
	store := &fakeOrgEnv{vars: []*domain.OrgEnvVar{
		{Key: "TOKEN", ValueEnc: []byte("s3cret"), IsSecret: true, Scope: "both"},
		{Key: "REGION", ValueEnc: []byte("us"), IsSecret: false, Scope: "runtime"},
	}}
	run := func(role, method, url, body string, pick func(h *OrgEnvHandler) http.HandlerFunc) *httptest.ResponseRecorder {
		inner := pick(NewOrgEnvHandler(store, fakeOrgRepo{role: role}))
		r := chi.NewRouter()
		r.Handle("/orgs/{orgID}/env", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			inner(w, req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: uuid.New()})))
		}))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(method, url, strings.NewReader(body)))
		return rec
	}
	list := func(h *OrgEnvHandler) http.HandlerFunc { return h.List }
	set := func(h *OrgEnvHandler) http.HandlerFunc { return h.Set }
	base := "/orgs/" + uuid.New().String() + "/env"

	var got []orgEnvVarResponse
	rec := run("member", "GET", base, "", list)
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != 200 || got[0].Value != secretMask || got[1].Value != "us" {
		t.Fatalf("member list: %d %s", rec.Code, rec.Body)
	}
	if rec := run("member", "GET", base+"?reveal=true", "", list); rec.Code != 403 {
		t.Fatalf("member reveal should be 403, got %d", rec.Code)
	}
	if rec := run("member", "PUT", base, `{"key":"x","value":"1"}`, set); rec.Code != 403 {
		t.Fatalf("member write should be 403, got %d", rec.Code)
	}
	rec = run("admin", "GET", base+"?reveal=true", "", list)
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != 200 || got[0].Value != "s3cret" {
		t.Fatalf("admin reveal: %d %s", rec.Code, rec.Body)
	}
	if rec := run("owner", "PUT", base, `{"key":"x","value":"1","scope":"bogus"}`, set); rec.Code != 422 {
		t.Fatalf("bad scope should be 422, got %d", rec.Code)
	}
	if rec := run("owner", "PUT", base, `{"key":"x","value":"1"}`, set); rec.Code != 200 {
		t.Fatalf("owner write: %d %s", rec.Code, rec.Body)
	}
	if rec := run("", "GET", base, "", list); rec.Code != 403 {
		t.Fatalf("non-member should be 403, got %d", rec.Code)
	}
}

func TestValidateDeployEnvMeta(t *testing.T) {
	env, meta, msg := validateDeployEnvMeta(map[string]string{"foo": "1"}, map[string]string{"ref": "main", "sha": "abc"})
	if msg != "" || env["FOO"] != "1" || meta["ref"] != "main" {
		t.Fatalf("unexpected: %v %v %q", env, meta, msg)
	}
	if _, _, msg := validateDeployEnvMeta(nil, map[string]string{"evil": "x"}); msg == "" {
		t.Fatal("unknown meta key should be rejected")
	}
	if _, _, msg := validateDeployEnvMeta(map[string]string{"A=B": "x"}, nil); msg == "" {
		t.Fatal("key with = should be rejected")
	}
}
