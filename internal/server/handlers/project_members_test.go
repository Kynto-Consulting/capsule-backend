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

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// ---- fakes -----------------------------------------------------------------

type pmOrgs struct {
	domain.OrganizationRepository
	roles   map[uuid.UUID]string
	owner   uuid.UUID
	members []*domain.OrgMember
}

func (f *pmOrgs) GetMemberRole(_ context.Context, _, u uuid.UUID) (string, error) {
	if r, ok := f.roles[u]; ok {
		return r, nil
	}
	return "", domain.ErrNotFound
}
func (f *pmOrgs) IsMember(_ context.Context, _, u uuid.UUID) (bool, error) {
	_, ok := f.roles[u]
	return ok, nil
}
func (f *pmOrgs) GetMembers(context.Context, uuid.UUID) ([]*domain.OrgMember, error) {
	return f.members, nil
}
func (f *pmOrgs) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	return &domain.Organization{ID: id, OwnerID: f.owner, Name: "Acme", Slug: "acme"}, nil
}
func (f *pmOrgs) Update(_ context.Context, o *domain.Organization) (*domain.Organization, error) {
	return o, nil
}

type pmProjects struct {
	domain.ProjectRepository
	p *domain.Project
}

func (f pmProjects) GetByID(context.Context, uuid.UUID) (*domain.Project, error) { return f.p, nil }

type pmStore struct {
	org      *pmOrgs
	mode     string
	explicit map[uuid.UUID]string // user -> role, single project
	audits   []authz.AuditEntry
	project  uuid.UUID
}

func (s *pmStore) LoadOrgAccess(_ context.Context, _, u uuid.UUID) (*authz.OrgAccess, error) {
	role, ok := s.org.roles[u]
	if !ok {
		return nil, nil
	}
	oa := &authz.OrgAccess{OrgRole: role, Mode: s.mode, Explicit: map[uuid.UUID]string{}}
	if r, ok := s.explicit[u]; ok {
		oa.Explicit[s.project] = r
	}
	return oa, nil
}
func (s *pmStore) UserGrants(context.Context, uuid.UUID) ([]authz.Grant, error) { return nil, nil }
func (s *pmStore) ListExplicit(context.Context, uuid.UUID) ([]authz.Member, error) {
	var out []authz.Member
	for u, r := range s.explicit {
		out = append(out, authz.Member{ProjectID: s.project, UserID: u, Role: r})
	}
	return out, nil
}
func (s *pmStore) UpsertMember(_ context.Context, _, u uuid.UUID, role string, _ uuid.UUID) error {
	s.explicit[u] = role
	return nil
}
func (s *pmStore) RemoveMember(_ context.Context, _, u uuid.UUID) (bool, error) {
	_, ok := s.explicit[u]
	delete(s.explicit, u)
	return ok, nil
}
func (s *pmStore) CountEffectiveAdmins(context.Context, uuid.UUID, uuid.UUID) (int, error) {
	n := 0
	for u, r := range s.org.roles {
		if r == "owner" || r == "admin" || (r == "member" && s.explicit[u] == "admin") {
			n++
		}
	}
	return n, nil
}
func (s *pmStore) SetOrgAccessMode(_ context.Context, _ uuid.UUID, m string) error {
	s.mode = m
	return nil
}
func (s *pmStore) GetOrgAccessMode(context.Context, uuid.UUID) (string, error) { return s.mode, nil }
func (s *pmStore) Audit(_ context.Context, e authz.AuditEntry) error {
	s.audits = append(s.audits, e)
	return nil
}

type pmEnv struct {
	org, proj uuid.UUID
	orgs      *pmOrgs
	store     *pmStore
	svc       *authz.Service
	project   *domain.Project
}

func newPMEnv(mode string) *pmEnv {
	e := &pmEnv{org: uuid.New(), proj: uuid.New()}
	e.orgs = &pmOrgs{roles: map[uuid.UUID]string{}}
	e.store = &pmStore{org: e.orgs, mode: mode, explicit: map[uuid.UUID]string{}, project: e.proj}
	e.svc = authz.New(e.store)
	e.project = &domain.Project{ID: e.proj, OrgID: e.org}
	return e
}

func (e *pmEnv) addUser(orgRole string) uuid.UUID {
	u := uuid.New()
	e.orgs.roles[u] = orgRole
	e.orgs.members = append(e.orgs.members, &domain.OrgMember{UserID: u, Email: u.String() + "@x.test", Name: orgRole, Role: orgRole})
	if orgRole == "owner" {
		e.orgs.owner = u
	}
	return u
}

func asUser(u uuid.UUID, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(middleware.WithUser(r.Context(), &domain.User{ID: u})))
	})
}

func (e *pmEnv) call(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/orgs/"+e.org.String()+"/projects/"+e.proj.String()+path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func (e *pmEnv) membersRouter(caller uuid.UUID) http.Handler {
	h := NewProjectMembersHandler(e.orgs, pmProjects{p: e.project}, e.store, e.svc)
	r := chi.NewRouter()
	base := "/orgs/{orgID}/projects/{projectID}/members"
	r.Get(base, h.List)
	r.Put(base+"/{userID}", h.Put)
	r.Delete(base+"/{userID}", h.Delete)
	return asUser(caller, r)
}

// ---- members API -------------------------------------------------------------

func TestMembersAPIListPutDelete(t *testing.T) {
	e := newPMEnv(authz.ModeOpen)
	owner, member, viewerOrg := e.addUser("owner"), e.addUser("member"), e.addUser("readonly")

	api := e.membersRouter(owner)
	rec := e.call(api, "GET", "/members", "")
	if rec.Code != 200 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	var list struct {
		Data []struct {
			UserID  uuid.UUID `json:"user_id"`
			OrgRole string    `json:"org_role"`
			Role    string    `json:"role"`
			Source  string    `json:"source"`
		} `json:"data"`
		Mode string `json:"access_mode"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	got := map[uuid.UUID][2]string{}
	for _, m := range list.Data {
		got[m.UserID] = [2]string{m.Role, m.Source}
	}
	if list.Mode != "open" || got[owner] != [2]string{"admin", "org"} || got[member] != [2]string{"deployer", "inherited"} || got[viewerOrg] != [2]string{"viewer", "inherited"} {
		t.Fatalf("effective list wrong: %+v mode=%s", got, list.Mode)
	}

	// explicit viewer restricts a member below the open-mode default
	if rec := e.call(api, "PUT", "/members/"+member.String(), `{"role":"viewer"}`); rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	if e.store.explicit[member] != "viewer" {
		t.Fatal("not stored")
	}
	// validation
	if rec := e.call(api, "PUT", "/members/"+member.String(), `{"role":"root"}`); rec.Code != 422 {
		t.Fatalf("bad role: %d", rec.Code)
	}
	if rec := e.call(api, "PUT", "/members/"+uuid.NewString(), `{"role":"viewer"}`); rec.Code != 404 {
		t.Fatalf("non org member: %d", rec.Code)
	}
	if rec := e.call(api, "PUT", "/members/"+owner.String(), `{"role":"viewer"}`); rec.Code != 422 {
		t.Fatalf("org owner target: %d", rec.Code)
	}
	if rec := e.call(api, "DELETE", "/members/"+viewerOrg.String(), ""); rec.Code != 404 {
		t.Fatalf("delete without row: %d", rec.Code)
	}
	if rec := e.call(api, "DELETE", "/members/"+member.String(), ""); rec.Code != 204 {
		t.Fatalf("delete: %d", rec.Code)
	}
	if _, ok := e.store.explicit[member]; ok {
		t.Fatal("not removed")
	}
	if len(e.store.audits) != 2 || e.store.audits[0].Action != "project_member.set" || e.store.audits[1].Action != "project_member.remove" {
		t.Fatalf("audit trail: %+v", e.store.audits)
	}
}

func TestMembersAPIRequiresProjectMembersPermission(t *testing.T) {
	e := newPMEnv(authz.ModeOpen)
	e.addUser("owner")
	member, ro := e.addUser("member"), e.addUser("readonly")
	target := e.addUser("member")
	for _, u := range []uuid.UUID{member, ro} { // deployer / viewer
		api := e.membersRouter(u)
		for _, c := range [][3]string{{"GET", "/members", ""}, {"PUT", "/members/" + target.String(), `{"role":"admin"}`}, {"DELETE", "/members/" + target.String(), ""}} {
			if rec := e.call(api, c[0], c[1], c[2]); rec.Code != 403 {
				t.Errorf("%s %s as non-admin: %d", c[0], c[1], rec.Code)
			}
		}
	}
	// a member explicitly promoted to admin may manage members
	e.store.explicit[member] = "admin"
	if rec := e.call(e.membersRouter(member), "PUT", "/members/"+target.String(), `{"role":"viewer"}`); rec.Code != 200 {
		t.Fatalf("project admin: %d %s", rec.Code, rec.Body)
	}
	// stranger: not a member of the org
	if rec := e.call(e.membersRouter(uuid.New()), "GET", "/members", ""); rec.Code != 403 {
		t.Fatalf("stranger: %d", rec.Code)
	}
}

func TestMembersAPIKeepsLastAdmin(t *testing.T) {
	e := newPMEnv(authz.ModeRestricted)
	// No org owner/admin: the only effective admin is a member with an explicit admin row.
	sole, other := e.addUser("member"), e.addUser("member")
	e.store.explicit[sole] = "admin"
	api := e.membersRouter(sole)

	if rec := e.call(api, "PUT", "/members/"+sole.String(), `{"role":"viewer"}`); rec.Code != 409 {
		t.Fatalf("demoting the last admin: %d %s", rec.Code, rec.Body)
	}
	if rec := e.call(api, "DELETE", "/members/"+sole.String(), ""); rec.Code != 409 {
		t.Fatalf("removing the last admin: %d %s", rec.Code, rec.Body)
	}
	if e.store.explicit[sole] != "admin" {
		t.Fatal("last admin was changed despite 409")
	}
	// with a second admin it is allowed
	if rec := e.call(api, "PUT", "/members/"+other.String(), `{"role":"admin"}`); rec.Code != 200 {
		t.Fatalf("promote second admin: %d", rec.Code)
	}
	if rec := e.call(api, "PUT", "/members/"+sole.String(), `{"role":"viewer"}`); rec.Code != 200 {
		t.Fatalf("demote with another admin present: %d %s", rec.Code, rec.Body)
	}
}

// ---- migrated handlers honour project roles ----------------------------------

type pmEnvVars struct{ domain.EnvVarRepository }

func (pmEnvVars) ListByProject(_ context.Context, id uuid.UUID) ([]*domain.EnvVar, error) {
	return []*domain.EnvVar{
		{Key: "PLAIN", ValueEnc: []byte("v"), ProjectID: id},
		{Key: "TOKEN", ValueEnc: []byte("s3cret"), IsSecret: true, ProjectID: id},
	}, nil
}
func (pmEnvVars) Upsert(_ context.Context, e *domain.EnvVar) (*domain.EnvVar, error) {
	e.ID = uuid.New()
	return e, nil
}

func (e *pmEnv) envRouter(caller uuid.UUID) http.Handler {
	h := NewEnvVarHandler(pmEnvVars{}, e.orgs, pmProjects{p: e.project})
	h.SetAuthz(e.svc)
	r := chi.NewRouter()
	r.Get("/orgs/{orgID}/projects/{projectID}/env", h.List)
	r.Put("/orgs/{orgID}/projects/{projectID}/env", h.Set)
	return asUser(caller, r)
}

func TestRestrictedProjectIsHiddenAndRolesGateEnv(t *testing.T) {
	e := newPMEnv(authz.ModeRestricted)
	owner := e.addUser("owner")
	hidden, viewer, deployer, admin := e.addUser("member"), e.addUser("member"), e.addUser("member"), e.addUser("member")
	e.store.explicit[viewer], e.store.explicit[deployer], e.store.explicit[admin] = "viewer", "deployer", "admin"
	put := `{"key":"a","value":"b"}`

	// restricted + no row => 404 on every route, never 403
	if rec := e.call(e.envRouter(hidden), "GET", "/env", ""); rec.Code != 404 {
		t.Fatalf("hidden list: %d", rec.Code)
	}
	if rec := e.call(e.envRouter(hidden), "PUT", "/env", put); rec.Code != 404 {
		t.Fatalf("hidden put: %d", rec.Code)
	}
	// viewer: read (masked), cannot write
	rec := e.call(e.envRouter(viewer), "GET", "/env", "")
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "s3cret") || !strings.Contains(rec.Body.String(), `"masked":true`) || !strings.Contains(rec.Body.String(), `"value":"v"`) {
		t.Fatalf("viewer list must mask secrets only: %d %s", rec.Code, rec.Body)
	}
	if rec := e.call(e.envRouter(viewer), "PUT", "/env", put); rec.Code != 403 {
		t.Fatalf("viewer put: %d", rec.Code)
	}
	// deployer: writes, still masked
	if rec := e.call(e.envRouter(deployer), "PUT", "/env", put); rec.Code != 200 {
		t.Fatalf("deployer put: %d", rec.Code)
	}
	if rec := e.call(e.envRouter(deployer), "GET", "/env", ""); strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatalf("deployer must not reveal secrets: %s", rec.Body)
	}
	// project admin and org owner reveal
	for _, u := range []uuid.UUID{admin, owner} {
		if rec := e.call(e.envRouter(u), "GET", "/env", ""); !strings.Contains(rec.Body.String(), "s3cret") || strings.Contains(rec.Body.String(), "masked") {
			t.Fatalf("admin must reveal: %s", rec.Body)
		}
	}
	// open mode: an org member is a deployer everywhere without any row
	e.store.mode = authz.ModeOpen
	if rec := e.call(e.envRouter(hidden), "PUT", "/env", put); rec.Code != 200 {
		t.Fatalf("open-mode member put: %d", rec.Code)
	}
	if rec := e.call(e.envRouter(hidden), "GET", "/env", ""); strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatalf("open-mode member must not reveal: %s", rec.Body)
	}
	// but an explicit viewer row restricts that member even in open mode
	e.store.explicit[hidden] = "viewer"
	if rec := e.call(e.envRouter(hidden), "PUT", "/env", put); rec.Code != 403 {
		t.Fatalf("explicit viewer in open mode: %d", rec.Code)
	}
}

type pmDeployments struct{ domain.DeploymentRepository }

func (pmDeployments) ListByProject(context.Context, uuid.UUID, int, int) ([]*domain.Deployment, int, error) {
	return nil, 0, nil
}

func TestDeploymentRoutesUseProjectRoles(t *testing.T) {
	e := newPMEnv(authz.ModeRestricted)
	e.addUser("owner")
	viewer, hidden := e.addUser("member"), e.addUser("member")
	e.store.explicit[viewer] = "viewer"
	mk := func(u uuid.UUID) http.Handler {
		h := NewDeploymentHandler(pmDeployments{}, e.orgs, pmProjects{p: e.project}, nil, "", nil)
		h.SetAuthz(e.svc)
		r := chi.NewRouter()
		base := "/orgs/{orgID}/projects/{projectID}/deployments"
		r.Get(base, h.List)
		r.Post(base, h.Create)
		r.Post(base+"/upload-url", h.UploadURL)
		r.Post(base+"/{deploymentID}/cancel", h.Cancel)
		return asUser(u, r)
	}
	if rec := e.call(mk(viewer), "GET", "/deployments", ""); rec.Code != 200 {
		t.Fatalf("viewer list: %d", rec.Code)
	}
	for _, p := range []string{"/deployments", "/deployments/upload-url", "/deployments/" + uuid.NewString() + "/cancel"} {
		if rec := e.call(mk(viewer), "POST", p, `{}`); rec.Code != 403 {
			t.Errorf("viewer POST %s: %d", p, rec.Code)
		}
		if rec := e.call(mk(hidden), "POST", p, `{}`); rec.Code != 404 {
			t.Errorf("hidden POST %s: %d", p, rec.Code)
		}
	}
	if rec := e.call(mk(hidden), "GET", "/deployments", ""); rec.Code != 404 {
		t.Fatalf("hidden list: %d", rec.Code)
	}
}

// ---- PATCH /orgs/{orgID} project_access_mode ---------------------------------

func TestOrgPatchProjectAccessMode(t *testing.T) {
	e := newPMEnv(authz.ModeOpen)
	owner, admin, member := e.addUser("owner"), e.addUser("admin"), e.addUser("member")
	h := NewOrgHandler(e.orgs)
	h.SetAccessModes(e.store)
	patch := func(u uuid.UUID, body string) *httptest.ResponseRecorder {
		r := chi.NewRouter()
		r.Patch("/orgs/{orgID}", h.Update)
		req := httptest.NewRequest("PATCH", "/orgs/"+e.org.String(), strings.NewReader(body))
		rec := httptest.NewRecorder()
		asUser(u, r).ServeHTTP(rec, req)
		return rec
	}
	if rec := patch(member, `{"project_access_mode":"restricted"}`); rec.Code != 403 {
		t.Fatalf("member: %d", rec.Code)
	}
	if rec := patch(owner, `{"project_access_mode":"bogus"}`); rec.Code != 422 {
		t.Fatalf("bogus: %d", rec.Code)
	}
	rec := patch(admin, `{"project_access_mode":"restricted"}`)
	if rec.Code != 200 || e.store.mode != "restricted" || !strings.Contains(rec.Body.String(), `"project_access_mode":"restricted"`) {
		t.Fatalf("admin set mode: %d %s mode=%s", rec.Code, rec.Body, e.store.mode)
	}
	if len(e.store.audits) != 1 || e.store.audits[0].Action != "org.project_access_mode.set" {
		t.Fatalf("audit: %+v", e.store.audits)
	}
	if rec := patch(admin, `{"name":"New"}`); rec.Code != 403 {
		t.Fatalf("admin must not rename: %d", rec.Code)
	}
	if rec := patch(owner, `{"name":"New","project_access_mode":"open"}`); rec.Code != 200 || e.store.mode != "open" {
		t.Fatalf("owner both: %d %s", rec.Code, rec.Body)
	}
	if rec := patch(owner, `{}`); rec.Code != 422 {
		t.Fatalf("empty: %d", rec.Code)
	}
}
