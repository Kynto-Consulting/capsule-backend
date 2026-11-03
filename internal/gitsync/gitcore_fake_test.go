package gitsync_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitcore/fake"
	"github.com/kynto/capsule/backend/internal/gitsync"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// The real gitcore.Service (against the fake Forgejo) must satisfy gitsync.Forge and work end to end.
var _ gitsync.Forge = (*gitcore.Service)(nil)

type ids struct {
	rows map[uuid.UUID]*gitsync.Identity
}

func (s *ids) Get(_ context.Context, id uuid.UUID) (*gitsync.Identity, error) {
	if r := s.rows[id]; r != nil {
		return r, nil
	}
	return nil, gitsync.ErrNoIdentity
}
func (s *ids) Ensure(_ context.Context, id uuid.UUID, l string) (*gitsync.Identity, error) {
	if r := s.rows[id]; r != nil {
		return r, nil
	}
	s.rows[id] = &gitsync.Identity{UserID: id, ForgejoUsername: l}
	return s.rows[id], nil
}
func (s *ids) MarkLinked(context.Context, uuid.UUID, int64) error { return nil }

type dir struct {
	info    *gitsync.ProjectInfo
	members []gitsync.Member
}

func (d *dir) Project(context.Context, uuid.UUID) (*gitsync.ProjectInfo, error) { return d.info, nil }
func (d *dir) Members(context.Context, uuid.UUID) ([]gitsync.Member, error)     { return d.members, nil }
func (d *dir) Access(context.Context, uuid.UUID, uuid.UUID) (string, map[uuid.UUID]string, error) {
	return authz.ModeOpen, nil, nil
}

func TestReconcileAgainstGitcoreAndFakeForgejo(t *testing.T) {
	fs := fake.New()
	t.Cleanup(fs.Close)
	svc := gitcore.New(gitcore.Config{URL: fs.URL, Token: fake.Token, Timeout: 2 * time.Second,
		BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond}, nil, nil)
	fs.AddRepo("acme", "api")
	fs.AddUser("ana")
	fs.AddUser("bob")

	p := uuid.New()
	ana, bob, ghost := uuid.New(), uuid.New(), uuid.New()
	d := &dir{
		info: &gitsync.ProjectInfo{ID: p, OrgID: uuid.New(), Slug: "api", Repo: gitcore.RepoRef{Owner: "acme", Repo: "api"}},
		members: []gitsync.Member{
			{UserID: ana, Email: "ana@x.io", OrgRole: "owner"},
			{UserID: bob, Email: "bob@x.io", OrgRole: "readonly"},
			{UserID: ghost, Email: "ghost@x.io", OrgRole: "member"}, // never logged into Forgejo
		},
	}
	rec := &gitsync.Reconciler{Forge: svc, Dir: d, IDs: &gitsync.Identities{Store: &ids{rows: map[uuid.UUID]*gitsync.Identity{}}}}

	rep, err := rec.Reconcile(context.Background(), p, gitsync.TriggerEvent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rep.Added, ",") != "ana,bob" || len(rep.Pending) != 1 || rep.Pending[0] != ghost {
		t.Fatalf("report: %+v", rep)
	}
	admin, _ := svc.EnsureTeam(context.Background(), "acme", gitsync.TeamSpecs("api")[authz.RoleAdmin])
	if got, _ := svc.TeamMembers(context.Background(), admin.ID); strings.Join(got, ",") != "ana" {
		t.Fatalf("admin team: %v", got)
	}
	viewer, _ := svc.EnsureTeam(context.Background(), "acme", gitsync.TeamSpecs("api")[authz.RoleViewer])
	if got, _ := svc.TeamMembers(context.Background(), viewer.ID); strings.Join(got, ",") != "bob" {
		t.Fatalf("viewer team: %v", got)
	}

	// second pass changes nothing; then the ghost shows up
	rep, err = rec.Reconcile(context.Background(), p, gitsync.TriggerPeriodic)
	if err != nil || len(rep.Added)+len(rep.Removed) != 0 {
		t.Fatalf("second pass: %+v %v", rep, err)
	}
	fs.AddUser("ghost")
	rep, err = rec.Reconcile(context.Background(), p, gitsync.TriggerEvent)
	if err != nil || strings.Join(rep.Added, ",") != "ghost" || len(rep.Pending) != 0 {
		t.Fatalf("after first login: %+v %v", rep, err)
	}
}

func TestReconcileRouteAuthorization(t *testing.T) {
	serve := func(d *gitsync.Deps, u *domain.User) *httptest.ResponseRecorder {
		r := chi.NewRouter()
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if u != nil {
					req = req.WithContext(middleware.WithUser(req.Context(), u))
				}
				next.ServeHTTP(w, req)
			})
		})
		gitsync.MountGitsync(r, d)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/git/admin/reconcile", nil))
		return w
	}
	admin := &domain.User{ID: uuid.New(), Role: "admin"}
	plain := &domain.User{ID: uuid.New(), Role: "user"}

	if w := serve(&gitsync.Deps{}, nil); w.Code != 401 {
		t.Errorf("anonymous: %d", w.Code)
	}
	if w := serve(&gitsync.Deps{}, plain); w.Code != 403 {
		t.Errorf("non-admin: %d", w.Code)
	}
	if w := serve(nil, admin); w.Code != 501 {
		t.Errorf("no integration: %d", w.Code)
	}

	fs := fake.New()
	t.Cleanup(fs.Close)
	svc := gitcore.New(gitcore.Config{URL: fs.URL, Token: fake.Token, Timeout: 2 * time.Second}, nil, nil)
	deps := &gitsync.Deps{Rec: &gitsync.Reconciler{Forge: svc, Dir: &dir{}, IDs: &gitsync.Identities{Store: &ids{rows: map[uuid.UUID]*gitsync.Identity{}}}, States: emptyStates{}}}
	w := serve(deps, admin)
	if w.Code != 202 || !strings.Contains(w.Body.String(), `"status":"queued"`) {
		t.Fatalf("admin: %d %s", w.Code, w.Body.String())
	}
	// wait for the job, then a second request is accepted again
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if w2 := serve(deps, admin); w2.Code == 202 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the busy flag never cleared")
}

type emptyStates struct{}

func (emptyStates) PutTeamState(context.Context, gitsync.TeamState, bool) error { return nil }
func (emptyStates) ListTeamStates(context.Context, uuid.UUID) ([]gitsync.TeamState, error) {
	return nil, nil
}
func (emptyStates) ListForgejoProjects(context.Context, uuid.UUID, int) ([]uuid.UUID, error) {
	return nil, nil
}
func (emptyStates) AuditDrift(context.Context, uuid.UUID, uuid.UUID, string, map[string]any) error {
	return nil
}
