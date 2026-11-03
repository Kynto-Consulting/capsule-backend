package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/gitreview"
)

type grProjects struct{ p gitreview.Project }

func (f grProjects) ByID(context.Context, uuid.UUID) (*gitreview.Project, error) {
	p := f.p
	return &p, nil
}
func (f grProjects) ByRef(context.Context, gitcore.RepoRef) (*gitreview.Project, error) {
	p := f.p
	return &p, nil
}

type grRoster []gitreview.Member

func (r grRoster) Members(context.Context, gitreview.Project) ([]gitreview.Member, error) {
	return r, nil
}

// newGrRig mounts the B8 routes on the B1 rig (same fake Forgejo, same fake auth).
func newGrRig(t *testing.T, role string) *gapiRig {
	t.Helper()
	g := newGapiRig(t, gapiOpts{role: role})
	access, orgRole := gapiAccess(role, g.proj.ID)
	roster := grRoster{
		{UserID: uuid.New(), Login: "alice", Role: authz.RoleAdmin},
		{UserID: g.user.ID, Login: gapiActor, Role: authz.RoleDeployer},
		{UserID: uuid.New(), Login: "vera", Role: authz.RoleViewer},
	}
	svc := gitreview.New(g.core, grProjects{gitreview.Project{ID: g.proj.ID, OrgID: g.org.ID, Ref: gitcore.RepoRef{Owner: gapiOrgSlug, Repo: gapiRepoSlug}}},
		roster, gitreview.NewMemStore(), gitreview.Config{}, nil)
	svc.Publisher = gitevents.Discard
	MountGitReview(g.router, GitReviewDeps{Authz: authz.New(gapiStore{access}), Orgs: &gapiOrgs{org: g.org, role: orgRole},
		Projects: gapiProjects{p: g.proj}, Svc: svc, Core: g.core,
		Actor: func(context.Context, *domain.User) (string, error) { return *g.actor, nil }})
	return g
}

func TestGitReviewPermissions(t *testing.T) {
	cases := []struct {
		role, method, path string
		body               any
		want               int
	}{
		{"viewer", "GET", "/codeowners", nil, 200},
		{"viewer", "PUT", "/pulls/1/auto-merge", map[string]any{"style": "squash"}, 403},
		{"viewer", "DELETE", "/pulls/1/auto-merge", nil, 403},
		{"viewer", "POST", "/pulls/1/ready", nil, 403},
		{"viewer", "POST", "/pulls/1/reviewers", map[string]any{"users": []string{"alice"}}, 403},
		{"deployer", "POST", "/pulls/1/reviews/1/dismiss", map[string]any{"reason": "obsoleta"}, 403},
		{"hidden", "GET", "/codeowners", nil, 404},
		{"none", "GET", "/codeowners", nil, 403},
	}
	for _, c := range cases {
		g := newGrRig(t, c.role)
		rec := g.do(c.method, c.path, c.body)
		if rec.Code != c.want {
			t.Errorf("%s %s %s: %d want %d: %s", c.role, c.method, c.path, rec.Code, c.want, rec.Body.String())
		}
	}
}

func TestGitReviewCodeowners(t *testing.T) {
	g := newGrRig(t, "viewer")
	empty := g.do("GET", "/codeowners?ref=feature", nil)
	gapiWant(t, empty, 200)
	m := gapiMap(t, empty)
	if rules, _ := m["rules"].([]any); len(rules) != 0 {
		t.Fatalf("no CODEOWNERS: %v", m)
	}
	g.fs.Commit(gapiOrgSlug, gapiRepoSlug, "main", "owners", map[string]string{
		"CODEOWNERS": "# owners\n^src/ @alice @ghost\n*.md @vera\n",
	})
	rec := g.do("GET", "/codeowners?ref=main", nil)
	gapiWant(t, rec, 200)
	m = gapiMap(t, rec)
	rules, _ := m["rules"].([]any)
	if m["path"] != "CODEOWNERS" || len(rules) != 1 {
		t.Fatalf("doc: %v", m)
	}
	r0 := rules[0].(map[string]any)
	users := r0["resolved_users"].([]any)
	if r0["pattern"] != "^src/" || len(users) != 1 || users[0].(map[string]any)["login"] != "alice" {
		t.Fatalf("rule: %v", r0)
	}
	w := strings.Join(toStrings(m["warnings"]), "|")
	if !strings.Contains(w, "@ghost") || !strings.Contains(w, "expresion regular invalida") {
		t.Fatalf("warnings: %s", w)
	}
	gapiWant(t, g.do("GET", "/codeowners?ref=bad..ref", nil), 422)
}

func toStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		out = append(out, x.(string))
	}
	return out
}

func TestGitReviewAutoMergeAndReady(t *testing.T) {
	g := newGrRig(t, "deployer")
	// body validation
	gapiWant(t, g.do("PUT", "/pulls/1/auto-merge", map[string]any{"style": "octopus"}), 422)
	gapiWant(t, g.do("PUT", "/pulls/1/auto-merge", map[string]any{"style": "squash", "head_sha": "zz"}), 422)
	gapiWant(t, g.do("PUT", "/pulls/1/auto-merge", `{"style":"squash","bogus":1}`), 422)
	// a stale head_sha is a 409 and nothing is armed
	rec := g.do("PUT", "/pulls/1/auto-merge", map[string]any{"style": "squash", "head_sha": strings.Repeat("a", 40)})
	gapiWant(t, rec, 409)
	if c := gapiErrCode(t, rec); c != "HEAD_CHANGED" {
		t.Fatalf("code %s", c)
	}
	// unknown pull request
	gapiWant(t, g.do("PUT", "/pulls/99/auto-merge", map[string]any{"style": "squash"}), 404)
	// disabling without auto-merge is idempotent
	gapiWant(t, g.do("DELETE", "/pulls/1/auto-merge", nil), 204)
	gapiWant(t, g.do("DELETE", "/pulls/1/auto-merge", nil), 204)
	// ready on a pull request that is not a draft is a no-op that returns the document
	rec = g.do("POST", "/pulls/1/ready", nil)
	gapiWant(t, rec, 200)
	if m := gapiMap(t, rec); m["draft"] != false || m["number"] != float64(1) {
		t.Fatalf("pull: %v", m)
	}
	// identity not ready: a strict action refuses to run as the service account
	g.as("")
	gapiWant(t, g.do("POST", "/pulls/1/ready", nil), 503)
	g.as(gapiActor)
	// enabling on the current head: either armed or merged right away, never an error
	rec = g.do("PUT", "/pulls/1/auto-merge", map[string]any{"style": "squash", "delete_branch": false})
	gapiWant(t, rec, 200)
	if m := gapiMap(t, rec); m["number"] != float64(1) {
		t.Fatalf("pull: %v", m)
	}
}

func TestGitReviewReviewersAndDismiss(t *testing.T) {
	g := newGrRig(t, "admin")
	// the viewer cannot review, unknown people are not members
	for _, u := range []string{"vera", "nobody"} {
		gapiWant(t, g.do("POST", "/pulls/1/reviewers", map[string]any{"users": []string{u}}), 422)
	}
	gapiWant(t, g.do("POST", "/pulls/1/reviewers", map[string]any{"users": []string{}}), 422)
	gapiWant(t, g.do("POST", "/pulls/1/reviewers", map[string]any{"users": []string{"bad login!"}}), 422)
	rec := g.do("POST", "/pulls/1/reviewers", map[string]any{"users": []string{"alice"}})
	// the pull request author is alice in the fixture: asking her is refused with a clear reason
	gapiWant(t, rec, 422)
	// dismiss: bad reason, unknown review
	gapiWant(t, g.do("POST", "/pulls/1/reviews/1/dismiss", map[string]any{"reason": "ab"}), 422)
	gapiWant(t, g.do("POST", "/pulls/1/reviews/abc/dismiss", map[string]any{"reason": "obsoleta"}), 400)
	gapiWant(t, g.do("POST", "/pulls/1/reviews/12345/dismiss", map[string]any{"reason": "obsoleta"}), 404)
	_ = http.StatusOK
}
