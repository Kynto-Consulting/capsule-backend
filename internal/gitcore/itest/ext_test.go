//go:build forgejo

package itest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

func (e *env) rawGet(t *testing.T, path string, out any) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.url+"/api/v1"+path, nil)
	req.Header.Set("Authorization", "token "+e.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		t.Fatalf("setup GET %s: %d %s", path, res.StatusCode, b)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
}

// TestForgejoIntegratorAdditions runs the gitcore additions (ext.go) against a REAL Forgejo:
// GetUser, PatchTeam, ListSecrets (repo+org), ListRunners (repo/org/global, with runners
// registered through the API; no daemon is attached so they are offline), tag protection and the
// explicit "not supported" answers. Run/artifact behaviour needs a runner and is NOT covered here
// (see TestForgejoRerunRun for the optional re-run check on a finished run).
func TestForgejoIntegratorAdditions(t *testing.T) {
	e := setup(t)
	s, ctx := e.s, context.Background()
	if err := s.EnsureOrg(ctx, e.org); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureRepo(ctx, e.r, gitcore.RepoCreate{Name: "web", Private: true, AutoInit: true, DefaultBranch: "main"}); err != nil {
		t.Fatal(err)
	}

	// GetUser: numeric id of an existing login, not found for a ghost
	u, err := s.GetUser(ctx, e.u1)
	if err != nil || u.ID < 1 || !strings.EqualFold(u.Login, e.u1) {
		t.Fatalf("GetUser: %+v %v", u, err)
	}
	if _, err := s.GetUser(ctx, "no-such-user-xyz"); !isCode(err, gitcore.CodeNotFound) {
		t.Fatalf("GetUser ghost: %v", err)
	}

	// PatchTeam: a team born with permission admin goes to write and gets its units fixed
	tm, err := s.EnsureTeam(ctx, e.org, gitcore.TeamSpec{Name: "web-admin", Permission: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddTeamRepo(ctx, tm.ID, e.r); err != nil {
		t.Fatal(err)
	}
	got, err := s.PatchTeam(ctx, tm.ID, gitcore.TeamPatch{Permission: "write", Units: []string{"repo.code", "repo.pulls", "repo.releases"}})
	if err != nil || got.Permission != "write" || got.Name != "web-admin" {
		t.Fatalf("PatchTeam: %+v %v", got, err)
	}
	var raw struct {
		Permission string            `json:"permission"`
		Units      []string          `json:"units"`
		UnitsMap   map[string]string `json:"units_map"`
	}
	e.rawGet(t, "/teams/"+itoa(tm.ID), &raw)
	t.Logf("team after patch: %+v", raw)
	if raw.Permission != "write" || len(raw.Units) != 3 || raw.UnitsMap["repo.pulls"] != "write" {
		t.Fatalf("team not patched in Forgejo: %+v", raw)
	}
	if _, err := s.PatchTeam(ctx, 987654, gitcore.TeamPatch{Permission: "read"}); !isCode(err, gitcore.CodeNotFound) {
		t.Fatalf("PatchTeam unknown: %v", err)
	}

	// ListSecrets: names only, repo and org
	if err := s.SetSecret(ctx, e.r, "REPO_TOKEN", "super-secret-value"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret(ctx, gitcore.RepoRef{Owner: e.org}, "ORG_TOKEN", "org-secret-value"); err != nil {
		t.Fatal(err)
	}
	rs, err := s.ListSecrets(ctx, e.r)
	if err != nil || len(rs) != 1 || rs[0].Name != "REPO_TOKEN" {
		t.Fatalf("ListSecrets repo: %+v %v", rs, err)
	}
	os_, err := s.ListSecrets(ctx, gitcore.RepoRef{Owner: e.org})
	if err != nil || len(os_) != 1 || os_[0].Name != "ORG_TOKEN" {
		t.Fatalf("ListSecrets org: %+v %v", os_, err)
	}
	if b, _ := json.Marshal(append(rs, os_...)); strings.Contains(string(b), "secret-value") {
		t.Fatal("a secret value leaked")
	}

	// ListRunners: register one per scope through the API (swagger registerRepoRunner/registerOrgRunner)
	e.rawPost(t, "/repos/"+e.org+"/web/actions/runners", map[string]any{"name": "r-repo", "description": "t", "ephemeral": false})
	e.rawPost(t, "/orgs/"+e.org+"/actions/runners", map[string]any{"name": "r-org", "description": "t", "ephemeral": false})
	rr, err := s.ListRunners(ctx, gitcore.RunnerScope{Owner: e.org, Repo: "web"})
	if err != nil || len(rr) != 1 || rr[0].Name != "r-repo" || rr[0].Scope != "repo" || rr[0].Status != "offline" {
		t.Fatalf("ListRunners repo: %+v %v", rr, err)
	}
	ro, err := s.ListRunners(ctx, gitcore.RunnerScope{Owner: e.org})
	if err != nil || len(ro) != 1 || ro[0].Name != "r-org" || ro[0].Scope != "org" {
		t.Fatalf("ListRunners org: %+v %v", ro, err)
	}
	rv, err := s.ListRunners(ctx, gitcore.RunnerScope{Owner: e.org, Repo: "web", Visible: true})
	if err != nil || len(rv) != 2 {
		t.Fatalf("ListRunners repo visible: %+v %v", rv, err)
	}
	if rg, err := s.ListRunners(ctx, gitcore.RunnerScope{Global: true}); err != nil || rg == nil {
		t.Fatalf("ListRunners global: %+v %v", rg, err)
	}

	// Tag protection: create, list, delete
	tp, err := s.CreateTagProtection(ctx, e.r, gitcore.TagProtectionSpec{Pattern: "v*", WhitelistTeams: []string{"web-admin"}})
	if err != nil || tp.ID < 1 || tp.Pattern != "v*" {
		t.Fatalf("CreateTagProtection: %+v %v", tp, err)
	}
	tl, err := s.ListTagProtections(ctx, e.r)
	if err != nil || len(tl) != 1 || tl[0].Pattern != "v*" || len(tl[0].WhitelistTeams) != 1 || tl[0].WhitelistTeams[0] != "web-admin" {
		t.Fatalf("ListTagProtections: %+v %v", tl, err)
	}
	// Observed on v15.0.11: the service account (site admin) is NOT exempt; only whitelisted
	// users/teams create protected tags. A member of the whitelisted team can (acting via Sudo),
	// another repo writer cannot.
	if _, errSvc := s.CreateTag(ctx, e.r, "v1.0.0", "main", ""); !isCode(errSvc, gitcore.CodeUnprocessed) {
		t.Fatalf("service account must be refused on a protected tag: %v", errSvc)
	}
	wt, err := s.EnsureTeam(ctx, e.org, gitcore.TeamSpec{Name: "web-deployer", Permission: "write"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddTeamRepo(ctx, wt.ID, e.r); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][2]any{{tm.ID, e.u1}, {wt.ID, e.u2}} {
		if err := s.AddTeamMember(ctx, p[0].(int64), p[1].(string)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateTag(gitcore.WithActor(ctx, e.u1), e.r, "v1.0.0", "main", ""); err != nil {
		t.Fatalf("whitelisted team member must create the protected tag: %v", err)
	}
	if _, err := s.CreateTag(gitcore.WithActor(ctx, e.u2), e.r, "v1.0.1", "main", ""); !isCode(err, gitcore.CodeUnprocessed) {
		t.Fatalf("a non-whitelisted writer must be refused: %v", err)
	}
	_, errOK := s.CreateTag(ctx, e.r, "free-1", "main", "")
	if errOK != nil {
		t.Fatalf("an unprotected tag name must be creatable: %v", errOK)
	}
	ed, err := s.EditTagProtection(ctx, e.r, tp.ID, gitcore.TagProtectionSpec{Pattern: "v*", WhitelistTeams: []string{"web-admin", "web-deployer"}})
	if err != nil || ed.ID != tp.ID || len(ed.WhitelistTeams) != 2 {
		t.Fatalf("EditTagProtection: %+v %v", ed, err)
	}
	if _, err := s.CreateTag(gitcore.WithActor(ctx, e.u2), e.r, "v1.0.2", "main", ""); err != nil {
		t.Fatalf("after the edit the deployer team may create protected tags: %v", err)
	}
	if err := s.DeleteTagProtection(ctx, e.r, tp.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTagProtection(ctx, e.r, tp.ID); !isCode(err, gitcore.CodeNotFound) {
		t.Fatalf("second delete must be NotFound: %v", err)
	}
	if tl, _ := s.ListTagProtections(ctx, e.r); len(tl) != 0 {
		t.Fatalf("rule not deleted: %+v", tl)
	}

	// Honest "not supported" answers
	if _, err := s.ListArtifacts(ctx, e.r, 1); !gitcore.IsUnsupported(err) {
		t.Fatalf("ListArtifacts: %v", err)
	}
	if _, err := s.RerunRun(ctx, e.r, 1, true); !gitcore.IsUnsupported(err) {
		t.Fatalf("RerunRun failedOnly: %v", err)
	}
}

// TestForgejoRerunRun re-runs a FINISHED run. Without a runner no run ever finishes, so the
// operator marks one finished in the instance database and passes it in:
// GITCORE_ITEST_RERUN="owner/repo#runID". Skipped otherwise.
func TestForgejoRerunRun(t *testing.T) {
	e := setup(t)
	spec := os.Getenv("GITCORE_ITEST_RERUN")
	if spec == "" {
		t.Skip("GITCORE_ITEST_RERUN not set")
	}
	repo, idS, _ := strings.Cut(spec, "#")
	o, n, _ := strings.Cut(repo, "/")
	var id int64
	for _, c := range idS {
		id = id*10 + int64(c-'0')
	}
	r := gitcore.RepoRef{Owner: o, Repo: n}
	old, err := e.s.GetRun(context.Background(), r, id)
	if err != nil {
		t.Fatal(err)
	}
	nw, err := e.s.RerunRun(context.Background(), r, id, false)
	if err != nil || nw.ID <= old.ID || nw.WorkflowID != old.WorkflowID {
		t.Fatalf("RerunRun: old %+v new %+v err %v", old, nw, err)
	}
	t.Logf("new run %d (%s) status %s event %s", nw.ID, nw.WorkflowID, nw.Status, nw.Event)
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }
