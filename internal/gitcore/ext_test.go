package gitcore_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

func code(err error) gitcore.Code {
	e, ok := gitcore.AsError(err)
	if !ok {
		return ""
	}
	return e.Code
}

func TestExtSecretsNamesOnly(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	r := gitcore.RepoRef{Owner: "acme", Repo: "web"}
	if err := s.SetSecret(ctx, r, "TOKEN_A", "value-one"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret(ctx, gitcore.RepoRef{Owner: "acme"}, "ORG_B", "value-two"); err != nil {
		t.Fatal(err)
	}
	rs, err := s.ListSecrets(ctx, r)
	if err != nil || len(rs) != 1 || rs[0].Name != "TOKEN_A" {
		t.Fatalf("repo: %+v %v", rs, err)
	}
	os, err := s.ListSecrets(ctx, gitcore.RepoRef{Owner: "acme"})
	if err != nil || len(os) != 1 || os[0].Name != "ORG_B" {
		t.Fatalf("org: %+v %v", os, err)
	}
	b, _ := json.Marshal(append(rs, os...))
	if strings.Contains(string(b), "value-") {
		t.Fatal("a secret value leaked")
	}
	if _, err := s.ListSecrets(ctx, gitcore.RepoRef{Owner: "ghost", Repo: "x"}); code(err) != gitcore.CodeNotFound {
		t.Fatalf("unknown repo: %v", err)
	}
}

func TestExtRunners(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	fs.AddRunner("repo", "acme", "web", "r1", "idle", "docker")
	fs.AddRunner("org", "acme", "", "r2", "active")
	fs.AddRunner("global", "", "", "r3", "offline")
	repo, err := s.ListRunners(ctx, gitcore.RunnerScope{Owner: "acme", Repo: "web"})
	if err != nil || len(repo) != 1 || repo[0].Status != "online" || repo[0].Scope != "repo" || repo[0].Labels[0] != "docker" {
		t.Fatalf("repo: %+v %v", repo, err)
	}
	org, err := s.ListRunners(ctx, gitcore.RunnerScope{Owner: "acme"})
	if err != nil || len(org) != 1 || org[0].Status != "busy" || org[0].Scope != "org" || org[0].Labels == nil {
		t.Fatalf("org: %+v %v", org, err)
	}
	vis, _ := s.ListRunners(ctx, gitcore.RunnerScope{Owner: "acme", Repo: "web", Visible: true})
	if len(vis) != 3 {
		t.Fatalf("visible: %+v", vis)
	}
	all, err := s.ListRunners(ctx, gitcore.RunnerScope{Global: true})
	if err != nil || len(all) != 3 || all[2].Status != "offline" || all[2].Scope != "global" {
		t.Fatalf("global: %+v %v", all, err)
	}
}

func TestExtRerunRun(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	r := gitcore.RepoRef{Owner: "acme", Repo: "web"}
	running, _ := fs.AddRun("acme", "web", "running", "")
	done, _ := fs.AddRun("acme", "web", "failure", "boom")
	if _, err := s.RerunRun(ctx, r, running, false); code(err) != gitcore.CodeConflict {
		t.Fatalf("unfinished run: %v", err)
	}
	// web re-run: Forgejo re-uses the SAME run (new attempt)
	nw, err := s.RerunRun(ctx, r, done, true)
	if err != nil || nw.ID != done || nw.Status != "waiting" {
		t.Fatalf("rerun failed only: %+v %v", nw, err)
	}
	if _, err := s.RerunRun(ctx, r, done, false); code(err) != gitcore.CodeConflict {
		t.Fatalf("re-running a run that is waiting again must conflict: %v", err)
	}
	if _, err := s.RerunRun(ctx, r, 999, false); code(err) != gitcore.CodeNotFound {
		t.Fatalf("unknown run: %v", err)
	}
	if st := (&gitcore.Error{Code: gitcore.CodeUnsupported}); st.HTTPStatus() == 0 {
		t.Fatal("status")
	}
}

func TestExtPatchTeamAndGetUser(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	fs.AddUser("alice")
	tm, err := s.EnsureTeam(ctx, "acme", gitcore.TeamSpec{Name: "web-admin", Permission: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.PatchTeam(ctx, tm.ID, gitcore.TeamPatch{Permission: "write", Units: []string{"repo.code", "repo.pulls"}})
	if err != nil || got.Permission != "write" || got.Name != "web-admin" {
		t.Fatalf("PatchTeam: %+v %v", got, err)
	}
	for _, rq := range fs.Requests() {
		if rq.Method == "PATCH" {
			if !strings.Contains(rq.Body, `"permission":"write"`) || !strings.Contains(rq.Body, `"repo.pulls":"write"`) || !strings.Contains(rq.Body, `"name":"web-admin"`) {
				t.Fatalf("patch body: %s", rq.Body)
			}
		}
	}
	if _, err := s.PatchTeam(ctx, 4242, gitcore.TeamPatch{Permission: "read"}); code(err) != gitcore.CodeNotFound {
		t.Fatalf("unknown team: %v", err)
	}
	if _, err := s.PatchTeam(ctx, tm.ID, gitcore.TeamPatch{Permission: "owner"}); code(err) != gitcore.CodeInvalid {
		t.Fatalf("bad permission: %v", err)
	}
	u, err := s.GetUser(ctx, "alice")
	if err != nil || u.ID < 1 || u.Login != "alice" {
		t.Fatalf("GetUser: %+v %v", u, err)
	}
	if _, err := s.GetUser(ctx, "ghost"); code(err) != gitcore.CodeNotFound {
		t.Fatalf("ghost: %v", err)
	}
	if _, err := s.GetUser(ctx, "a/b"); code(err) != gitcore.CodeInvalid {
		t.Fatalf("path chars: %v", err)
	}
}

func TestExtTagProtection(t *testing.T) {
	s, fs, _ := newSvc(t)
	ctx := context.Background()
	fs.AddRepo("acme", "web")
	r := gitcore.RepoRef{Owner: "acme", Repo: "web"}
	if l, err := s.ListTagProtections(ctx, r); err != nil || len(l) != 0 {
		t.Fatalf("empty: %+v %v", l, err)
	}
	tp, err := s.CreateTagProtection(ctx, r, gitcore.TagProtectionSpec{Pattern: "v*", WhitelistTeams: []string{"web-admin"}})
	if err != nil || tp.ID < 1 || !fs.HasTagProtection("acme", "web", "v*") {
		t.Fatalf("create: %+v %v", tp, err)
	}
	if _, err := s.CreateTagProtection(ctx, r, gitcore.TagProtectionSpec{Pattern: "v*"}); code(err) != gitcore.CodeUnprocessed {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := s.CreateTagProtection(ctx, r, gitcore.TagProtectionSpec{}); code(err) != gitcore.CodeInvalid {
		t.Fatalf("empty pattern: %v", err)
	}
	l, err := s.ListTagProtections(ctx, r)
	if err != nil || len(l) != 1 || l[0].WhitelistTeams[0] != "web-admin" || l[0].WhitelistUsers == nil {
		t.Fatalf("list: %+v %v", l, err)
	}
	ed, err := s.EditTagProtection(ctx, r, tp.ID, gitcore.TagProtectionSpec{Pattern: "v*", WhitelistTeams: []string{"web-admin", "web-deployer"}})
	if err != nil || ed.ID != tp.ID || len(ed.WhitelistTeams) != 2 {
		t.Fatalf("edit: %+v %v", ed, err)
	}
	if _, err := s.EditTagProtection(ctx, r, 999, gitcore.TagProtectionSpec{Pattern: "v*"}); code(err) != gitcore.CodeNotFound {
		t.Fatalf("edit unknown: %v", err)
	}
	if err := s.DeleteTagProtection(ctx, r, tp.ID); err != nil || fs.HasTagProtection("acme", "web", "v*") {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeleteTagProtection(ctx, r, tp.ID); code(err) != gitcore.CodeNotFound {
		t.Fatalf("delete twice: %v", err)
	}
}

func TestExtInterfaces(t *testing.T) {
	var c gitcore.Core = gitcore.New(gitcore.Config{}, nil, nil)
	if _, ok := c.(gitcore.ActionsExt); !ok {
		t.Fatal("ActionsExt")
	}
	if _, ok := c.(gitcore.TeamAdmin); !ok {
		t.Fatal("TeamAdmin")
	}
	if _, ok := c.(gitcore.UserDirectory); !ok {
		t.Fatal("UserDirectory")
	}
	if _, ok := c.(gitcore.TagProtections); !ok {
		t.Fatal("TagProtections")
	}
}
