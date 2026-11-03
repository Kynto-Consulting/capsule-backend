//go:build forgejo

// Package itest checks the assumptions of gitimport against a REAL Forgejo (C1). Run it against a
// Forgejo 15.0.11 started locally with SQLite and `[migrations] ALLOW_LOCALNETWORKS = true` (push
// mirrors and migrations refuse private/loopback targets otherwise, and push_mirrors answers 401
// "Permission denied" for them):
//
//	GITIMPORT_ITEST_URL=http://127.0.0.1:3411 GITIMPORT_ITEST_TOKEN=<admin token> \
//	GITIMPORT_ITEST_BASIC=<admin user>:<admin password> GITIMPORT_ITEST_USERS=alice,bob \
//	go test -tags=forgejo ./internal/gitimport/itest/ -count=1 -v
//
// GITIMPORT_ITEST_BASIC is the credential the push mirror uses to push to the second repository.
// GITIMPORT_ITEST_USERS must be two existing users (only the CODEOWNERS test needs them).
// What this does NOT cover: GitHub itself (migrating from github.com, a push mirror to github.com).
package itest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitimport"
)

type env struct {
	s          *gitcore.Service
	url, token string
	org        string
	basicUser  string
	basicPass  string
	users      []string
}

func setup(t *testing.T) *env {
	t.Helper()
	url, tok := os.Getenv("GITIMPORT_ITEST_URL"), os.Getenv("GITIMPORT_ITEST_TOKEN")
	if url == "" || tok == "" {
		t.Skip("GITIMPORT_ITEST_URL / GITIMPORT_ITEST_TOKEN not set")
	}
	e := &env{s: gitcore.New(gitcore.Config{URL: url, Token: tok, Timeout: 60 * time.Second}, nil, nil), url: url, token: tok,
		org: fmt.Sprintf("c1-%d", time.Now().Unix())}
	e.basicUser, e.basicPass, _ = strings.Cut(os.Getenv("GITIMPORT_ITEST_BASIC"), ":")
	e.users = strings.Split(os.Getenv("GITIMPORT_ITEST_USERS"), ",")
	if err := e.s.EnsureOrg(context.Background(), e.org); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) raw(t *testing.T, method, path string, body any) []byte {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.url+"/api/v1"+path, rd)
	req.Header.Set("Authorization", "token "+e.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		t.Fatalf("%s %s: %d %s", method, path, res.StatusCode, out)
	}
	return out
}

func (e *env) putFile(t *testing.T, repo, branch, path, content string) {
	t.Helper()
	body := map[string]any{"content": base64.StdEncoding.EncodeToString([]byte(content)), "message": "add " + path, "branch": branch}
	// update when it exists
	if out, err := e.try("GET", "/repos/"+e.org+"/"+repo+"/contents/"+path+"?ref="+branch); err == nil {
		var f struct{ SHA string }
		_ = json.Unmarshal(out, &f)
		body["sha"] = f.SHA
		e.raw(t, "PUT", "/repos/"+e.org+"/"+repo+"/contents/"+path, body)
		return
	}
	e.raw(t, "POST", "/repos/"+e.org+"/"+repo+"/contents/"+path, body)
}

func (e *env) try(method, path string) ([]byte, error) {
	req, _ := http.NewRequest(method, e.url+"/api/v1"+path, nil)
	req.Header.Set("Authorization", "token "+e.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return out, fmt.Errorf("%d", res.StatusCode)
	}
	return out, nil
}

func branchNames(t *testing.T, s *gitcore.Service, r gitcore.RepoRef) []string {
	t.Helper()
	l, err := s.ListBranches(context.Background(), r, gitcore.Page{})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, b := range l.Items {
		out = append(out, b.Name)
	}
	sort.Strings(out)
	return out
}

// The push mirror as Mirrors.Put configures it: comma-separated branch_filter (names and globs),
// credentials, interval "0" for on_push; only the configured branches arrive.
func TestForgejoPushMirrorBranchFilter(t *testing.T) {
	e := setup(t)
	if e.basicUser == "" {
		t.Skip("GITIMPORT_ITEST_BASIC not set")
	}
	ctx := context.Background()
	src, dst := gitcore.RepoRef{Owner: e.org, Repo: "src"}, gitcore.RepoRef{Owner: e.org, Repo: "dst"}
	for _, r := range []gitcore.RepoRef{src, dst} {
		if _, err := e.s.EnsureRepo(ctx, r, gitcore.RepoCreate{Name: r.Repo, Private: true, AutoInit: r == src, DefaultBranch: "main"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, b := range []string{"dev", "rel/1", "rel/2"} {
		if _, err := e.s.CreateBranch(ctx, src, b, "main"); err != nil {
			t.Fatal(err)
		}
	}
	pm, err := e.s.AddPushMirror(ctx, src, gitcore.PushMirrorSpec{
		RemoteAddress: e.url + "/" + e.org + "/dst.git", RemoteUsername: e.basicUser, RemotePassword: e.basicPass,
		Interval: "0", SyncOnCommit: true, BranchFilter: gitimport.BranchFilter([]string{"main", "rel/*"})})
	if err != nil {
		if ge, ok := gitcore.AsError(err); ok && ge.Status == 401 {
			t.Skip("Forgejo refused the loopback remote (401 Permission denied): start it with [migrations] ALLOW_LOCALNETWORKS = true")
		}
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprint(pm), e.basicPass) {
		t.Fatal("the mirror object must not carry the password")
	}
	before, _ := e.s.ListPushMirrors(ctx, src)
	var prev time.Time
	if len(before) > 0 {
		prev = before[0].LastUpdate
	}
	if err := e.s.SyncPushMirrors(ctx, src); err != nil {
		t.Fatal(err)
	}
	// Forgejo only QUEUES the push: wait for its verdict (a new last_update) like MirrorService.Sync does
	list := waitVerdict(t, e.s, src, prev)
	got := branchNames(t, e.s, dst)
	for i := 0; i < 20 && len(got) == 0; i++ {
		time.Sleep(500 * time.Millisecond)
		got = branchNames(t, e.s, dst)
	}
	if strings.Join(got, ",") != "main,rel/1,rel/2" {
		t.Fatalf("pushed branches: %v (dev must not leave); mirror state: %+v", got, list)
	}
	if list[0].LastError != "" {
		t.Fatalf("mirror state: %+v", list)
	}
	if err := e.s.DeletePushMirror(ctx, src, pm.RemoteName); err != nil {
		t.Fatal(err)
	}
	// a brace alternation is NOT understood (it is split on commas): the encoding must stay a plain list
	if _, err := e.s.AddPushMirror(ctx, src, gitcore.PushMirrorSpec{RemoteAddress: e.url + "/" + e.org + "/dst.git", RemoteUsername: e.basicUser,
		RemotePassword: e.basicPass, Interval: "0", BranchFilter: "{main,dev}"}); err == nil {
		// the refspec error surfaces either on the call (500) or later as last_error
		if err := e.s.SyncPushMirrors(ctx, src); err == nil {
			if l := waitVerdict(t, e.s, src, time.Time{}); l[0].LastError == "" {
				t.Fatal("expected the brace form to fail: if Forgejo learned it, BranchFilter may change")
			}
		}
	}
}

// Migration from a (local) git remote with the ephemeral token: service git, private flag, idempotent.
func TestForgejoMigrateWithAuthToken(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	src := gitcore.RepoRef{Owner: e.org, Repo: "msrc"}
	if _, err := e.s.EnsureRepo(ctx, src, gitcore.RepoCreate{Name: "msrc", Private: true, AutoInit: true, DefaultBranch: "main"}); err != nil {
		t.Fatal(err)
	}
	spec := gitcore.MigrateSpec{Owner: e.org, Repo: "mdst", CloneAddr: e.url + "/" + e.org + "/msrc.git", AuthToken: e.token, Service: "git", Private: true}
	r, err := e.s.Migrate(ctx, spec)
	if err != nil {
		if ge, ok := gitcore.AsError(err); ok && strings.Contains(ge.Message, "disallowed hosts") {
			t.Skip("Forgejo refused the loopback source: start it with [migrations] ALLOW_LOCALNETWORKS = true")
		}
		t.Fatal(err)
	}
	if !r.Private || r.Name != "mdst" {
		t.Fatalf("migrated: %+v", r)
	}
	if strings.Join(branchNames(t, e.s, gitcore.RepoRef{Owner: e.org, Repo: "mdst"}), ",") != "main" {
		t.Fatal("main must arrive")
	}
	if _, err := e.s.Migrate(ctx, spec); err != nil {
		t.Fatalf("migrating again must be idempotent: %v", err)
	}
}

// ConvertCodeOwners output, committed as CODEOWNERS, requests the expected reviewers on a real pull
// request (Forgejo wraps the expression in ^...$, unites every matching rule, ignores e-mail owners).
func TestForgejoCodeOwnersConversion(t *testing.T) {
	e := setup(t)
	if len(e.users) < 2 || e.users[1] == "" {
		t.Skip("GITIMPORT_ITEST_USERS not set")
	}
	alice, bob := e.users[0], e.users[1]
	ctx := context.Background()
	r := gitcore.RepoRef{Owner: e.org, Repo: "co"}
	if _, err := e.s.EnsureRepo(ctx, r, gitcore.RepoCreate{Name: "co", Private: true, AutoInit: true, DefaultBranch: "main"}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{alice, bob} {
		e.raw(t, "PUT", "/repos/"+e.org+"/co/collaborators/"+u, map[string]string{"permission": "write"})
	}
	for p, c := range map[string]string{"src/x.go": "package x\n", "docs/a.md": "a\n", "lib/b.txt": "b\n"} {
		e.putFile(t, "co", "main", p, c)
	}
	github := "# owners\n*.go @" + alice + "\n/docs/ @" + bob + " @" + e.org + "/writers dev@example.org\n/lib/ @" + bob + "\n"
	rep := gitimport.ConvertCodeOwners(github, e.org)
	e.putFile(t, "co", "main", "CODEOWNERS", rep.Converted)

	changed := func(files ...string) []string {
		br := fmt.Sprintf("pr-%d", time.Now().UnixNano())
		if _, err := e.s.CreateBranch(ctx, r, br, "main"); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			e.putFile(t, "co", br, f, "changed "+br+"\n")
		}
		out := e.raw(t, "POST", "/repos/"+e.org+"/co/pulls", map[string]string{"title": br, "head": br, "base": "main"})
		var pr struct{ Number int }
		_ = json.Unmarshal(out, &pr)
		revs := e.raw(t, "GET", fmt.Sprintf("/repos/%s/co/pulls/%d/reviews", e.org, pr.Number), nil)
		var rs []struct{ User struct{ Login string } }
		_ = json.Unmarshal(revs, &rs)
		var got []string
		for _, x := range rs {
			got = append(got, x.User.Login)
		}
		sort.Strings(got)
		return got
	}
	want := func(users ...string) string { sort.Strings(users); return strings.Join(users, ",") }
	if got := strings.Join(changed("src/x.go"), ","); got != want(alice) {
		t.Errorf("*.go -> %s, want %s\nconverted:\n%s", got, alice, rep.Converted)
	}
	if got := strings.Join(changed("docs/a.md"), ","); got != want(bob) {
		t.Errorf("/docs/ -> %s, want %s (team and e-mail owners are dropped)", got, bob)
	}
	if got := strings.Join(changed("src/x.go", "lib/b.txt"), ","); got != want(alice, bob) {
		t.Errorf("two rules -> %s, want %s", got, want(alice, bob))
	}
}

// waitVerdict polls until the push mirror reports a last_update (the queued push ran).
func waitVerdict(t *testing.T, s *gitcore.Service, r gitcore.RepoRef, after time.Time) []gitcore.PushMirror {
	t.Helper()
	for i := 0; i < 40; i++ {
		l, err := s.ListPushMirrors(context.Background(), r)
		if err == nil && len(l) > 0 && l[len(l)-1].LastUpdate.Year() > 2000 && l[len(l)-1].LastUpdate.After(after) {
			return l
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("Forgejo reported no outcome of the queued push within 20 s")
	return nil
}
