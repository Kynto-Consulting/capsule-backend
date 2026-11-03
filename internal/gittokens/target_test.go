package gittokens_test

import (
	"testing"

	"github.com/kynto/capsule/backend/internal/gittokens"
)

func TestClassifyGitRequest(t *testing.T) {
	tests := []struct {
		name, method, uri string
		want              gittokens.Target
		ok                bool
	}{
		{"clone refs", "GET", "/acme/web.git/info/refs?service=git-upload-pack", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpRead}, true},
		{"clone refs without .git", "GET", "/acme/web/info/refs?service=git-upload-pack", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpRead}, true},
		{"fetch", "POST", "/acme/web.git/git-upload-pack", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpRead}, true},
		{"push refs", "GET", "/acme/web.git/info/refs?service=git-receive-pack", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpWrite}, true},
		{"push", "POST", "/acme/web.git/git-receive-pack", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpWrite}, true},
		{"case folded", "GET", "/ACME/Web.git/info/refs?service=git-upload-pack", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpRead}, true},
		{"dumb refs", "GET", "/acme/web.git/info/refs", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpRead}, true},
		{"HEAD file", "GET", "/acme/web.git/HEAD", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpRead}, true},
		{"loose object", "GET", "/acme/web.git/objects/ab/cdef0123456789012345678901234567890123", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpRead}, true},
		{"lfs batch is read", "POST", "/acme/web.git/info/lfs/objects/batch", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpRead}, true},
		{"lfs download", "GET", "/acme/web.git/info/lfs/objects/abc123", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpRead}, true},
		{"lfs upload", "PUT", "/acme/web.git/info/lfs/objects/abc123/42", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpWrite}, true},
		{"lfs verify", "POST", "/acme/web.git/info/lfs/verify", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpWrite}, true},
		{"lfs lock create", "POST", "/acme/web.git/info/lfs/locks", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpWrite}, true},
		{"lfs lock list", "GET", "/acme/web.git/info/lfs/locks", gittokens.Target{Owner: "acme", Repo: "web", Op: gittokens.OpRead}, true},

		// Rejected: wrong verbs, unknown services, unknown routes.
		{"upload-pack via GET", "GET", "/acme/web.git/git-upload-pack", gittokens.Target{}, false},
		{"receive-pack via GET", "GET", "/acme/web.git/git-receive-pack", gittokens.Target{}, false},
		{"unknown service", "GET", "/acme/web.git/info/refs?service=evil", gittokens.Target{}, false},
		{"api path is not git", "GET", "/api/v1/repos/acme/web", gittokens.Target{}, false},
		{"settings page", "GET", "/acme/web/settings", gittokens.Target{}, false},
		{"missing repo", "GET", "/acme/info/refs", gittokens.Target{}, false},
		{"empty", "GET", "", gittokens.Target{}, false},
		{"not a path", "GET", "http://evil/acme/web.git/info/refs", gittokens.Target{}, false},

		// Rejected: anything non-canonical, so the repo checked is the repo Forgejo serves.
		{"dot dot", "GET", "/acme/web.git/../other.git/info/refs", gittokens.Target{}, false},
		{"dot dot owner", "GET", "/acme/../other/web.git/info/refs", gittokens.Target{}, false},
		{"double slash", "GET", "/acme//web.git/info/refs", gittokens.Target{}, false},
		{"leading double slash", "GET", "//acme/web.git/info/refs", gittokens.Target{}, false},
		{"percent encoded slash", "GET", "/acme/web%2f..%2fother.git/info/refs", gittokens.Target{}, false},
		{"percent encoded dot", "GET", "/acme/%2e%2e/other/info/refs", gittokens.Target{}, false},
		{"backslash", "GET", "/acme/web\\..\\other.git/info/refs", gittokens.Target{}, false},
		{"space", "GET", "/acme/we b.git/info/refs", gittokens.Target{}, false},
		{"double .git", "GET", "/acme/web.git.git/info/refs", gittokens.Target{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := gittokens.ClassifyGitRequest(tt.method, tt.uri)
			if (err == nil) != tt.ok {
				t.Fatalf("ok=%v, err=%v", tt.ok, err)
			}
			if tt.ok && got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseRepoPath(t *testing.T) {
	for in, want := range map[string]string{"acme/web": "acme/web", "/acme/web.git": "acme/web", "ACME/Web.git": "acme/web"} {
		o, r, err := gittokens.ParseRepoPath(in)
		if err != nil || o+"/"+r != want {
			t.Fatalf("%q => %s/%s, %v", in, o, r, err)
		}
	}
	for _, in := range []string{"", "acme", "acme/web/extra", "../web", "acme/we b", "acme/web?x=1"} {
		if _, _, err := gittokens.ParseRepoPath(in); err == nil {
			t.Fatalf("%q must be rejected", in)
		}
	}
}
