package gitsource

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- signatures -----------------------------------------------------------

func TestVerifySignaturePerProvider(t *testing.T) {
	body := []byte(`{"ref":"refs/heads/main"}`)
	secret := "s3cret"
	hexSig := strings.TrimPrefix(Sign(body, secret), "sha256=")
	cases := []struct {
		name   string
		header string
		value  string
		secret string
		want   bool
	}{
		{"github valid", "X-Hub-Signature-256", "sha256=" + hexSig, secret, true},
		{"forgejo hex valid", "X-Forgejo-Signature", hexSig, secret, true},
		{"gitea hex valid", "X-Gitea-Signature", hexSig, secret, true},
		{"gitea via hub header", "X-Hub-Signature-256", "sha256=" + hexSig, secret, true},
		{"generic valid", "X-Capsule-Signature", hexSig, secret, true},
		{"generic prefixed valid", "X-Capsule-Signature", "sha256=" + hexSig, secret, true},
		{"github wrong secret", "X-Hub-Signature-256", "sha256=" + hexSig, "other", false},
		{"forgejo tampered", "X-Forgejo-Signature", strings.Repeat("0", 64), secret, false},
		{"not hex", "X-Gitea-Signature", "zzzz", secret, false},
		{"empty header value", "X-Hub-Signature-256", "", secret, false},
		{"sha1 legacy ignored", "X-Hub-Signature", "sha1=abc", secret, false},
		{"empty secret never verifies", "X-Hub-Signature-256", "sha256=" + hexSig, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := http.Header{}
			h.Set(c.header, c.value)
			if got := VerifySignature(h, body, c.secret); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
	t.Run("no signature header at all", func(t *testing.T) {
		if VerifySignature(http.Header{}, body, secret) {
			t.Fatal("must not verify without signature")
		}
	})
	t.Run("body modified", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-Hub-Signature-256", "sha256="+hexSig)
		if VerifySignature(h, append(body, ' '), secret) {
			t.Fatal("signature must cover the body")
		}
	})
}

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func TestParseEventPush(t *testing.T) {
	body := []byte(`{"ref":"refs/heads/main","after":"0123456789abcdef0123456789abcdef01234567",
	 "head_commit":{"message":"fix: thing\n\nbody","url":"https://github.com/o/r/commit/0123456"},
	 "pusher":{"name":"Ana"},"sender":{"login":"ana"},
	 "repository":{"clone_url":"https://github.com/o/r.git","html_url":"https://github.com/o/r"}}`)
	ev, err := ParseEvent(hdr("X-GitHub-Event", "push"), body)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != EventPush || ev.Branch != "main" || ev.Provider != "github" || ev.Actor != "ana" || ev.Deleted {
		t.Fatalf("unexpected event %+v", ev)
	}
	if !SameRepo("https://github.com/O/R", ev.RepoURLs) || SameRepo("https://github.com/o/other", ev.RepoURLs) {
		t.Fatal("repo matching wrong")
	}

	// tag push and branch deletion
	ev, _ = ParseEvent(hdr("X-GitHub-Event", "push"), []byte(`{"ref":"refs/tags/v1","after":"abc"}`))
	if ev.Kind != EventIgnored {
		t.Fatal("tags must be ignored")
	}
	ev, _ = ParseEvent(hdr("X-Gitea-Event", "push"), []byte(`{"ref":"refs/heads/x","after":"0000000000000000000000000000000000000000"}`))
	if !ev.Deleted {
		t.Fatal("branch deletion not detected")
	}
	// unrelated event
	ev, _ = ParseEvent(hdr("X-GitHub-Event", "issues"), []byte(`{}`))
	if ev.Kind != EventIgnored {
		t.Fatal("other events must be ignored")
	}
	if _, err := ParseEvent(hdr(), []byte(`not json`)); err == nil {
		t.Fatal("expected error on bad json")
	}
}

func TestParseEventPullRequest(t *testing.T) {
	mk := func(action, headRepo string) []byte {
		b, _ := json.Marshal(map[string]any{
			"action": action, "number": 7,
			"pull_request": map[string]any{
				"html_url": "https://git.x/o/r/pulls/7", "merged": true,
				"head": map[string]any{"ref": "feat/x", "sha": "abcdef1234567", "repo": map[string]any{"full_name": headRepo}},
				"base": map[string]any{"ref": "main", "repo": map[string]any{"full_name": "o/r", "clone_url": "https://git.x/o/r.git"}},
			},
			"sender": map[string]any{"login": "bob"},
		})
		return b
	}
	for action, want := range map[string]string{"opened": "opened", "reopened": "reopened", "synchronize": "synchronize", "synchronized": "synchronize", "closed": "closed"} {
		ev, err := ParseEvent(hdr("X-Forgejo-Event", "pull_request"), mk(action, "o/r"))
		if err != nil || ev.Kind != EventPullRequest || ev.Action != want || ev.PR != 7 || ev.Branch != "feat/x" || ev.HeadFork {
			t.Fatalf("%s: %+v %v", action, ev, err)
		}
	}
	ev, _ := ParseEvent(hdr("X-GitHub-Event", "pull_request"), mk("labeled", "o/r"))
	if ev.Kind != EventIgnored {
		t.Fatal("labeled must be ignored")
	}
	ev, _ = ParseEvent(hdr("X-GitHub-Event", "pull_request"), mk("opened", "evil/r"))
	if !ev.HeadFork {
		t.Fatal("fork not detected")
	}
}

// ---- branch / slug sanitization ---------------------------------------------

func TestValidBranch(t *testing.T) {
	good := []string{"main", "feature/login", "release-1.2", "fix_123", "a"}
	bad := []string{"", "-x", "--upload-pack=touch /tmp/x", "--help", "../etc/passwd", "a/../b", "a//b", "a b", "a;b", "a$(id)",
		"x/", "x.", "x.lock", "a@{1}", ".hidden", "/abs", "a\nb", "a/.b", strings.Repeat("a", 201), "ref:name", "a*", "a?", "a[", "a~1", "a^"}
	for _, b := range good {
		if !ValidBranch(b) {
			t.Errorf("%q should be valid", b)
		}
	}
	for _, b := range bad {
		if ValidBranch(b) {
			t.Errorf("%q should be invalid", b)
		}
	}
}

func TestPreviewSlug(t *testing.T) {
	s, err := PreviewSlug("my-app", 12)
	if err != nil || s != "my-app-pr-12" {
		t.Fatalf("%q %v", s, err)
	}
	long := strings.Repeat("a", 120)
	s, err = PreviewSlug(long, 3)
	if err != nil || len(s) > 100 || !strings.HasSuffix(s, "-pr-3") || !ValidSlug(s) {
		t.Fatalf("%q %v", s, err)
	}
	if _, err := PreviewSlug("x", 0); err == nil {
		t.Fatal("pr 0 must fail")
	}
	if _, err := PreviewSlug("Bad_Slug", 1); err == nil {
		t.Fatal("invalid parent slug must fail")
	}
}

// ---- SSRF --------------------------------------------------------------------

func TestParseRepoURL(t *testing.T) {
	ok := []string{
		"https://github.com/o/r.git", "https://git.example.com/group/sub/repo",
		"ssh://git@github.com/o/r.git", "ssh://git@git.example.com:2222/o/r.git",
	}
	bad := []string{
		"", "http://github.com/o/r", "git://github.com/o/r", "file:///etc/passwd", "ftp://x/y",
		"https://user:pw@github.com/o/r", "https://tok@github.com/o/r", "ssh://root@github.com/o/r", "ssh://github.com/o/r",
		"git@github.com:o/r.git", "-oProxyCommand=x", "https://github.com/o/r?x=1", "https://github.com/o/r#frag",
		"https://github.com/../etc", "https://github.com/o/r with space", "https://exa mple.com/o/r", "https://a..b/o/r",
		"ext::sh -c id", "https://[::1]/x", "https://github.com:99999x/o/r",
	}
	for _, u := range ok {
		if _, err := ParseRepoURL(u); err != nil {
			t.Errorf("%q should parse: %v", u, err)
		}
	}
	for _, u := range bad {
		if _, err := ParseRepoURL(u); err == nil && !strings.Contains(u, "[::1]") {
			t.Errorf("%q should be rejected", u)
		}
	}
}

func fakeLookup(m map[string][]string) LookupFunc {
	return func(_ context.Context, host string) ([]net.IP, error) {
		v, ok := m[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []net.IP
		for _, s := range v {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
}

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "169.254.0.1",
		"0.0.0.0", "100.64.0.1", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fc00::1", "fd12::1", "::ffff:127.0.0.1",
		"::ffff:169.254.169.254", "::", "64:ff9b::7f00:1", "198.18.0.1"}
	public := []string{"8.8.8.8", "140.82.112.3", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"}
	for _, s := range blocked {
		if !IsBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s must be blocked", s)
		}
	}
	for _, s := range public {
		if IsBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

func TestValidateRepoURLSSRF(t *testing.T) {
	p := Policy{Lookup: fakeLookup(map[string][]string{
		"good.example.com":     {"140.82.112.3"},
		"internal.example.com": {"10.0.0.5"},
		"rebind.example.com":   {"140.82.112.3", "127.0.0.1"},
		"meta.example.com":     {"169.254.169.254"},
		"v6.example.com":       {"::1"},
	})}
	ctx := context.Background()
	if _, ips, err := p.ValidateRepoURL(ctx, "https://good.example.com/o/r"); err != nil || len(ips) != 1 {
		t.Fatalf("public host must pass: %v", err)
	}
	for _, u := range []string{
		"https://internal.example.com/o/r", "https://rebind.example.com/o/r", "https://meta.example.com/o/r",
		"https://v6.example.com/o/r", "https://169.254.169.254/o/r", "https://127.0.0.1/o/r", "https://10.0.0.1/o/r",
		"ssh://git@192.168.0.4/o/r", "https://unknown.example.com/o/r", "https://[::ffff:7f00:1]/o/r",
	} {
		if _, _, err := p.ValidateRepoURL(ctx, u); err == nil {
			t.Errorf("%s must be rejected", u)
		}
	}
	if _, _, err := p.ValidateRepoURL(ctx, "https://internal.example.com/o/r"); !errors.Is(err, ErrBlockedHost) {
		t.Fatalf("expected ErrBlockedHost, got %v", err)
	}
}

func TestAllowedHosts(t *testing.T) {
	p := Policy{AllowedHosts: []string{"git.corp.io"}, Lookup: fakeLookup(map[string][]string{
		"git.corp.io": {"8.8.8.8"}, "github.com": {"140.82.112.3"},
	})}
	ctx := context.Background()
	if _, _, err := p.ValidateRepoURL(ctx, "https://git.corp.io/o/r"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.ValidateRepoURL(ctx, "https://github.com/o/r"); err == nil {
		t.Fatal("host outside allow-list must fail")
	}
}

func TestRedirectsAreRevalidated(t *testing.T) {
	p := Policy{Lookup: fakeLookup(map[string][]string{
		"ok.example.com": {"8.8.8.8"}, "evil.example.com": {"10.0.0.9"},
	})}
	c := p.NewHTTPClient(5 * time.Second)
	mkReq := func(raw string) *http.Request {
		u, _ := url.Parse(raw)
		return &http.Request{URL: u}
	}
	check := c.CheckRedirect
	if err := check(mkReq("https://ok.example.com/x"), []*http.Request{{}}); err != nil {
		t.Fatalf("public https redirect must pass: %v", err)
	}
	for _, target := range []string{
		"https://evil.example.com/x", "http://ok.example.com/x", "https://169.254.169.254/latest/meta-data",
		"https://127.0.0.1:8080/", "https://user:pw@ok.example.com/",
	} {
		if err := check(mkReq(target), []*http.Request{{}}); err == nil {
			t.Errorf("redirect to %s must be refused", target)
		}
	}
	if err := check(mkReq("https://ok.example.com/x"), make([]*http.Request, 3)); err == nil {
		t.Fatal("too many redirects must stop")
	}
}

func TestHTTPClientRefusesLoopbackAtDialTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	c := (Policy{}).NewHTTPClient(3 * time.Second)
	resp, err := c.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("dial to loopback must be blocked (DNS-rebinding guard)")
	}
}

// ---- provider client ---------------------------------------------------------

type recorded struct {
	Method, Path, Auth string
	Body               map[string]any
}

func providerServer(t *testing.T, status int, resp string, rec *[]recorded) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		*rec = append(*rec, recorded{r.Method, r.URL.Path, r.Header.Get("Authorization"), m})
		w.WriteHeader(status)
		_, _ = w.Write([]byte(resp))
	}))
}

func TestProviderStatusCalls(t *testing.T) {
	for _, kind := range []string{"github", "forgejo", "gitea"} {
		var rec []recorded
		srv := providerServer(t, 201, `{"id":1}`, &rec)
		pc := &ProviderClient{Kind: kind, APIBase: srv.URL, Owner: "o", Repo: "r", Token: "tok", HTTP: srv.Client()}
		err := pc.SetStatus(context.Background(), "abcdef1234567", "pending", "https://app", "queued")
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		r := rec[0]
		if r.Method != "POST" || r.Path != "/repos/o/r/statuses/abcdef1234567" {
			t.Fatalf("%s: %s %s", kind, r.Method, r.Path)
		}
		if r.Body["context"] != "capsule/deploy" || r.Body["state"] != "pending" || r.Body["target_url"] != "https://app" {
			t.Fatalf("%s body: %v", kind, r.Body)
		}
		wantAuth := "token tok"
		if kind == "github" {
			wantAuth = "Bearer tok"
		}
		if r.Auth != wantAuth {
			t.Fatalf("%s auth %q", kind, r.Auth)
		}
	}
	pc := &ProviderClient{Kind: "github", APIBase: "http://x", Owner: "o", Repo: "r", Token: "t", HTTP: http.DefaultClient}
	if err := pc.SetStatus(context.Background(), "../../x", "success", "", ""); err == nil {
		t.Fatal("invalid sha must be refused before any request")
	}
}

func TestProviderUpsertComment(t *testing.T) {
	var rec []recorded
	srv := providerServer(t, 201, `{"id":99}`, &rec)
	pc := &ProviderClient{Kind: "gitea", APIBase: srv.URL, Owner: "g/sub", Repo: "r", Token: "t", HTTP: srv.Client()}
	id, err := pc.UpsertComment(context.Background(), 5, 0, "hello")
	srv.Close()
	if err != nil || id != 99 {
		t.Fatalf("%d %v", id, err)
	}
	if rec[0].Method != "POST" || rec[0].Path != "/repos/g/sub/r/issues/5/comments" {
		t.Fatalf("%+v", rec[0])
	}
	if body, _ := rec[0].Body["body"].(string); !strings.HasPrefix(body, CommentMarker) || !strings.HasSuffix(body, "hello") {
		t.Fatalf("body %q", body)
	}

	// Existing comment is edited in place.
	rec = nil
	srv = providerServer(t, 200, `{"id":99}`, &rec)
	pc.APIBase, pc.HTTP = srv.URL, srv.Client()
	id, err = pc.UpsertComment(context.Background(), 5, 99, "again")
	srv.Close()
	if err != nil || id != 99 || len(rec) != 1 || rec[0].Method != "PATCH" || rec[0].Path != "/repos/g/sub/r/issues/comments/99" {
		t.Fatalf("%d %v %+v", id, err, rec)
	}

	// Deleted comment: PATCH 404 then a new POST.
	var calls []string
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method)
		if r.Method == "PATCH" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":123}`))
	}))
	defer srv.Close()
	pc.APIBase, pc.HTTP = srv.URL, srv.Client()
	id, err = pc.UpsertComment(context.Background(), 5, 99, "x")
	if err != nil || id != 123 || strings.Join(calls, ",") != "PATCH,POST" {
		t.Fatalf("%d %v %v", id, err, calls)
	}
}

func TestNewProviderClient(t *testing.T) {
	hc := http.DefaultClient
	pc, err := NewProviderClient("github", "https://github.com/o/r.git", "t", hc)
	if err != nil || pc.APIBase != "https://api.github.com" || pc.Owner != "o" || pc.Repo != "r" {
		t.Fatalf("%+v %v", pc, err)
	}
	pc, err = NewProviderClient("forgejo", "https://git.example.com/team/sub/app", "t", hc)
	if err != nil || pc.APIBase != "https://git.example.com/api/v1" || pc.Owner != "team/sub" || pc.Repo != "app" {
		t.Fatalf("%+v %v", pc, err)
	}
	if _, err := NewProviderClient("generic", "https://x.io/o/r", "t", hc); !errors.Is(err, ErrUnsupported) {
		t.Fatal("generic must be unsupported")
	}
	if _, err := NewProviderClient("github", "https://github.com/o/r", "", hc); !errors.Is(err, ErrUnsupported) {
		t.Fatal("no token must be unsupported")
	}
}

// ---- packaging ------------------------------------------------------------------

func TestPackageTarGz(t *testing.T) {
	src := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(src, ".git", "objects"), 0o755))
	must(os.WriteFile(filepath.Join(src, ".git", "config"), []byte("secret"), 0o644))
	must(os.MkdirAll(filepath.Join(src, "app", "sub"), 0o755))
	must(os.WriteFile(filepath.Join(src, "Dockerfile"), []byte("FROM scratch\n"), 0o644))
	must(os.WriteFile(filepath.Join(src, "app", "sub", "main.go"), []byte("package main"), 0o644))
	_ = os.Symlink("/etc/passwd", filepath.Join(src, "link")) // may fail on Windows: fine
	dst := filepath.Join(t.TempDir(), "out.tar.gz")
	size, err := PackageTarGz(src, dst, 1<<20)
	if err != nil || size <= 0 {
		t.Fatalf("%d %v", size, err)
	}
	f, _ := os.Open(dst)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	must(err)
	tr := tar.NewReader(gz)
	names := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		must(err)
		names[h.Name] = true
		if strings.HasPrefix(h.Name, "/") || strings.Contains(h.Name, "..") || strings.HasPrefix(h.Name, "./") {
			t.Fatalf("unsafe entry name %q", h.Name)
		}
		if h.Typeflag == tar.TypeSymlink {
			t.Fatal("symlinks must not be packaged")
		}
	}
	for _, want := range []string{"Dockerfile", "app/sub/main.go"} {
		if !names[want] {
			t.Errorf("missing %s in %v", want, names)
		}
	}
	for n := range names {
		if strings.HasPrefix(n, ".git") || n == "link" {
			t.Errorf("must not contain %s", n)
		}
	}

	// size cap
	if _, err := PackageTarGz(src, filepath.Join(t.TempDir(), "x.tar.gz"), 5); err == nil {
		t.Fatal("size limit must fail the packaging")
	}
}

func TestScrubRemovesSecrets(t *testing.T) {
	got := scrub("fatal: could not read tok_ABC123 from remote", "tok_ABC123")
	if strings.Contains(got, "tok_ABC123") {
		t.Fatal(got)
	}
}

func TestFetchRejectsBadInputBeforeRunningGit(t *testing.T) {
	g := &GitFetcher{GitBin: "/nonexistent/git-should-not-run", Policy: Policy{Lookup: fakeLookup(map[string][]string{"internal.example.com": {"10.0.0.1"}})}}
	ctx := context.Background()
	if _, err := g.Fetch(ctx, "https://internal.example.com/o/r", "main", Auth{}); err == nil || !errors.Is(err, ErrBlockedHost) {
		t.Fatalf("private host must be refused: %v", err)
	}
	if _, err := g.Fetch(ctx, "https://good.example.com/o/r", "--upload-pack=x", Auth{}); err == nil {
		t.Fatal("option-like branch must be refused")
	}
	if _, err := g.ListBranches(ctx, "https://169.254.169.254/o/r", Auth{}); err == nil {
		t.Fatal("metadata address must be refused")
	}
}
