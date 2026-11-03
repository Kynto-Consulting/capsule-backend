// Package fake is an in-memory imitation of the subset of the Forgejo REST API v1 that gitcore
// uses, served by httptest. It exists so every package that depends on gitcore (A2, A4-A7, B1,
// B6-B8, C1, C3) can be tested without a real Forgejo.
//
// IT IS A DOUBLE: it implements the field names gitcore expects (taken from the Forgejo swagger),
// not Forgejo's behaviour. Passing against the fake does not prove Forgejo accepts the call; the
// `-tags=forgejo` tests in gitcore/itest are the check against a real instance.
package fake

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Token is the service token the fake accepts.
const Token = "fake-service-token-0123456789"

// Request is one recorded call.
type Request struct {
	Method, Path, Query string
	Sudo                string
	Auth                string
	Body                string
}

type commit struct {
	SHA     string
	Message string
	Author  string
	Parents []string
	Files   map[string]string // full snapshot
	When    time.Time
	Changed []string
}

type pull struct {
	N                 int
	Title, Body, Head string
	Base              string
	HeadSHA, MergeSHA string
	State             string
	Merged            bool
	Author            string
	Reviewers         []string
	Reviews           []map[string]any
	Comments          []map[string]any
	AutoMerge         bool
}

type repo struct {
	Owner, Name, Default string
	Private              bool
	Branches             map[string]string // name -> sha
	Commits              map[string]*commit
	Order                []string // newest last
	Tags                 map[string]string
	Pulls                []*pull
	Prot                 map[string]map[string]any
	Hooks                []map[string]any
	Statuses             map[string][]map[string]any
	Mirrors              []map[string]any
	Runs                 []map[string]any
	Jobs                 map[int64][]map[string]any
	Logs                 map[int64]string
	Vars                 map[string]string
	Secrets              map[string]string
	Teams                map[int64]bool
}

// Server is the fake Forgejo.
type Server struct {
	*httptest.Server
	mu    sync.Mutex
	seq   int
	users map[string]bool
	orgs  map[string]bool
	repos map[string]*repo
	teams map[int64]map[string]any
	tmem  map[int64]map[string]bool
	keys  map[string][]map[string]any // by user
	ovars map[string]map[string]string
	ext   extState
	web   webState
	reqs  []Request
	mux   *http.ServeMux
	// Fail, when set, is consulted for every API call before handling: return a status (>0) to
	// answer with it (body "{\"message\":\"injected\"}"), or 0 to continue. Delay sleeps first.
	Fail  func(r Request) int
	Delay func(r Request) time.Duration
	// ExtraHeader is added to every response (e.g. to prove nothing echoes it back).
	Max int // upstream clamp for limit (default 50, like Forgejo MAX_RESPONSE_ITEMS)
}

// New starts the fake. Close it with s.Close().
func New() *Server {
	s := &Server{users: map[string]bool{}, orgs: map[string]bool{}, repos: map[string]*repo{},
		teams: map[int64]map[string]any{}, tmem: map[int64]map[string]bool{}, keys: map[string][]map[string]any{},
		ovars: map[string]map[string]string{}, Max: 50}
	s.mux = s.buildMux()
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// ---- helpers for tests --------------------------------------------------------------------

func (s *Server) next() int { s.seq++; return s.seq }

func sha(seed string) string {
	h := sha1.Sum([]byte(seed))
	return hex.EncodeToString(h[:])
}

// AddUser registers a Forgejo user (it exists after first OIDC login).
func (s *Server) AddUser(login string) { s.mu.Lock(); s.users[login] = true; s.mu.Unlock() }

// AddRepo creates org (if needed) and a repository with an initial commit on main.
func (s *Server) AddRepo(owner, name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgs[owner] = true
	return s.newRepo(owner, name, true)
}

func (s *Server) newRepo(owner, name string, private bool) string {
	r := &repo{Owner: owner, Name: name, Default: "main", Private: private, Branches: map[string]string{}, Commits: map[string]*commit{},
		Tags: map[string]string{}, Prot: map[string]map[string]any{}, Statuses: map[string][]map[string]any{},
		Jobs: map[int64][]map[string]any{}, Logs: map[int64]string{}, Vars: map[string]string{}, Secrets: map[string]string{}, Teams: map[int64]bool{}}
	s.repos[owner+"/"+name] = r
	return s.commit(r, "main", "Initial commit", "capsule-bot", map[string]string{"README.md": "# " + name + "\n"})
}

// Commit adds a commit with the given file changes (nil value = delete) to branch (created from
// main if missing) and returns its SHA.
func (s *Server) Commit(owner, name, branch, msg string, files map[string]string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.repos[owner+"/"+name]
	if r == nil {
		return ""
	}
	return s.commit(r, branch, msg, "alice", files)
}

func (s *Server) commit(r *repo, branch, msg, author string, files map[string]string) string {
	parent, ok := r.Branches[branch]
	if !ok {
		parent = r.Branches[r.Default]
		if branch == r.Default {
			parent = ""
		}
	}
	snap := map[string]string{}
	var parents []string
	if parent != "" {
		for k, v := range r.Commits[parent].Files {
			snap[k] = v
		}
		parents = []string{parent}
	}
	var changed []string
	for k, v := range files {
		snap[k] = v
		changed = append(changed, k)
	}
	sort.Strings(changed)
	c := &commit{SHA: sha(fmt.Sprintf("%s/%s/%d/%s", r.Owner, r.Name, s.next(), msg)), Message: msg, Author: author, Parents: parents, Files: snap,
		When: time.Date(2026, 11, 2, 12, 0, s.seq%60, 0, time.UTC), Changed: changed}
	r.Commits[c.SHA] = c
	r.Order = append(r.Order, c.SHA)
	r.Branches[branch] = c.SHA
	return c.SHA
}

// AddPull opens a PR from head to base and returns its number.
func (s *Server) AddPull(owner, name, title, head, base string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.repos[owner+"/"+name]
	p := &pull{N: len(r.Pulls) + 1, Title: title, Head: head, Base: base, HeadSHA: r.Branches[head], State: "open", Author: "alice"}
	r.Pulls = append(r.Pulls, p)
	return p.N
}

// AddRun registers an Actions run with one job and a log.
func (s *Server) AddRun(owner, name string, status, log string) (runID, jobID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.repos[owner+"/"+name]
	runID, jobID = int64(len(r.Runs)+1), int64(1000+len(r.Runs)+1)
	r.Runs = append(r.Runs, map[string]any{"id": runID, "index_in_repo": runID, "workflow_id": "ci.yml", "title": "CI", "event": "push",
		"prettyref": "main", "commit_sha": r.Branches["main"], "status": status, "need_approval": false,
		"trigger_user": map[string]any{"login": "alice"}, "started": "2026-11-02T12:00:00Z", "stopped": "2026-11-02T12:01:00Z", "html_url": s.URL + "/x"})
	r.Jobs[runID] = []map[string]any{{"id": jobID, "name": "build", "status": status, "runs_on": []string{"ubuntu"}}}
	r.Logs[jobID] = log
	return
}

// SetLimitClamp changes the upstream max page size (Forgejo MAX_RESPONSE_ITEMS).
func (s *Server) SetLimitClamp(n int) { s.mu.Lock(); s.Max = n; s.mu.Unlock() }

// Requests returns a copy of every recorded call.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

// Count returns how many recorded calls match method and path prefix.
func (s *Server) Count(method, pathPrefix string) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Method == method && strings.HasPrefix(r.Path, pathPrefix) {
			n++
		}
	}
	return n
}

// Reset clears recorded calls.
func (s *Server) Reset() { s.mu.Lock(); s.reqs = nil; s.mu.Unlock() }

// Repo helpers for assertions.
func (s *Server) HasProtection(owner, name, rule string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.repos[owner+"/"+name]
	return r != nil && r.Prot[rule] != nil
}

func (s *Server) Protection(owner, name, rule string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.repos[owner+"/"+name]; r != nil {
		return r.Prot[rule]
	}
	return nil
}

func (s *Server) HasVar(owner, name, key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "" {
		v, ok := s.ovars[owner][key]
		return v, ok
	}
	v, ok := s.repos[owner+"/"+name].Vars[key]
	return v, ok
}

// ---- HTTP -------------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func msg(w http.ResponseWriter, code int, m string) {
	writeJSON(w, code, map[string]string{"message": m})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body := ""
	if r.Body != nil {
		b := make([]byte, 0, 512)
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			b = append(b, buf[:n]...)
			if err != nil {
				break
			}
		}
		body = string(b)
	}
	rec := Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Sudo: r.Header.Get("Sudo"), Auth: r.Header.Get("Authorization"), Body: body}
	s.mu.Lock()
	s.reqs = append(s.reqs, rec)
	fail, delay, max := s.Fail, s.Delay, s.Max
	s.mu.Unlock()
	if delay != nil {
		if d := delay(rec); d > 0 {
			time.Sleep(d)
		}
	}
	if fail != nil {
		if code := fail(rec); code > 0 {
			msg(w, code, "injected")
			return
		}
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") { // the UI web routes (cookie session, see routes_web.go)
		s.serveWeb(w, r, body)
		return
	}
	if rec.Auth != "token "+Token {
		msg(w, 401, "token is required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.Sudo != "" && !s.users[rec.Sudo] {
		msg(w, 404, "user does not exist")
		return
	}
	s.route(w, r, body, max)
}

func (s *Server) getRepo(w http.ResponseWriter, r *http.Request) *repo {
	rp := s.repos[r.PathValue("o")+"/"+r.PathValue("r")]
	if rp == nil {
		msg(w, 404, "The target couldn't be found.")
	}
	return rp
}

// paginate slices items by page/limit (limit clamped to max) and sets the paging headers.
func paginate[T any](w http.ResponseWriter, r *http.Request, items []T, max int) []T {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if l2, _ := strconv.Atoi(r.URL.Query().Get("per_page")); l2 > 0 {
		limit = l2
	}
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > max {
		limit = max
	}
	w.Header().Set("X-Total-Count", strconv.Itoa(len(items)))
	lo := (page - 1) * limit
	if lo > len(items) {
		lo = len(items)
	}
	hi := lo + limit
	if hi < len(items) {
		w.Header().Set("Link", fmt.Sprintf(`<%s?page=%d>; rel="next"`, r.URL.Path, page+1))
	} else {
		hi = len(items)
	}
	return items[lo:hi]
}

func decode(body string) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal([]byte(body), &m)
	return m
}

func userObj(login string) map[string]any {
	return map[string]any{"id": userID(login), "active": true, "login": login, "full_name": strings.ToUpper(login[:1]) + login[1:], "email": login + "@example.test"}
}

func (s *Server) commitObj(rp *repo, c *commit, files bool) map[string]any {
	ps := []map[string]any{}
	for _, p := range c.Parents {
		ps = append(ps, map[string]any{"sha": p})
	}
	m := map[string]any{"sha": c.SHA, "html_url": s.URL + "/" + rp.Owner + "/" + rp.Name + "/commit/" + c.SHA, "created": c.When.Format(time.RFC3339),
		"commit": map[string]any{"message": c.Message, "author": map[string]any{"name": c.Author, "email": c.Author + "@example.test", "date": c.When.Format(time.RFC3339)},
			"verification": map[string]any{"verified": false}},
		"author": userObj(c.Author), "parents": ps}
	if files {
		fs := []map[string]any{}
		for _, f := range c.Changed {
			fs = append(fs, map[string]any{"filename": f, "status": "modified"})
		}
		m["files"] = fs
	}
	return m
}

func (s *Server) branchObj(rp *repo, name string) map[string]any {
	c := rp.Commits[rp.Branches[name]]
	_, protected := rp.Prot[name]
	return map[string]any{"name": name, "protected": protected, "effective_branch_protection_name": ifThen(protected, name, ""),
		"commit": map[string]any{"id": c.SHA, "message": c.Message, "timestamp": c.When.Format(time.RFC3339), "author": map[string]any{"name": c.Author}}}
}

func ifThen(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

func (s *Server) pullObj(rp *repo, p *pull) map[string]any {
	revs := []map[string]any{}
	for _, u := range p.Reviewers {
		revs = append(revs, userObj(u))
	}
	st := p.State
	mergeBase := ""
	if b := rp.Branches[p.Base]; b != "" {
		mergeBase = b
	}
	return map[string]any{"number": p.N, "title": p.Title, "body": p.Body, "state": st, "draft": false, "merged": p.Merged,
		"head": map[string]any{"ref": p.Head, "sha": p.HeadSHA}, "base": map[string]any{"ref": p.Base, "sha": rp.Branches[p.Base]},
		"user": userObj(p.Author), "requested_reviewers": revs, "labels": []any{}, "mergeable": !p.Merged, "merge_commit_sha": p.MergeSHA,
		"merge_base": mergeBase, "html_url": s.URL + "/" + rp.Owner + "/" + rp.Name + "/pulls/" + strconv.Itoa(p.N),
		"created_at": "2026-11-02T12:00:00Z", "updated_at": "2026-11-02T12:05:00Z"}
}

func unified(a, b map[string]string) string {
	names := map[string]bool{}
	for k := range a {
		names[k] = true
	}
	for k := range b {
		names[k] = true
	}
	var keys []string
	for k := range names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		av, aok := a[k]
		bv, bok := b[k]
		if aok && bok && av == bv {
			continue
		}
		fmt.Fprintf(&sb, "diff --git a/%s b/%s\n", k, k)
		switch {
		case !aok:
			sb.WriteString("new file mode 100644\n--- /dev/null\n+++ b/" + k + "\n")
		case !bok:
			sb.WriteString("deleted file mode 100644\n--- a/" + k + "\n+++ /dev/null\n")
		default:
			sb.WriteString("--- a/" + k + "\n+++ b/" + k + "\n")
		}
		sb.WriteString("@@ -1 +1 @@\n")
		if aok {
			for _, l := range strings.Split(strings.TrimRight(av, "\n"), "\n") {
				sb.WriteString("-" + l + "\n")
			}
		}
		if bok {
			for _, l := range strings.Split(strings.TrimRight(bv, "\n"), "\n") {
				sb.WriteString("+" + l + "\n")
			}
		}
	}
	return sb.String()
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
