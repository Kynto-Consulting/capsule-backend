package gitimporttest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// GitHubRepo describes one repository of the fake GitHub.
type GitHubRepo struct {
	Private       bool
	DefaultBranch string
	Description   string
	Archived      bool
	Files         map[string]string // path -> content
}

// GitHub is a fake GitHub REST API (httptest). Only repositories added with Add exist; every request
// must carry Token as Bearer (otherwise 401 "Bad credentials"). It records the Authorization headers.
type GitHub struct {
	*httptest.Server
	Token string

	mu     sync.Mutex
	repos  map[string]*GitHubRepo
	Auths  []string
	Hits   []string
	Status map[string]int // path -> forced status
}

// NewGitHub starts the fake. Close it with Close().
func NewGitHub(token string) *GitHub {
	g := &GitHub{Token: token, repos: map[string]*GitHubRepo{}, Status: map[string]int{}}
	g.Server = httptest.NewServer(http.HandlerFunc(g.serve))
	return g
}

// Add registers owner/name.
func (g *GitHub) Add(full string, r GitHubRepo) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if r.DefaultBranch == "" {
		r.DefaultBranch = "main"
	}
	g.repos[strings.ToLower(full)] = &r
}

func (g *GitHub) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.Auths = append(g.Auths, r.Header.Get("Authorization"))
	g.Hits = append(g.Hits, r.URL.Path)
	forced := g.Status[r.URL.Path]
	g.mu.Unlock()
	write := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	if r.Header.Get("Authorization") != "Bearer "+g.Token {
		write(401, map[string]string{"message": "Bad credentials"})
		return
	}
	if forced != 0 {
		write(forced, map[string]string{"message": "forced"})
		return
	}
	// /repos/{o}/{r}[/contents/{path...}]
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/repos/"), "/", 3)
	if len(parts) < 2 {
		write(404, map[string]string{"message": "Not Found"})
		return
	}
	g.mu.Lock()
	repo := g.repos[strings.ToLower(parts[0]+"/"+parts[1])]
	g.mu.Unlock()
	if repo == nil {
		write(404, map[string]string{"message": "Not Found"})
		return
	}
	if len(parts) == 2 {
		write(200, map[string]any{"full_name": parts[0] + "/" + parts[1], "private": repo.Private, "archived": repo.Archived,
			"default_branch": repo.DefaultBranch, "description": repo.Description, "has_issues": true, "size": 10})
		return
	}
	path := strings.TrimPrefix(parts[2], "contents/")
	path = strings.TrimSuffix(path, "/")
	if c, ok := repo.Files[path]; ok {
		write(200, map[string]any{"type": "file", "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(c))})
		return
	}
	var dir []map[string]string
	for p := range repo.Files {
		if strings.HasPrefix(p, path+"/") && !strings.Contains(strings.TrimPrefix(p, path+"/"), "/") {
			dir = append(dir, map[string]string{"name": strings.TrimPrefix(p, path+"/"), "type": "file"})
		}
	}
	if len(dir) > 0 {
		write(200, dir)
		return
	}
	write(404, map[string]string{"message": "Not Found"})
}
