package gitimport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// GitHub is the small part of the GitHub REST API an import needs: repository metadata (does it exist,
// can the token read it), and file/directory contents (CODEOWNERS and workflows). The token travels
// only in the Authorization header; every error text is scrubbed of it.
type GitHub struct {
	BaseURL string       // https://api.github.com
	HTTP    *http.Client // production: gitsource.Policy.NewHTTPClient (no private destinations, validated redirects)
}

// GHRepo is the metadata of a GitHub repository.
type GHRepo struct {
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	Fork          bool   `json:"fork"`
	DefaultBranch string `json:"default_branch"`
	Description   string `json:"description"`
	HasIssues     bool   `json:"has_issues"`
	Size          int64  `json:"size"` // KiB
}

// GHError is a GitHub API failure with the HTTP status.
type GHError struct {
	Status int
	Msg    string
}

func (e *GHError) Error() string { return fmt.Sprintf("github: %d %s", e.Status, e.Msg) }

const maxGitHubBody = 2 << 20

func (g *GitHub) do(ctx context.Context, token, path string, q url.Values) ([]byte, error) {
	u := strings.TrimRight(g.BaseURL, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, &GHError{Msg: "invalid request"}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "capsule-git-import")
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := g.HTTP.Do(req)
	if err != nil {
		// net/http errors carry the URL (no secrets: the token is in a header) but scrub anyway.
		return nil, &GHError{Msg: clip(Redact(err.Error(), token), 200)}
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, maxGitHubBody))
	if res.StatusCode >= 300 {
		var m struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &m)
		msg := m.Message
		if msg == "" {
			msg = http.StatusText(res.StatusCode)
		}
		if res.StatusCode == 403 && res.Header.Get("X-RateLimit-Remaining") == "0" {
			msg = "GitHub API rate limit reached"
		}
		return nil, &GHError{Status: res.StatusCode, Msg: clip(Redact(msg, token), 200)}
	}
	return body, nil
}

// Repo returns the metadata of owner/name.
func (g *GitHub) Repo(ctx context.Context, token, owner, name string) (*GHRepo, error) {
	b, err := g.do(ctx, token, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name), nil)
	if err != nil {
		return nil, err
	}
	var r GHRepo
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, &GHError{Msg: "malformed response"}
	}
	return &r, nil
}

// File returns the content of a file; found=false for 404 and for non-files.
func (g *GitHub) File(ctx context.Context, token, owner, name, ref, path string) (data []byte, found bool, err error) {
	b, err := g.do(ctx, token, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/contents/"+escapePath(path), url.Values{"ref": {ref}})
	if err != nil {
		if ge, ok := err.(*GHError); ok && ge.Status == http.StatusNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}
	var f struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	if json.Unmarshal(b, &f) != nil || f.Type != "file" || f.Encoding != "base64" {
		return nil, false, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\n", "", "\r", "").Replace(f.Content))
	if err != nil {
		return nil, false, nil
	}
	return raw, true, nil
}

// Dir lists the file names of a directory (nil when it does not exist).
func (g *GitHub) Dir(ctx context.Context, token, owner, name, ref, path string) ([]string, error) {
	b, err := g.do(ctx, token, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/contents/"+escapePath(path), url.Values{"ref": {ref}})
	if err != nil {
		if ge, ok := err.(*GHError); ok && ge.Status == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	var items []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if json.Unmarshal(b, &items) != nil {
		return nil, nil
	}
	var out []string
	for _, it := range items {
		if it.Type == "file" {
			out = append(out, it.Name)
		}
	}
	return out, nil
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}
