package gitsource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Read-only views over GitHub / Forgejo / Gitea (their JSON is near-identical).

// BranchInfo is one branch.
type BranchInfo struct {
	Name      string
	SHA       string
	Protected bool
}

// CommitInfo is one commit of a branch listing.
type CommitInfo struct {
	SHA        string
	Message    string
	Author     string
	AuthoredAt time.Time
	URL        string
}

// PullInfo is one pull request.
type PullInfo struct {
	Number  int
	Title   string
	Author  string
	State   string
	HeadRef string
	BaseRef string
	URL     string
	HeadSHA string
}

// DefaultBranch returns the repository's default branch.
func (c *ProviderClient) DefaultBranch(ctx context.Context) (string, error) {
	data, _, err := c.do(ctx, http.MethodGet, c.repoPath(), nil)
	if err != nil {
		return "", err
	}
	var r struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return "", errors.New("invalid provider response")
	}
	return r.DefaultBranch, nil
}

// Branches lists up to 100 branches.
func (c *ProviderClient) Branches(ctx context.Context) ([]BranchInfo, error) {
	data, _, err := c.do(ctx, http.MethodGet, c.repoPath()+"/branches?page=1&limit=100&per_page=100", nil)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Name   string `json:"name"`
		Commit struct {
			ID  string `json:"id"`  // Forgejo / Gitea
			SHA string `json:"sha"` // GitHub
		} `json:"commit"`
		Protected bool `json:"protected"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, errors.New("invalid provider response")
	}
	out := make([]BranchInfo, 0, len(raw))
	for _, b := range raw {
		out = append(out, BranchInfo{Name: b.Name, SHA: firstNonEmpty(b.Commit.ID, b.Commit.SHA), Protected: b.Protected})
	}
	return out, nil
}

func hasMore(h http.Header, got, limit int) bool {
	if v := h.Get("X-HasMore"); v != "" {
		return strings.EqualFold(v, "true")
	}
	if l := h.Get("Link"); l != "" {
		return strings.Contains(l, `rel="next"`)
	}
	return got >= limit
}

// Commits lists one page of commits of branch (branch must be validated by the caller).
func (c *ProviderClient) Commits(ctx context.Context, branch string, page, limit int) ([]CommitInfo, bool, error) {
	if page < 1 {
		page = 1
	}
	q := url.Values{}
	if branch != "" {
		q.Set("sha", branch)
	}
	q.Set("page", fmt.Sprint(page))
	q.Set("limit", fmt.Sprint(limit))
	q.Set("per_page", fmt.Sprint(limit))
	q.Set("stat", "false")
	q.Set("files", "false")
	q.Set("verification", "false")
	data, _, hdr, err := c.doH(ctx, http.MethodGet, c.repoPath()+"/commits?"+q.Encode(), nil)
	if err != nil {
		return nil, false, err
	}
	var raw []struct {
		SHA     string `json:"sha"`
		HTMLURL string `json:"html_url"`
		Commit  struct {
			Message string `json:"message"`
			Author  struct {
				Name string    `json:"name"`
				Date time.Time `json:"date"`
			} `json:"author"`
		} `json:"commit"`
		Author *struct {
			Login string `json:"login"`
		} `json:"author"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, false, errors.New("invalid provider response")
	}
	out := make([]CommitInfo, 0, len(raw))
	for _, r := range raw {
		author := r.Commit.Author.Name
		if author == "" && r.Author != nil {
			author = r.Author.Login
		}
		out = append(out, CommitInfo{SHA: r.SHA, Message: r.Commit.Message, Author: author, AuthoredAt: r.Commit.Author.Date, URL: r.HTMLURL})
	}
	return out, hasMore(hdr, len(raw), limit), nil
}

// Pulls lists up to limit pull requests; state is open | closed | all.
func (c *ProviderClient) Pulls(ctx context.Context, state string, limit int) ([]PullInfo, error) {
	q := url.Values{"state": {state}, "page": {"1"}, "limit": {fmt.Sprint(limit)}, "per_page": {fmt.Sprint(limit)}}
	data, _, err := c.do(ctx, http.MethodGet, c.repoPath()+"/pulls?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		State   string `json:"state"`
		HTMLURL string `json:"html_url"`
		User    struct {
			Login string `json:"login"`
		} `json:"user"`
		Head struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, errors.New("invalid provider response")
	}
	out := make([]PullInfo, 0, len(raw))
	for _, p := range raw {
		out = append(out, PullInfo{
			Number: p.Number, Title: p.Title, Author: p.User.Login, State: p.State,
			HeadRef: p.Head.Ref, BaseRef: p.Base.Ref, URL: p.HTMLURL, HeadSHA: p.Head.SHA,
		})
	}
	return out, nil
}
