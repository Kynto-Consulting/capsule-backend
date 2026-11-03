package gitsource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CommentMarker identifies the single comment Capsule maintains per PR.
const CommentMarker = "<!-- capsule-preview -->"

// ErrUnsupported is returned for providers without a status/comment API.
var ErrUnsupported = errors.New("provider does not support this operation")

// ProviderClient talks to the GitHub / Forgejo / Gitea REST API.
type ProviderClient struct {
	Kind    string // github | forgejo | gitea
	APIBase string // e.g. https://api.github.com or https://git.example.com/api/v1
	Owner   string
	Repo    string
	Token   string
	HTTP    *http.Client
}

// NewProviderClient builds a client for repoURL. It returns ErrUnsupported
// for the generic provider or when there is no token.
func NewProviderClient(kind, repoURL, token string, hc *http.Client) (*ProviderClient, error) {
	if token == "" {
		return nil, ErrUnsupported
	}
	return newProviderClient(kind, repoURL, token, hc)
}

// NewReadClient is NewProviderClient for read-only views: public repositories
// work without a token.
func NewReadClient(kind, repoURL, token string, hc *http.Client) (*ProviderClient, error) {
	return newProviderClient(kind, repoURL, token, hc)
}

func newProviderClient(kind, repoURL, token string, hc *http.Client) (*ProviderClient, error) {
	ref, err := ParseRepoURL(repoURL)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimSuffix(strings.Trim(ref.Path, "/"), ".git"), "/")
	if len(parts) < 2 {
		return nil, errors.New("repository URL needs owner/repo")
	}
	repo := parts[len(parts)-1]
	owner := strings.Join(parts[:len(parts)-1], "/")
	pc := &ProviderClient{Kind: kind, Owner: owner, Repo: repo, Token: token, HTTP: hc}
	switch kind {
	case "github":
		if ref.Host == "github.com" {
			pc.APIBase = "https://api.github.com"
		} else {
			pc.APIBase = "https://" + ref.Host + "/api/v3"
		}
	case "forgejo", "gitea":
		pc.APIBase = "https://" + ref.Host + "/api/v1"
	default:
		return nil, ErrUnsupported
	}
	if pc.HTTP == nil {
		return nil, errors.New("http client required")
	}
	return pc, nil
}

func (c *ProviderClient) repoPath() string {
	return "/repos/" + c.Owner + "/" + c.Repo
}

func (c *ProviderClient) do(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	data, status, _, err := c.doH(ctx, method, path, body)
	return data, status, err
}

// doH is do that also returns the response headers (pagination).
func (c *ProviderClient) doH(ctx context.Context, method, path string, body any) ([]byte, int, http.Header, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.APIBase+path, rd)
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Kind == "github" {
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	} else if c.Token != "" {
		req.Header.Set("Authorization", "token "+c.Token)
	}
	req.Header.Set("User-Agent", "capsule-git")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return data, resp.StatusCode, resp.Header, fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	return data, resp.StatusCode, resp.Header, nil
}

// SetStatus posts a commit status with context "capsule/deploy".
// state is pending | success | failure.
func (c *ProviderClient) SetStatus(ctx context.Context, sha, state, targetURL, description string) error {
	if !ValidSHA(sha) {
		return errors.New("invalid sha")
	}
	if len(description) > 140 {
		description = description[:140]
	}
	_, _, err := c.do(ctx, http.MethodPost, c.repoPath()+"/statuses/"+sha, map[string]string{
		"state":       state,
		"target_url":  targetURL,
		"description": description,
		"context":     "capsule/deploy",
	})
	return err
}

// UpsertComment creates the PR comment, or edits existingID when given
// (falling back to a new comment if the old one is gone). It returns the comment id.
func (c *ProviderClient) UpsertComment(ctx context.Context, pr int, existingID int64, body string) (int64, error) {
	if pr <= 0 {
		return 0, errors.New("invalid pull request")
	}
	payload := map[string]string{"body": CommentMarker + "\n" + body}
	if existingID > 0 {
		data, status, err := c.do(ctx, http.MethodPatch, fmt.Sprintf("%s/issues/comments/%d", c.repoPath(), existingID), payload)
		if err == nil {
			if id := commentID(data); id > 0 {
				return id, nil
			}
			return existingID, nil
		}
		if status != http.StatusNotFound {
			return existingID, err
		}
	}
	data, _, err := c.do(ctx, http.MethodPost, fmt.Sprintf("%s/issues/%d/comments", c.repoPath(), pr), payload)
	if err != nil {
		return 0, err
	}
	id := commentID(data)
	if id <= 0 {
		return 0, errors.New("provider returned no comment id")
	}
	return id, nil
}

func commentID(data []byte) int64 {
	var r struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(data, &r)
	return r.ID
}
