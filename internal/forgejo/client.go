// Package forgejo integrates Capsule with the core Git service (Forgejo): a small
// API client plus the provisioning and team-synchronization logic built on it.
package forgejo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config is read from CAPSULE_GIT_URL / CAPSULE_GIT_TOKEN / CAPSULE_GIT_SSH_HOST.
type Config struct {
	URL     string // https://git.tumi-ai.com (no trailing slash)
	Token   string // service-account token (secret)
	SSHHost string // host (optionally host:port) shown in clone_url_ssh
}

// ConfigFromEnv reads the CAPSULE_GIT_* variables.
func ConfigFromEnv() Config {
	return Config{
		URL:     strings.TrimRight(strings.TrimSpace(os.Getenv("CAPSULE_GIT_URL")), "/"),
		Token:   strings.TrimSpace(os.Getenv("CAPSULE_GIT_TOKEN")),
		SSHHost: strings.TrimSpace(os.Getenv("CAPSULE_GIT_SSH_HOST")),
	}
}

// Enabled reports whether the integration is configured (URL and token).
func (c Config) Enabled() bool { return c.URL != "" && c.Token != "" }

// Host is the hostname (no port) of the Git URL, lower-case.
func (c Config) Host() string {
	u, err := url.Parse(c.URL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// SSHAddress is the host[:port] used for SSH clone URLs (falls back to the web host).
func (c Config) SSHAddress() string {
	if c.SSHHost != "" {
		return c.SSHHost
	}
	return c.Host()
}

// APIError is a non-2xx answer from Forgejo. It never carries the token.
type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("forgejo %s %s: HTTP %d", e.Method, e.Path, e.Status)
	}
	return fmt.Sprintf("forgejo %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// Client talks to the Forgejo REST API v1 with the service token.
type Client struct {
	Cfg  Config
	HTTP *http.Client
}

// NewClient builds a client with a sane timeout.
func NewClient(cfg Config) *Client {
	return &Client{Cfg: cfg, HTTP: &http.Client{Timeout: 20 * time.Second}}
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Cfg.URL+"/api/v1"+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "token "+c.Cfg.Token)
	req.Header.Set("User-Agent", "capsule-forgejo")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, scrubErr(err, c.Cfg.Token)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		var m struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &m) == nil && m.Message != "" {
			msg = m.Message
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return resp.StatusCode, &APIError{Method: method, Path: path, Status: resp.StatusCode, Body: msg}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("forgejo %s %s: invalid response: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

func scrubErr(err error, token string) error {
	if token == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token, "***"))
}

func isStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == status
}

// ---- URLs ------------------------------------------------------------------

// WebURL is the browser URL of a repository.
func (c Config) WebURL(org, repo string) string { return c.URL + "/" + org + "/" + repo }

// CloneHTTPS is the HTTPS clone URL.
func (c Config) CloneHTTPS(org, repo string) string { return c.WebURL(org, repo) + ".git" }

// CloneSSH is the SSH clone URL (scp-like, or ssh:// when a port is set).
func (c Config) CloneSSH(org, repo string) string {
	addr := c.SSHAddress()
	if addr == "" {
		return ""
	}
	if strings.Contains(addr, ":") {
		return "ssh://git@" + addr + "/" + org + "/" + repo + ".git"
	}
	return "git@" + addr + ":" + org + "/" + repo + ".git"
}

// ---- organizations and repositories -----------------------------------------

// Repo is the subset of a Forgejo repository Capsule uses.
type Repo struct {
	Name          string `json:"name"`
	HTMLURL       string `json:"html_url"`
	DefaultBranch string `json:"default_branch"`
}

// EnsureOrg creates the organization when it does not exist (GET -> 404 -> POST).
func (c *Client) EnsureOrg(ctx context.Context, slug string) error {
	_, err := c.do(ctx, http.MethodGet, "/orgs/"+url.PathEscape(slug), nil, nil)
	if err == nil {
		return nil
	}
	if !isStatus(err, http.StatusNotFound) {
		return err
	}
	_, err = c.do(ctx, http.MethodPost, "/orgs", map[string]string{"username": slug, "visibility": "private"}, nil)
	if err == nil || isStatus(err, http.StatusUnprocessableEntity) {
		// 422: created concurrently (name taken). Confirm it is there.
		if _, gerr := c.do(ctx, http.MethodGet, "/orgs/"+url.PathEscape(slug), nil, nil); gerr == nil {
			return nil
		}
	}
	return err
}

// GetRepo returns the repository or (nil, nil) when it does not exist.
func (c *Client) GetRepo(ctx context.Context, org, name string) (*Repo, error) {
	var r Repo
	_, err := c.do(ctx, http.MethodGet, "/repos/"+url.PathEscape(org)+"/"+url.PathEscape(name), nil, &r)
	if isStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// EnsureRepo returns the existing private repository or creates it (auto_init, branch main).
func (c *Client) EnsureRepo(ctx context.Context, org, name string) (*Repo, error) {
	if r, err := c.GetRepo(ctx, org, name); err != nil || r != nil {
		return r, err
	}
	var r Repo
	_, err := c.do(ctx, http.MethodPost, "/orgs/"+url.PathEscape(org)+"/repos", map[string]any{
		"name": name, "private": true, "auto_init": true, "default_branch": "main",
	}, &r)
	if isStatus(err, http.StatusConflict) {
		return c.mustRepo(ctx, org, name)
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) mustRepo(ctx context.Context, org, name string) (*Repo, error) {
	r, err := c.GetRepo(ctx, org, name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, errors.New("forgejo: repository vanished after conflict")
	}
	return r, nil
}

// MigrateRepo imports cloneAddr into a new private repository (POST /repos/migrate).
// An existing repository is returned untouched (idempotent). created tells which happened.
func (c *Client) MigrateRepo(ctx context.Context, org, name, cloneAddr string) (repo *Repo, created bool, err error) {
	if r, err := c.GetRepo(ctx, org, name); err != nil || r != nil {
		return r, false, err
	}
	var r Repo
	_, err = c.do(ctx, http.MethodPost, "/repos/migrate", map[string]any{
		"clone_addr": cloneAddr, "repo_owner": org, "repo_name": name,
		"private": true, "mirror": false, "service": "git",
	}, &r)
	if isStatus(err, http.StatusConflict) {
		r2, err := c.mustRepo(ctx, org, name)
		return r2, false, err
	}
	if err != nil {
		return nil, false, err
	}
	return &r, true, nil
}

// HookEvents are the events Capsule subscribes to. Names verified against a real Forgejo 15.0.11
// (the hook is created with them and read back): "pull_request" also brings synchronize, assign,
// label, milestone and conversation comments; the review names are pull_request_review_* (the
// shorter pull_request_approved/rejected are silently rewritten to them by Forgejo).
var HookEvents = []string{
	"push", "create", "delete",
	"pull_request", "pull_request_review_request",
	"pull_request_review_approved", "pull_request_review_rejected", "pull_request_review_comment",
	"action_run_failure", "action_run_recover", "action_run_success",
}

// EnsureWebhook registers (or updates, keeping the secret in sync) the webhook to hookURL.
func (c *Client) EnsureWebhook(ctx context.Context, org, repo, hookURL, secret string) error {
	base := "/repos/" + url.PathEscape(org) + "/" + url.PathEscape(repo) + "/hooks"
	var hooks []struct {
		ID     int64 `json:"id"`
		Config struct {
			URL string `json:"url"`
		} `json:"config"`
	}
	if _, err := c.do(ctx, http.MethodGet, base, nil, &hooks); err != nil {
		return err
	}
	cfg := map[string]string{"url": hookURL, "content_type": "json", "secret": secret}
	for _, h := range hooks {
		if h.Config.URL == hookURL {
			_, err := c.do(ctx, http.MethodPatch, fmt.Sprintf("%s/%d", base, h.ID),
				map[string]any{"active": true, "events": HookEvents, "config": cfg}, nil)
			return err
		}
	}
	_, err := c.do(ctx, http.MethodPost, base, map[string]any{
		"type": "forgejo", "active": true, "events": HookEvents, "config": cfg,
	}, nil)
	return err
}

// ---- users and teams ---------------------------------------------------------

// UserExists reports whether the Forgejo user exists (it appears on first OIDC login).
func (c *Client) UserExists(ctx context.Context, username string) (bool, error) {
	_, err := c.do(ctx, http.MethodGet, "/users/"+url.PathEscape(username), nil, nil)
	if isStatus(err, http.StatusNotFound) {
		return false, nil
	}
	return err == nil, err
}

// Team is a Forgejo organization team.
type Team struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// TeamSpec describes a project team: permission and units.
type TeamSpec struct {
	Name       string
	Permission string // read | write | admin
}

var teamUnits = []string{"repo.code", "repo.issues", "repo.pulls", "repo.releases"}

// EnsureTeam finds the team by exact name or creates it.
func (c *Client) EnsureTeam(ctx context.Context, org string, spec TeamSpec) (*Team, error) {
	find := func() (*Team, error) {
		var res struct {
			Data []Team `json:"data"`
		}
		q := url.Values{"q": {spec.Name}, "limit": {"50"}}
		if _, err := c.do(ctx, http.MethodGet, "/orgs/"+url.PathEscape(org)+"/teams/search?"+q.Encode(), nil, &res); err != nil {
			return nil, err
		}
		for i := range res.Data {
			if strings.EqualFold(res.Data[i].Name, spec.Name) {
				return &res.Data[i], nil
			}
		}
		return nil, nil
	}
	if t, err := find(); err != nil || t != nil {
		return t, err
	}
	unitPerm := spec.Permission
	if unitPerm == "admin" {
		unitPerm = "write"
	}
	unitsMap := map[string]string{}
	for _, u := range teamUnits {
		unitsMap[u] = unitPerm
	}
	var t Team
	_, err := c.do(ctx, http.MethodPost, "/orgs/"+url.PathEscape(org)+"/teams", map[string]any{
		"name": spec.Name, "permission": spec.Permission, "includes_all_repositories": false,
		"can_create_org_repo": false, "units": teamUnits, "units_map": unitsMap,
		"description": "Managed by Capsule",
	}, &t)
	if isStatus(err, http.StatusUnprocessableEntity) || isStatus(err, http.StatusConflict) {
		if t2, ferr := find(); ferr == nil && t2 != nil {
			return t2, nil
		}
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// AddTeamRepo gives the team access to the repository (PUT /teams/{id}/repos/{org}/{repo}).
func (c *Client) AddTeamRepo(ctx context.Context, teamID int64, org, repo string) error {
	_, err := c.do(ctx, http.MethodPut, fmt.Sprintf("/teams/%d/repos/%s/%s", teamID, url.PathEscape(org), url.PathEscape(repo)), nil, nil)
	return err
}

// TeamMembers lists the logins in the team (all pages).
func (c *Client) TeamMembers(ctx context.Context, teamID int64) ([]string, error) {
	var all []string
	const limit = 50
	for page := 1; page <= 100; page++ {
		var users []struct {
			Login string `json:"login"`
		}
		if _, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/teams/%d/members?page=%d&limit=%d", teamID, page, limit), nil, &users); err != nil {
			return nil, err
		}
		for _, u := range users {
			all = append(all, u.Login)
		}
		if len(users) < limit {
			break
		}
	}
	return all, nil
}

// AddTeamMember adds the user to the team (also makes them an org member).
func (c *Client) AddTeamMember(ctx context.Context, teamID int64, username string) error {
	_, err := c.do(ctx, http.MethodPut, fmt.Sprintf("/teams/%d/members/%s", teamID, url.PathEscape(username)), nil, nil)
	return err
}

// RemoveTeamMember removes the user from the team (not being a member is fine).
func (c *Client) RemoveTeamMember(ctx context.Context, teamID int64, username string) error {
	_, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/teams/%d/members/%s", teamID, url.PathEscape(username)), nil, nil)
	if isStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}
