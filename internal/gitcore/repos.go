package gitcore

import (
	"context"
	"net/http"
	"net/url"
)

type fgUser struct {
	Login     string `json:"login"`
	FullName  string `json:"full_name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (u fgUser) person() Person {
	return Person{Login: u.Login, Name: u.FullName, Email: u.Email, AvatarURL: u.AvatarURL}
}

type fgRepo struct {
	Name          string `json:"name"`
	Owner         fgUser `json:"owner"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Empty         bool   `json:"empty"`
	Archived      bool   `json:"archived"`
	Size          int64  `json:"size"`
	HTMLURL       string `json:"html_url"`
	DeleteBranch  bool   `json:"default_delete_branch_after_merge"`
	AllowMerge    bool   `json:"allow_merge_commits"`
	AllowSquash   bool   `json:"allow_squash_merge"`
	AllowRebase   bool   `json:"allow_rebase"`
	AllowFF       bool   `json:"allow_fast_forward_only_merge"`
}

func (f fgRepo) repo(owner string) *Repository {
	o := f.Owner.Login
	if o == "" {
		o = owner
	}
	var styles []string
	if f.AllowMerge {
		styles = append(styles, "merge")
	}
	if f.AllowSquash {
		styles = append(styles, "squash")
	}
	if f.AllowRebase {
		styles = append(styles, "rebase")
	}
	if f.AllowFF {
		styles = append(styles, "fast-forward")
	}
	return &Repository{Owner: o, Name: f.Name, DefaultBranch: f.DefaultBranch, Private: f.Private, Empty: f.Empty,
		Archived: f.Archived, SizeKB: f.Size, HTMLURL: f.HTMLURL, DeleteBranchOnPR: f.DeleteBranch, AllowedMergeStyles: styles}
}

func (s *Service) Ping(ctx context.Context) error {
	if !s.cfg.Enabled() {
		return &Error{Code: CodeNotReady, Message: "git integration is not configured", Op: "GET /version"}
	}
	_, err := s.do(ctx, req{method: http.MethodGet, path: "/version", op: "/version"}, nil)
	return err
}

func (s *Service) EnsureOrg(ctx context.Context, slug string) error {
	if slug == "" {
		return invalid("organization slug is required")
	}
	rq := req{method: http.MethodGet, path: "/orgs/" + esc(slug), op: "/orgs/{org}"}
	_, err := s.do(ctx, rq, nil)
	if err == nil || !errIs(err, CodeNotFound) {
		return err
	}
	_, err = s.do(ctx, req{method: http.MethodPost, path: "/orgs", op: "/orgs",
		body: map[string]any{"username": slug, "visibility": "private"}}, nil)
	if errIs(err, CodeUnprocessed) || errIs(err, CodeConflict) { // created concurrently
		if _, gerr := s.do(ctx, rq, nil); gerr == nil {
			return nil
		}
	}
	return err
}

func errIs(err error, c Code) bool {
	e, ok := AsError(err)
	return ok && e.Code == c
}

func (s *Service) GetRepo(ctx context.Context, r RepoRef) (*Repository, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	var f fgRepo
	if _, err := s.do(ctx, req{method: http.MethodGet, path: r.base(), op: "/repos/{o}/{r}"}, &f); err != nil {
		return nil, err
	}
	return f.repo(r.Owner), nil
}

func (s *Service) EnsureRepo(ctx context.Context, r RepoRef, spec RepoCreate) (*Repository, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if got, err := s.GetRepo(ctx, r); err == nil {
		return got, nil
	} else if !errIs(err, CodeNotFound) {
		return nil, err
	}
	body := map[string]any{"name": r.Repo, "private": spec.Private, "auto_init": spec.AutoInit}
	if spec.DefaultBranch != "" {
		body["default_branch"] = spec.DefaultBranch
	}
	if spec.Description != "" {
		body["description"] = spec.Description
	}
	var f fgRepo
	_, err := s.do(ctx, req{method: http.MethodPost, path: "/orgs/" + esc(r.Owner) + "/repos", op: "/orgs/{o}/repos", body: body}, &f)
	if errIs(err, CodeConflict) {
		return s.GetRepo(ctx, r)
	}
	if err != nil {
		return nil, err
	}
	return f.repo(r.Owner), nil
}

func (s *Service) PatchRepo(ctx context.Context, r RepoRef, p RepoPatch) (*Repository, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	body := map[string]any{}
	if p.DefaultBranch != nil {
		body["default_branch"] = *p.DefaultBranch
	}
	if p.Archived != nil {
		body["archived"] = *p.Archived
	}
	if p.DeleteBranchOnPR != nil {
		body["default_delete_branch_after_merge"] = *p.DeleteBranchOnPR
	}
	if p.AllowedMergeStyles != nil {
		set := map[string]bool{}
		for _, m := range p.AllowedMergeStyles {
			set[m] = true
		}
		body["allow_merge_commits"] = set["merge"]
		body["allow_squash_merge"] = set["squash"]
		body["allow_rebase"] = set["rebase"]
		body["allow_fast_forward_only_merge"] = set["fast-forward"]
	}
	var f fgRepo
	if _, err := s.do(ctx, req{method: http.MethodPatch, path: r.base(), op: "/repos/{o}/{r}", body: body}, &f); err != nil {
		return nil, err
	}
	return f.repo(r.Owner), nil
}

func (s *Service) Migrate(ctx context.Context, m MigrateSpec) (*Repository, error) {
	ref := RepoRef{m.Owner, m.Repo}
	if err := ref.valid(); err != nil {
		return nil, err
	}
	if m.CloneAddr == "" {
		return nil, invalid("clone address is required")
	}
	if got, err := s.GetRepo(ctx, ref); err == nil {
		return got, nil
	} else if !errIs(err, CodeNotFound) {
		return nil, err
	}
	svc := m.Service
	if svc == "" {
		svc = "git"
	}
	body := map[string]any{"clone_addr": m.CloneAddr, "repo_owner": m.Owner, "repo_name": m.Repo, "service": svc,
		"private": m.Private, "mirror": m.Mirror, "issues": m.Issues, "pull_requests": m.PullRequests,
		"releases": m.Releases, "wiki": m.Wiki, "lfs": m.LFS}
	if m.AuthToken != "" {
		body["auth_token"] = m.AuthToken
	}
	if m.Mirror && m.MirrorEvery != "" {
		body["mirror_interval"] = m.MirrorEvery
	}
	var f fgRepo
	_, err := s.do(ctx, req{method: http.MethodPost, path: "/repos/migrate", op: "/repos/migrate", body: body}, &f)
	if errIs(err, CodeConflict) {
		return s.GetRepo(ctx, ref)
	}
	if err != nil {
		return nil, err
	}
	return f.repo(m.Owner), nil
}

func (s *Service) UserExists(ctx context.Context, login string) (bool, error) {
	if login == "" {
		return false, invalid("login is required")
	}
	_, err := s.do(ctx, req{method: http.MethodGet, path: "/users/" + url.PathEscape(login), op: "/users/{u}"}, nil)
	if errIs(err, CodeNotFound) {
		return false, nil
	}
	return err == nil, err
}
