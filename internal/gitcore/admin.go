package gitcore

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// ---- branch protections ----------------------------------------------------------------------

type fgProtection struct {
	RuleName                string   `json:"rule_name"`
	BranchName              string   `json:"branch_name"`
	EnablePush              bool     `json:"enable_push"`
	EnablePushWhitelist     bool     `json:"enable_push_whitelist"`
	PushWhitelistUsers      []string `json:"push_whitelist_usernames"`
	PushWhitelistTeams      []string `json:"push_whitelist_teams"`
	PushWhitelistDeployKeys bool     `json:"push_whitelist_deploy_keys"`
	EnableMergeWhitelist    bool     `json:"enable_merge_whitelist"`
	MergeWhitelistUsers     []string `json:"merge_whitelist_usernames"`
	MergeWhitelistTeams     []string `json:"merge_whitelist_teams"`
	EnableStatusCheck       bool     `json:"enable_status_check"`
	StatusCheckContexts     []string `json:"status_check_contexts"`
	RequiredApprovals       int      `json:"required_approvals"`
	EnableApprovalsWL       bool     `json:"enable_approvals_whitelist"`
	ApprovalsWLUsers        []string `json:"approvals_whitelist_username"`
	ApprovalsWLTeams        []string `json:"approvals_whitelist_teams"`
	BlockOnRejected         bool     `json:"block_on_rejected_reviews"`
	BlockOnOfficial         bool     `json:"block_on_official_review_requests"`
	BlockOnOutdated         bool     `json:"block_on_outdated_branch"`
	DismissStale            bool     `json:"dismiss_stale_approvals"`
	IgnoreStale             bool     `json:"ignore_stale_approvals"`
	RequireSigned           bool     `json:"require_signed_commits"`
	ProtectedFiles          string   `json:"protected_file_patterns"`
	UnprotectedFiles        string   `json:"unprotected_file_patterns"`
	ApplyToAdmins           bool     `json:"apply_to_admins"`
	CreatedAt               string   `json:"created_at"`
	UpdatedAt               string   `json:"updated_at"`
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// body is the full desired state; create adds the rule name.
func (sp ProtectionSpec) body(create bool) map[string]any {
	m := map[string]any{
		"enable_push": sp.EnablePush, "enable_push_whitelist": sp.EnablePushWhitelist,
		"push_whitelist_usernames": nz(sp.PushWhitelistUsers), "push_whitelist_teams": nz(sp.PushWhitelistTeams),
		"push_whitelist_deploy_keys": sp.PushWhitelistDeployKeys,
		"enable_merge_whitelist":     sp.EnableMergeWhitelist,
		"merge_whitelist_usernames":  nz(sp.MergeWhitelistUsers), "merge_whitelist_teams": nz(sp.MergeWhitelistTeams),
		"enable_status_check": sp.EnableStatusCheck, "status_check_contexts": nz(sp.StatusCheckContexts),
		"required_approvals":           sp.RequiredApprovals,
		"enable_approvals_whitelist":   sp.EnableApprovalsWhitelist,
		"approvals_whitelist_username": nz(sp.ApprovalsWhitelistUsers), "approvals_whitelist_teams": nz(sp.ApprovalsWhitelistTeams),
		"block_on_rejected_reviews": sp.BlockOnRejectedReviews, "block_on_official_review_requests": sp.BlockOnOfficialReviewRequest,
		"block_on_outdated_branch": sp.BlockOnOutdatedBranch, "dismiss_stale_approvals": sp.DismissStaleApprovals,
		"ignore_stale_approvals": sp.IgnoreStaleApprovals, "require_signed_commits": sp.RequireSignedCommits,
		"protected_file_patterns": sp.ProtectedFilePatterns, "unprotected_file_patterns": sp.UnprotectedFilePatterns,
		"apply_to_admins": sp.ApplyToAdmins,
	}
	if create {
		m["rule_name"] = sp.RuleName
	}
	return m
}

func (f fgProtection) protection() Protection {
	name := f.RuleName
	if name == "" {
		name = f.BranchName
	}
	return Protection{ProtectionSpec: ProtectionSpec{RuleName: name, EnablePush: f.EnablePush, EnablePushWhitelist: f.EnablePushWhitelist,
		PushWhitelistUsers: f.PushWhitelistUsers, PushWhitelistTeams: f.PushWhitelistTeams, PushWhitelistDeployKeys: f.PushWhitelistDeployKeys,
		EnableMergeWhitelist: f.EnableMergeWhitelist, MergeWhitelistUsers: f.MergeWhitelistUsers, MergeWhitelistTeams: f.MergeWhitelistTeams,
		EnableStatusCheck: f.EnableStatusCheck, StatusCheckContexts: f.StatusCheckContexts, RequiredApprovals: f.RequiredApprovals,
		EnableApprovalsWhitelist: f.EnableApprovalsWL, ApprovalsWhitelistUsers: f.ApprovalsWLUsers, ApprovalsWhitelistTeams: f.ApprovalsWLTeams,
		BlockOnRejectedReviews: f.BlockOnRejected, BlockOnOfficialReviewRequest: f.BlockOnOfficial, BlockOnOutdatedBranch: f.BlockOnOutdated,
		DismissStaleApprovals: f.DismissStale, IgnoreStaleApprovals: f.IgnoreStale, RequireSignedCommits: f.RequireSigned,
		ProtectedFilePatterns: f.ProtectedFiles, UnprotectedFilePatterns: f.UnprotectedFiles, ApplyToAdmins: f.ApplyToAdmins},
		CreatedAt: parseTime(f.CreatedAt), UpdatedAt: parseTime(f.UpdatedAt)}
}

func (s *Service) ListProtections(ctx context.Context, r RepoRef) ([]Protection, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	var fs []fgProtection
	if _, err := s.do(ctx, req{method: http.MethodGet, path: r.base() + "/branch_protections", op: "/repos/{o}/{r}/branch_protections"}, &fs); err != nil {
		return nil, err
	}
	out := make([]Protection, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.protection())
	}
	return out, nil
}

func (s *Service) GetProtection(ctx context.Context, r RepoRef, rule string) (*Protection, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if rule == "" {
		return nil, invalid("rule name is required")
	}
	var f fgProtection
	// (?) rule names with "/" or "*" travel percent-encoded; confirm against Forgejo routing.
	if _, err := s.do(ctx, req{method: http.MethodGet, path: r.base() + "/branch_protections/" + esc(rule), op: "/repos/{o}/{r}/branch_protections/{name}"}, &f); err != nil {
		return nil, err
	}
	p := f.protection()
	return &p, nil
}

func (s *Service) UpsertProtection(ctx context.Context, r RepoRef, sp ProtectionSpec) (*Protection, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(sp.RuleName) == "" {
		return nil, invalid("rule name is required")
	}
	if sp.RequiredApprovals < 0 || sp.RequiredApprovals > 10 {
		return nil, invalid("required approvals must be between 0 and 10")
	}
	var f fgProtection
	_, err := s.do(ctx, req{method: http.MethodPatch, path: r.base() + "/branch_protections/" + esc(sp.RuleName),
		op: "/repos/{o}/{r}/branch_protections/{name}", body: sp.body(false)}, &f)
	if errIs(err, CodeNotFound) {
		_, err = s.do(ctx, req{method: http.MethodPost, path: r.base() + "/branch_protections", op: "/repos/{o}/{r}/branch_protections", body: sp.body(true)}, &f)
		if errIs(err, CodeConflict) || errIs(err, CodeUnprocessed) { // created concurrently: edit it
			_, err = s.do(ctx, req{method: http.MethodPatch, path: r.base() + "/branch_protections/" + esc(sp.RuleName),
				op: "/repos/{o}/{r}/branch_protections/{name}", body: sp.body(false)}, &f)
		}
	}
	if err != nil {
		return nil, err
	}
	_ = s.InvalidateRepo(ctx, r) // branches show protected/rule
	p := f.protection()
	if p.RuleName == "" {
		p.RuleName = sp.RuleName
	}
	return &p, nil
}

func (s *Service) DeleteProtection(ctx context.Context, r RepoRef, rule string) error {
	if err := r.valid(); err != nil {
		return err
	}
	if rule == "" {
		return invalid("rule name is required")
	}
	_, err := s.do(ctx, req{method: http.MethodDelete, path: r.base() + "/branch_protections/" + esc(rule), op: "/repos/{o}/{r}/branch_protections/{name}"}, nil)
	if err == nil {
		_ = s.InvalidateRepo(ctx, r)
	}
	return err
}

// ---- teams -------------------------------------------------------------------------------------

var defaultTeamUnits = []string{"repo.code", "repo.issues", "repo.pulls", "repo.releases"}

type fgTeam struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Permission string `json:"permission"`
}

func (s *Service) EnsureTeam(ctx context.Context, org string, spec TeamSpec) (*Team, error) {
	if org == "" || spec.Name == "" {
		return nil, invalid("organization and team name are required")
	}
	switch spec.Permission {
	case "read", "write", "admin":
	default:
		return nil, invalid("team permission must be read, write or admin")
	}
	find := func() (*Team, error) {
		var res struct {
			Data []fgTeam `json:"data"`
		}
		q := url.Values{"q": {spec.Name}, "limit": {"50"}}
		if _, err := s.do(ctx, req{method: http.MethodGet, path: "/orgs/" + esc(org) + "/teams/search", op: "/orgs/{o}/teams/search", query: q}, &res); err != nil {
			return nil, err
		}
		for _, t := range res.Data {
			if strings.EqualFold(t.Name, spec.Name) {
				return &Team{ID: t.ID, Name: t.Name, Permission: t.Permission}, nil
			}
		}
		return nil, nil
	}
	if t, err := find(); err != nil || t != nil {
		return t, err
	}
	units := spec.Units
	if len(units) == 0 {
		units = defaultTeamUnits
	}
	unitPerm := spec.Permission
	if unitPerm == "admin" {
		unitPerm = "write"
	}
	um := map[string]string{}
	for _, u := range units {
		um[u] = unitPerm
	}
	var t fgTeam
	_, err := s.do(ctx, req{method: http.MethodPost, path: "/orgs/" + esc(org) + "/teams", op: "/orgs/{o}/teams", body: map[string]any{
		"name": spec.Name, "permission": spec.Permission, "includes_all_repositories": false, "can_create_org_repo": false,
		"units": units, "units_map": um, "description": "Managed by Capsule"}}, &t)
	if errIs(err, CodeUnprocessed) || errIs(err, CodeConflict) {
		if t2, ferr := find(); ferr == nil && t2 != nil {
			return t2, nil
		}
	}
	if err != nil {
		return nil, err
	}
	return &Team{ID: t.ID, Name: t.Name, Permission: spec.Permission}, nil
}

func (s *Service) AddTeamRepo(ctx context.Context, teamID int64, r RepoRef) error {
	if err := r.valid(); err != nil {
		return err
	}
	_, err := s.do(ctx, req{method: http.MethodPut, path: "/teams/" + i64(teamID) + "/repos/" + esc(r.Owner) + "/" + esc(r.Repo), op: "/teams/{id}/repos/{o}/{r}"}, nil)
	return err
}

func (s *Service) TeamMembers(ctx context.Context, teamID int64) ([]string, error) {
	out := []string{}
	cur := ""
	for i := 0; i < 100; i++ {
		items, next, err := fetchPaged[fgUser](ctx, s, req{method: http.MethodGet, path: "/teams/" + i64(teamID) + "/members", op: "/teams/{id}/members"}, Page{Cursor: cur, Limit: MaxLimit}, "", nil)
		if err != nil {
			return nil, err
		}
		for _, u := range items {
			out = append(out, u.Login)
		}
		if next == "" {
			break
		}
		cur = next
	}
	return out, nil
}

func (s *Service) AddTeamMember(ctx context.Context, teamID int64, login string) error {
	if login == "" {
		return invalid("login is required")
	}
	_, err := s.do(ctx, req{method: http.MethodPut, path: "/teams/" + i64(teamID) + "/members/" + esc(login), op: "/teams/{id}/members/{u}"}, nil)
	return err
}

func (s *Service) RemoveTeamMember(ctx context.Context, teamID int64, login string) error {
	if login == "" {
		return invalid("login is required")
	}
	_, err := s.do(ctx, req{method: http.MethodDelete, path: "/teams/" + i64(teamID) + "/members/" + esc(login), op: "/teams/{id}/members/{u}"}, nil)
	if errIs(err, CodeNotFound) {
		return nil // not being a member is the desired end state
	}
	return err
}

// ---- hooks -------------------------------------------------------------------------------------

type fgHook struct {
	ID     int64             `json:"id"`
	Active bool              `json:"active"`
	Events []string          `json:"events"`
	Config map[string]string `json:"config"`
}

func (h fgHook) hook() Hook {
	return Hook{ID: h.ID, URL: h.Config["url"], Events: h.Events, Active: h.Active}
}

func (s *Service) ListHooks(ctx context.Context, r RepoRef) ([]Hook, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	out := []Hook{}
	cur := ""
	for i := 0; i < 10; i++ {
		items, next, err := fetchPaged[fgHook](ctx, s, req{method: http.MethodGet, path: r.base() + "/hooks", op: "/repos/{o}/{r}/hooks"}, Page{Cursor: cur, Limit: MaxLimit}, "", nil)
		if err != nil {
			return nil, err
		}
		for _, h := range items {
			out = append(out, h.hook())
		}
		if next == "" {
			break
		}
		cur = next
	}
	return out, nil
}

func (s *Service) EnsureHook(ctx context.Context, r RepoRef, spec HookSpec) (*Hook, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if spec.URL == "" || len(spec.Events) == 0 {
		return nil, invalid("hook url and events are required")
	}
	hooks, err := s.ListHooks(ctx, r)
	if err != nil {
		return nil, err
	}
	cfg := map[string]string{"url": spec.URL, "content_type": "json"}
	if spec.Secret != "" {
		cfg["secret"] = spec.Secret
	}
	body := map[string]any{"active": spec.Active, "events": spec.Events, "config": cfg}
	if spec.BranchFilter != "" {
		body["branch_filter"] = spec.BranchFilter
	}
	var f fgHook
	for _, h := range hooks {
		if h.URL == spec.URL {
			if _, err := s.do(ctx, req{method: http.MethodPatch, path: r.base() + "/hooks/" + i64(h.ID), op: "/repos/{o}/{r}/hooks/{id}", body: body}, &f); err != nil {
				return nil, err
			}
			out := f.hook()
			if out.ID == 0 {
				out = Hook{ID: h.ID, URL: spec.URL, Events: spec.Events, Active: spec.Active}
			}
			return &out, nil
		}
	}
	t := spec.Type
	if t == "" {
		t = "forgejo"
	}
	body["type"] = t
	if _, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/hooks", op: "/repos/{o}/{r}/hooks", body: body}, &f); err != nil {
		return nil, err
	}
	out := f.hook()
	return &out, nil
}

func (s *Service) DeleteHook(ctx context.Context, r RepoRef, id int64) error {
	if err := r.valid(); err != nil {
		return err
	}
	_, err := s.do(ctx, req{method: http.MethodDelete, path: r.base() + "/hooks/" + i64(id), op: "/repos/{o}/{r}/hooks/{id}"}, nil)
	return err
}

// ---- SSH keys (as the Sudo user) -------------------------------------------------------------

type fgKey struct {
	ID          int64  `json:"id"`
	Title       string `json:"title"`
	Fingerprint string `json:"fingerprint"`
	Key         string `json:"key"`
	ReadOnly    bool   `json:"read_only"`
	CreatedAt   string `json:"created_at"`
}

func (k fgKey) key() SSHKey {
	return SSHKey{ID: k.ID, Title: k.Title, Fingerprint: k.Fingerprint, Key: k.Key, ReadOnly: k.ReadOnly, CreatedAt: parseTime(k.CreatedAt)}
}

func needActor(ctx context.Context) error {
	if ActorFrom(ctx) == "" {
		return invalid("this operation acts on a user: use WithActor")
	}
	return nil
}

func (s *Service) ListSSHKeys(ctx context.Context) ([]SSHKey, error) {
	if err := needActor(ctx); err != nil {
		return nil, err
	}
	out := []SSHKey{}
	cur := ""
	for i := 0; i < 10; i++ {
		items, next, err := fetchPaged[fgKey](ctx, s, req{method: http.MethodGet, path: "/user/keys", op: "/user/keys"}, Page{Cursor: cur, Limit: MaxLimit}, "", nil)
		if err != nil {
			return nil, err
		}
		for _, k := range items {
			out = append(out, k.key())
		}
		if next == "" {
			break
		}
		cur = next
	}
	return out, nil
}

func (s *Service) AddSSHKey(ctx context.Context, title, key string, readOnly bool) (*SSHKey, error) {
	if err := needActor(ctx); err != nil {
		return nil, err
	}
	if strings.TrimSpace(title) == "" || strings.TrimSpace(key) == "" {
		return nil, invalid("title and key are required")
	}
	var f fgKey
	if _, err := s.do(ctx, req{method: http.MethodPost, path: "/user/keys", op: "/user/keys",
		body: map[string]any{"title": title, "key": key, "read_only": readOnly}}, &f); err != nil {
		return nil, err
	}
	k := f.key()
	return &k, nil
}

func (s *Service) DeleteSSHKey(ctx context.Context, id int64) error {
	if err := needActor(ctx); err != nil {
		return err
	}
	_, err := s.do(ctx, req{method: http.MethodDelete, path: "/user/keys/" + i64(id), op: "/user/keys/{id}"}, nil)
	return err
}

// ---- push mirrors ----------------------------------------------------------------------------

type fgMirror struct {
	RemoteName   string `json:"remote_name"`
	RemoteAddr   string `json:"remote_address"`
	Interval     string `json:"interval"`
	SyncOnCommit bool   `json:"sync_on_commit"`
	LastUpdate   string `json:"last_update"`
	LastError    string `json:"last_error"`
	PublicKey    string `json:"public_key"`
}

func (m fgMirror) mirror() PushMirror {
	return PushMirror{RemoteName: m.RemoteName, RemoteURL: m.RemoteAddr, Interval: m.Interval, SyncOnCommit: m.SyncOnCommit,
		LastUpdate: parseTime(m.LastUpdate), LastError: m.LastError, PublicKey: m.PublicKey}
}

func (s *Service) ListPushMirrors(ctx context.Context, r RepoRef) ([]PushMirror, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	out := []PushMirror{}
	cur := ""
	for i := 0; i < 10; i++ {
		items, next, err := fetchPaged[fgMirror](ctx, s, req{method: http.MethodGet, path: r.base() + "/push_mirrors", op: "/repos/{o}/{r}/push_mirrors"}, Page{Cursor: cur, Limit: MaxLimit}, "", nil)
		if err != nil {
			return nil, err
		}
		for _, m := range items {
			out = append(out, m.mirror())
		}
		if next == "" {
			break
		}
		cur = next
	}
	return out, nil
}

func (s *Service) AddPushMirror(ctx context.Context, r RepoRef, sp PushMirrorSpec) (*PushMirror, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if sp.RemoteAddress == "" {
		return nil, invalid("remote address is required")
	}
	iv := sp.Interval
	if iv == "" {
		iv = "8h0m0s"
	}
	body := map[string]any{"remote_address": sp.RemoteAddress, "interval": iv, "sync_on_commit": sp.SyncOnCommit, "use_ssh": sp.UseSSH}
	if sp.RemoteUsername != "" {
		body["remote_username"] = sp.RemoteUsername
	}
	if sp.RemotePassword != "" {
		body["remote_password"] = sp.RemotePassword
	}
	if sp.BranchFilter != "" {
		body["branch_filter"] = sp.BranchFilter
	}
	var f fgMirror
	if _, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/push_mirrors", op: "/repos/{o}/{r}/push_mirrors", body: body}, &f); err != nil {
		return nil, err
	}
	m := f.mirror()
	return &m, nil
}

func (s *Service) DeletePushMirror(ctx context.Context, r RepoRef, name string) error {
	if err := r.valid(); err != nil {
		return err
	}
	if name == "" {
		return invalid("mirror name is required")
	}
	_, err := s.do(ctx, req{method: http.MethodDelete, path: r.base() + "/push_mirrors/" + esc(name), op: "/repos/{o}/{r}/push_mirrors/{name}"}, nil)
	return err
}

func (s *Service) SyncPushMirrors(ctx context.Context, r RepoRef) error {
	if err := r.valid(); err != nil {
		return err
	}
	_, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/push_mirrors-sync", op: "/repos/{o}/{r}/push_mirrors-sync"}, nil)
	return err
}
