package gitcore

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Integration additions (hueco list of the backend integrator). types.go is fixed, so everything
// here is exposed as NEW interfaces that *Service implements; consumers detect them with a type
// assertion on the Core they hold (the same way ReviewAdmin works).
//
// Verified against the swagger served by a real Forgejo v15.0.11 (see ext_test.go and
// itest/ext_test.go). What the v15.0.11 API does NOT offer is stated on each method.

// CodeUnsupported marks a capability Forgejo's HTTP API does not offer (answered 501 by B1).
const CodeUnsupported Code = "NOT_SUPPORTED"

func unsupported(op, why string) error {
	return &Error{Code: CodeUnsupported, Message: why, Op: op}
}

// IsUnsupported reports whether err is a CodeUnsupported error.
func IsUnsupported(err error) bool { return errIs(err, CodeUnsupported) }

// ---------------------------------------------------------------------------------------------
// Actions: re-run, artifacts, secrets (names), runners
// ---------------------------------------------------------------------------------------------

// SecretInfo is a secret as listed: only the name (Forgejo never returns values).
type SecretInfo struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"` // Forgejo reports the creation time only
}

// RunnerScope selects which runners to list. Global needs a site-administrator token.
type RunnerScope struct {
	Owner  string // organization (or user) login; with Repo empty: the organization's runners
	Repo   string // with Owner: the repository's runners
	Global bool   // every runner of the instance (/admin/actions/runners)
	// Visible also lists the runners a repository/organization can use but does not own
	// (inherited from the organization or the instance).
	Visible bool
}

// Runner is an Actions runner.
type Runner struct {
	ID        int64    `json:"id"`
	UUID      string   `json:"uuid,omitempty"`
	Name      string   `json:"name"`
	Labels    []string `json:"labels"`
	Status    string   `json:"status"` // online|offline|busy (Forgejo: idle|offline|active)
	Version   string   `json:"version,omitempty"`
	Ephemeral bool     `json:"ephemeral,omitempty"`
	// Scope is where the runner is registered: repo, org or global.
	Scope string `json:"scope"`
}

// Artifact is a workflow-run artifact.
type Artifact struct {
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	DownloadURL string    `json:"download_url"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ActionsExt is the Actions surface added after A1.
type ActionsExt interface {
	// RerunRun re-runs a FINISHED run. With the web session (CAPSULE_GIT_BOT_PASSWORD) it uses the UI re-run:
	// Forgejo re-uses the SAME run (new attempt), so the returned run has the same ID; failedOnly re-runs
	// only the failed/cancelled jobs. Without it, it falls back to dispatching the run workflow
	// (workflow_dispatch: only workflows that declare it, new run ID) and failedOnly is CodeUnsupported.
	RerunRun(ctx context.Context, r RepoRef, runID int64, failedOnly bool) (*Run, error)
	// ListArtifacts lists the run artifacts through the web session (the REST API has none); without
	// it CodeUnsupported (never an empty list that would hide them). DownloadURL is the Forgejo web URL.
	ListArtifacts(ctx context.Context, r RepoRef, runID int64) ([]Artifact, error)
	// ListSecrets lists secret NAMES of a repository, or of an organization when r.Repo == "".
	// Values are never readable.
	ListSecrets(ctx context.Context, r RepoRef) ([]SecretInfo, error)
	ListRunners(ctx context.Context, sc RunnerScope) ([]Runner, error)
}

var _ ActionsExt = (*Service)(nil)

func isFinished(status string) bool {
	switch strings.ToLower(status) {
	case "success", "failure", "cancelled", "canceled", "skipped":
		return true
	}
	return false
}

func (s *Service) RerunRun(ctx context.Context, r RepoRef, runID int64, failedOnly bool) (*Run, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if runID < 1 {
		return nil, invalid("run id must be positive")
	}
	if s.web == nil && failedOnly {
		return nil, unsupported("rerun failed jobs", "re-running only the failed jobs needs the Forgejo web session (CAPSULE_GIT_BOT_PASSWORD is not configured); re-run the whole run or use Forgejo: "+s.cfg.URL+"/"+r.Owner+"/"+r.Repo+"/actions")
	}
	old, err := s.GetRun(ctx, r, runID)
	if err != nil {
		return nil, err
	}
	if !isFinished(old.Status) {
		return nil, &Error{Code: CodeConflict, Message: "the run has not finished yet", Op: "rerun"}
	}
	if s.web != nil {
		run, err := s.web.rerun(ctx, r, runID, failedOnly)
		if err == nil {
			_ = s.InvalidateRepo(ctx, r)
		}
		return run, err
	}
	if old.WorkflowID == "" || old.Ref == "" {
		return nil, &Error{Code: CodeUnprocessed, Message: "the run has no workflow or ref to start again", Op: "rerun"}
	}
	var out struct {
		ID int64 `json:"id"`
	}
	res, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/actions/workflows/" + esc(old.WorkflowID) + "/dispatches",
		op: "/repos/{o}/{r}/actions/workflows/{wf}/dispatches", body: map[string]any{"ref": old.Ref, "return_run_info": true}}, &out)
	if err != nil {
		return nil, err
	}
	_ = s.InvalidateRepo(ctx, r)
	if res.status == http.StatusCreated && out.ID > 0 {
		return s.GetRun(ctx, r, out.ID)
	}
	// 204 (older Forgejo): the new run is the newest one of that workflow.
	l, err := s.ListRuns(ctx, r, RunQuery{Ref: old.Ref}, Page{Limit: 20})
	if err != nil {
		return nil, err
	}
	var best *Run
	for i := range l.Items {
		it := &l.Items[i]
		if it.WorkflowID == old.WorkflowID && it.ID > old.ID && (best == nil || it.ID > best.ID) {
			best = it
		}
	}
	if best == nil {
		return nil, &Error{Code: CodeUpstream, Message: "the workflow was dispatched but the new run was not found", Op: "rerun"}
	}
	return best, nil
}

func (s *Service) ListArtifacts(ctx context.Context, r RepoRef, runID int64) ([]Artifact, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if s.web == nil {
		return nil, unsupported("GET run artifacts", "Forgejo does not offer run artifacts through its API and the web session is not configured (CAPSULE_GIT_BOT_PASSWORD); download them from the Forgejo run page: "+s.cfg.URL+"/"+r.Owner+"/"+r.Repo+"/actions/runs/"+i64(runID))
	}
	if runID < 1 {
		return nil, invalid("run id must be positive")
	}
	return s.web.listArtifacts(ctx, r, runID)
}

func (s *Service) ListSecrets(ctx context.Context, r RepoRef) ([]SecretInfo, error) {
	base, tmpl, err := scope(r)
	if err != nil {
		return nil, err
	}
	out := []SecretInfo{}
	cur := ""
	for i := 0; i < 10; i++ {
		items, next, err := fetchPaged[struct {
			Name    string `json:"name"`
			Created string `json:"created_at"`
		}](ctx, s, req{method: http.MethodGet, path: base + "/actions/secrets", op: tmpl + "/actions/secrets"}, Page{Cursor: cur, Limit: MaxLimit}, "", nil)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			out = append(out, SecretInfo{Name: it.Name, UpdatedAt: parseTime(it.Created)})
		}
		if next == "" {
			break
		}
		cur = next
	}
	return out, nil
}

type fgRunner struct {
	ID        int64    `json:"id"`
	UUID      string   `json:"uuid"`
	Name      string   `json:"name"`
	Labels    []string `json:"labels"`
	Status    string   `json:"status"`
	Version   string   `json:"version"`
	Ephemeral bool     `json:"ephemeral"`
	OwnerID   int64    `json:"owner_id"`
	RepoID    int64    `json:"repo_id"`
}

func (f fgRunner) runner() Runner {
	st := f.Status
	switch st {
	case "idle":
		st = "online"
	case "active":
		st = "busy"
	}
	sc := "global"
	switch {
	case f.RepoID != 0:
		sc = "repo"
	case f.OwnerID != 0:
		sc = "org"
	}
	if f.Labels == nil {
		f.Labels = []string{}
	}
	return Runner{ID: f.ID, UUID: f.UUID, Name: f.Name, Labels: f.Labels, Status: st, Version: f.Version, Ephemeral: f.Ephemeral, Scope: sc}
}

func (s *Service) ListRunners(ctx context.Context, sc RunnerScope) ([]Runner, error) {
	var path, op string
	switch {
	case sc.Global:
		path, op = "/admin/actions/runners", "/admin/actions/runners"
	case sc.Repo != "":
		r := RepoRef{Owner: sc.Owner, Repo: sc.Repo}
		if err := r.valid(); err != nil {
			return nil, err
		}
		path, op = r.base()+"/actions/runners", "/repos/{o}/{r}/actions/runners"
	default:
		if _, _, err := scope(RepoRef{Owner: sc.Owner}); err != nil {
			return nil, err
		}
		path, op = "/orgs/"+esc(sc.Owner)+"/actions/runners", "/orgs/{o}/actions/runners"
	}
	qv := url.Values{}
	if sc.Visible {
		qv.Set("visible", "true")
	}
	out := []Runner{}
	cur := ""
	for i := 0; i < 10; i++ {
		items, next, err := fetchPaged[fgRunner](ctx, s, req{method: http.MethodGet, path: path, op: op, query: qv}, Page{Cursor: cur, Limit: MaxLimit}, "", nil)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			out = append(out, it.runner())
		}
		if next == "" {
			break
		}
		cur = next
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------
// Teams: patch an existing team; users: lookup by login
// ---------------------------------------------------------------------------------------------

// TeamPatch changes an existing team. Permission "" keeps it; Units nil keeps the units.
type TeamPatch struct {
	Permission string   // read|write|admin
	Units      []string // e.g. repo.code, repo.pulls
}

// TeamAdmin edits teams that already exist (EnsureTeam only creates).
type TeamAdmin interface {
	// PatchTeam sets the team's permission and units. As in EnsureTeam, the per-unit level of an
	// "admin" team is write (units never grant repository settings).
	PatchTeam(ctx context.Context, teamID int64, p TeamPatch) (*Team, error)
}

// UserInfo is a Forgejo account.
type UserInfo struct {
	ID         int64  `json:"id"`
	Login      string `json:"login"`
	FullName   string `json:"full_name"`
	Email      string `json:"email"`
	Active     bool   `json:"active"`
	Restricted bool   `json:"restricted"`
}

// UserDirectory looks accounts up.
type UserDirectory interface {
	// GetUser returns the account with that login (NotFound error if absent).
	GetUser(ctx context.Context, login string) (*UserInfo, error)
}

var (
	_ TeamAdmin     = (*Service)(nil)
	_ UserDirectory = (*Service)(nil)
)

func (s *Service) PatchTeam(ctx context.Context, teamID int64, p TeamPatch) (*Team, error) {
	if teamID < 1 {
		return nil, invalid("team id must be positive")
	}
	switch p.Permission {
	case "", "read", "write", "admin":
	default:
		return nil, invalid("team permission must be read, write or admin")
	}
	var cur struct {
		Name       string            `json:"name"`
		Permission string            `json:"permission"`
		Units      []string          `json:"units"`
		UnitsMap   map[string]string `json:"units_map"`
	}
	if _, err := s.do(ctx, req{method: http.MethodGet, path: "/teams/" + i64(teamID), op: "/teams/{id}"}, &cur); err != nil {
		return nil, err
	}
	perm := p.Permission
	if perm == "" {
		perm = cur.Permission
	}
	units := p.Units
	if units == nil {
		units = cur.Units
	}
	unitPerm := perm
	if unitPerm == "admin" || unitPerm == "owner" {
		unitPerm = "write"
	}
	um := map[string]string{}
	for _, u := range units {
		um[u] = unitPerm
	}
	if units == nil {
		units = []string{}
	}
	var t fgTeam
	if _, err := s.do(ctx, req{method: http.MethodPatch, path: "/teams/" + i64(teamID), op: "/teams/{id}", body: map[string]any{
		"name": cur.Name, "permission": perm, "includes_all_repositories": false, "can_create_org_repo": false,
		"units": units, "units_map": um}}, &t); err != nil {
		return nil, err
	}
	name := t.Name
	if name == "" {
		name = cur.Name
	}
	return &Team{ID: teamID, Name: name, Permission: perm}, nil
}

func (s *Service) GetUser(ctx context.Context, login string) (*UserInfo, error) {
	login = strings.TrimSpace(login)
	if login == "" || strings.ContainsAny(login, "/\\?#%") || login == "." || login == ".." {
		return nil, invalid("a valid user login is required")
	}
	var u struct {
		ID         int64  `json:"id"`
		Login      string `json:"login"`
		FullName   string `json:"full_name"`
		Email      string `json:"email"`
		Active     bool   `json:"active"`
		Restricted bool   `json:"restricted"`
	}
	if _, err := s.do(ctx, req{method: http.MethodGet, path: "/users/" + esc(login), op: "/users/{u}"}, &u); err != nil {
		return nil, err
	}
	if u.Login == "" {
		u.Login = login
	}
	return &UserInfo{ID: u.ID, Login: u.Login, FullName: u.FullName, Email: u.Email, Active: u.Active, Restricted: u.Restricted}, nil
}

// ---------------------------------------------------------------------------------------------
// Tag protection
// ---------------------------------------------------------------------------------------------

// TagProtectionSpec is a protected-tag rule. Forgejo lets ONLY the whitelisted users/teams create
// tags matching Pattern (an empty whitelist means nobody; it is not "everybody").
type TagProtectionSpec struct {
	Pattern        string // glob (Forgejo: name_pattern), e.g. "v*"
	WhitelistUsers []string
	WhitelistTeams []string
}

type TagProtection struct {
	ID int64 `json:"id"`
	TagProtectionSpec
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TagProtections manages Forgejo's protected-tag rules.
type TagProtections interface {
	ListTagProtections(ctx context.Context, r RepoRef) ([]TagProtection, error)
	CreateTagProtection(ctx context.Context, r RepoRef, spec TagProtectionSpec) (*TagProtection, error)
	// EditTagProtection replaces the pattern and whitelists of rule id in place (no unprotected
	// window, unlike delete + create).
	EditTagProtection(ctx context.Context, r RepoRef, id int64, spec TagProtectionSpec) (*TagProtection, error)
	DeleteTagProtection(ctx context.Context, r RepoRef, id int64) error
}

var _ TagProtections = (*Service)(nil)

type fgTagProt struct {
	ID      int64    `json:"id"`
	Pattern string   `json:"name_pattern"`
	Users   []string `json:"whitelist_usernames"`
	Teams   []string `json:"whitelist_teams"`
	Created string   `json:"created_at"`
	Updated string   `json:"updated_at"`
}

func (f fgTagProt) value() TagProtection {
	return TagProtection{ID: f.ID, TagProtectionSpec: TagProtectionSpec{Pattern: f.Pattern, WhitelistUsers: nz(f.Users), WhitelistTeams: nz(f.Teams)},
		CreatedAt: parseTime(f.Created), UpdatedAt: parseTime(f.Updated)}
}

func (s *Service) ListTagProtections(ctx context.Context, r RepoRef) ([]TagProtection, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	var fs []fgTagProt
	if _, err := s.do(ctx, req{method: http.MethodGet, path: r.base() + "/tag_protections", op: "/repos/{o}/{r}/tag_protections"}, &fs); err != nil {
		return nil, err
	}
	out := make([]TagProtection, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.value())
	}
	return out, nil
}

func (s *Service) CreateTagProtection(ctx context.Context, r RepoRef, sp TagProtectionSpec) (*TagProtection, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(sp.Pattern) == "" {
		return nil, invalid("a tag pattern is required")
	}
	var f fgTagProt
	if _, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/tag_protections", op: "/repos/{o}/{r}/tag_protections",
		body: map[string]any{"name_pattern": sp.Pattern, "whitelist_usernames": nz(sp.WhitelistUsers), "whitelist_teams": nz(sp.WhitelistTeams)}}, &f); err != nil {
		return nil, err
	}
	v := f.value()
	if v.Pattern == "" {
		v.Pattern = sp.Pattern
	}
	return &v, nil
}

func (s *Service) DeleteTagProtection(ctx context.Context, r RepoRef, id int64) error {
	if err := r.valid(); err != nil {
		return err
	}
	if id < 1 {
		return invalid("tag protection id must be positive")
	}
	_, err := s.do(ctx, req{method: http.MethodDelete, path: r.base() + "/tag_protections/" + i64(id), op: "/repos/{o}/{r}/tag_protections/{id}"}, nil)
	return err
}

func (s *Service) EditTagProtection(ctx context.Context, r RepoRef, id int64, sp TagProtectionSpec) (*TagProtection, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if id < 1 {
		return nil, invalid("tag protection id must be positive")
	}
	if strings.TrimSpace(sp.Pattern) == "" {
		return nil, invalid("a tag pattern is required")
	}
	var f fgTagProt
	if _, err := s.do(ctx, req{method: http.MethodPatch, path: r.base() + "/tag_protections/" + i64(id), op: "/repos/{o}/{r}/tag_protections/{id}",
		body: map[string]any{"name_pattern": sp.Pattern, "whitelist_usernames": nz(sp.WhitelistUsers), "whitelist_teams": nz(sp.WhitelistTeams)}}, &f); err != nil {
		return nil, err
	}
	v := f.value()
	if v.ID == 0 {
		v.ID = id
	}
	if v.Pattern == "" {
		v.Pattern = sp.Pattern
	}
	return &v, nil
}

// ---------------------------------------------------------------------------------------------
// Web-session extras (see websession.go)
// ---------------------------------------------------------------------------------------------

// JobStepLister lists the steps of every job of a run (one Forgejo web call per job). Optional:
// CodeUnsupported without the web session.
type JobStepLister interface {
	ListJobSteps(ctx context.Context, r RepoRef, runID int64) (map[int64][]JobStep, error)
}

// ArtifactDownloader returns the zip of a run artifact (bounded to 512 MiB). Optional.
type ArtifactDownloader interface {
	DownloadArtifact(ctx context.Context, r RepoRef, runID int64, name string) ([]byte, error)
}

var (
	_ JobStepLister      = (*Service)(nil)
	_ ArtifactDownloader = (*Service)(nil)
)

func (s *Service) ListJobSteps(ctx context.Context, r RepoRef, runID int64) (map[int64][]JobStep, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if s.web == nil {
		return nil, s.webOff("list job steps", r)
	}
	return s.web.listSteps(ctx, r, runID)
}

func (s *Service) DownloadArtifact(ctx context.Context, r RepoRef, runID int64, name string) ([]byte, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if s.web == nil {
		return nil, s.webOff("download a run artifact", r)
	}
	return s.web.downloadArtifact(ctx, r, runID, name)
}
