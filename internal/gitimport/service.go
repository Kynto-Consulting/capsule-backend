package gitimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

// Forge is the part of gitcore the import uses. *gitcore.Service satisfies it. The shared service has a
// short per-call timeout; for imports the wiring builds a DEDICATED gitcore.Service whose Timeout is
// Config.RepoTimeout (POST /repos/migrate answers when the whole clone is done).
type Forge interface {
	gitcore.Repos
	Enabled() bool
}

// Projects is the part of the project repository the import uses.
type Projects interface {
	GetBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*domain.Project, error)
	Create(ctx context.Context, p *domain.Project) (*domain.Project, error)
}

// Linker records that a project's repository exists in Forgejo (git_core_state = ready), so the
// provisioning retry loop of 000030 never tries to create an empty repository over the import.
type Linker interface {
	MarkReady(ctx context.Context, projectID uuid.UUID) error
}

// Deps wires the import service.
type Deps struct {
	Store    Store
	Forge    Forge
	GitHub   *GitHub
	Projects Projects
	Linker   Linker
	Audit    Auditor
	Policy   gitsource.Policy
	// AfterImport runs after a repository was imported (A2: reconcile the project's teams). Optional;
	// its failure is reported as a warning of the repository, not as a failure.
	AfterImport func(ctx context.Context, projectID uuid.UUID) error
	Logger      *slog.Logger
	Now         func() time.Time
}

// Service runs imports. Create it with New.
type Service struct {
	cfg Config
	d   Deps

	base context.Context
	mu   sync.Mutex
	live map[uuid.UUID]bool
	wg   sync.WaitGroup
}

// New builds the service. base bounds every background import (it is the process worker context).
func New(base context.Context, cfg Config, d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if base == nil {
		base = context.Background()
	}
	return &Service{cfg: cfg.withDefaults(), d: d, base: base, live: map[uuid.UUID]bool{}}
}

// Config returns the effective configuration.
func (s *Service) Config() Config { return s.cfg }

// Wait blocks until every background import finished (tests, graceful shutdown).
func (s *Service) Wait() { s.wg.Wait() }

// StartInput is a validated importCreate request plus its context. Token is the ephemeral GitHub
// token: it is used by the goroutine and then dropped; it is never persisted.
type StartInput struct {
	OrgID          uuid.UUID
	OrgSlug        string
	UserID         uuid.UUID
	IP             string
	Token          string
	Repos          []string // owner/name or https://github.com/owner/name
	Include        []string
	CreateProjects bool
	IdemKey        string
}

var (
	ghNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	includes = map[string]bool{"issues": true, "pull_requests": true, "wiki": true, "releases": true, "labels": true}
)

type repoRef struct{ owner, name, full, slug string }

func parseRepo(raw string) (repoRef, error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "https://github.com/")
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	parts := strings.Split(s, "/")
	if len(parts) != 2 || !ghNameRe.MatchString(parts[0]) || !ghNameRe.MatchString(parts[1]) || parts[1] == "." || parts[1] == ".." {
		return repoRef{}, invalid("repositories must be written owner/name")
	}
	slug := Slugify(parts[1])
	if slug == "" {
		return repoRef{}, invalid("repository name " + parts[1] + " cannot be used as a project name")
	}
	return repoRef{owner: parts[0], name: parts[1], full: parts[0] + "/" + parts[1], slug: slug}, nil
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify turns a repository name into a project slug (lower case, letters, digits and dashes).
func Slugify(name string) string {
	s := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(s) > 100 {
		s = strings.Trim(s[:100], "-")
	}
	if !gitsource.ValidSlug(s) {
		return ""
	}
	return s
}

func requestHash(repos []repoRef, include []string, createProjects bool) string {
	full := make([]string, len(repos))
	for i, r := range repos {
		full[i] = strings.ToLower(r.full)
	}
	sort.Strings(full)
	inc := append([]string(nil), include...)
	sort.Strings(inc)
	h := sha256.Sum256([]byte("github|" + strings.Join(full, ",") + "|" + strings.Join(inc, ",") + "|" + map[bool]string{true: "p", false: "n"}[createProjects]))
	return hex.EncodeToString(h[:])
}

// Start validates the request, records the import and runs it in the background. It returns the import
// (status queued) and whether it resumed an earlier one with the same Idempotency-Key.
func (s *Service) Start(ctx context.Context, in StartInput) (*Import, bool, error) {
	if !s.d.Forge.Enabled() {
		return nil, false, ErrNotConfigured
	}
	if strings.TrimSpace(in.Token) == "" {
		return nil, false, invalid("a GitHub token is required")
	}
	if len(in.Repos) == 0 {
		return nil, false, invalid("at least one repository is required")
	}
	if len(in.Repos) > s.cfg.MaxRepos {
		return nil, false, invalid("too many repositories in one import")
	}
	var repos []repoRef
	seen := map[string]bool{}
	slugs := map[string]string{}
	for _, raw := range in.Repos {
		r, err := parseRepo(raw)
		if err != nil {
			return nil, false, err
		}
		if seen[strings.ToLower(r.full)] {
			continue
		}
		if other, dup := slugs[r.slug]; dup {
			return nil, false, invalid(r.full + " and " + other + " would become the same project name (" + r.slug + ")")
		}
		seen[strings.ToLower(r.full)] = true
		slugs[r.slug] = r.full
		repos = append(repos, r)
	}
	inc := make([]string, 0, len(in.Include))
	for _, i := range in.Include {
		if !includes[i] {
			return nil, false, invalid("unknown include value " + i)
		}
		inc = append(inc, i)
	}
	// create_projects=false imports into an EXISTING project of that slug (checked per repository).
	hash := requestHash(repos, inc, in.CreateProjects)

	// Resume or replay.
	if in.IdemKey != "" {
		if prev, err := s.d.Store.FindByIdem(ctx, in.OrgID, in.IdemKey); err == nil {
			return s.resumeOrReplay(ctx, prev, hash, in)
		} else if !errors.Is(err, ErrNotFound) {
			return nil, false, err
		}
	}

	// The token must at least work for the first repository: a typo is answered now, not in a job.
	if _, err := s.d.GitHub.Repo(ctx, in.Token, repos[0].owner, repos[0].name); err != nil {
		var ge *GHError
		if errors.As(err, &ge) && (ge.Status == 401) {
			return nil, false, ErrBadToken
		}
	}

	names := make([]string, len(repos))
	slugList := make([]string, len(repos))
	for i, r := range repos {
		names[i], slugList[i] = r.full, r.slug
	}
	if busy, err := s.d.Store.BusySlugs(ctx, in.OrgID, slugList, uuid.Nil); err != nil {
		return nil, false, err
	} else if len(busy) > 0 {
		return nil, false, ErrSlugBusy
	}

	now := s.d.Now().UTC()
	im := &Import{ID: uuid.New(), OrgID: in.OrgID, Source: "github", Status: StatusQueued, Include: inc,
		CreateProjects: in.CreateProjects, IdemKey: in.IdemKey, RequestHash: hash, Attempts: 1, CreatedAt: now, UpdatedAt: now}
	if in.UserID != uuid.Nil {
		u := in.UserID
		im.CreatedBy = &u
	}
	for _, r := range repos {
		im.Repos = append(im.Repos, RepoState{Name: r.full, Slug: r.slug, Status: StatusQueued, Warnings: []string{}})
	}
	if err := s.d.Store.CreateImport(ctx, im); err != nil {
		if errors.Is(err, ErrDuplicateKey) && in.IdemKey != "" { // lost a race with the same key
			if prev, ferr := s.d.Store.FindByIdem(ctx, in.OrgID, in.IdemKey); ferr == nil {
				return s.resumeOrReplay(ctx, prev, hash, in)
			}
		}
		return nil, false, err
	}
	s.audit(ctx, in, AuditImportStart, im, map[string]any{"source": "github", "repos": names, "include": inc, "create_projects": in.CreateProjects, "attempt": 1})
	s.launch(im.ID, in)
	return im, false, nil
}

func (s *Service) resumeOrReplay(ctx context.Context, prev *Import, hash string, in StartInput) (*Import, bool, error) {
	if prev.RequestHash != hash {
		return nil, false, ErrIdempotencyConflict
	}
	s.mu.Lock()
	live := s.live[prev.ID]
	s.mu.Unlock()
	if live {
		return nil, false, ErrIdempotencyConflict // still running in this process
	}
	switch prev.Status {
	case StatusSuccess:
		return prev, false, nil // replay
	case StatusQueued, StatusRunning:
		if s.d.Now().Sub(prev.UpdatedAt) < s.cfg.RepoTimeout+time.Minute {
			return nil, false, ErrIdempotencyConflict // another instance is working on it
		}
	}
	// partial, failed or abandoned: run again ONLY what is not done, with the token of this request.
	if _, err := s.d.GitHub.Repo(ctx, in.Token, firstOwner(prev), firstName(prev)); err != nil {
		var ge *GHError
		if errors.As(err, &ge) && ge.Status == 401 {
			return nil, false, ErrBadToken
		}
	}
	if err := s.d.Store.Resume(ctx, prev.ID); err != nil {
		return nil, false, err
	}
	im, err := s.d.Store.GetImport(ctx, prev.OrgID, prev.ID)
	if err != nil {
		return nil, false, err
	}
	s.audit(ctx, in, AuditImportStart, im, map[string]any{"source": "github", "resumed": true, "attempt": im.Attempts})
	s.launch(im.ID, in)
	return im, true, nil
}

func firstOwner(im *Import) string { o, _, _ := strings.Cut(im.Repos[0].Name, "/"); return o }
func firstName(im *Import) string  { _, n, _ := strings.Cut(im.Repos[0].Name, "/"); return n }

// Get returns an import with the state of its repositories.
func (s *Service) Get(ctx context.Context, orgID, id uuid.UUID) (*Import, error) {
	return s.d.Store.GetImport(ctx, orgID, id)
}

// Recover marks imports that were running when the process stopped as interrupted. They can be resumed
// by repeating the request with the same Idempotency-Key and a token. Call it at start-up.
func (s *Service) Recover(ctx context.Context) {
	n, err := s.d.Store.FailInterrupted(ctx, s.d.Now().Add(-(s.cfg.RepoTimeout + time.Minute)), "interrupted: repeat the request with the same Idempotency-Key and a GitHub token to resume")
	if err != nil {
		s.d.Logger.Warn("git import: recovering interrupted imports failed", "error", err)
	} else if n > 0 {
		s.d.Logger.Info("git import: interrupted imports marked for resume", "count", n)
	}
}

func (s *Service) launch(id uuid.UUID, in StartInput) {
	s.mu.Lock()
	s.live[id] = true
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			s.mu.Lock()
			delete(s.live, id)
			s.mu.Unlock()
		}()
		defer func() {
			if rec := recover(); rec != nil {
				s.d.Logger.Error("git import: panic", "import_id", id, "panic", Redact(asString(rec), in.Token))
				_ = s.d.Store.SetStatus(context.WithoutCancel(s.base), id, StatusFailed, true)
			}
		}()
		s.run(id, in)
	}()
}

func asString(v any) string {
	if e, ok := v.(error); ok {
		return e.Error()
	}
	if s, ok := v.(string); ok {
		return s
	}
	return "unknown panic"
}

func (s *Service) run(id uuid.UUID, in StartInput) {
	ctx := s.base
	im, err := s.d.Store.GetImport(ctx, in.OrgID, id)
	if err != nil {
		s.d.Logger.Warn("git import: loading the import failed", "import_id", id, "error", Redact(err.Error(), in.Token))
		return
	}
	_ = s.d.Store.SetStatus(ctx, id, StatusRunning, false)
	for _, r := range im.Repos {
		if r.Status == StatusSuccess {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		s.runRepo(ctx, im, in, r.Name)
		_ = s.d.Store.Touch(ctx, id)
	}
	// final status from the stored rows (also covers the repos that succeeded in an earlier attempt)
	final, err := s.d.Store.GetImport(context.WithoutCancel(ctx), in.OrgID, id)
	if err != nil {
		return
	}
	ok, failed := 0, 0
	for _, r := range final.Repos {
		switch r.Status {
		case StatusSuccess:
			ok++
		default:
			failed++
		}
	}
	status := StatusSuccess
	switch {
	case failed > 0 && ok == 0:
		status = StatusFailed
	case failed > 0:
		status = StatusPartial
	}
	_ = s.d.Store.SetStatus(context.WithoutCancel(ctx), id, status, true)
	s.audit(context.WithoutCancel(ctx), in, AuditImportFinish, final, map[string]any{"status": status, "succeeded": ok, "failed": failed})
}

// fail records a repository failure; msg never contains the token.
func (s *Service) fail(ctx context.Context, im *Import, in StartInput, name, msg string, warns []string) {
	msg = clip(Redact(msg, in.Token), 500)
	if err := s.d.Store.UpdateRepo(context.WithoutCancel(ctx), im.ID, name, RepoUpdate{Status: StatusFailed, Error: msg, Warnings: warns, Finished: true}); err != nil {
		s.d.Logger.Warn("git import: saving a repository failure failed", "import_id", im.ID, "repo", name, "error", Redact(err.Error(), in.Token))
	}
	s.d.Logger.Info("git import: repository failed", "import_id", im.ID, "repo", name, "reason", msg)
}

func (s *Service) runRepo(ctx context.Context, im *Import, in StartInput, name string) {
	row, err := s.d.Store.BeginRepo(ctx, im.ID, name)
	if err != nil {
		s.d.Logger.Warn("git import: starting a repository failed", "import_id", im.ID, "repo", name, "error", Redact(err.Error(), in.Token))
		return
	}
	owner, repoName, _ := strings.Cut(name, "/")
	warns := []string{}

	gh, err := s.d.GitHub.Repo(ctx, in.Token, owner, repoName)
	if err != nil {
		var ge *GHError
		switch {
		case errors.As(err, &ge) && (ge.Status == 404 || ge.Status == 403):
			s.fail(ctx, im, in, name, "repository not found, or the token has no access to it", warns)
		case errors.As(err, &ge) && ge.Status == 401:
			s.fail(ctx, im, in, name, "the GitHub token was rejected", warns)
		default:
			s.fail(ctx, im, in, name, "GitHub could not be reached: "+err.Error(), warns)
		}
		return
	}
	if gh.Archived {
		warns = append(warns, "the repository is archived on GitHub; it is imported as a normal repository")
	}

	// T2: the address Forgejo will clone is built here (fixed host) and still goes through the policy.
	cloneURL := "https://github.com/" + owner + "/" + repoName + ".git"
	if _, _, err := s.d.Policy.ValidateRepoURL(ctx, cloneURL); err != nil {
		s.fail(ctx, im, in, name, "the clone address is not allowed: "+err.Error(), warns)
		return
	}

	// project
	org := in.OrgSlug
	var projectID uuid.UUID
	created, ours := false, false // ours: this import created the project in an EARLIER attempt
	if row.ProjectID != nil {
		projectID, created, ours = *row.ProjectID, row.CreatedProject, row.CreatedProject
	} else {
		p, err := s.d.Projects.GetBySlug(ctx, im.OrgID, row.Slug)
		switch {
		case err == nil && im.CreateProjects:
			s.fail(ctx, im, in, name, "a project named "+row.Slug+" already exists in this organization", warns)
			return
		case err == nil:
			projectID = p.ID
		case errors.Is(err, domain.ErrNotFound) && im.CreateProjects:
			branch := gh.DefaultBranch
			if branch == "" {
				branch = "main"
			}
			np, cerr := s.d.Projects.Create(ctx, &domain.Project{OrgID: im.OrgID, Name: repoName, Slug: row.Slug,
				Branch: branch, BuildStrategy: "auto", Replicas: 1})
			if cerr != nil {
				msg := "the project could not be created"
				if strings.Contains(cerr.Error(), "unique") || strings.Contains(cerr.Error(), "duplicate") {
					msg = "a project named " + row.Slug + " already exists in this organization"
				}
				s.fail(ctx, im, in, name, msg, warns)
				return
			}
			projectID, created = np.ID, true
		case errors.Is(err, domain.ErrNotFound):
			s.fail(ctx, im, in, name, "there is no project named "+row.Slug+" and create_projects is false", warns)
			return
		default:
			s.fail(ctx, im, in, name, "the project could not be looked up", warns)
			return
		}
		pid := projectID
		_ = s.d.Store.UpdateRepo(ctx, im.ID, name, RepoUpdate{Status: StatusRunning, ProjectID: &pid, CreatedProject: &created, Warnings: warns})
	}

	// Forgejo
	ref := gitcore.RepoRef{Owner: org, Repo: row.Slug}
	if err := s.d.Forge.EnsureOrg(ctx, org); err != nil {
		s.fail(ctx, im, in, name, "the Git service refused the organization: "+gitErrText(err), warns)
		return
	}
	existing, gerr := s.d.Forge.GetRepo(ctx, ref)
	switch {
	case gerr == nil && existing != nil:
		// A repository already there is ours only if an EARLIER attempt of this import created the project (a crash after
		// the migration finished, before it was recorded). Otherwise it is somebody else's: never adopt it.
		if !ours {
			s.fail(ctx, im, in, name, "the Git service already has a repository named "+row.Slug+" in this organization", warns)
			return
		}
	case gerr != nil && !errors.Is(gerr, gitcore.ErrNotFound):
		s.fail(ctx, im, in, name, "the Git service could not be queried: "+gitErrText(gerr), warns)
		return
	default:
		mctx, cancel := context.WithTimeout(ctx, s.cfg.RepoTimeout)
		stop := s.heartbeat(mctx, im.ID)
		spec := gitcore.MigrateSpec{Owner: org, Repo: row.Slug, CloneAddr: cloneURL, AuthToken: in.Token, Service: "github",
			Private: gh.Private, Issues: has(im.Include, "issues"), PullRequests: has(im.Include, "pull_requests"),
			Releases: has(im.Include, "releases"), Wiki: has(im.Include, "wiki")}
		_, merr := s.d.Forge.Migrate(mctx, spec)
		stop()
		cancel()
		if merr != nil {
			s.fail(ctx, im, in, name, "the migration failed: "+gitErrText(merr), warns)
			return
		}
	}
	if has(im.Include, "labels") && !has(im.Include, "issues") && !has(im.Include, "pull_requests") {
		warns = append(warns, "labels are only brought with issues or pull requests: the Git service client has no separate labels switch")
	}
	if has(im.Include, "issues") {
		warns = append(warns, "issues are stored in Forgejo; the Git Capsule dashboard does not show them")
	}

	if s.d.Linker != nil {
		if err := s.d.Linker.MarkReady(ctx, projectID); err != nil {
			warns = append(warns, "the repository was imported but could not be linked to the project: "+clip(err.Error(), 200))
		}
	}

	// CODEOWNERS and workflows (read from GitHub; best effort, they only add notes)
	ref0 := gh.DefaultBranch
	report, cw := s.inspect(ctx, in.Token, owner, repoName, ref0, org)
	warns = append(warns, cw...)

	if s.d.AfterImport != nil {
		if err := s.d.AfterImport(ctx, projectID); err != nil {
			warns = append(warns, "teams will be reconciled later: "+clip(Redact(err.Error(), in.Token), 200))
		}
	}
	pid := projectID
	if err := s.d.Store.UpdateRepo(context.WithoutCancel(ctx), im.ID, name, RepoUpdate{Status: StatusSuccess, ProjectID: &pid, CreatedProject: &created,
		Warnings: warns, CodeOwners: report, Finished: true}); err != nil {
		s.d.Logger.Warn("git import: saving a repository result failed", "import_id", im.ID, "repo", name, "error", Redact(err.Error(), in.Token))
	}
}

func (s *Service) heartbeat(ctx context.Context, id uuid.UUID) (stop func()) {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = s.d.Store.Touch(ctx, id)
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return func() { close(done) }
}

func has(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// gitErrText renders a gitcore error for the report (message is already scrubbed of the service token;
// the caller redacts the import token again).
func gitErrText(err error) string {
	if e, ok := gitcore.AsError(err); ok {
		return e.Message
	}
	return "unexpected error"
}

func (s *Service) audit(ctx context.Context, in StartInput, action string, im *Import, vals map[string]any) {
	if s.d.Audit == nil {
		return
	}
	id := im.ID
	rec := AuditRecord{OrgID: im.OrgID, Action: action, ResourceType: "git_import", ResourceID: &id, IP: in.IP, Values: vals}
	if in.UserID != uuid.Nil {
		u := in.UserID
		rec.UserID = &u
	}
	if err := s.d.Audit.Audit(ctx, rec); err != nil {
		s.d.Logger.Warn("git import: audit failed", "action", action, "error", Redact(err.Error(), in.Token))
	}
}
