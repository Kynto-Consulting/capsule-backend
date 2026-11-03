package forgejo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

var (
	// ErrDisabled is returned when CAPSULE_GIT_URL / CAPSULE_GIT_TOKEN are not set.
	ErrDisabled = errors.New("the core Git service is not configured")
	// ErrAlreadyLinked means the project already points at a non-Forgejo repository.
	ErrAlreadyLinked = errors.New("project already has a git link to another provider")
	// ErrInvalidImport means the import URL was rejected (permanent, never retried).
	ErrInvalidImport = errors.New("invalid import URL")
)

const (
	maxProvisionAttempts = 10
	teamSyncInterval     = 2 * time.Minute
)

// ProjectTeams are the three per-project teams, role -> spec.
func ProjectTeams(projectSlug string) map[authz.Role]TeamSpec {
	return map[authz.Role]TeamSpec{
		authz.RoleAdmin:    {Name: projectSlug + "-admin", Permission: "admin"},
		authz.RoleDeployer: {Name: projectSlug + "-deployer", Permission: "write"},
		authz.RoleViewer:   {Name: projectSlug + "-viewer", Permission: "read"},
	}
}

// Core provisions repositories and keeps Forgejo teams in sync with Capsule roles.
// With a disabled Client every operation is a no-op.
type Core struct {
	Client    *Client
	PublicURL string // CAPSULE_PUBLIC_URL, base of the webhook URL
	Git       domain.GitRepository
	Projects  domain.ProjectRepository
	Orgs      domain.OrganizationRepository
	Members   authz.MemberStore // nil = open mode, no explicit roles
	Store     domain.GitCoreStore
	// Username returns the Forgejo login of a Capsule user (the OIDC preferred_username).
	Username func(ctx context.Context, userID uuid.UUID, email string) (string, error)
	Policy   gitsource.Policy
	Logger   *slog.Logger
	Now      func() time.Time

	mu    sync.Mutex
	locks map[string]*sync.Mutex
	wg    sync.WaitGroup
}

// Enabled reports whether the integration is configured.
func (c *Core) Enabled() bool { return c != nil && c.Client != nil && c.Client.Cfg.Enabled() }

func (c *Core) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func (c *Core) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Wait blocks until background work finishes (tests, shutdown).
func (c *Core) Wait() { c.wg.Wait() }

func (c *Core) lock(key string) func() {
	c.mu.Lock()
	if c.locks == nil {
		c.locks = map[string]*sync.Mutex{}
	}
	m := c.locks[key]
	if m == nil {
		m = &sync.Mutex{}
		c.locks[key] = m
	}
	c.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// Go runs fn in the background with its own context (used by API handlers that
// must answer before a slow Forgejo call finishes).
func (c *Core) Go(timeout time.Duration, fn func(ctx context.Context)) { c.bg(timeout, fn) }

func (c *Core) bg(timeout time.Duration, fn func(ctx context.Context)) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				c.logger().Error("git core: panic in background task", "panic", fmt.Sprint(r))
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		fn(ctx)
	}()
}

// Result is what provisioning returns for the API.
type Result struct {
	WebURL     string `json:"web_url"`
	CloneHTTPS string `json:"clone_url_https"`
	CloneSSH   string `json:"clone_url_ssh"`
}

// Links builds the URLs of a Forgejo-provider link ("" when disabled or not Forgejo).
func (c *Core) Links(g *domain.ProjectGit) (web, https, ssh string) {
	if !c.Enabled() || g == nil || g.Provider != "forgejo" {
		return "", "", ""
	}
	org, repo, ok := splitRepoURL(g.RepoURL)
	if !ok {
		return "", "", ""
	}
	cfg := c.Client.Cfg
	return cfg.WebURL(org, repo), cfg.CloneHTTPS(org, repo), cfg.CloneSSH(org, repo)
}

func splitRepoURL(raw string) (org, repo string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", false
	}
	parts := strings.Split(strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git"), "/")
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// ---- provisioning -----------------------------------------------------------

// OnProjectCreated provisions the repository in the background (non-blocking,
// idempotent, retried by RunRetry while it keeps failing).
func (c *Core) OnProjectCreated(p *domain.Project) {
	if !c.Enabled() || p == nil || c.Store == nil {
		return
	}
	id := p.ID
	c.bg(3*time.Minute, func(ctx context.Context) {
		if _, err := c.Provision(ctx, id, ""); err != nil {
			c.logger().Warn("git core: provisioning failed (will retry)", "project_id", id, "error", err)
		}
	})
}

func backoff(attempts int) time.Duration {
	if attempts > 7 {
		attempts = 7
	}
	d := 30 * time.Second << attempts
	if d > time.Hour {
		d = time.Hour
	}
	return d
}

func clipErr(err error, token string) string {
	s := err.Error()
	if token != "" {
		s = strings.ReplaceAll(s, token, "***")
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// Provision creates organization, repository and webhook in Forgejo and links the
// project. Safe to call repeatedly. importURL (optional) imports an existing repository.
func (c *Core) Provision(ctx context.Context, projectID uuid.UUID, importURL string) (*Result, error) {
	if !c.Enabled() {
		return nil, ErrDisabled
	}
	unlock := c.lock("prov:" + projectID.String())
	res, err := c.provision(ctx, projectID, importURL)
	unlock()
	if err != nil {
		return nil, err
	}
	// Teams after the repository exists (outside the provisioning lock).
	if serr := c.SyncProject(ctx, projectID); serr != nil {
		c.logger().Warn("git core: team sync after provisioning failed", "project_id", projectID, "error", serr)
	}
	return res, nil
}

func (c *Core) provision(ctx context.Context, projectID uuid.UUID, importURL string) (*Result, error) {
	p, err := c.Projects.GetByID(ctx, projectID)
	if err != nil {
		return nil, err
	}
	org, err := c.Orgs.GetByID(ctx, p.OrgID)
	if err != nil {
		return nil, err
	}
	existing, gerr := c.Git.Get(ctx, projectID)
	if gerr != nil && !errors.Is(gerr, domain.ErrNotFound) {
		return nil, gerr
	}
	if gerr == nil && existing.Provider != "forgejo" {
		return nil, ErrAlreadyLinked
	}
	importURL = strings.TrimSpace(importURL)
	if importURL == "" {
		// A retry of an earlier import keeps its URL.
		if st, err := c.Store.GetState(ctx, projectID); err == nil && st.Status != domain.GitCoreReady {
			importURL = st.ImportURL
		}
	}
	if importURL != "" {
		if _, _, verr := c.Policy.ValidateRepoURL(ctx, importURL); verr != nil {
			// Permanent: stop retrying a pending import, but never downgrade a ready project.
			if st, serr := c.Store.GetState(ctx, projectID); serr == nil && st.Status == domain.GitCorePending {
				c.saveState(ctx, projectID, domain.GitCoreFailed, st.Attempts, verr.Error(), importURL)
			}
			return nil, fmt.Errorf("%w: %v", ErrInvalidImport, verr)
		}
	}

	attempts := 0
	if st, err := c.Store.GetState(ctx, projectID); err == nil {
		attempts = st.Attempts
	}
	res, perr := c.doProvision(ctx, p, org, existing, importURL)
	if perr != nil {
		attempts++
		status := domain.GitCorePending
		if attempts >= maxProvisionAttempts {
			status = domain.GitCoreFailed
		}
		c.saveStateAt(ctx, projectID, status, attempts, clipErr(perr, c.Client.Cfg.Token), importURL, c.now().Add(backoff(attempts)))
		return nil, perr
	}
	c.saveState(ctx, projectID, domain.GitCoreReady, 0, "", "")
	return res, nil
}

func (c *Core) saveState(ctx context.Context, id uuid.UUID, status string, attempts int, lastErr, importURL string) {
	c.saveStateAt(ctx, id, status, attempts, lastErr, importURL, c.now())
}

func (c *Core) saveStateAt(ctx context.Context, id uuid.UUID, status string, attempts int, lastErr, importURL string, next time.Time) {
	if err := c.Store.PutState(ctx, &domain.GitCoreState{
		ProjectID: id, Status: status, Attempts: attempts, LastError: lastErr, ImportURL: importURL, NextAttemptAt: next,
	}); err != nil {
		c.logger().Warn("git core: saving provision state failed", "project_id", id, "error", err)
	}
}

func (c *Core) hookURL(projectID uuid.UUID) (string, error) {
	base := strings.TrimRight(c.PublicURL, "/")
	if base == "" {
		return "", errors.New("CAPSULE_PUBLIC_URL is not configured: cannot register the webhook")
	}
	return base + "/hooks/git/" + projectID.String(), nil
}

func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (c *Core) doProvision(ctx context.Context, p *domain.Project, org *domain.Organization, existing *domain.ProjectGit, importURL string) (*Result, error) {
	hook, err := c.hookURL(p.ID)
	if err != nil {
		return nil, err
	}
	cl, cfg := c.Client, c.Client.Cfg
	if err := cl.EnsureOrg(ctx, org.Slug); err != nil {
		return nil, fmt.Errorf("organization: %w", err)
	}
	var repo *Repo
	if importURL != "" {
		repo, _, err = cl.MigrateRepo(ctx, org.Slug, p.Slug, importURL)
	} else {
		repo, err = cl.EnsureRepo(ctx, org.Slug, p.Slug)
	}
	if err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}

	g := &domain.ProjectGit{ProjectID: p.ID, PreviewMax: 5, PreviewTTLHours: 168, AutoDeploy: true}
	if existing != nil {
		c2 := *existing
		g = &c2
	}
	g.Provider = "forgejo"
	g.RepoURL = cfg.CloneHTTPS(org.Slug, p.Slug)
	g.AuthKind, g.Credential = "token", cfg.Token
	if existing == nil {
		g.Branch = "main"
		if repo != nil && gitsource.ValidBranch(repo.DefaultBranch) {
			g.Branch = repo.DefaultBranch
		}
	}
	if g.WebhookSecret == "" {
		if g.WebhookSecret, err = newSecret(); err != nil {
			return nil, err
		}
	}
	if err := cl.EnsureWebhook(ctx, org.Slug, p.Slug, hook, g.WebhookSecret); err != nil {
		return nil, fmt.Errorf("webhook: %w", err)
	}
	if _, err := c.Git.Upsert(ctx, g); err != nil {
		return nil, fmt.Errorf("saving git link: %w", err)
	}
	return &Result{
		WebURL: cfg.WebURL(org.Slug, p.Slug), CloneHTTPS: cfg.CloneHTTPS(org.Slug, p.Slug), CloneSSH: cfg.CloneSSH(org.Slug, p.Slug),
	}, nil
}

// Status returns the provisioning state (ErrNotFound when none was ever recorded).
func (c *Core) Status(ctx context.Context, projectID uuid.UUID) (*domain.GitCoreState, error) {
	if c == nil || c.Store == nil {
		return nil, domain.ErrNotFound
	}
	return c.Store.GetState(ctx, projectID)
}

// ---- team synchronization -----------------------------------------------------

// OnMembersChanged re-syncs the teams of one project in the background.
func (c *Core) OnMembersChanged(_, projectID uuid.UUID) {
	if !c.Enabled() {
		return
	}
	c.bg(3*time.Minute, func(ctx context.Context) {
		if err := c.SyncProject(ctx, projectID); err != nil {
			c.logger().Warn("git core: team sync failed", "project_id", projectID, "error", err)
		}
	})
}

// OnOrgChanged re-syncs every project of the organization (access mode or members changed).
func (c *Core) OnOrgChanged(orgID uuid.UUID) {
	if !c.Enabled() {
		return
	}
	c.bg(10*time.Minute, func(ctx context.Context) {
		for page := 1; page <= 100; page++ {
			projects, _, err := c.Projects.ListByOrg(ctx, orgID, page, 100)
			if err != nil {
				c.logger().Warn("git core: listing projects for team sync failed", "org_id", orgID, "error", err)
				return
			}
			for _, p := range projects {
				if err := c.SyncProject(ctx, p.ID); err != nil {
					c.logger().Warn("git core: team sync failed", "project_id", p.ID, "error", err)
				}
			}
			if len(projects) < 100 {
				return
			}
		}
	})
}

// SyncProject makes the Forgejo teams of a Forgejo-linked project match the effective
// Capsule roles. Users that do not exist in Forgejo yet are left pending.
func (c *Core) SyncProject(ctx context.Context, projectID uuid.UUID) error {
	if !c.Enabled() {
		return nil
	}
	// Git Capsule A2: when gitsync is wired it owns the team projection (identities, pending
	// queue, drift state); the code below stays as the fallback and for its own tests.
	if fn := teamSyncDelegate(); fn != nil {
		return fn(ctx, projectID)
	}
	defer c.lock("sync:" + projectID.String())()

	link, err := c.Git.Get(ctx, projectID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if link.Provider != "forgejo" {
		return nil
	}
	orgSlug, repoName, ok := splitRepoURL(link.RepoURL)
	if !ok {
		return nil
	}
	p, err := c.Projects.GetByID(ctx, projectID)
	if err != nil {
		return err
	}
	members, err := c.Orgs.GetMembers(ctx, p.OrgID)
	if err != nil {
		return err
	}
	mode, explicit := authz.ModeOpen, map[uuid.UUID]string{}
	if c.Members != nil {
		if mode, err = c.Members.GetOrgAccessMode(ctx, p.OrgID); err != nil {
			return err
		}
		rows, err := c.Members.ListExplicit(ctx, projectID)
		if err != nil {
			return err
		}
		for _, m := range rows {
			explicit[m.UserID] = m.Role
		}
	}

	cl := c.Client
	if err := cl.EnsureOrg(ctx, orgSlug); err != nil {
		return err
	}
	specs := ProjectTeams(p.Slug)
	teams := map[authz.Role]*Team{}
	current := map[authz.Role]map[string]bool{}
	for role, spec := range specs {
		t, err := cl.EnsureTeam(ctx, orgSlug, spec)
		if err != nil {
			return fmt.Errorf("team %s: %w", spec.Name, err)
		}
		if err := cl.AddTeamRepo(ctx, t.ID, orgSlug, repoName); err != nil {
			return fmt.Errorf("team %s repo: %w", spec.Name, err)
		}
		logins, err := cl.TeamMembers(ctx, t.ID)
		if err != nil {
			return fmt.Errorf("team %s members: %w", spec.Name, err)
		}
		set := map[string]bool{}
		for _, l := range logins {
			set[strings.ToLower(l)] = true
		}
		teams[role], current[role] = t, set
	}

	desired := map[string]authz.Role{}
	var pending []uuid.UUID
	var firstErr error
	for _, m := range members {
		role := authz.Resolve(m.Role, mode, explicit[m.UserID]).Role
		if role == "" {
			continue
		}
		name, err := c.Username(ctx, m.UserID, m.Email)
		if err != nil || name == "" {
			if err == nil {
				err = errors.New("empty username")
			}
			firstErr = err
			pending = append(pending, m.UserID)
			continue
		}
		name = strings.ToLower(name)
		if current[role][name] {
			desired[name] = role
			continue
		}
		exists, err := cl.UserExists(ctx, name)
		if err != nil {
			return err
		}
		if !exists {
			pending = append(pending, m.UserID)
			continue
		}
		if err := cl.AddTeamMember(ctx, teams[role].ID, name); err != nil {
			return fmt.Errorf("adding %s to %s: %w", name, specs[role].Name, err)
		}
		desired[name] = role
	}
	// Remove everyone who is in a team without being entitled to it (role changed or left).
	for role, set := range current {
		for login := range set {
			if desired[login] == role {
				continue
			}
			if err := cl.RemoveTeamMember(ctx, teams[role].ID, login); err != nil {
				return fmt.Errorf("removing %s from %s: %w", login, specs[role].Name, err)
			}
		}
	}
	if c.Store != nil {
		msg := "forgejo user does not exist yet (first OIDC login pending)"
		if firstErr != nil {
			msg = clipErr(firstErr, "")
		}
		next := c.now().Add(teamSyncInterval)
		if err := c.Store.ReplaceTeamSync(ctx, projectID, pending, msg, next); err != nil {
			return err
		}
	}
	return nil
}

// RunRetry retries pending provisioning and pending team synchronization until ctx ends.
func (c *Core) RunRetry(ctx context.Context, every time.Duration) {
	if !c.Enabled() || c.Store == nil {
		return
	}
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		c.RetryOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RetryOnce runs one retry pass (exposed for tests).
func (c *Core) RetryOnce(ctx context.Context) {
	if !c.Enabled() || c.Store == nil {
		return
	}
	now := c.now()
	if states, err := c.Store.ListDueStates(ctx, now, 20); err != nil {
		c.logger().Warn("git core: listing pending provisioning failed", "error", err)
	} else {
		for _, s := range states {
			pctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			if _, err := c.Provision(pctx, s.ProjectID, s.ImportURL); err != nil {
				c.logger().Warn("git core: provisioning retry failed", "project_id", s.ProjectID, "attempts", s.Attempts+1, "error", err)
			}
			cancel()
		}
	}
	due, err := c.Store.ListDueTeamSync(ctx, now, 200)
	if err != nil {
		c.logger().Warn("git core: listing pending team sync failed", "error", err)
		return
	}
	seen := map[uuid.UUID]bool{}
	for _, d := range due {
		if seen[d.ProjectID] {
			continue
		}
		seen[d.ProjectID] = true
		sctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		if err := c.SyncProject(sctx, d.ProjectID); err != nil {
			c.logger().Warn("git core: team sync retry failed", "project_id", d.ProjectID, "error", err)
		}
		cancel()
	}
}
