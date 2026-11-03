package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

// Uploader stores a local file in the artifacts bucket.
type Uploader interface {
	Upload(ctx context.Context, key, path string) error
}

// StatusClient reports back to the Git provider (commit statuses, PR comments).
type StatusClient interface {
	SetStatus(ctx context.Context, sha, state, targetURL, description string) error
	UpsertComment(ctx context.Context, pr int, existingID int64, body string) (int64, error)
}

// StatusClientFactory builds a provider client for a project link; it returns
// an error (e.g. gitsource.ErrUnsupported) when the link has no usable token.
type StatusClientFactory func(g *domain.ProjectGit) (StatusClient, error)

// RuntimeRemover tears down the running app of a project (container, image,
// volume, ECS service and ALB wiring).
type RuntimeRemover interface {
	Remove(ctx context.Context, projectID uuid.UUID) error
}

// Coalescer keeps only the newest request per key: starting a new one marks
// every previous one for the same key as superseded.
type Coalescer struct {
	mu  sync.Mutex
	gen map[string]uint64
}

// Begin registers a new request for key and returns a func that reports
// whether it is still the newest one.
func (c *Coalescer) Begin(key string) (isCurrent func() bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen == nil {
		c.gen = map[string]uint64{}
	}
	c.gen[key]++
	mine := c.gen[key]
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.gen[key] == mine
	}
}

// ErrSuperseded is returned when a newer push replaced this one while it was cloning.
var ErrSuperseded = errors.New("superseded by a newer push")

// GitService turns webhook events into deployments and preview lifecycles.
type GitService struct {
	Git         domain.GitRepository
	Projects    domain.ProjectRepository
	Deployments domain.DeploymentRepository
	Uploader    Uploader
	Fetcher     gitsource.Fetcher
	Provider    StatusClientFactory
	Runtime     RuntimeRemover
	Logger      *slog.Logger

	AppsDomain string // e.g. apps.example.com: preview URL = https://<slug>.<AppsDomain>
	ConsoleURL string // optional link target for commit statuses

	Now           func() time.Time
	WatchInterval time.Duration // default 5s
	WatchTimeout  time.Duration // default 45m

	coal Coalescer
	sem  chan struct{}
	once sync.Once
	wg   sync.WaitGroup
}

func (s *GitService) init() {
	s.once.Do(func() {
		s.sem = make(chan struct{}, 2) // at most 2 concurrent clones
		if s.Now == nil {
			s.Now = time.Now
		}
		if s.WatchInterval <= 0 {
			s.WatchInterval = 5 * time.Second
		}
		if s.WatchTimeout <= 0 {
			s.WatchTimeout = 45 * time.Minute
		}
		if s.Logger == nil {
			s.Logger = slog.Default()
		}
	})
}

// Go runs fn in the background (webhooks answer immediately).
func (s *GitService) Go(fn func()) {
	s.init()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				s.Logger.Error("git service: panic in background task", "panic", fmt.Sprint(r))
			}
		}()
		fn()
	}()
}

// Wait blocks until background tasks finish (tests, shutdown).
func (s *GitService) Wait() { s.wg.Wait() }

// AppURL is the public URL of a project.
func (s *GitService) AppURL(slug string) string {
	if s.AppsDomain == "" || slug == "" {
		return ""
	}
	return "https://" + slug + "." + s.AppsDomain
}

func (s *GitService) client(g *domain.ProjectGit) StatusClient {
	if s.Provider == nil {
		return nil
	}
	c, err := s.Provider(g)
	if err != nil || c == nil {
		return nil
	}
	return c
}

// deployInput describes one clone-and-deploy.
type deployInput struct {
	Link      *domain.ProjectGit
	Target    *domain.Project // project the deployment belongs to (parent or preview)
	Branch    string
	Actor     string
	Message   string // hint from the event; the commit's own subject wins
	CommitURL string
	PR        int
	CoalKey   string
}

// deployFromGit clones, packages, uploads and creates a source=git deployment.
func (s *GitService) deployFromGit(ctx context.Context, in deployInput) (*domain.Deployment, string, error) {
	s.init()
	if !gitsource.ValidBranch(in.Branch) {
		return nil, "", errors.New("invalid branch name")
	}
	isCurrent := s.coal.Begin(in.CoalKey)

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
	if !isCurrent() { // a newer push arrived while waiting for a clone slot
		return nil, "", ErrSuperseded
	}

	snap, err := s.Fetcher.Fetch(ctx, in.Link.RepoURL, in.Branch, gitsource.Auth{Kind: in.Link.AuthKind, Credential: in.Link.Credential})
	if err != nil {
		return nil, "", fmt.Errorf("fetching repository: %w", err)
	}
	defer snap.Close()
	if !isCurrent() {
		return nil, snap.SHA, ErrSuperseded
	}

	key := "deployments/" + in.Target.ID.String() + "/" + uuid.New().String() + ".tar.gz"
	if err := s.Uploader.Upload(ctx, key, snap.TarPath); err != nil {
		return nil, snap.SHA, fmt.Errorf("uploading source: %w", err)
	}
	if !isCurrent() {
		return nil, snap.SHA, ErrSuperseded
	}

	msg := snap.Message
	if msg == "" {
		msg = in.Message
	}
	commitURL := in.CommitURL
	if commitURL == "" {
		commitURL = commitLink(in.Link, snap.SHA)
	}
	meta := map[string]string{
		"source":         "git",
		"ref":            in.Branch,
		"sha":            snap.SHA,
		"actor":          clip(in.Actor, 200),
		"commit_message": clip(firstLine(msg), 300),
		"repo":           clip(in.Link.RepoURL, 500),
		"run_url":        clip(commitURL, 500),
	}
	if in.PR > 0 {
		meta["pr"] = fmt.Sprint(in.PR)
	}
	strategy := in.Target.DeployType
	if strategy == "" {
		strategy = in.Target.BuildStrategy
	}
	port := 8080
	if prev, err := s.Deployments.GetLatestSuccessfulByProject(ctx, in.Target.ID); err == nil && prev != nil && prev.ContainerPort > 0 {
		port = prev.ContainerPort
	}
	dep, err := s.Deployments.Create(ctx, &domain.Deployment{
		ProjectID:     in.Target.ID,
		Version:       "git-" + short(snap.SHA),
		GitSHA:        snap.SHA,
		BuildStrategy: strategy,
		ContainerPort: port,
		Trigger:       "git",
		SourceKey:     &key,
		Meta:          meta,
	})
	if err != nil {
		return nil, snap.SHA, fmt.Errorf("creating deployment: %w", err)
	}
	// Newest wins: cancel older queued git deployments of this project.
	if ids, err := s.Git.CancelSupersededGit(ctx, in.Target.ID, dep.ID); err != nil {
		s.Logger.Warn("git deploy: cancelling superseded deployments failed", "project_id", in.Target.ID, "error", err)
	} else {
		for _, id := range ids {
			_ = s.Deployments.AppendLog(ctx, &domain.BuildLog{DeploymentID: id, Level: "info",
				Message: "Cancelled: superseded by a newer git deployment " + dep.ID.String()})
		}
	}
	_ = s.Deployments.AppendLog(ctx, &domain.BuildLog{DeploymentID: dep.ID, Level: "info",
		Message: fmt.Sprintf("Source fetched from git (%s@%s)", in.Branch, short(snap.SHA))})
	return dep, snap.SHA, nil
}

// HandlePush deploys a push to the configured branch (auto_deploy only).
func (s *GitService) HandlePush(ctx context.Context, link *domain.ProjectGit, project *domain.Project, ev *gitsource.Event) error {
	s.init()
	if !link.AutoDeploy || ev.Kind != gitsource.EventPush || ev.Deleted || ev.Branch != link.Branch {
		return nil
	}
	dep, sha, err := s.deployFromGit(ctx, deployInput{
		Link: link, Target: project, Branch: ev.Branch, Actor: ev.Actor,
		Message: ev.Message, CommitURL: ev.CommitURL, CoalKey: "push:" + project.ID.String(),
	})
	if err != nil {
		if errors.Is(err, ErrSuperseded) {
			s.Logger.Info("git deploy superseded", "project_id", project.ID)
			return nil
		}
		s.report(ctx, link, sha, "failure", "", "Capsule could not fetch the repository")
		return err
	}
	s.report(ctx, link, sha, "pending", s.targetURL(project, dep), "Deployment queued")
	s.Go(func() { s.watch(link, project, dep, sha, 0, nil) })
	return nil
}

func (s *GitService) targetURL(project *domain.Project, dep *domain.Deployment) string {
	if s.ConsoleURL != "" {
		return strings.TrimRight(s.ConsoleURL, "/") + "/projects/" + project.ID.String() + "/deployments/" + dep.ID.String()
	}
	return s.AppURL(project.Slug)
}

// report posts a commit status; failures only log.
func (s *GitService) report(ctx context.Context, link *domain.ProjectGit, sha, state, target, desc string) {
	if sha == "" || !gitsource.ValidSHA(sha) {
		return
	}
	c := s.client(link)
	if c == nil {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := c.SetStatus(rctx, sha, state, target, desc); err != nil {
		s.Logger.Warn("git status report failed", "provider", link.Provider, "state", state, "error", err)
	}
}

// watch polls the deployment until it ends, then reports the final state
// (commit status, and the PR comment for previews). Uses its own context so it
// outlives the webhook request.
func (s *GitService) watch(link *domain.ProjectGit, project *domain.Project, dep *domain.Deployment, sha string, pr int, pv *domain.Preview) {
	ctx, cancel := context.WithTimeout(context.Background(), s.WatchTimeout)
	defer cancel()
	t := time.NewTicker(s.WatchInterval)
	defer t.Stop()
	for {
		st, err := s.Git.DeploymentStatus(ctx, dep.ID)
		if err == nil {
			switch st {
			case "success":
				url := s.AppURL(project.Slug)
				if d, err := s.Deployments.GetByID(ctx, dep.ID); err == nil && d.AppURL != nil && *d.AppURL != "" {
					url = *d.AppURL
				}
				s.report(ctx, link, sha, "success", firstNonEmpty(url, s.targetURL(project, dep)), "Deployed")
				if pv != nil {
					s.comment(ctx, link, pv, pr, sha, "success", url)
				}
				return
			case "failed":
				s.report(ctx, link, sha, "failure", s.targetURL(project, dep), "Deployment failed")
				if pv != nil {
					s.comment(ctx, link, pv, pr, sha, "failed", "")
				}
				return
			case "cancelled":
				return // superseded or cancelled by the user; the newer run reports itself
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func commitLink(link *domain.ProjectGit, sha string) string {
	ref, err := gitsource.ParseRepoURL(link.RepoURL)
	if err != nil {
		return ""
	}
	path := strings.TrimSuffix(ref.Path, ".git")
	switch link.Provider {
	case "github", "forgejo", "gitea":
		return "https://" + ref.Host + path + "/commit/" + sha
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
