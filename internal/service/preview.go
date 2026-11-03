package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

const defaultPreviewMax = 5

func previewTTL(link *domain.ProjectGit) time.Duration {
	h := link.PreviewTTLHours
	if h <= 0 {
		h = 168
	}
	return time.Duration(h) * time.Hour
}

// HandlePullRequest drives the preview lifecycle from a pull_request event.
func (s *GitService) HandlePullRequest(ctx context.Context, link *domain.ProjectGit, parent *domain.Project, ev *gitsource.Event) error {
	s.init()
	if ev.Kind != gitsource.EventPullRequest || ev.PR <= 0 {
		return nil
	}
	if ev.Action == "closed" {
		return s.closePreview(ctx, link, parent, ev.PR)
	}
	if !link.PreviewEnabled {
		return nil
	}
	if ev.HeadFork {
		// Forks are untrusted: building them would expose inherited variables.
		s.Logger.Info("git preview: ignoring pull request from a fork", "project_id", parent.ID, "pr", ev.PR)
		return nil
	}
	if !gitsource.ValidBranch(ev.Branch) {
		return errors.New("invalid pull request branch")
	}
	slug, err := gitsource.PreviewSlug(parent.Slug, ev.PR)
	if err != nil {
		return err
	}
	expires := s.Now().Add(previewTTL(link))

	pv, err := s.Git.GetPreview(ctx, parent.ID, ev.PR)
	switch {
	case err == nil:
		if err := s.Git.TouchPreview(ctx, pv.ProjectID, expires); err != nil {
			return err
		}
	case errors.Is(err, domain.ErrNotFound):
		if err := s.enforceMax(ctx, link, parent); err != nil {
			return err
		}
		if pv, err = s.Git.CreatePreview(ctx, parent, ev.PR, slug, expires); err != nil {
			return err
		}
	default:
		return err
	}

	target, err := s.Projects.GetByID(ctx, pv.ProjectID)
	if err != nil {
		return err
	}
	s.comment(ctx, link, pv, ev.PR, ev.SHA, "building", s.AppURL(target.Slug))

	dep, sha, err := s.deployFromGit(ctx, deployInput{
		Link: link, Target: target, Branch: ev.Branch, Actor: ev.Actor, PR: ev.PR,
		CommitURL: ev.PRURL, CoalKey: "pr:" + parent.ID.String() + ":" + fmt.Sprint(ev.PR),
	})
	if err != nil {
		if errors.Is(err, ErrSuperseded) {
			return nil
		}
		s.comment(ctx, link, pv, ev.PR, firstNonEmpty(sha, ev.SHA), "failed", "")
		return err
	}
	s.report(ctx, link, sha, "pending", s.targetURL(target, dep), "Preview queued")
	s.Go(func() { s.watch(link, target, dep, sha, ev.PR, pv) })
	return nil
}

// enforceMax makes room for one more preview by destroying the oldest ones.
func (s *GitService) enforceMax(ctx context.Context, link *domain.ProjectGit, parent *domain.Project) error {
	max := link.PreviewMax
	if max <= 0 {
		max = defaultPreviewMax
	}
	all, err := s.Git.ListPreviews(ctx, parent.ID) // oldest first
	if err != nil {
		return err
	}
	for len(all) >= max {
		oldest := all[0]
		all = all[1:]
		s.Logger.Info("git preview: removing oldest preview (preview_max)", "project_id", parent.ID, "pr", oldest.PR)
		if err := s.DestroyPreview(ctx, link, oldest, "removed: preview limit reached"); err != nil {
			return err
		}
	}
	return nil
}

func (s *GitService) closePreview(ctx context.Context, link *domain.ProjectGit, parent *domain.Project, pr int) error {
	pv, err := s.Git.GetPreview(ctx, parent.ID, pr)
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.DestroyPreview(ctx, link, pv, "closed")
}

// DestroyPreview tears down the runtime, then archives the ephemeral project
// (deployments, domains and variables go with it).
func (s *GitService) DestroyPreview(ctx context.Context, link *domain.ProjectGit, pv *domain.Preview, reason string) error {
	s.init()
	if s.Runtime != nil {
		if err := s.Runtime.Remove(ctx, pv.ProjectID); err != nil {
			// Still archive the project: leaving it would keep it counted and expiring forever.
			s.Logger.Warn("git preview: runtime removal failed", "project_id", pv.ProjectID, "error", err)
		}
	}
	if err := s.Git.DestroyPreview(ctx, pv.ProjectID); err != nil && !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	if link != nil && pv.CommentID > 0 {
		s.comment(ctx, link, pv, pv.PR, "", "removed", "")
	}
	return nil
}

// ReapExpired destroys previews whose TTL elapsed. Returns how many were removed.
func (s *GitService) ReapExpired(ctx context.Context) (int, error) {
	s.init()
	list, err := s.Git.ListExpiredPreviews(ctx, s.Now())
	if err != nil {
		return 0, err
	}
	n := 0
	for _, pv := range list {
		var link *domain.ProjectGit
		if l, err := s.Git.Get(ctx, pv.ParentProjectID); err == nil {
			link = l
		}
		if err := s.DestroyPreview(ctx, link, pv, "expired"); err != nil {
			s.Logger.Warn("git preview: reaping failed", "project_id", pv.ProjectID, "error", err)
			continue
		}
		n++
	}
	return n, nil
}

// RunReaper reaps expired previews periodically until ctx ends.
func (s *GitService) RunReaper(ctx context.Context, every time.Duration) {
	s.init()
	if every <= 0 {
		every = 15 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if n, err := s.ReapExpired(ctx); err != nil {
			s.Logger.Warn("git preview reaper failed", "error", err)
		} else if n > 0 {
			s.Logger.Info("git preview reaper removed expired previews", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// comment creates or updates the single Capsule comment on the PR; failures only log.
func (s *GitService) comment(ctx context.Context, link *domain.ProjectGit, pv *domain.Preview, pr int, sha, state, url string) {
	c := s.client(link)
	if c == nil {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	id, err := c.UpsertComment(rctx, pr, pv.CommentID, PreviewCommentBody(state, url, sha))
	if err != nil {
		s.Logger.Warn("git preview comment failed", "provider", link.Provider, "pr", pr, "error", err)
		return
	}
	if id > 0 && id != pv.CommentID {
		pv.CommentID = id
		if err := s.Git.SetPreviewComment(ctx, pv.ProjectID, id); err != nil {
			s.Logger.Warn("git preview: saving comment id failed", "error", err)
		}
	}
}

// PreviewCommentBody renders the PR comment text for a preview state
// (building | success | failed | removed).
func PreviewCommentBody(state, url, sha string) string {
	commit := ""
	if sha != "" {
		commit = fmt.Sprintf("\n\nCommit: `%s`", short(sha))
	}
	switch state {
	case "success":
		return fmt.Sprintf("### Capsule preview ready\n\n%s%s", url, commit)
	case "failed":
		return "### Capsule preview failed\n\nThe build or deployment failed. Check the deployment logs in Capsule." + commit
	case "removed":
		return "### Capsule preview removed\n\nThis preview environment has been deleted."
	default:
		if url != "" {
			return fmt.Sprintf("### Capsule preview building\n\nIt will be available at %s when ready.%s", url, commit)
		}
		return "### Capsule preview building\n\nThe preview is being built." + commit
	}
}
