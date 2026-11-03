package gitreview

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

// ErrNotSupported: the shared gitcore cannot dismiss reviews (not a *gitcore.Service).
var ErrNotSupported = errors.New("gitreview: review administration is not available")

// ErrReviewNotDismissable: the review does not exist on the pull request or has no decision to dismiss.
var ErrReviewNotDismissable = errors.New("gitreview: the review cannot be dismissed")

func (s *Service) reviewAdmin() (gitcore.ReviewAdmin, error) {
	if ra, ok := s.Core.(gitcore.ReviewAdmin); ok {
		return ra, nil
	}
	return nil, ErrNotSupported
}

// MarkReady removes the draft prefix (idempotent) and refreshes capsule/policy. ctx must act as
// the requesting user.
func (s *Service) MarkReady(ctx context.Context, p Project, n int) (*gitcore.Pull, error) {
	pr, err := s.Core.GetPull(ctx, p.Ref, n)
	if err != nil {
		return nil, err
	}
	if pr.State != gitcore.PullOpen {
		return nil, ErrNotOpen
	}
	if pr.Draft {
		f := false
		if pr, err = s.Core.PatchPull(ctx, p.Ref, n, gitcore.PullPatch{Draft: &f}); err != nil {
			return nil, err
		}
	}
	if perr := s.RefreshPolicy(gitcore.WithActor(ctx, ""), p, *pr); perr != nil {
		s.log().Warn("gitreview: refreshing capsule/policy failed", "project_id", p.ID, "pr", n, "error", perr)
	}
	return pr, nil
}

// RequestReviewers validates users and teams against the project roster (only people whose role
// can review, never the author) and asks Forgejo. ctx must act as the requesting user.
func (s *Service) RequestReviewers(ctx context.Context, p Project, n int, users, teams []string) (*gitcore.Pull, error) {
	if len(users)+len(teams) == 0 {
		return nil, &ValidationError{"at least one user or team is required"}
	}
	if len(users)+len(teams) > 20 {
		return nil, &ValidationError{"at most 20 reviewers can be requested at once"}
	}
	pr, err := s.Core.GetPull(ctx, p.Ref, n)
	if err != nil {
		return nil, err
	}
	if pr.State != gitcore.PullOpen {
		return nil, ErrNotOpen
	}
	roster, err := s.members(ctx, p)
	if err != nil {
		return nil, err
	}
	byLogin := map[string]Member{}
	for _, m := range roster {
		byLogin[strings.ToLower(m.Login)] = m
	}
	var outUsers, outTeams []string
	seen := map[string]bool{}
	for _, u := range users {
		l := strings.ToLower(strings.TrimSpace(u))
		if seen[l] {
			continue
		}
		seen[l] = true
		m, ok := byLogin[l]
		switch {
		case !ok:
			return nil, &ValidationError{fmt.Sprintf("%s is not a member of this project", u)}
		case !authz.RoleAllows(m.Role, authz.GitReview):
			return nil, &ValidationError{fmt.Sprintf("%s cannot review in this project (role %s)", u, m.Role)}
		case l == strings.ToLower(pr.Author.Login):
			return nil, &ValidationError{"the author of a pull request cannot review it"}
		}
		outUsers = append(outUsers, l)
	}
	for _, t := range teams {
		ok := false
		for _, role := range []authz.Role{authz.RoleAdmin, authz.RoleDeployer} {
			ok = ok || strings.EqualFold(t, p.Ref.Repo+teamRoleSeparator+string(role))
		}
		if !ok {
			return nil, &ValidationError{fmt.Sprintf("team %q is not a reviewing team of this project (%s-deployer, %s-admin)", t, p.Ref.Repo, p.Ref.Repo)}
		}
		if !seen["team:"+strings.ToLower(t)] {
			seen["team:"+strings.ToLower(t)] = true
			outTeams = append(outTeams, t)
		}
	}
	if err := s.Core.RequestReviewers(ctx, p.Ref, n, outUsers, outTeams); err != nil {
		return nil, err
	}
	return s.Core.GetPull(ctx, p.Ref, n)
}

// DismissReview dismisses an approval or change request. Forgejo only lets repository admins do
// it and Capsule users are never repo admins there, so the call goes out as the service account
// and the message names the Capsule user who decided.
func (s *Service) DismissReview(ctx context.Context, p Project, n int, reviewID int64, by Actor, reason string) (*gitcore.Review, error) {
	ra, err := s.reviewAdmin()
	if err != nil {
		return nil, err
	}
	reason = strings.TrimSpace(reason)
	if len([]rune(reason)) < 3 {
		return nil, &ValidationError{"reason must have at least 3 characters"}
	}
	reviews, err := s.Core.ListReviews(gitcore.WithActor(ctx, ""), p.Ref, n)
	if err != nil {
		return nil, err
	}
	var target *gitcore.Review
	for i := range reviews {
		if reviews[i].ID == reviewID {
			target = &reviews[i]
		}
	}
	if target == nil {
		return nil, gitcore.ErrNotFound
	}
	if target.State != "approved" && target.State != "changes_requested" {
		return nil, ErrReviewNotDismissable
	}
	msg := reason
	if by.Login != "" {
		msg = "Dismissed by @" + by.Login + ": " + reason
	}
	rv, err := ra.DismissReview(gitcore.WithActor(ctx, ""), p.Ref, n, reviewID, msg)
	if err != nil {
		return nil, err
	}
	if rv.Author.Login == "" {
		rv.Author = target.Author
		rv.CommitSHA = target.CommitSHA
	}
	if s.Dismissals != nil {
		if lerr := s.Dismissals.Record(ctx, Dismissal{ProjectID: p.ID, PR: n, ReviewID: reviewID, Reviewer: target.Author.Login,
			ReviewState: target.State, CommitSHA: target.CommitSHA, DismissedBy: by.UserID, Reason: reason}); lerr != nil {
			s.log().Warn("gitreview: recording the dismissal failed", "project_id", p.ID, "pr", n, "review_id", reviewID, "error", lerr)
		}
	}
	if pr, gerr := s.Core.GetPull(ctx, p.Ref, n); gerr == nil {
		_ = s.RefreshPolicy(ctx, p, *pr)
	}
	return rv, nil
}

// Janitor implements gitsync.ReviewJanitor: when a user loses the ability to review, the review
// requests that still wait for them in the open pull requests are withdrawn (and capsule/policy is
// recomputed, which re-lists the remaining owners as pending).
type Janitor struct {
	Svc *Service
	// Repo resolves the project of a repository for the policy refresh (optional).
}

// DropPendingReviews returns how many review requests were withdrawn.
func (j Janitor) DropPendingReviews(ctx context.Context, repo gitcore.RepoRef, login string) (int, error) {
	s := j.Svc
	ra, err := s.reviewAdmin()
	if err != nil {
		return 0, err
	}
	login = strings.ToLower(login)
	ctx = gitcore.WithActor(ctx, "")
	dropped := 0
	var errs []error
	cursor := ""
	for page := 0; page < 20; page++ {
		l, err := s.Core.ListPulls(ctx, repo, gitcore.PullQuery{State: "open"}, gitcore.Page{Cursor: cursor, Limit: gitcore.MaxLimit})
		if err != nil {
			return dropped, err
		}
		for _, pr := range l.Items {
			requested := false
			for _, u := range pr.Reviewers {
				requested = requested || strings.EqualFold(u.Login, login)
			}
			if !requested {
				continue
			}
			if err := ra.RemoveReviewRequest(ctx, repo, pr.Number, []string{login}, nil); err != nil {
				errs = append(errs, fmt.Errorf("pr %d: %w", pr.Number, err))
				continue
			}
			dropped++
			if p, perr := s.Projects.ByRef(ctx, repo); perr == nil {
				if cur, gerr := s.Core.GetPull(ctx, repo, pr.Number); gerr == nil {
					_ = s.RefreshPolicy(ctx, *p, *cur)
				}
			}
		}
		if l.NextCursor == "" {
			break
		}
		cursor = l.NextCursor
	}
	sort.Slice(errs, func(i, k int) bool { return errs[i].Error() < errs[k].Error() })
	return dropped, errors.Join(errs...)
}
