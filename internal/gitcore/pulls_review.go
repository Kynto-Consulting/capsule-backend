package gitcore

import (
	"context"
	"net/http"
	"strconv"
	"strings"
)

// Review administration (Git Capsule B8). These two calls are NOT part of the fixed Core
// interface of types.go (A1 froze it): *Service implements them and the packages that need them
// (gitreview) ask for ReviewAdmin with a type assertion on gitcore.Shared(). Wire shapes follow the
// Forgejo swagger (POST .../reviews/{id}/dismissals, DELETE .../requested_reviewers); they were
// checked against Forgejo v15.0.11 only if the itest says so (see gitcore/itest).

// ReviewAdmin is the optional surface for dismissing reviews and withdrawing review requests.
type ReviewAdmin interface {
	// DismissReview marks a submitted approval / change request as dismissed with a message.
	DismissReview(ctx context.Context, r RepoRef, n int, reviewID int64, message string) (*Review, error)
	// RemoveReviewRequest withdraws the pending review requests of users and teams (a request
	// that does not exist is not an error).
	RemoveReviewRequest(ctx context.Context, r RepoRef, n int, users, teams []string) error
}

var _ ReviewAdmin = (*Service)(nil)

// DismissReview dismisses review reviewID of pull request n. Forgejo only lets repository
// administrators do it (the service account is one); Capsule decides git.admin BEFORE calling.
func (s *Service) DismissReview(ctx context.Context, r RepoRef, n int, reviewID int64, message string) (*Review, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if n < 1 || reviewID < 1 {
		return nil, invalid("pull request number and review id must be positive")
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return nil, invalid("a dismissal message is required")
	}
	var f fgReview
	_, err := s.do(ctx, req{method: http.MethodPost,
		path: r.base() + "/pulls/" + itoa(n) + "/reviews/" + strconv.FormatInt(reviewID, 10) + "/dismissals",
		op:   "/repos/{o}/{r}/pulls/{n}/reviews/{id}/dismissals",
		body: map[string]any{"message": message}}, &f)
	if err != nil {
		return nil, err
	}
	_ = s.InvalidateRepo(ctx, r)
	rv := f.review()
	if rv.ID == 0 {
		rv.ID = reviewID
	}
	rv.State = "dismissed"
	return &rv, nil
}

// RemoveReviewRequest withdraws pending review requests. Users or teams that were never
// requested are ignored by Forgejo; a 404 (unknown login/team) is also treated as "nothing to
// withdraw" so a janitor over many pull requests never stops on a stale name.
func (s *Service) RemoveReviewRequest(ctx context.Context, r RepoRef, n int, users, teams []string) error {
	if err := r.valid(); err != nil {
		return err
	}
	if n < 1 {
		return invalid("pull request number must be positive")
	}
	if len(users) == 0 && len(teams) == 0 {
		return nil
	}
	if users == nil {
		users = []string{}
	}
	if teams == nil {
		teams = []string{}
	}
	_, err := s.do(ctx, req{method: http.MethodDelete, path: r.base() + "/pulls/" + itoa(n) + "/requested_reviewers",
		op: "/repos/{o}/{r}/pulls/{n}/requested_reviewers", body: map[string]any{"reviewers": users, "team_reviewers": teams}}, nil)
	if errIs(err, CodeNotFound) {
		return nil
	}
	if err == nil {
		_ = s.InvalidateRepo(ctx, r)
	}
	return err
}
