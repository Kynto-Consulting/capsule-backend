package gitreview

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

// Errors of the auto-merge entry points (handlers map them to HTTP).
var (
	ErrNotOpen     = errors.New("gitreview: the pull request is not open")
	ErrHeadChanged = errors.New("gitreview: the head of the pull request changed")
	ErrDraft       = errors.New("gitreview: the pull request is a draft")
)

// ValidationError is a 422.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// Outcome is what one Attempt did.
type Outcome string

const (
	OutcomeNone      Outcome = "none"      // no active auto-merge
	OutcomeWaiting   Outcome = "waiting"   // blockers remain
	OutcomeMerged    Outcome = "merged"    // merged now (or by somebody else)
	OutcomeCancelled Outcome = "cancelled" // disarmed (head moved, closed, role lost...)
	OutcomeBusy      Outcome = "busy"      // another worker holds the row
	OutcomeRetry     Outcome = "retry"     // transient failure, scheduled again
)

// Actor is who asks for something.
type Actor struct {
	UserID uuid.UUID
	Login  string // Forgejo login ("" = service account)
}

// MergeInput is the body of autoMergeEnable.
type MergeInput struct {
	Style        gitcore.MergeStyle
	Title        string
	Message      string
	DeleteBranch bool
	HeadSHA      string
}

// EnableAutoMerge arms auto-merge on the CURRENT head of the pull request (409/ErrHeadChanged when
// in.HeadSHA names another one) and tries to merge right away if nothing blocks it.
func (s *Service) EnableAutoMerge(ctx context.Context, p Project, who Actor, n int, in MergeInput) (*gitcore.Pull, *AutoMerge, error) {
	switch in.Style {
	case gitcore.MergeCommit, gitcore.MergeSquash, gitcore.MergeRebase, gitcore.MergeFF:
	default:
		return nil, nil, &ValidationError{"style must be merge, squash, rebase or fast-forward"}
	}
	pr, err := s.Core.GetPull(ctx, p.Ref, n)
	if err != nil {
		return nil, nil, err
	}
	if pr.State != gitcore.PullOpen {
		return nil, nil, ErrNotOpen
	}
	if in.HeadSHA != "" && !strings.EqualFold(in.HeadSHA, pr.HeadSHA) {
		return nil, nil, ErrHeadChanged
	}
	if pr.Draft {
		return nil, nil, ErrDraft
	}
	if repo, err := s.Core.GetRepo(ctx, p.Ref); err == nil && len(repo.AllowedMergeStyles) > 0 {
		ok := false
		for _, st := range repo.AllowedMergeStyles {
			ok = ok || st == string(in.Style)
		}
		if !ok {
			return nil, nil, &ValidationError{fmt.Sprintf("merge style %q is not allowed in this repository", in.Style)}
		}
	}
	row, err := s.Store.Arm(ctx, AutoMerge{ProjectID: p.ID, PR: n, HeadSHA: pr.HeadSHA, Style: in.Style, Title: in.Title,
		Message: in.Message, DeleteBranch: in.DeleteBranch, RequestedBy: who.UserID, RequestedLogin: who.Login, NextAttemptAt: s.now()})
	if err != nil {
		return nil, nil, err
	}
	_ = s.publisher().Publish(ctx, gitevents.Event{ProjectID: p.ID, Name: gitevents.PRAutoMergeEnabled, Actor: who.Login, ActorUserID: who.UserID,
		Branch: pr.Base, Data: map[string]any{"pr": n, "style": string(in.Style), "sha": pr.HeadSHA}})
	if _, err := s.Attempt(ctx, p, n); err != nil {
		s.log().Warn("gitreview: first auto-merge attempt failed", "project_id", p.ID, "pr", n, "error", err)
	}
	cur, err := s.Core.GetPull(ctx, p.Ref, n)
	if err != nil {
		cur = pr
	}
	if r, gerr := s.Store.Get(ctx, p.ID, n); gerr == nil {
		row = r
	}
	return cur, row, nil
}

// DisableAutoMerge disarms auto-merge; no row is not an error (idempotent).
func (s *Service) DisableAutoMerge(ctx context.Context, p Project, n int) error {
	_, err := s.Store.Cancel(ctx, p.ID, n, "cancelled_by_user")
	return err
}

// Active returns the active auto-merge of a pull request or nil.
func (s *Service) Active(ctx context.Context, projectID uuid.UUID, n int) *AutoMerge {
	a, err := s.Store.Get(ctx, projectID, n)
	if err != nil || !a.Active() {
		return nil
	}
	return a
}

// Attempt evaluates one armed pull request and merges it if every requirement is met. It always
// re-reads the truth (pull request, checks, reviews) instead of trusting the event that woke it,
// so out-of-order events cannot cause a wrong merge, and it claims the row atomically so two
// triggers at once merge once. The merge carries head_sha: Forgejo answers 409 if the head moved.
func (s *Service) Attempt(ctx context.Context, p Project, n int) (Outcome, error) {
	row, err := s.Store.Get(ctx, p.ID, n)
	if errors.Is(err, ErrNotFound) || (err == nil && !row.Active()) {
		return OutcomeNone, nil
	}
	if err != nil {
		return OutcomeNone, err
	}
	now := s.now()
	finish := func(state, reason string, o Outcome) (Outcome, error) {
		return o, s.Store.Finish(ctx, p.ID, n, state, reason)
	}
	if now.Sub(row.CreatedAt) > s.cfg().MaxAge {
		return finish(StateCancelled, "expired", OutcomeCancelled)
	}
	pr, err := s.Core.GetPull(ctx, p.Ref, n)
	if err != nil {
		if errors.Is(err, gitcore.ErrNotFound) {
			return finish(StateCancelled, "pr_not_found", OutcomeCancelled)
		}
		return OutcomeRetry, s.Store.Defer(ctx, p.ID, n, now.Add(30*time.Second), "could not read the pull request")
	}
	switch {
	case pr.Merged || pr.State == gitcore.PullMerged:
		return finish(StateMerged, "merged_externally", OutcomeMerged)
	case pr.State == gitcore.PullClosed:
		return finish(StateCancelled, "pr_closed", OutcomeCancelled)
	case !strings.EqualFold(pr.HeadSHA, row.HeadSHA):
		return finish(StateCancelled, "head_changed", OutcomeCancelled)
	}
	wait := func(note string) (Outcome, error) {
		return OutcomeWaiting, s.Store.Defer(ctx, p.ID, n, now.Add(s.cfg().SweepEvery), note)
	}
	if pr.Draft {
		return wait("draft")
	}
	if s.Authz != nil && row.RequestedBy != uuid.Nil {
		ok, aerr := s.Authz.Can(ctx, row.RequestedBy, p.OrgID, p.ID, authz.GitMerge)
		if aerr != nil {
			return OutcomeRetry, s.Store.Defer(ctx, p.ID, n, now.Add(30*time.Second), "could not check the requester role")
		}
		if !ok {
			return finish(StateCancelled, "requester_lost_access", OutcomeCancelled)
		}
	}
	as, err := gitapi.Assess(ctx, s.Core, p.Ref, *pr)
	if err != nil {
		return OutcomeRetry, s.Store.Defer(ctx, p.ID, n, now.Add(30*time.Second), "merge requirements could not be evaluated")
	}
	if !as.Mergeability.CanMerge {
		codes := make([]string, 0, len(as.Mergeability.Blockers))
		for _, b := range as.Mergeability.Blockers {
			codes = append(codes, b.Code)
		}
		return wait(strings.Join(codes, ","))
	}
	claimed, ok, err := s.Store.Claim(ctx, p.ID, n, pr.HeadSHA, now, now.Add(s.cfg().Lease))
	if err != nil {
		return OutcomeRetry, err
	}
	if !ok {
		return OutcomeBusy, nil
	}
	res, merr := s.Core.MergePull(actorOf(ctx, claimed.RequestedLogin), p.Ref, n, gitcore.MergeRequest{
		Style: claimed.Style, Title: claimed.Title, Message: claimed.Message, DeleteBranch: claimed.DeleteBranch, HeadSHA: claimed.HeadSHA})
	if merr == nil && res != nil && res.Merged {
		return OutcomeMerged, s.Store.Finish(ctx, p.ID, n, StateMerged, "merged")
	}
	if merr == nil {
		return OutcomeRetry, s.Store.Release(ctx, p.ID, n, claimed.HeadSHA, now.Add(30*time.Second), "merge not confirmed", false)
	}
	return s.afterMergeError(ctx, p, n, claimed, merr, now)
}

func (s *Service) afterMergeError(ctx context.Context, p Project, n int, row *AutoMerge, merr error, now time.Time) (Outcome, error) {
	ge, _ := gitcore.AsError(merr)
	msg := "merge failed"
	if ge != nil {
		msg = string(ge.Code) + ": " + ge.Message
		if len(msg) > 300 {
			msg = msg[:300]
		}
	}
	if ge != nil && ge.Code == gitcore.CodeConflict {
		if ge.Status == 423 { // Forgejo is still checking the pull request: not a failure
			return OutcomeRetry, s.Store.Release(ctx, p.ID, n, row.HeadSHA, now.Add(5*time.Second), "forgejo busy (423)", false)
		}
		if cur, err := s.Core.GetPull(ctx, p.Ref, n); err == nil {
			switch {
			case cur.Merged:
				return OutcomeMerged, s.Store.Finish(ctx, p.ID, n, StateMerged, "merged_externally")
			case !strings.EqualFold(cur.HeadSHA, row.HeadSHA):
				return OutcomeCancelled, s.Store.Finish(ctx, p.ID, n, StateCancelled, "head_changed")
			case cur.State == gitcore.PullClosed:
				return OutcomeCancelled, s.Store.Finish(ctx, p.ID, n, StateCancelled, "pr_closed")
			}
		}
	}
	retryable := ge != nil && ge.Retry
	next := now.Add(s.cfg().SweepEvery)
	if retryable {
		next = now.Add(30 * time.Second)
	}
	if row.Attempts+1 >= s.cfg().MaxAttempts {
		_ = s.Store.Release(ctx, p.ID, n, row.HeadSHA, next, msg, true)
		return OutcomeCancelled, s.Store.Finish(ctx, p.ID, n, StateCancelled, "too_many_failures")
	}
	return OutcomeRetry, s.Store.Release(ctx, p.ID, n, row.HeadSHA, next, msg, true)
}

// Name implements gitevents.Subscriber.
func (s *Service) Name() string { return "gitreview" }

// Handle implements gitevents.Subscriber. It is idempotent and never returns an error: a failure
// here must not make the bus redeliver the event to the other subscribers (the periodic sweep
// picks the work up again).
func (s *Service) Handle(ctx context.Context, e gitevents.Event) error {
	switch e.Name {
	case gitevents.PROpened, gitevents.PRUpdated, gitevents.PRReadyForReview, gitevents.PRReviewSubmitted,
		gitevents.PRReviewRequested, gitevents.PRMerged, gitevents.PRClosed, gitevents.CheckCompleted, gitevents.WorkflowRunCompleted:
	default:
		return nil
	}
	p, err := s.Projects.ByID(ctx, e.ProjectID)
	if err != nil {
		return nil
	}
	if e.Name == gitevents.CheckCompleted || e.Name == gitevents.WorkflowRunCompleted {
		sha, _ := e.Data["sha"].(string)
		if sha == "" {
			return nil
		}
		rows, err := s.Store.ListArmedByHead(ctx, p.ID, sha)
		if err != nil {
			s.log().Warn("gitreview: listing armed pull requests failed", "project_id", p.ID, "error", err)
			return nil
		}
		for _, r := range rows {
			s.safeAttempt(ctx, *p, r.PR)
		}
		return nil
	}
	n := dataInt(e.Data["pr"])
	if n < 1 {
		return nil
	}
	switch e.Name {
	case gitevents.PRMerged:
		_ = s.Store.Finish(ctx, p.ID, n, StateMerged, "merged")
		return nil
	case gitevents.PRClosed:
		_ = s.Store.Finish(ctx, p.ID, n, StateCancelled, "pr_closed")
		return nil
	}
	if pr, err := s.Core.GetPull(ctx, p.Ref, n); err == nil {
		if perr := s.RefreshPolicy(ctx, *p, *pr); perr != nil {
			s.log().Warn("gitreview: refreshing capsule/policy failed", "project_id", p.ID, "pr", n, "error", perr)
		}
	}
	s.safeAttempt(ctx, *p, n)
	return nil
}

func (s *Service) safeAttempt(ctx context.Context, p Project, n int) {
	defer func() {
		if r := recover(); r != nil {
			s.log().Error("gitreview: auto-merge attempt panicked", "project_id", p.ID, "pr", n, "panic", fmt.Sprint(r))
		}
	}()
	if _, err := s.Attempt(ctx, p, n); err != nil {
		s.log().Warn("gitreview: auto-merge attempt failed", "project_id", p.ID, "pr", n, "error", err)
	}
}

func dataInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	}
	return 0
}

// Sweep attempts every due row once (periodic safety net for lost events and 423 retries).
func (s *Service) Sweep(ctx context.Context) int {
	rows, err := s.Store.ListDue(ctx, s.now(), 100)
	if err != nil {
		s.log().Warn("gitreview: listing due auto-merges failed", "error", err)
		return 0
	}
	for _, r := range rows {
		p, err := s.Projects.ByID(ctx, r.ProjectID)
		if err != nil {
			_ = s.Store.Finish(ctx, r.ProjectID, r.PR, StateCancelled, "project_gone")
			continue
		}
		s.safeAttempt(ctx, *p, r.PR)
	}
	return len(rows)
}

// Run sweeps until ctx ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg().SweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sweep(ctx)
		}
	}
}
