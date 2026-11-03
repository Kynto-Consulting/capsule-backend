package gitinsights

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Window limits of /git/insights.
const (
	DefaultWindow = 30 * 24 * time.Hour
	MaxWindow     = 366 * 24 * time.Hour
)

// ErrInvalidWindow is returned for a bad since/until pair.
var ErrInvalidWindow = errors.New("since must be before until and the window at most 366 days")

// Person is the API Person of a contributor.
type Person struct {
	UserID *uuid.UUID `json:"user_id"`
	Login  string     `json:"login"`
}

// ContributorOut is one contributor of the Insights schema (line counts are not tracked).
type ContributorOut struct {
	Person  Person `json:"person"`
	Commits int    `json:"commits"`
}

// Insights is the API Insights object.
//
//	commits          commits pushed in the window (the commits count of each push, 1 when unknown)
//	prs_opened       pull requests opened in the window (reopenings do not count)
//	prs_merged       pull requests merged in the window
//	median_*_s       medians in seconds; 0 when there is no sample
//	deploys          deployments that finished in the window (succeeded + failed)
//	change_failure_rate  failed / deploys, 0 when there are none
type Insights struct {
	Commits                 int              `json:"commits"`
	PRsOpened               int              `json:"prs_opened"`
	PRsMerged               int              `json:"prs_merged"`
	MedianTimeToFirstReview int64            `json:"median_time_to_first_review_s"`
	MedianTimeToMerge       int64            `json:"median_time_to_merge_s"`
	Deploys                 int              `json:"deploys"`
	ChangeFailureRate       float64          `json:"change_failure_rate"`
	Contributors            []ContributorOut `json:"contributors"`
}

// Median returns the median of v (seconds). For an even count it is the integer mean of the two
// middle values (rounded down); 0 for no samples. v is not modified.
func Median(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]int64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return s[n/2-1] + (s[n/2]-s[n/2-1])/2
}

// PRStats are the pull request figures of a window.
type PRStats struct {
	Opened, Merged int
	ToFirstReview  []int64 // seconds, PRs opened in the window that got a review
	ToMerge        []int64 // seconds, PRs merged in the window whose opening is known
}

// ComputePRStats derives the figures from the events of the involved pull requests.
//
//   - opened: PR whose earliest "opened" event is inside [since, until].
//   - first review: the earliest review at or after the opening whose author is not the PR author.
//   - merged: PR whose earliest merge at or after the opening (or any merge when the opening is
//     unknown) is inside the window; time to merge needs a known opening.
//   - negative or zero-length spans (clock skew, out-of-order delivery) are discarded.
func ComputePRStats(events []PREvent, since, until time.Time) PRStats {
	type pr struct {
		opened, merged *time.Time
		reviews        []PREvent
	}
	byPR := map[int]*pr{}
	for _, e := range events {
		p := byPR[e.PR]
		if p == nil {
			p = &pr{}
			byPR[e.PR] = p
		}
		at := e.At
		switch e.Type {
		case TypePROpened:
			if p.opened == nil || at.Before(*p.opened) {
				p.opened = &at
			}
		case TypePRReview:
			p.reviews = append(p.reviews, e)
		case TypePRMerged:
			if p.merged == nil || at.Before(*p.merged) {
				p.merged = &at
			}
		}
	}
	in := func(t time.Time) bool { return !t.Before(since) && !t.After(until) }
	var st PRStats
	for _, p := range byPR {
		if p.opened != nil && in(*p.opened) {
			st.Opened++
			var first *time.Time
			for _, r := range p.reviews {
				if r.At.Before(*p.opened) || strings.EqualFold(r.Actor, r.Author) {
					continue
				}
				at := r.At
				if first == nil || at.Before(*first) {
					first = &at
				}
			}
			if first != nil {
				if d := int64(first.Sub(*p.opened) / time.Second); d >= 0 {
					st.ToFirstReview = append(st.ToFirstReview, d)
				}
			}
		}
		if p.merged != nil && in(*p.merged) {
			st.Merged++
			if p.opened != nil && !p.merged.Before(*p.opened) {
				st.ToMerge = append(st.ToMerge, int64(p.merged.Sub(*p.opened)/time.Second))
			}
		}
	}
	return st
}

// Service computes insights and lists activity.
type Service struct {
	Store Store
	Now   func() time.Time
}

// ResolveWindow applies the defaults (until = now, since = until - 30 days) and the limits.
func (s *Service) ResolveWindow(since, until *time.Time) (time.Time, time.Time, error) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	u := now().UTC()
	if until != nil {
		u = until.UTC()
	}
	f := u.Add(-DefaultWindow)
	if since != nil {
		f = since.UTC()
	}
	if !f.Before(u) || u.Sub(f) > MaxWindow {
		return f, u, ErrInvalidWindow
	}
	return f, u, nil
}

// Insights computes the figures of a project for [since, until].
func (s *Service) Insights(ctx context.Context, projectID uuid.UUID, since, until time.Time) (Insights, error) {
	out := Insights{Contributors: []ContributorOut{}}
	c, err := s.Store.Counts(ctx, projectID, since, until)
	if err != nil {
		return out, fmt.Errorf("counting activity: %w", err)
	}
	ev, err := s.Store.PRTimeline(ctx, projectID, since, until)
	if err != nil {
		return out, fmt.Errorf("reading pull request timeline: %w", err)
	}
	st := ComputePRStats(ev, since, until)
	out.Commits = c.Commits
	out.PRsOpened, out.PRsMerged = st.Opened, st.Merged
	out.MedianTimeToFirstReview = Median(st.ToFirstReview)
	out.MedianTimeToMerge = Median(st.ToMerge)
	out.Deploys = c.DeploysOK + c.DeploysFailed
	if out.Deploys > 0 {
		out.ChangeFailureRate = math.Round(float64(c.DeploysFailed)/float64(out.Deploys)*10000) / 10000
	}
	for _, k := range c.Contributors {
		out.Contributors = append(out.Contributors, ContributorOut{Person: Person{UserID: k.UserID, Login: k.Login}, Commits: k.Commits})
	}
	sort.SliceStable(out.Contributors, func(i, j int) bool {
		a, b := out.Contributors[i], out.Contributors[j]
		if a.Commits != b.Commits {
			return a.Commits > b.Commits
		}
		return a.Person.Login < b.Person.Login
	})
	return out, nil
}

// ActivityPage lists one page and the next cursor ("" at the end).
func (s *Service) ActivityPage(ctx context.Context, projectID uuid.UUID, cursor string, limit int) ([]Activity, string, error) {
	cur, err := ParseCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 30
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := s.Store.List(ctx, projectID, cur, limit+1)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		l := rows[len(rows)-1]
		next = Cursor{At: l.OccurredAt, ID: l.ID}.Encode()
	}
	return rows, next, nil
}
