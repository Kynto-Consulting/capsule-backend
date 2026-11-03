package handlers

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

const (
	activityPerSource = 40
	insightsMaxPages  = 10
	insightsWindowMax = 366 * 24 * time.Hour
	insightsReviewMax = 30
)

type activityOut struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Actor     gitcore.Person `json:"actor"`
	Ref       string         `json:"ref,omitempty"`
	Summary   string         `json:"summary"`
	CreatedAt time.Time      `json:"created_at"`
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// activityList: GET .../git/activity. It is derived on the fly from the newest commits, pull
// requests and runs (no storage): a feed of what happened, not an audit trail.
func (a *gitAPI) activityList(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitRead)
	if !ok {
		return
	}
	pg, ok := pageParams(w, r)
	if !ok {
		return
	}
	var evs []activityOut
	src := gitcore.Page{Limit: activityPerSource}
	commits, err := sc.core.ListCommits(sc.ctx, sc.ref, gitcore.CommitQuery{}, src)
	if err != nil && !isNotFound(err) {
		a.fail(w, err, false)
		return
	}
	for _, c := range commits.Items {
		evs = append(evs, activityOut{ID: gitapi.DeterministicID("commit", c.SHA), Type: "push", Actor: c.Author, Ref: short(c.SHA),
			Summary: firstLine(c.Message), CreatedAt: c.CommittedAt})
	}
	pulls, err := sc.core.ListPulls(sc.ctx, sc.ref, gitcore.PullQuery{State: "all"}, src)
	if err != nil && !isNotFound(err) {
		a.fail(w, err, false)
		return
	}
	for _, p := range pulls.Items {
		ref := fmt.Sprintf("#%d", p.Number)
		evs = append(evs, activityOut{ID: gitapi.DeterministicID("pr-open", itoa(p.Number)), Type: "pull_request.opened", Actor: p.Author, Ref: ref,
			Summary: p.Title, CreatedAt: p.CreatedAt})
		switch {
		case p.Merged && p.MergedAt != nil:
			evs = append(evs, activityOut{ID: gitapi.DeterministicID("pr-merge", itoa(p.Number)), Type: "pull_request.merged", Actor: p.Author, Ref: ref,
				Summary: p.Title, CreatedAt: *p.MergedAt})
		case p.State == gitcore.PullClosed && !p.Merged:
			evs = append(evs, activityOut{ID: gitapi.DeterministicID("pr-close", itoa(p.Number)), Type: "pull_request.closed", Actor: p.Author, Ref: ref,
				Summary: p.Title, CreatedAt: p.UpdatedAt})
		}
	}
	runs, err := sc.core.ListRuns(sc.ctx, sc.ref, gitcore.RunQuery{}, src)
	if err != nil && !isNotFound(err) {
		a.fail(w, err, false)
		return
	}
	for _, run := range runs.Items {
		o := gitapi.ToRun(run)
		evs = append(evs, activityOut{ID: gitapi.DeterministicID("run", o.ID), Type: "workflow_run", Actor: run.Actor, Ref: run.Ref,
			Summary: fmt.Sprintf("%s: %s (%s)", firstLine(run.Title), o.Status, run.Event), CreatedAt: run.StartedAt})
	}
	sort.SliceStable(evs, func(i, j int) bool {
		if !evs[i].CreatedAt.Equal(evs[j].CreatedAt) {
			return evs[i].CreatedAt.After(evs[j].CreatedAt)
		}
		return evs[i].ID < evs[j].ID
	})
	items, next, err := gitapi.SliceByCursor(evs, pg)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusOK, newList(items, next))
}

func isNotFound(err error) bool {
	e, ok := gitcore.AsError(err)
	return ok && e.Code == gitcore.CodeNotFound
}

func parseWhen(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

type contributorOut struct {
	Person  gitcore.Person `json:"person"`
	Commits int            `json:"commits"`
}

type insightsOut struct {
	Commits                 int              `json:"commits"`
	PRsOpened               int              `json:"prs_opened"`
	PRsMerged               int              `json:"prs_merged"`
	MedianTimeToFirstReview int              `json:"median_time_to_first_review_s"`
	MedianTimeToMerge       int              `json:"median_time_to_merge_s"`
	Deploys                 int              `json:"deploys"`
	ChangeFailureRate       float64          `json:"change_failure_rate"`
	Contributors            []contributorOut `json:"contributors"`
}

// insights: GET .../git/insights?since=&until= (default: the last 30 days, at most 366 days).
// Computed from Forgejo (commits and pull requests of the default branch) and the project's
// deployments; line counts per contributor are not available and are left out.
func (a *gitAPI) insights(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitRead)
	if !ok {
		return
	}
	until := time.Now().UTC()
	since := until.Add(-30 * 24 * time.Hour)
	if v := r.URL.Query().Get("until"); v != "" {
		t, ok := parseWhen(v)
		if !ok {
			badRequest(w, "until must be RFC 3339 or YYYY-MM-DD")
			return
		}
		until = t
		if len(v) == 10 { // a bare date means the whole day
			until = t.Add(24*time.Hour - time.Second)
		}
		since = until.Add(-30 * 24 * time.Hour)
	}
	if v := r.URL.Query().Get("since"); v != "" {
		t, ok := parseWhen(v)
		if !ok {
			badRequest(w, "since must be RFC 3339 or YYYY-MM-DD")
			return
		}
		since = t
	}
	if !since.Before(until) || until.Sub(since) > insightsWindowMax {
		badRequest(w, "since must be before until, and the window at most 366 days")
		return
	}
	out := insightsOut{Contributors: []contributorOut{}}
	in := func(t time.Time) bool { return !t.Before(since) && !t.After(until) }

	// commits
	byAuthor := map[string]*contributorOut{}
	cursor := ""
scan:
	for page := 0; page < insightsMaxPages; page++ {
		l, err := sc.core.ListCommits(sc.ctx, sc.ref, gitcore.CommitQuery{}, gitcore.Page{Cursor: cursor, Limit: gitcore.MaxLimit})
		if err != nil {
			if isNotFound(err) {
				break
			}
			a.fail(w, err, false)
			return
		}
		for _, c := range l.Items {
			if c.CommittedAt.Before(since) {
				break scan // newest first: everything after is older
			}
			if !in(c.CommittedAt) {
				continue
			}
			out.Commits++
			key := c.Author.Login
			if key == "" {
				key = c.Author.Email
			}
			if e := byAuthor[key]; e != nil {
				e.Commits++
			} else {
				byAuthor[key] = &contributorOut{Person: c.Author, Commits: 1}
			}
		}
		if l.NextCursor == "" {
			break
		}
		cursor = l.NextCursor
	}
	for _, c := range byAuthor {
		out.Contributors = append(out.Contributors, *c)
	}
	sort.Slice(out.Contributors, func(i, j int) bool {
		if out.Contributors[i].Commits != out.Contributors[j].Commits {
			return out.Contributors[i].Commits > out.Contributors[j].Commits
		}
		return out.Contributors[i].Person.Login < out.Contributors[j].Person.Login
	})

	// pull requests
	var toMerge, toReview []time.Duration
	var mergedInWindow []gitcore.Pull
	cursor = ""
	for page := 0; page < insightsMaxPages; page++ {
		l, err := sc.core.ListPulls(sc.ctx, sc.ref, gitcore.PullQuery{State: "all"}, gitcore.Page{Cursor: cursor, Limit: gitcore.MaxLimit})
		if err != nil {
			if isNotFound(err) {
				break
			}
			a.fail(w, err, false)
			return
		}
		for _, p := range l.Items {
			if in(p.CreatedAt) {
				out.PRsOpened++
			}
			if p.Merged && p.MergedAt != nil && in(*p.MergedAt) {
				out.PRsMerged++
				toMerge = append(toMerge, p.MergedAt.Sub(p.CreatedAt))
				mergedInWindow = append(mergedInWindow, p)
			}
		}
		if l.NextCursor == "" {
			break
		}
		cursor = l.NextCursor
	}
	for i, p := range mergedInWindow {
		if i >= insightsReviewMax {
			break
		}
		reviews, err := sc.core.ListReviews(sc.ctx, sc.ref, p.Number)
		if err != nil {
			continue
		}
		var first *time.Time
		for _, rv := range reviews {
			if rv.State == "pending" || strings.EqualFold(rv.Author.Login, p.Author.Login) {
				continue
			}
			if first == nil || rv.SubmittedAt.Before(*first) {
				t := rv.SubmittedAt
				first = &t
			}
		}
		if first != nil && !first.Before(p.CreatedAt) {
			toReview = append(toReview, first.Sub(p.CreatedAt))
		}
	}
	out.MedianTimeToMerge = gitapi.MedianSeconds(toMerge)
	out.MedianTimeToFirstReview = gitapi.MedianSeconds(toReview)

	// deployments of the project
	if a.d.Deployments != nil {
		var ok, bad int
		for page := 1; page <= insightsMaxPages; page++ {
			list, _, err := a.d.Deployments.ListByProject(r.Context(), sc.proj.ID, page, 100)
			if err != nil || len(list) == 0 {
				break
			}
			older := false
			for _, d := range list { // newest first
				if d.CreatedAt.Before(since) {
					older = true
					continue
				}
				if !in(d.CreatedAt) {
					continue
				}
				switch d.Status {
				case "success":
					ok++
				case "failed", "rolled_back":
					bad++
				}
			}
			if older || len(list) < 100 {
				break
			}
		}
		out.Deploys = ok + bad
		if out.Deploys > 0 {
			out.ChangeFailureRate = float64(bad) / float64(out.Deploys)
		}
	}
	respondJSON(w, http.StatusOK, out)
}
