//go:build dbtest

package repository

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitreview"
)

const prSHA = "1111111111111111111111111111111111111111"

func TestPRAutoMergeDB(t *testing.T) {
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	r := NewPRAutoMergeRepository(pool)
	ctx := context.Background()
	owner := f.user("", time.Now())
	org := f.org(owner)
	proj := f.project(org, "")
	now := time.Now().UTC().Truncate(time.Millisecond)

	if _, err := r.Get(ctx, proj, 1); err != gitreview.ErrNotFound {
		t.Fatalf("missing row: %v", err)
	}
	a, err := r.Arm(ctx, gitreview.AutoMerge{ProjectID: proj, PR: 1, HeadSHA: prSHA, Style: gitcore.MergeSquash, Title: "t",
		RequestedBy: owner, RequestedLogin: "ana", NextAttemptAt: now})
	if err != nil || a.State != gitreview.StateArmed || a.Style != gitcore.MergeSquash || a.RequestedBy != owner {
		t.Fatalf("arm: %+v %v", a, err)
	}
	// no requester (uuid.Nil) is stored as NULL
	if _, err := r.Arm(ctx, gitreview.AutoMerge{ProjectID: proj, PR: 2, HeadSHA: prSHA, Style: gitcore.MergeCommit, NextAttemptAt: now}); err != nil {
		t.Fatal(err)
	}

	// listing: by head (case-insensitive) and due
	byHead, err := r.ListArmedByHead(ctx, proj, "1111111111111111111111111111111111111111")
	if err != nil || len(byHead) != 2 {
		t.Fatalf("by head: %d %v", len(byHead), err)
	}
	due, err := r.ListDue(ctx, now.Add(time.Second), 10)
	if err != nil || len(due) != 2 {
		t.Fatalf("due: %d %v", len(due), err)
	}

	// Claim is exclusive: 10 concurrent claimers, one wins
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := r.Claim(ctx, proj, 1, prSHA, now, now.Add(2*time.Minute))
			if err != nil {
				t.Error(err)
			}
			if ok {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("claim winners: %d", wins)
	}
	// a claim with another head never wins, a merging row is not due until its lease ends
	if _, ok, _ := r.Claim(ctx, proj, 2, "2222222222222222222222222222222222222222", now, now.Add(time.Minute)); ok {
		t.Fatal("claimed with the wrong head")
	}
	if d, _ := r.ListDue(ctx, now.Add(time.Minute), 10); len(d) != 1 || d[0].PR != 2 {
		t.Fatalf("due while leased: %+v", d)
	}
	// expired lease: claimable again
	if _, ok, _ := r.Claim(ctx, proj, 1, prSHA, now.Add(3*time.Minute), now.Add(5*time.Minute)); !ok {
		t.Fatal("expired lease must be claimable")
	}

	// Release counts failed attempts only when asked; Defer never does
	if err := r.Release(ctx, proj, 1, prSHA, now.Add(time.Hour), "boom", true); err != nil {
		t.Fatal(err)
	}
	g, _ := r.Get(ctx, proj, 1)
	if g.State != gitreview.StateArmed || g.Attempts != 1 || g.LastError != "boom" || g.ClaimedUntil != nil {
		t.Fatalf("after release: %+v", g)
	}
	if err := r.Defer(ctx, proj, 1, now.Add(2*time.Hour), "waiting"); err != nil {
		t.Fatal(err)
	}
	if g, _ = r.Get(ctx, proj, 1); g.Attempts != 1 || g.LastError != "waiting" {
		t.Fatalf("after defer: %+v", g)
	}

	// Finish and Cancel only act on active rows
	if err := r.Finish(ctx, proj, 1, gitreview.StateMerged, "merged"); err != nil {
		t.Fatal(err)
	}
	if err := r.Finish(ctx, proj, 1, gitreview.StateCancelled, "late"); err != nil {
		t.Fatal(err)
	}
	if g, _ = r.Get(ctx, proj, 1); g.State != gitreview.StateMerged || g.Reason != "merged" {
		t.Fatalf("finished rows must not change: %+v", g)
	}
	if err := r.Finish(ctx, proj, 1, "bogus", ""); err == nil {
		t.Fatal("invalid state must fail")
	}
	if ok, _ := r.Cancel(ctx, proj, 1, "x"); ok {
		t.Fatal("cancel of a merged row")
	}
	if ok, err := r.Cancel(ctx, proj, 2, "cancelled_by_user"); err != nil || !ok {
		t.Fatalf("cancel active: %v %v", ok, err)
	}
	if ok, _ := r.Cancel(ctx, proj, 2, "again"); ok {
		t.Fatal("second cancel must report nothing to do")
	}
	// re-arming replaces a finished row
	re, err := r.Arm(ctx, gitreview.AutoMerge{ProjectID: proj, PR: 1, HeadSHA: "3333333333333333333333333333333333333333", Style: gitcore.MergeRebase, NextAttemptAt: now})
	if err != nil || re.State != gitreview.StateArmed || re.Attempts != 0 || re.Reason != "" || re.HeadSHA[0] != '3' {
		t.Fatalf("re-arm: %+v %v", re, err)
	}
	// deleting the project removes its rows
	if _, err := pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, proj); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, proj, 1); err != gitreview.ErrNotFound {
		t.Fatalf("cascade: %v", err)
	}
	_ = uuid.Nil
}

func TestPRReviewDismissalsDB(t *testing.T) {
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	r := NewPRReviewDismissalRepository(pool)
	ctx := context.Background()
	owner := f.user("", time.Now())
	proj := f.project(f.org(owner), "")
	if err := r.Record(ctx, gitreview.Dismissal{ProjectID: proj, PR: 4, ReviewID: 9, Reviewer: "bob", ReviewState: "approved", CommitSHA: prSHA, DismissedBy: owner, Reason: "obsoleta"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Record(ctx, gitreview.Dismissal{ProjectID: proj, PR: 4, ReviewID: 10, Reason: "sin autor"}); err != nil { // nobody: stored as NULL
		t.Fatal(err)
	}
	got, err := r.List(ctx, proj, 4)
	if err != nil || len(got) != 2 || got[0].DismissedBy != owner || got[0].Reviewer != "bob" || got[1].DismissedBy != uuid.Nil {
		t.Fatalf("list: %+v %v", got, err)
	}
	if other, _ := r.List(ctx, proj, 5); len(other) != 0 {
		t.Fatalf("other PR: %+v", other)
	}
}
