package handlers

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

func TestCronDue(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	cases := []struct {
		expr, tz string
		now      time.Time
		want     bool
	}{
		{"*/5 * * * *", "UTC", at("2026-11-24T17:40:07Z"), true},
		{"*/5 * * * *", "UTC", at("2026-11-24T17:41:00Z"), false},
		{"* * * * *", "", at("2026-11-24T17:41:59Z"), true},
		{"0 6 * * *", "America/Lima", at("2026-11-24T11:00:30Z"), true}, // 06:00 in Lima
		{"0 6 * * *", "America/Lima", at("2026-11-24T06:00:30Z"), false},
		{"0 0 1 1 *", "UTC", at("2026-11-24T00:00:00Z"), false},
	}
	for _, c := range cases {
		got, err := cronDue(c.expr, c.tz, c.now)
		if err != nil || got != c.want {
			t.Errorf("cronDue(%q,%q,%s) = %v, %v; want %v", c.expr, c.tz, c.now, got, err, c.want)
		}
	}
	if _, err := cronDue("not a cron", "UTC", time.Now()); err == nil {
		t.Error("an invalid expression must be an error")
	}
	if _, err := cronDue("* * * * *", "Nowhere/City", time.Now()); err == nil {
		t.Error("an invalid timezone must be an error")
	}
}

type fakeCrons struct {
	domain.CronJobRepository
	mu   sync.Mutex
	jobs []*domain.CronJob
	runs map[uuid.UUID]string
	next map[uuid.UUID]*time.Time
}

func (f *fakeCrons) ListActive(context.Context) ([]*domain.CronJob, error) { return f.jobs, nil }
func (f *fakeCrons) UpdateLastRun(_ context.Context, id uuid.UUID, st string, next *time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs[id] = st
	f.next[id] = next
	return nil
}

func TestCronTickRunsDueJobsOnceAndSkipsOverlap(t *testing.T) {
	due := &domain.CronJob{ID: uuid.New(), ProjectID: uuid.New(), Name: "due", Schedule: "*/5 * * * *", Timezone: "UTC", Command: "echo a"}
	notDue := &domain.CronJob{ID: uuid.New(), ProjectID: uuid.New(), Name: "later", Schedule: "0 0 1 1 *", Timezone: "UTC", Command: "echo b"}
	broken := &domain.CronJob{ID: uuid.New(), ProjectID: uuid.New(), Name: "broken", Schedule: "nope", Timezone: "UTC", Command: "echo c"}
	repo := &fakeCrons{jobs: []*domain.CronJob{due, notDue, broken}, runs: map[uuid.UUID]string{}, next: map[uuid.UUID]*time.Time{}}

	release := make(chan struct{})
	var mu sync.Mutex
	var ran []string
	old := cronExec
	cronExec = func(_ context.Context, container, command string) ([]byte, error) {
		mu.Lock()
		ran = append(ran, command)
		mu.Unlock()
		<-release
		return []byte("ok"), nil
	}
	defer func() { cronExec = old }()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sem := make(chan struct{}, 2)
	var wg sync.WaitGroup
	now, _ := time.Parse(time.RFC3339, "2026-11-24T17:40:00Z")

	if n := cronTick(context.Background(), repo, nil, logger, sem, now, &wg); n != 1 {
		t.Fatalf("first tick started %d jobs, want 1", n)
	}
	// The same job is still running: the next due tick must not start it again.
	if n := cronTick(context.Background(), repo, nil, logger, sem, now.Add(5*time.Minute), &wg); n != 0 {
		t.Fatalf("overlapping tick started %d jobs, want 0", n)
	}
	close(release)
	wg.Wait()

	if len(ran) != 1 || ran[0] != "echo a" {
		t.Fatalf("ran = %v, want only the due job", ran)
	}
	if repo.runs[due.ID] != "success" || repo.next[due.ID] == nil {
		t.Fatalf("the run was not recorded with its next time: %q %v", repo.runs[due.ID], repo.next[due.ID])
	}
	// Once finished it can run again.
	if n := cronTick(context.Background(), repo, nil, logger, sem, now.Add(10*time.Minute), &wg); n != 1 {
		t.Fatalf("tick after completion started %d jobs, want 1", n)
	}
	wg.Wait()
}
