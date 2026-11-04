package ciwake

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitevents"
)

type fakeEC2 struct {
	state    ec2types.InstanceStateName
	none     bool
	descErr  error
	startErr error
	descs    int
	starts   int
	lastIDs  []string
}

func (f *fakeEC2) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	f.descs++
	f.lastIDs = in.InstanceIds
	if f.descErr != nil {
		return nil, f.descErr
	}
	if f.none {
		return &ec2.DescribeInstancesOutput{}, nil
	}
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{{State: &ec2types.InstanceState{Name: f.state}}}}}}, nil
}

func (f *fakeEC2) StartInstances(_ context.Context, _ *ec2.StartInstancesInput, _ ...func(*ec2.Options)) (*ec2.StartInstancesOutput, error) {
	f.starts++
	if f.startErr != nil {
		return nil, f.startErr
	}
	f.state = ec2types.InstanceStateNamePending
	return &ec2.StartInstancesOutput{}, nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newW(f *fakeEC2, max int) (*Waker, *clock) {
	w := New(f, Config{InstanceID: "i-abc", MaxPerHour: max}, nil, nil)
	c := &clock{t: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)}
	w.now = c.now
	return w, c
}

func ev(name string) gitevents.Event { return gitevents.Event{ProjectID: uuid.New(), Name: name} }

func TestOffWhenNoInstance(t *testing.T) {
	if New(&fakeEC2{}, Config{}, nil, nil) != nil || New(nil, Config{InstanceID: "i-1"}, nil, nil) != nil {
		t.Fatal("expected nil waker")
	}
}

func TestStatesTable(t *testing.T) {
	cases := []struct {
		state  ec2types.InstanceStateName
		none   bool
		want   Outcome
		starts int
	}{
		{ec2types.InstanceStateNameStopped, false, OutcomeStarted, 1},
		{ec2types.InstanceStateNameRunning, false, OutcomeAlready, 0},
		{ec2types.InstanceStateNamePending, false, OutcomeAlready, 0},
		{ec2types.InstanceStateNameStopping, false, OutcomeStopping, 0},
		{ec2types.InstanceStateNameTerminated, false, OutcomeUnusable, 0},
		{ec2types.InstanceStateNameShuttingDown, false, OutcomeUnusable, 0},
		{"", true, OutcomeUnusable, 0},
	}
	for _, c := range cases {
		f := &fakeEC2{state: c.state, none: c.none}
		w, _ := newW(f, 5)
		if got := w.Wake(context.Background(), "t"); got != c.want || f.starts != c.starts {
			t.Errorf("state %q: outcome %s starts %d, want %s %d", c.state, got, f.starts, c.want, c.starts)
		}
		if len(f.lastIDs) != 1 || f.lastIDs[0] != "i-abc" {
			t.Errorf("describe must target only the configured instance, got %v", f.lastIDs)
		}
	}
}

func TestDebounce(t *testing.T) {
	f := &fakeEC2{state: ec2types.InstanceStateNameStopped}
	w, c := newW(f, 5)
	if w.Wake(context.Background(), "a") != OutcomeStarted {
		t.Fatal("first must start")
	}
	f.state = ec2types.InstanceStateNameStopped // even if it still looks stopped
	c.t = c.t.Add(30 * time.Second)
	if w.Wake(context.Background(), "b") != OutcomeDebounced || f.descs != 1 || f.starts != 1 {
		t.Fatalf("within 60s must be debounced without calls: descs=%d starts=%d", f.descs, f.starts)
	}
	c.t = c.t.Add(31 * time.Second)
	if w.Wake(context.Background(), "c") != OutcomeStarted || f.starts != 2 {
		t.Fatal("after 60s it must act again")
	}
}

func TestHourlyLimit(t *testing.T) {
	f := &fakeEC2{state: ec2types.InstanceStateNameStopped}
	w, c := newW(f, 2)
	for i := 0; i < 2; i++ {
		if w.Wake(context.Background(), "x") != OutcomeStarted {
			t.Fatalf("start %d", i)
		}
		f.state = ec2types.InstanceStateNameStopped
		c.t = c.t.Add(2 * time.Minute)
	}
	if got := w.Wake(context.Background(), "x"); got != OutcomeRateLimited || f.starts != 2 {
		t.Fatalf("third must be limited, got %s starts=%d", got, f.starts)
	}
	c.t = c.t.Add(58 * time.Minute) // the first start is now older than 1 h
	if w.Wake(context.Background(), "x") != OutcomeStarted || f.starts != 3 {
		t.Fatal("window must roll")
	}
}

func TestSDKErrors(t *testing.T) {
	f := &fakeEC2{descErr: errors.New("AccessDenied")}
	w, c := newW(f, 5)
	if w.Wake(context.Background(), "x") != OutcomeError || f.starts != 0 {
		t.Fatal("describe error")
	}
	c.t = c.t.Add(time.Second) // errors are not debounced: retry right away
	f.descErr = nil
	f.state = ec2types.InstanceStateNameStopped
	f.startErr = errors.New("InsufficientInstanceCapacity")
	if w.Wake(context.Background(), "x") != OutcomeError || f.starts != 1 {
		t.Fatal("start error")
	}
	f.startErr = nil
	if w.Wake(context.Background(), "x") != OutcomeStarted {
		t.Fatal("a failed start must not consume the hourly budget nor debounce")
	}
}

type repos map[uuid.UUID]bool

func (r repos) HasRepo(_ context.Context, id uuid.UUID) (bool, error) { return r[id], nil }

func TestHandleFiltersEvents(t *testing.T) {
	f := &fakeEC2{state: ec2types.InstanceStateNameStopped}
	with, without := uuid.New(), uuid.New()
	w := New(f, Config{InstanceID: "i-abc"}, repos{with: true}, nil)

	for _, name := range []string{gitevents.WorkflowRunCompleted, gitevents.PRMerged, gitevents.DeploymentCreated} {
		_ = w.Handle(context.Background(), gitevents.Event{ProjectID: with, Name: name})
	}
	_ = w.Handle(context.Background(), gitevents.Event{ProjectID: without, Name: gitevents.GitPush})
	_ = w.Handle(context.Background(), gitevents.Event{Name: gitevents.GitPush}) // no project
	if f.descs != 0 {
		t.Fatalf("no EC2 call expected, got %d", f.descs)
	}
	if err := w.Handle(context.Background(), gitevents.Event{ProjectID: with, Name: gitevents.PROpened}); err != nil || f.starts != 1 {
		t.Fatalf("pr.opened of a repo project must start: err=%v starts=%d", err, f.starts)
	}
	s := w.Stats()
	if s.Ignored != 5 || s.Started != 1 {
		t.Fatalf("stats %+v", s)
	}
}

func TestHandleAllWakeEvents(t *testing.T) {
	for _, n := range []string{gitevents.GitPush, gitevents.PROpened, gitevents.PRUpdated, gitevents.PRReadyForReview} {
		f := &fakeEC2{state: ec2types.InstanceStateNameStopped}
		w, _ := newW(f, 5)
		if err := w.Handle(context.Background(), ev(n)); err != nil || f.starts != 1 {
			t.Errorf("%s: err=%v starts=%d", n, err, f.starts)
		}
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("CAPSULE_CI_RUNNER_INSTANCE_ID", " i-123 ")
	t.Setenv("CAPSULE_CI_WAKE_MAX_PER_HOUR", "9")
	t.Setenv("CAPSULE_CI_RUNNER_REGION", "us-east-1")
	cfg, region := ConfigFromEnv()
	if cfg.InstanceID != "i-123" || cfg.MaxPerHour != 9 || region != "us-east-1" {
		t.Fatalf("%+v %s", cfg, region)
	}
	t.Setenv("CAPSULE_CI_WAKE_MAX_PER_HOUR", "x")
	if cfg, _ := ConfigFromEnv(); cfg.MaxPerHour != 0 {
		t.Fatal("bad number must fall back to the default")
	}
}
