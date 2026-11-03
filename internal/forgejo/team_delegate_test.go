package forgejo

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestSyncProjectRunsTheDelegateWhenSet(t *testing.T) {
	t.Cleanup(func() { SetTeamSyncDelegate(nil) })
	c := &Core{Client: NewClient(Config{URL: "http://127.0.0.1:1", Token: "t"})}
	if !c.Enabled() {
		t.Fatal("core should be enabled")
	}
	id := uuid.New()
	var got uuid.UUID
	calls := 0
	SetTeamSyncDelegate(func(_ context.Context, p uuid.UUID) error { calls++; got = p; return nil })
	if err := c.SyncProject(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || got != id {
		t.Fatalf("delegate calls=%d project=%s", calls, got)
	}
	// a disabled core never calls it
	off := &Core{Client: NewClient(Config{})}
	if err := off.SyncProject(context.Background(), id); err != nil || calls != 1 {
		t.Fatalf("disabled core: %v calls=%d", err, calls)
	}
}
