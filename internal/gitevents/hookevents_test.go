package gitevents_test

import (
	"reflect"
	"testing"

	"github.com/kynto/capsule/backend/internal/forgejo"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

func TestHookEventsMatchProvisioning(t *testing.T) {
	if !reflect.DeepEqual(forgejo.HookEvents, gitevents.ForgejoHookEvents) {
		t.Fatalf("forgejo.HookEvents %v != gitevents.ForgejoHookEvents %v", forgejo.HookEvents, gitevents.ForgejoHookEvents)
	}
}
