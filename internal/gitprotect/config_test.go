package gitprotect

import (
	"reflect"
	"testing"
	"time"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("GITPROTECT_RECONCILE_MINUTES", "")
	t.Setenv("GITPROTECT_PRUNE_UNMANAGED", "")
	t.Setenv("GITPROTECT_TAG_PATTERNS", "")
	c := ConfigFromEnv()
	if c.ReconcileEvery != 10*time.Minute || c.PruneUnmanaged || !reflect.DeepEqual(c.TagPatterns, []string{"v*"}) {
		t.Fatalf("defaults: %+v", c)
	}
	t.Setenv("GITPROTECT_RECONCILE_MINUTES", "0")
	t.Setenv("GITPROTECT_PRUNE_UNMANAGED", "TRUE")
	t.Setenv("GITPROTECT_TAG_PATTERNS", " v*, release-* ,")
	c = ConfigFromEnv()
	if c.ReconcileEvery != 0 || !c.PruneUnmanaged || !reflect.DeepEqual(c.TagPatterns, []string{"v*", "release-*"}) {
		t.Fatalf("custom: %+v", c)
	}
	t.Setenv("GITPROTECT_TAG_PATTERNS", "-")
	t.Setenv("GITPROTECT_RECONCILE_MINUTES", "junk")
	c = ConfigFromEnv()
	if len(c.TagPatterns) != 0 || c.ReconcileEvery != 10*time.Minute {
		t.Fatalf("disabled tags / bad minutes: %+v", c)
	}
}
