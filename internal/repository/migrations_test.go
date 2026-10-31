package repository

import (
	"fmt"
	"testing"
)

// Migrations are embedded from this package's migrations/ directory only.
// This guards against files added elsewhere or versions skipped.
func TestMigrationsAreContiguousAndPaired(t *testing.T) {
	entries, err := MigrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	up := map[int]bool{}
	down := map[int]bool{}
	for _, e := range entries {
		var v int
		var name string
		if _, err := fmt.Sscanf(e.Name(), "%06d_%s", &v, &name); err != nil {
			t.Fatalf("bad migration name %q", e.Name())
		}
		switch {
		case len(name) > 7 && name[len(name)-7:] == ".up.sql":
			up[v] = true
		case len(name) > 9 && name[len(name)-9:] == ".down.sql":
			down[v] = true
		default:
			t.Fatalf("migration %q must end in .up.sql or .down.sql", e.Name())
		}
	}
	for v := 1; v <= len(up); v++ {
		if !up[v] || !down[v] {
			t.Errorf("migration %06d missing its up/down pair or version is skipped", v)
		}
	}
}
