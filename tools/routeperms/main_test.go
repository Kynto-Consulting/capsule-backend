package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// skipUnderRace is set by race_test.go: the extractor is single-threaded, so the race detector adds minutes
// and nothing else; `go test ./...` and `make routes-check` run it without -race.
var skipUnderRace bool

// The checked-in golden file must equal what the extractor produces from the current router.
func TestGoldenIsFresh(t *testing.T) {
	if testing.Short() {
		t.Skip("type-checks the whole server; skipped with -short")
	}
	if skipUnderRace {
		t.Skip("single-threaded type-check: run without -race (make routes-check)")
	}
	rows, err := Extract("../..")
	if err != nil {
		t.Fatal(err)
	}
	got := Render(rows)
	want, err := os.ReadFile("../../" + goldenRel)
	if err != nil {
		t.Fatalf("golden file missing: %v (run `make routes-gen`)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("routes_authz.golden is stale: run `make routes-gen` and review the diff")
	}
	// coverage of the shapes the router uses
	if len(rows) < 300 {
		t.Fatalf("only %d routes extracted", len(rows))
	}
	seen := map[string]bool{}
	for _, r := range rows {
		k := r.Method + " " + r.Path
		if seen[k] {
			t.Errorf("duplicate row %s", k)
		}
		seen[k] = true
		if r.Class == "" {
			t.Errorf("%s has no class", k)
		}
		if (r.Class == "action") != (len(r.Actions) > 0) {
			t.Errorf("%s: class %s with actions %v", k, r.Class, r.Actions)
		}
	}
}

func TestApplyClassesFailsClosed(t *testing.T) {
	// a route with neither an action nor a class is an error
	if _, err := applyClasses([]Row{{Method: "GET", Path: "/api/v1/new", Handler: "handlers.New.Handler"}}); err == nil ||
		!strings.Contains(err.Error(), "no old action found and no class") {
		t.Fatalf("unclassified route accepted: %v", err)
	}
	// a handler that checks an authz action cannot be classified as something else
	rows := []Row{{Method: "GET", Path: "/x", Handler: "handlers.AdminHandler.ListUsers", Actions: []string{"project.read"}, Class: "action"}}
	if _, err := applyClasses(rows); err == nil {
		t.Fatal("class that hides an authz action accepted")
	}
}
