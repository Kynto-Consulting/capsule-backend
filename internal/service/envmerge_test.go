package service

import (
	"reflect"
	"testing"
)

func TestEnvPrecedenceDeployOverProjectOverOrg(t *testing.T) {
	org := map[string]EnvEntry{
		"A": {"org-a", "runtime"},
		"B": {"org-b", "both"},
		"C": {"org-c", "runtime"},
		"D": {"org-d", "runtime"},
	}
	proj := map[string]EnvEntry{
		"B": {"proj-b", "runtime"},
		"C": {"proj-c", "build"}, // project redefines scope: no longer a runtime var
		"E": {"proj-e", "both"},
	}
	deploy := map[string]EnvEntry{
		"E": {"deploy-e", "both"},
		"F": {"deploy-f", "both"},
	}
	merged := MergeEnvLayers(org, proj, deploy)

	got := FilterEnvByScope(merged, "runtime")
	want := []KV{{"A", "org-a"}, {"B", "proj-b"}, {"D", "org-d"}, {"E", "deploy-e"}, {"F", "deploy-f"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runtime env mismatch\n got: %v\nwant: %v", got, want)
	}

	build := FilterEnvByScope(merged, "build")
	wantBuild := []KV{{"C", "proj-c"}, {"E", "deploy-e"}, {"F", "deploy-f"}}
	if !reflect.DeepEqual(build, wantBuild) {
		t.Fatalf("build env mismatch\n got: %v\nwant: %v", build, wantBuild)
	}
}

func TestMergeEnvLayersNilSafe(t *testing.T) {
	if got := MergeEnvLayers(nil, nil, nil); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}
