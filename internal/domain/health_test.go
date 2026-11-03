package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStatusMatches(t *testing.T) {
	cases := []struct {
		spec string
		code int
		want bool
	}{
		{"200-399", 200, true}, {"200-399", 302, true}, {"200-399", 404, false}, {"200-399", 500, false},
		{"200", 200, true}, {"200", 201, false}, {"200,204", 204, true}, {"200,204,301-302", 302, true},
		{"200,204,301-302", 303, false}, {"garbage", 200, true}, {"garbage", 500, false},
	}
	for _, c := range cases {
		if got := StatusMatches(c.spec, c.code); got != c.want {
			t.Errorf("%q %d: got %v", c.spec, c.code, got)
		}
	}
}

func TestValidateHealthPath(t *testing.T) {
	for _, ok := range []string{"", "/", "/healthz", "/api/v1/health?deep=1"} {
		if err := ValidateHealthPath(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"healthz", "http://x/y", "https://x", "//x/y", "/a b", "/a\tb", "/x#f", "/a\b", "/" + strings.Repeat("a", MaxHealthPathLen)} {
		if err := ValidateHealthPath(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestValidateTimeoutAndStatusSpec(t *testing.T) {
	for _, s := range []int{5, 60, 600} {
		if ValidateHealthTimeout(s) != nil {
			t.Errorf("%d should be valid", s)
		}
	}
	for _, s := range []int{-1, 0, 4, 601} {
		if ValidateHealthTimeout(s) == nil {
			t.Errorf("%d should be invalid", s)
		}
	}
	if ValidateExpectedStatus("200-399") != nil || ValidateExpectedStatus("x") == nil {
		t.Fatal("expected status validation")
	}
}

// The exact JSON other pieces consume.
func TestDeploymentHealthJSON(t *testing.T) {
	ts := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	d := Deployment{Health: &DeploymentHealth{Status: HealthHealthy, Path: "/healthz", LastCheck: &ts, Detail: "HTTP 200"}}
	b, _ := json.Marshal(d)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	if string(m["health"]) != `{"status":"healthy","path":"/healthz","last_check":"2026-11-02T10:00:00Z","detail":"HTTP 200"}` {
		t.Fatalf("health JSON: %s", m["health"])
	}
	b, _ = json.Marshal(Deployment{})
	if strings.Contains(string(b), `"health"`) || strings.Contains(string(b), "error_message") {
		t.Fatalf("health must be omitted when not applicable: %s", b)
	}
}
