package security

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGlobMatching(t *testing.T) {
	cases := []struct {
		glob, path string
		want       bool
	}{
		{"src/legacy/**", "src/legacy/a/b.go", true},
		{"src/legacy/**", "src/other/a.go", false},
		{"src/*.go", "src/a.go", true},
		{"src/*.go", "src/sub/a.go", false},
		{"**/*.test.ts", "a/b/c.test.ts", true},
		{"**/*.test.ts", "c.test.ts", true},
		{"**/vendor/**", "x/vendor/y/z.go", true},
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"file?.go", "file1.go", true},
		{"file?.go", "file12.go", false},
		{"a.b", "aXb", false}, // the dot is literal
		{"x+(y)", "x+(y)", true},
	}
	for _, c := range cases {
		re, err := globToRegexp(c.glob)
		if err != nil {
			t.Fatalf("%s: %v", c.glob, err)
		}
		if got := re.MatchString(c.path); got != c.want {
			t.Errorf("%q vs %q = %v, want %v", c.glob, c.path, got, c.want)
		}
	}
	for _, g := range []string{"**", "*", "**/*", "/**", "**/**", " ** ", "*/*", "///"} {
		if !globMatchesEverything(g) {
			t.Errorf("%q must count as match-everything", g)
		}
	}
	for _, g := range []string{"src/**", "*.go", "a", "**/x"} {
		if globMatchesEverything(g) {
			t.Errorf("%q is a bounded glob", g)
		}
	}
}

func TestReconcilePureCycle(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pid := uuid.New()
	f := func(fp string, sev Severity) Finding {
		return Finding{Kind: KindCode, Tool: ToolSemgrep, ToolName: ToolSemgrep, RuleID: "r", Severity: sev, Title: "t", Fingerprint: fp, Path: "a.go"}
	}
	in := ReconcileInput{ProjectID: pid, Branch: "main", SHA: "s1", UploadID: uuid.New(), Scope: Scope{ToolSemgrep, ToolSemgrep},
		Findings: []Finding{f("a", SevHigh), f("b", SevLow), f("a", SevHigh)}, Now: now}
	p1 := Reconcile(in)
	if len(p1.Insert) != 2 || len(p1.Created) != 2 || p1.Fixed != 0 || len(p1.Update) != 0 {
		t.Fatalf("first run: %+v", p1)
	}
	existing := p1.Insert
	// b disappears, a changes severity
	in2 := in
	in2.SHA, in2.Existing, in2.Findings = "s2", existing, []Finding{f("a", SevCritical)}
	p2 := Reconcile(in2)
	if p2.Fixed != 1 || len(p2.Created) != 0 || len(p2.Insert) != 0 {
		t.Fatalf("second run: %+v", p2)
	}
	var sawA, sawB bool
	for _, a := range p2.Update {
		switch a.Fingerprint {
		case "a":
			sawA = a.Severity == SevCritical && a.LastSeenSHA == "s2" && a.FirstSeenSHA == "s1" && a.State == StateOpen
		case "b":
			sawB = a.State == StateFixed && a.FixedAt != nil
		}
	}
	if !sawA || !sawB {
		t.Fatalf("updates: %+v", p2.Update)
	}
	// a dismissed alert that is still found stays dismissed and is not "created" again
	dismissed := p2.Update[0]
	dismissed.State = StateDismissed
	dismissed.Dismissal = &Dismissal{Reason: ReasonWontFix, ExpiresAt: now.Add(time.Hour)}
	in3 := in
	in3.Existing, in3.Findings = []Alert{dismissed}, []Finding{f(dismissed.Fingerprint, SevHigh)}
	p3 := Reconcile(in3)
	if len(p3.Created) != 0 || p3.Update[0].State != StateDismissed {
		t.Fatalf("dismissed: %+v", p3)
	}
	// ... and one whose dismissal expired is reopened
	in3.Now = now.Add(2 * time.Hour)
	p4 := Reconcile(in3)
	if len(p4.Created) != 1 || p4.Update[0].State != StateOpen || p4.Update[0].Dismissal != nil {
		t.Fatalf("expired dismissal: %+v", p4)
	}
	// an absent dismissed alert is neither fixed nor touched
	in5 := in
	in5.Existing, in5.Findings = []Alert{dismissed}, nil
	if p5 := Reconcile(in5); p5.Fixed != 0 || len(p5.Update) != 0 {
		t.Fatalf("absent dismissed: %+v", p5)
	}
}

func TestSuppressionSetSkipsInactive(t *testing.T) {
	now := time.Now()
	mk := func(state string, exp time.Time, m SuppressionMatch, high bool) Suppression {
		return Suppression{ID: uuid.New(), State: state, ExpiresAt: exp, Match: m, CoversHigh: high}
	}
	set := NewSuppressionSet([]Suppression{
		mk(SuppActive, now.Add(time.Hour), SuppressionMatch{RuleID: "live"}, false),
		mk(SuppExpired, now.Add(time.Hour), SuppressionMatch{RuleID: "expired-state"}, false),
		mk(SuppActive, now.Add(-time.Hour), SuppressionMatch{RuleID: "past"}, false),
		mk(SuppRevoked, now.Add(time.Hour), SuppressionMatch{RuleID: "revoked"}, false),
		mk(SuppActive, now.Add(time.Hour), SuppressionMatch{RuleID: "both", PathGlob: "src/**"}, true),
	}, now)
	hit := func(rule, path string, sev Severity) bool {
		return set.MatchAlert(&Alert{RuleID: rule, Path: path, Severity: sev}) != nil
	}
	if !hit("live", "x", SevMedium) || hit("expired-state", "x", SevLow) || hit("past", "x", SevLow) || hit("revoked", "x", SevLow) {
		t.Fatal("state/expiry filtering")
	}
	if hit("live", "x", SevHigh) {
		t.Fatal("a suppression without CoversHigh covered a high alert")
	}
	if !hit("both", "src/a/b.go", SevCritical) || hit("both", "lib/a.go", SevCritical) {
		t.Fatal("AND semantics of rule + path glob")
	}
}
