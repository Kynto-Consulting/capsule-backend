package security

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

func fieldsOf(t *testing.T, err error) map[string]bool {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %v", err)
	}
	m := map[string]bool{}
	for _, f := range ve.Fields {
		m[f.Field] = true
	}
	return m
}

func ctx() context.Context { return context.Background() }

// ---- upload and the open -> fixed cycle ------------------------------------------------------

func TestUploadCreatesAlertsAndFixesThemWhenGone(t *testing.T) {
	r := newRig(t)
	two := miniSarif("semgrep", mini{"rule.a", "a.go", "x := 1", "error"}, mini{"rule.b", "b.go", "y := 2", "warning"})
	u := r.upload(shaA, "refs/heads/main", two, adminActor)
	if u.AlertsCreated != 2 || u.AlertsFixed != 0 {
		t.Fatalf("first upload: %+v", u)
	}
	open := r.alerts(AlertQuery{State: "open"})
	if len(open) != 2 {
		t.Fatalf("open = %d", len(open))
	}
	sev := map[string]Severity{}
	for _, a := range open {
		sev[a.RuleID] = a.Severity
		if a.Branch != "main" || a.FirstSeenSHA != shaA || a.LastSeenSHA != shaA {
			t.Errorf("alert location: %+v", a)
		}
	}
	if sev["rule.a"] != SevHigh || sev["rule.b"] != SevMedium {
		t.Fatalf("severities = %v", sev)
	}
	if n := len(r.pub.named(gitevents.SecurityAlertCreated)); n != 2 {
		t.Fatalf("created events = %d", n)
	}

	// same findings again: nothing new, nothing fixed, last_seen moves
	u = r.upload(shaB, "refs/heads/main", two, adminActor)
	if u.AlertsCreated != 0 || u.AlertsFixed != 0 {
		t.Fatalf("repeat upload: %+v", u)
	}
	for _, a := range r.alerts(AlertQuery{State: "open"}) {
		if a.FirstSeenSHA != shaA || a.LastSeenSHA != shaB {
			t.Errorf("dedup lost history: %+v", a)
		}
	}

	// one gone: fixed
	one := miniSarif("semgrep", mini{"rule.a", "a.go", "x := 1", "error"})
	u = r.upload(shaC, "refs/heads/main", one, adminActor)
	if u.AlertsFixed != 1 {
		t.Fatalf("fixed = %d", u.AlertsFixed)
	}
	fixed := r.alerts(AlertQuery{State: "fixed"})
	if len(fixed) != 1 || fixed[0].RuleID != "rule.b" || fixed[0].FixedAt == nil {
		t.Fatalf("fixed alerts: %+v", fixed)
	}

	// it comes back: reopened (counts as created again)
	u = r.upload(shaC, "refs/heads/main", two, adminActor)
	if u.AlertsCreated != 1 {
		t.Fatalf("reappearing alert: %+v", u)
	}
	if got := r.alerts(AlertQuery{State: "open"}); len(got) != 2 {
		t.Fatalf("open after reappearing = %d", len(got))
	}

	// an empty run of the same tool fixes everything
	empty := miniSarif("semgrep")
	if u = r.upload(shaA, "refs/heads/main", empty, adminActor); u.AlertsFixed != 2 {
		t.Fatalf("empty run fixed = %d", u.AlertsFixed)
	}
}

func TestFixedCycleIsPerToolAndPerBranch(t *testing.T) {
	r := newRig(t)
	r.upload(shaA, "refs/heads/main", miniSarif("semgrep", mini{"s.rule", "a.go", "a", "error"}), adminActor)
	r.upload(shaA, "refs/heads/main", miniSarif("gosec", mini{"G101x", "a.go", "b", "error"}), adminActor)
	r.upload(shaA, "refs/heads/feature", miniSarif("semgrep", mini{"s.rule", "a.go", "a", "error"}), adminActor)
	// an empty semgrep run on main fixes only main's semgrep alert
	r.upload(shaB, "refs/heads/main", miniSarif("semgrep"), adminActor)
	for _, a := range r.alerts(AlertQuery{}) {
		wantOpen := !(a.Tool == "semgrep" && a.Branch == "main")
		if (a.State == StateOpen) != wantOpen {
			t.Errorf("%s/%s on %s is %s", a.Tool, a.RuleID, a.Branch, a.State)
		}
	}
}

func TestPullRefsAndBranchNormalization(t *testing.T) {
	for in, want := range map[string]struct {
		branch string
		pr     int
	}{
		"refs/heads/main": {"main", 0}, "main": {"main", 0}, "refs/pull/12/head": {"pull/12", 12},
		"refs/pull/7/merge": {"pull/7", 7}, "refs/tags/v1": {"tag/v1", 0}, "refs/heads/feat/x": {"feat/x", 0},
	} {
		b, pr, err := NormalizeRef(in)
		if err != nil || b != want.branch || pr != want.pr {
			t.Errorf("%s -> %q %d %v", in, b, pr, err)
		}
	}
	for _, bad := range []string{"", "refs/remotes/x", "refs/heads/", "a b", "x/../y", strings.Repeat("a", 300)} {
		if _, _, err := NormalizeRef(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestUploadValidationIdempotencyAndRateLimit(t *testing.T) {
	r := newRig(t)
	good := miniSarif("semgrep", mini{"r", "a.go", "x", "error"})
	_, err := r.svc.Upload(ctx(), r.tgt, adminActor, UploadInput{CommitSHA: "xyz", Ref: "", Sarif: good, ToolName: "bad\nname", PR: -1, IdempotencyKey: "has space"})
	f := fieldsOf(t, err)
	for _, want := range []string{"commit_sha", "ref", "tool_name", "pr", "Idempotency-Key"} {
		if !f[want] {
			t.Errorf("missing field error %s in %v", want, f)
		}
	}
	// SARIF errors surface as *SarifError
	_, err = r.svc.Upload(ctx(), r.tgt, adminActor, UploadInput{CommitSHA: shaA, Ref: "main", Sarif: "{}"})
	var se *SarifError
	if !errors.As(err, &se) || se.Code != "SARIF_INVALID" {
		t.Fatalf("err = %v", err)
	}
	// idempotency: the same key returns the first upload and queues nothing new
	u1, err := r.svc.Upload(ctx(), r.tgt, adminActor, UploadInput{CommitSHA: shaA, Ref: "main", Sarif: good, IdempotencyKey: "k-1"})
	if err != nil {
		t.Fatal(err)
	}
	u2, err := r.svc.Upload(ctx(), r.tgt, adminActor, UploadInput{CommitSHA: shaB, Ref: "main", Sarif: good, IdempotencyKey: "k-1"})
	if err != nil || u2.ID != u1.ID {
		t.Fatalf("idempotent upload: %v %v", u2, err)
	}
	if len(r.store.Uploads) != 1 {
		t.Fatalf("uploads stored = %d", len(r.store.Uploads))
	}
	// rate limit per project
	r.svc.cfg.UploadsPerMinute = 3
	var limited bool
	for i := 0; i < 6; i++ {
		if _, err := r.svc.Upload(ctx(), r.tgt, adminActor, UploadInput{CommitSHA: shaA, Ref: "main", Sarif: good}); errors.Is(err, ErrRateLimit) {
			limited = true
		}
	}
	if !limited {
		t.Fatal("no rate limit")
	}
	r.advance(2 * time.Minute)
	if _, err := r.svc.Upload(ctx(), r.tgt, adminActor, UploadInput{CommitSHA: shaA, Ref: "main", Sarif: good}); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

func TestStaleUploadIsSuperseded(t *testing.T) {
	r := newRig(t)
	old := miniSarif("semgrep", mini{"old.rule", "a.go", "o", "error"})
	newer := miniSarif("semgrep", mini{"new.rule", "a.go", "n", "error"})
	u1, _ := r.svc.Upload(ctx(), r.tgt, adminActor, UploadInput{CommitSHA: shaA, Ref: "main", Sarif: old})
	r.advance(time.Second)
	u2, _ := r.svc.Upload(ctx(), r.tgt, adminActor, UploadInput{CommitSHA: shaB, Ref: "main", Sarif: newer})
	// the newer one is processed first (workers race): process it explicitly, then the old one
	claimed, _ := r.store.ClaimUploads(ctx(), 10, time.Minute, *r.clock)
	for _, want := range []uuid.UUID{u2.ID, u1.ID} {
		for _, cu := range claimed {
			if cu.ID == want {
				r.svc.processOne(ctx(), cu)
			}
		}
	}
	got1, _ := r.svc.UploadStatus(ctx(), r.tgt.ProjectID, u1.ID)
	if !got1.Superseded {
		t.Fatal("the older upload processed last must be superseded, not applied over the newer one")
	}
	open := r.alerts(AlertQuery{State: "open"})
	if len(open) != 1 || open[0].RuleID != "new.rule" {
		t.Fatalf("open = %+v: the stale upload changed the state", open)
	}
}

func TestSimultaneousUploadsOfTheSameTool(t *testing.T) {
	r := newRig(t)
	same := miniSarif("semgrep", mini{"r1", "a.go", "1", "error"}, mini{"r2", "b.go", "2", "error"})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.svc.Upload(ctx(), r.tgt, adminActor, UploadInput{CommitSHA: shaA, Ref: "main", Sarif: same}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var pw sync.WaitGroup
	for i := 0; i < 4; i++ {
		pw.Add(1)
		go func() {
			defer pw.Done()
			for {
				n, err := r.svc.ProcessPending(ctx(), 1)
				if err != nil {
					t.Error(err)
					return
				}
				if n == 0 {
					return
				}
			}
		}()
	}
	pw.Wait()
	if open := r.alerts(AlertQuery{State: "open"}); len(open) != 2 {
		t.Fatalf("open = %d, want exactly 2 alerts (no duplicates from racing uploads)", len(open))
	}
}

func TestFailedUploadRetriesThenFails(t *testing.T) {
	r := newRig(t)
	u, _ := r.svc.Upload(ctx(), r.tgt, adminActor, UploadInput{CommitSHA: shaA, Ref: "main", Sarif: miniSarif("semgrep", mini{"r", "a.go", "x", "error"})})
	r.store.FailApplyN = 100
	for i := 0; i < maxUploadAttempts; i++ {
		r.advance(time.Second)
		if n, _ := r.svc.ProcessPending(ctx(), 5); n != 1 {
			t.Fatalf("attempt %d handled %d", i+1, n)
		}
	}
	got, _ := r.svc.UploadStatus(ctx(), r.tgt.ProjectID, u.ID)
	if got.Status != UploadFailed || got.Error == "" {
		t.Fatalf("after %d failures: %+v", maxUploadAttempts, got)
	}
	if n, _ := r.svc.ProcessPending(ctx(), 5); n != 0 {
		t.Fatal("a failed upload must not be claimed again")
	}
}

// ---- the value of a secret never persists ----------------------------------------------------

func TestSecretValueNeverPersistedReturnedOrPublished(t *testing.T) {
	r := newRig(t)
	r.forge.pulls = []gitcore.Pull{{Number: 1, Base: "main", Head: "feat", HeadSHA: shaA}}
	_, _ = r.svc.PutPolicy(ctx(), r.tgt, adminActor, DefaultPolicy())
	u := r.upload(shaA, "refs/heads/feat", fixtureBytes(t, "gitleaks.sarif"), adminActor)
	if u.AlertsCreated != 3 {
		t.Fatalf("created = %d", u.AlertsCreated)
	}
	// dismiss one and create a suppression so audit and dismissal rows exist as well
	al := r.alerts(AlertQuery{Kind: "secret"})
	if len(al) != 3 {
		t.Fatalf("secret alerts = %d", len(al))
	}
	if _, err := r.svc.Dismiss(ctx(), r.tgt, adminActor, al[0].ID, DismissInput{Reason: ReasonFalsePositive, Justification: "fixture value in a test file", ExpiresAt: r.clock.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// everything the package keeps or emits, serialized
	var dump strings.Builder
	enc := func(v any) { b, _ := json.Marshal(v); dump.Write(b); dump.WriteByte('\n') }
	r.store.mu.Lock()
	enc(r.store.Alerts)
	enc(r.store.Supps)
	enc(r.store.Uploads)
	enc(r.store.Payloads)
	enc(r.store.Audits)
	enc(r.store.Checks)
	r.store.mu.Unlock()
	enc(r.pub.events)
	enc(r.forge.checks)
	items, _, _ := r.svc.ListAlerts(ctx(), r.tgt.ProjectID, AlertQuery{IncludeSecrets: true, Limit: 100})
	enc(items)
	got, _ := r.svc.GetAlert(ctx(), r.tgt.ProjectID, al[1].ID)
	enc(got)
	for ph, v := range fakeSecrets {
		if strings.Contains(dump.String(), v) {
			t.Fatalf("the value %s... of a detected secret was found in stored/returned/published data", v[:6])
		}
		if strings.Contains(dump.String(), ph) {
			t.Fatal("placeholder leaked")
		}
	}
	// what IS kept: rule, path and line
	for _, a := range items {
		if a.Kind != KindSecret || a.RuleID == "" || a.Path == "" || a.StartLine == 0 || a.Evidence != "" {
			t.Errorf("secret alert shape: %+v", a)
		}
	}
}

// ---- dismissals and suppressions -------------------------------------------------------------

func openAlert(t *testing.T, r *rig, sev string) Alert {
	t.Helper()
	lvl := map[string]string{"high": "error", "medium": "warning", "low": "note"}[sev]
	r.upload(shaA, "refs/heads/main", miniSarif("semgrep", mini{"rule." + sev, "src/" + sev + ".go", sev, lvl}), adminActor)
	for _, a := range r.alerts(AlertQuery{State: "open"}) {
		if a.RuleID == "rule."+sev {
			return a
		}
	}
	t.Fatal("alert not found")
	return Alert{}
}

func TestDismissRules(t *testing.T) {
	r := newRig(t)
	med := openAlert(t, r, "medium")
	exp := r.clock.Add(30 * 24 * time.Hour)
	good := DismissInput{Reason: ReasonWontFix, Justification: "accepted by the product owner", ExpiresAt: exp}

	bad := func(in DismissInput, want ...string) {
		t.Helper()
		_, err := r.svc.Dismiss(ctx(), r.tgt, triageActor, med.ID, in)
		f := fieldsOf(t, err)
		for _, w := range want {
			if !f[w] {
				t.Errorf("%+v: missing field error %q in %v", in, w, f)
			}
		}
	}
	bad(DismissInput{Reason: "other", Justification: good.Justification, ExpiresAt: exp}, "reason")
	bad(DismissInput{Reason: ReasonWontFix, Justification: "short", ExpiresAt: exp}, "justification")
	bad(DismissInput{Reason: ReasonWontFix, Justification: "         x         ", ExpiresAt: exp}, "justification")
	bad(DismissInput{Reason: ReasonWontFix, Justification: good.Justification}, "expires_at")
	bad(DismissInput{Reason: ReasonWontFix, Justification: good.Justification, ExpiresAt: r.clock.Add(-time.Hour)}, "expires_at")
	bad(DismissInput{Reason: ReasonWontFix, Justification: good.Justification, ExpiresAt: r.clock.Add(400 * 24 * time.Hour)}, "expires_at")
	bad(DismissInput{}, "reason", "justification", "expires_at")
	// exactly 365 days is the limit for medium
	if _, err := r.svc.Dismiss(ctx(), r.tgt, triageActor, med.ID, DismissInput{Reason: ReasonWontFix, Justification: good.Justification, ExpiresAt: r.clock.Add(364 * 24 * time.Hour)}); err == nil {
		t.Fatal("the default policy limit is 180 days: 364 must be refused")
	}
	if _, err := r.svc.PutPolicy(ctx(), r.tgt, adminActor, Policy{
		BlockMergeOn: BlockMerge{"high", "high", "any"}, BlockDeployOn: "critical", MaxSuppressionDays: 365,
	}); err != nil {
		t.Fatal(err)
	}
	a, err := r.svc.Dismiss(ctx(), r.tgt, triageActor, med.ID, DismissInput{Reason: ReasonWontFix, Justification: good.Justification, ExpiresAt: r.clock.Add(364 * 24 * time.Hour)})
	if err != nil || a.State != StateDismissed || a.Dismissal == nil || a.Dismissal.Reason != ReasonWontFix {
		t.Fatalf("dismiss: %+v %v", a, err)
	}
	// not open any more
	_, err = r.svc.Dismiss(ctx(), r.tgt, triageActor, med.ID, good)
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("dismissing twice: %v", err)
	}
	if len(r.pub.named(gitevents.SecurityAlertDismiss)) != 1 {
		t.Fatal("dismiss event missing")
	}
	if !auditHas(r.store, AuditAlertDismiss) {
		t.Fatal("dismissal is not audited")
	}
}

func auditHas(s *MemStore, action string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.Audits {
		if a.Action == action {
			return true
		}
	}
	return false
}

func TestDismissHighNeedsAdminAnd180Days(t *testing.T) {
	r := newRig(t)
	hi := openAlert(t, r, "high")
	in := DismissInput{Reason: ReasonRiskAccepted, Justification: "risk accepted until the vendor ships", ExpiresAt: r.clock.Add(90 * 24 * time.Hour)}
	_, err := r.svc.Dismiss(ctx(), r.tgt, triageActor, hi.ID, in)
	var fe *ForbiddenError
	if !errors.As(err, &fe) || fe.Code != "ADMIN_REQUIRED" {
		t.Fatalf("triage dismissing a high alert: %v", err)
	}
	// admin: 181 days refused (critical/high are capped at 180), 180 allowed
	in.ExpiresAt = r.clock.Add(181 * 24 * time.Hour)
	if _, err := r.svc.Dismiss(ctx(), r.tgt, adminActor, hi.ID, in); !fieldsOf(t, err)["expires_at"] {
		t.Fatal("181 days must be refused for a high alert")
	}
	_, _ = r.svc.PutPolicy(ctx(), r.tgt, adminActor, Policy{BlockMergeOn: BlockMerge{"high", "high", "any"}, BlockDeployOn: "critical", MaxSuppressionDays: 365})
	if _, err := r.svc.Dismiss(ctx(), r.tgt, adminActor, hi.ID, in); !fieldsOf(t, err)["expires_at"] {
		t.Fatal("a 365 day project policy must not lift the 180 day cap of critical/high")
	}
	in.ExpiresAt = r.clock.Add(179 * 24 * time.Hour)
	if _, err := r.svc.Dismiss(ctx(), r.tgt, adminActor, hi.ID, in); err != nil {
		t.Fatal(err)
	}
}

func TestDismissAppliesToTheSameFingerprintOnOtherBranches(t *testing.T) {
	r := newRig(t)
	s := miniSarif("semgrep", mini{"r.med", "a.go", "same code", "warning"})
	r.upload(shaA, "refs/heads/main", s, adminActor)
	r.upload(shaB, "refs/heads/feature", s, adminActor)
	all := r.alerts(AlertQuery{State: "open"})
	if len(all) != 2 {
		t.Fatalf("alerts = %d", len(all))
	}
	if _, err := r.svc.Dismiss(ctx(), r.tgt, triageActor, all[0].ID, DismissInput{Reason: ReasonFalsePositive, Justification: "not reachable from outside", ExpiresAt: r.clock.Add(48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if got := r.alerts(AlertQuery{State: "dismissed"}); len(got) != 2 {
		t.Fatalf("dismissed = %d: the same fingerprint on another branch must be dismissed too", len(got))
	}
	// a later upload on a third branch inherits it
	r.upload(shaC, "refs/heads/third", s, adminActor)
	if got := r.alerts(AlertQuery{State: "dismissed"}); len(got) != 3 {
		t.Fatalf("dismissed after third branch = %d", len(got))
	}
	// reopening one reopens them all and revokes the suppression
	first := r.alerts(AlertQuery{State: "dismissed"})[0]
	if _, err := r.svc.Reopen(ctx(), r.tgt, triageActor, first.ID); err != nil {
		t.Fatal(err)
	}
	if got := r.alerts(AlertQuery{State: "open"}); len(got) != 3 {
		t.Fatalf("open after reopen = %d", len(got))
	}
	sup, _ := r.svc.ListSuppressions(ctx(), r.tgt.ProjectID)
	if len(sup) != 1 || sup[0].State != SuppRevoked {
		t.Fatalf("suppressions after reopen: %+v", sup)
	}
	// reopening an open alert is a conflict
	_, err := r.svc.Reopen(ctx(), r.tgt, triageActor, first.ID)
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("reopen open alert: %v", err)
	}
}

func TestSuppressionValidation(t *testing.T) {
	r := newRig(t)
	exp := r.clock.Add(30 * 24 * time.Hour)
	base := SuppressionInput{Match: SuppressionMatch{RuleID: "rule.x"}, Reason: ReasonUsedInTests, Justification: "only used by the test suite", ExpiresAt: exp}
	mod := func(f func(*SuppressionInput)) SuppressionInput { x := base; f(&x); return x }
	cases := map[string]struct {
		in   SuppressionInput
		want string
	}{
		"no match":            {mod(func(s *SuppressionInput) { s.Match = SuppressionMatch{} }), "match"},
		"glob **":             {mod(func(s *SuppressionInput) { s.Match = SuppressionMatch{PathGlob: "**"} }), "match.path_glob"},
		"glob *":              {mod(func(s *SuppressionInput) { s.Match = SuppressionMatch{PathGlob: "*"} }), "match.path_glob"},
		"glob **/*":           {mod(func(s *SuppressionInput) { s.Match = SuppressionMatch{PathGlob: "**/*"} }), "match.path_glob"},
		"glob /**":            {mod(func(s *SuppressionInput) { s.Match = SuppressionMatch{PathGlob: "/**"} }), "match.path_glob"},
		"glob with rule too":  {mod(func(s *SuppressionInput) { s.Match = SuppressionMatch{RuleID: "r", PathGlob: "**"} }), "match.path_glob"},
		"glob traversal":      {mod(func(s *SuppressionInput) { s.Match = SuppressionMatch{PathGlob: "../**/x"} }), "match.path_glob"},
		"bad fingerprint":     {mod(func(s *SuppressionInput) { s.Match = SuppressionMatch{Fingerprint: "zz"} }), "match.fingerprint"},
		"bad reason":          {mod(func(s *SuppressionInput) { s.Reason = "because" }), "reason"},
		"short justification": {mod(func(s *SuppressionInput) { s.Justification = "too short" }), "justification"},
		"no expiry":           {mod(func(s *SuppressionInput) { s.ExpiresAt = time.Time{} }), "expires_at"},
		"too long":            {mod(func(s *SuppressionInput) { s.ExpiresAt = r.clock.Add(366 * 24 * time.Hour) }), "expires_at"},
	}
	for name, c := range cases {
		_, _, err := r.svc.CreateSuppression(ctx(), r.tgt, adminActor, c.in)
		if !fieldsOf(t, err)[c.want] {
			t.Errorf("%s: expected a field error on %s, got %v", name, c.want, err)
		}
	}
	sp, applied, err := r.svc.CreateSuppression(ctx(), r.tgt, triageActor, mod(func(s *SuppressionInput) { s.Match = SuppressionMatch{PathGlob: "src/legacy/**"} }))
	if err != nil || applied != 0 || sp.State != SuppActive || sp.CoversHigh {
		t.Fatalf("valid suppression: %+v %d %v", sp, applied, err)
	}
}

func TestSuppressionCoveringHighNeedsAdmin(t *testing.T) {
	r := newRig(t)
	hi := openAlert(t, r, "high") // rule.high at src/high.go
	in := SuppressionInput{Match: SuppressionMatch{RuleID: hi.RuleID}, Reason: ReasonRiskAccepted, Justification: "vendor fix scheduled", ExpiresAt: r.clock.Add(60 * 24 * time.Hour)}
	_, _, err := r.svc.CreateSuppression(ctx(), r.tgt, triageActor, in)
	var fe *ForbiddenError
	if !errors.As(err, &fe) {
		t.Fatalf("triage covering a high alert: %v", err)
	}
	in.ExpiresAt = r.clock.Add(200 * 24 * time.Hour)
	if _, _, err := r.svc.CreateSuppression(ctx(), r.tgt, adminActor, in); !fieldsOf(t, err)["expires_at"] {
		t.Fatal("covering a high alert is capped at 180 days")
	}
	in.ExpiresAt = r.clock.Add(100 * 24 * time.Hour)
	sp, applied, err := r.svc.CreateSuppression(ctx(), r.tgt, adminActor, in)
	if err != nil || applied != 1 || !sp.CoversHigh {
		t.Fatalf("admin suppression: %+v applied=%d %v", sp, applied, err)
	}
	if got := r.alerts(AlertQuery{State: "dismissed"}); len(got) != 1 {
		t.Fatalf("dismissed = %d", len(got))
	}
	// a manual (rule) suppression cannot be undone by reopening one alert: it must be revoked
	_, err = r.svc.Reopen(ctx(), r.tgt, triageActor, hi.ID)
	var ce *ConflictError
	if !errors.As(err, &ce) || ce.Code != "SUPPRESSED_BY_RULE" {
		t.Fatalf("reopen under a rule: %v", err)
	}
	if err := r.svc.RevokeSuppression(ctx(), r.tgt, triageActor, sp.ID); err != nil {
		t.Fatal(err)
	}
	if got := r.alerts(AlertQuery{State: "open"}); len(got) != 1 {
		t.Fatalf("open after revoke = %d", len(got))
	}
	if err := r.svc.RevokeSuppression(ctx(), r.tgt, triageActor, sp.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking twice: %v", err)
	}
}

func TestSuppressionNeverHidesLaterCriticalOrHigh(t *testing.T) {
	r := newRig(t)
	// a triage suppression of a rule while only a medium alert exists
	r.upload(shaA, "refs/heads/main", miniSarif("semgrep", mini{"shared.rule", "a.go", "m", "warning"}), adminActor)
	if _, _, err := r.svc.CreateSuppression(ctx(), r.tgt, triageActor, SuppressionInput{
		Match: SuppressionMatch{RuleID: "shared.rule"}, Reason: ReasonWontFix, Justification: "known and accepted", ExpiresAt: r.clock.Add(30 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// later the same rule fires as high elsewhere: the suppression must not cover it
	r.upload(shaB, "refs/heads/main", miniSarif("semgrep",
		mini{"shared.rule", "a.go", "m", "warning"}, mini{"shared.rule", "b.go", "n", "error"}), adminActor)
	open := r.alerts(AlertQuery{State: "open"})
	if len(open) != 1 || open[0].Severity != SevHigh {
		t.Fatalf("open = %+v: a triage suppression hid a high alert", open)
	}
}

func TestSuppressionExpiryReopensAndNotifiesSevenDaysBefore(t *testing.T) {
	r := newRig(t)
	med := openAlert(t, r, "medium")
	if _, err := r.svc.PutPolicy(ctx(), r.tgt, adminActor, Policy{BlockMergeOn: BlockMerge{"high", "high", "any"}, BlockDeployOn: "critical", MaxSuppressionDays: 365}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Dismiss(ctx(), r.tgt, triageActor, med.ID, DismissInput{Reason: ReasonWontFix, Justification: "revisit in a month", ExpiresAt: r.clock.Add(30 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r.svc.Sweep(ctx())
	if n := len(r.pub.named(gitevents.SecuritySuppExpiring)); n != 0 {
		t.Fatalf("notice sent %d days early", 30)
	}
	r.advance(22 * 24 * time.Hour) // 8 days left
	r.svc.Sweep(ctx())
	if n := len(r.pub.named(gitevents.SecuritySuppExpiring)); n != 0 {
		t.Fatal("notice before the 7 day window")
	}
	r.advance(2 * 24 * time.Hour) // 6 days left
	r.svc.Sweep(ctx())
	r.svc.Sweep(ctx()) // idempotent: one notice only
	ev := r.pub.named(gitevents.SecuritySuppExpiring)
	if len(ev) != 1 {
		t.Fatalf("notices = %d, want exactly 1", len(ev))
	}
	if ev[0].Data["days_left"].(int) != 6 {
		t.Errorf("days_left = %v", ev[0].Data["days_left"])
	}
	if got := r.alerts(AlertQuery{State: "dismissed"}); len(got) != 1 {
		t.Fatal("still dismissed before expiry")
	}
	r.advance(7 * 24 * time.Hour) // expired
	r.svc.Sweep(ctx())
	if got := r.alerts(AlertQuery{State: "open"}); len(got) != 1 {
		t.Fatalf("after expiry the alert must be open again, open=%d", len(got))
	}
	sup, _ := r.svc.ListSuppressions(ctx(), r.tgt.ProjectID)
	if len(sup) != 1 || sup[0].State != SuppExpired {
		t.Fatalf("suppression state: %+v", sup)
	}
	// and an upload that still contains it keeps it open instead of re-suppressing
	r.upload(shaB, "refs/heads/main", miniSarif("semgrep", mini{"rule.medium", "src/medium.go", "medium", "warning"}), adminActor)
	if got := r.alerts(AlertQuery{State: "open"}); len(got) != 1 {
		t.Fatalf("open after upload = %d", len(got))
	}
}

func TestExpiredDismissalIsReopenedByTheNextUploadEvenBeforeTheSweep(t *testing.T) {
	r := newRig(t)
	med := openAlert(t, r, "medium")
	if _, err := r.svc.Dismiss(ctx(), r.tgt, triageActor, med.ID, DismissInput{Reason: ReasonWontFix, Justification: "short lived exception", ExpiresAt: r.clock.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r.advance(48 * time.Hour)
	r.upload(shaB, "refs/heads/main", miniSarif("semgrep", mini{"rule.medium", "src/medium.go", "medium", "warning"}), adminActor)
	if got := r.alerts(AlertQuery{State: "open"}); len(got) != 1 {
		t.Fatalf("open = %d", len(got))
	}
}

// ---- policy ----------------------------------------------------------------------------------

func TestPolicyValidationAndDefault(t *testing.T) {
	r := newRig(t)
	p, err := r.svc.GetPolicy(ctx(), r.tgt.ProjectID)
	if err != nil || p.BlockMergeOn.Dependency != "high" || p.BlockMergeOn.Secret != "any" || p.BlockDeployOn != "critical" || p.MaxSuppressionDays != 180 {
		t.Fatalf("default policy: %+v %v", p, err)
	}
	_, err = r.svc.PutPolicy(ctx(), r.tgt, adminActor, Policy{BlockMergeOn: BlockMerge{"urgent", "", "all"}, BlockDeployOn: "medium", MaxSuppressionDays: 400, RequiredTools: []string{"Bad Name"}, AppliesToBranches: []string{"has space"}})
	f := fieldsOf(t, err)
	for _, w := range []string{"block_merge_on.dependency", "block_merge_on.code", "block_merge_on.secret", "block_deploy_on", "max_suppression_days", "required_tools[0]", "applies_to_branches[0]"} {
		if !f[w] {
			t.Errorf("missing %s in %v", w, f)
		}
	}
	in := Policy{BlockMergeOn: BlockMerge{"medium", "off", "off"}, BlockDeployOn: "high", MaxSuppressionDays: 90, RequiredTools: []string{"Semgrep", "semgrep", "gitleaks"}, AppliesToBranches: []string{"main", "release/*"}}
	got, err := r.svc.PutPolicy(ctx(), r.tgt, adminActor, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RequiredTools) != 2 || got.RequiredTools[0] != "semgrep" {
		t.Errorf("required tools not normalized: %v", got.RequiredTools)
	}
	if !auditHas(r.store, AuditPolicyChange) {
		t.Error("policy change not audited")
	}
	b, _ := json.Marshal(got)
	for _, key := range []string{`"block_merge_on"`, `"block_deploy_on"`, `"required_tools"`, `"max_suppression_days"`, `"applies_to_branches"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("policy JSON lacks %s: %s", key, b)
		}
	}
}

func prRef(sha string) PullRef { return PullRef{Number: 5, Base: "main", Head: "feat", HeadSHA: sha} }

func TestCheckOnlyNewAlertsOfThePullRequestBlock(t *testing.T) {
	r := newRig(t)
	debt := mini{"old.rule", "a.go", "old code", "error"}
	// the base branch already has a high alert (debt)
	r.upload(shaA, "refs/heads/main", miniSarif("semgrep", debt), adminActor)
	// the PR branch has the same debt: it does not block
	r.upload(shaB, "refs/heads/feat", miniSarif("semgrep", debt), adminActor)
	run, err := r.svc.EvaluatePull(ctx(), r.tgt, prRef(shaB))
	if err != nil {
		t.Fatal(err)
	}
	if run.State != "success" {
		t.Fatalf("debt blocked the PR: %s %s", run.State, run.Description)
	}
	if c := r.forge.lastCheck(); c.Context != "capsule/security" || c.State != gitcore.CheckSuccess {
		t.Fatalf("published check: %+v", c)
	}
	// a NEW high alert in the PR blocks (new commit)
	r.upload(shaC, "refs/heads/feat", miniSarif("semgrep", debt, mini{"new.rule", "b.go", "new code", "error"}), adminActor)
	run, _ = r.svc.EvaluatePull(ctx(), r.tgt, prRef(shaC))
	if run.State != "failure" || !strings.Contains(run.Description, "new.rule") || !strings.Contains(run.Description, "1 high") {
		t.Fatalf("new alert must block: %s %s", run.State, run.Description)
	}
	if n := len(r.pub.named(gitevents.SecurityPolicyBlock)); n != 1 {
		t.Fatalf("policy block events = %d", n)
	}
	// re-evaluating does not publish the block again
	_, _ = r.svc.EvaluatePull(ctx(), r.tgt, prRef(shaC))
	if n := len(r.pub.named(gitevents.SecurityPolicyBlock)); n != 1 {
		t.Fatalf("policy block event repeated: %d", n)
	}
	// dismissing the new alert unblocks the check (re-evaluated automatically)
	var newAlert Alert
	for _, a := range r.alerts(AlertQuery{State: "open", Branch: "feat"}) {
		if a.RuleID == "new.rule" {
			newAlert = a
		}
	}
	if _, err := r.svc.PutPolicy(ctx(), r.tgt, adminActor, Policy{BlockMergeOn: BlockMerge{"high", "high", "any"}, BlockDeployOn: "critical", MaxSuppressionDays: 365}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Dismiss(ctx(), r.tgt, adminActor, newAlert.ID, DismissInput{Reason: ReasonFalsePositive, Justification: "verified by hand", ExpiresAt: r.clock.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if c := r.forge.lastCheck(); c.State != gitcore.CheckSuccess {
		t.Fatalf("check after dismissal: %+v", c)
	}
}

func TestCheckThresholdsByKind(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.PutPolicy(ctx(), r.tgt, adminActor, Policy{BlockMergeOn: BlockMerge{"critical", "low", "off"}, BlockDeployOn: "off", MaxSuppressionDays: 180}); err != nil {
		t.Fatal(err)
	}
	// code: a low alert blocks (threshold low); dependency high does not (threshold critical); secret off
	r.upload(shaB, "refs/heads/feat", miniSarif("semgrep", mini{"low.code", "a.go", "l", "note"}), adminActor)
	r.upload(shaB, "refs/heads/feat", miniSarif("osv-scanner", mini{"CVE-2024-1", "package-lock.json", "", "error"}), adminActor)
	r.upload(shaB, "refs/heads/feat", fixtureBytes(t, "gitleaks.sarif"), adminActor)
	run, _ := r.svc.EvaluatePull(ctx(), r.tgt, prRef(shaB))
	if run.State != "failure" || !strings.Contains(run.Description, "low.code") || strings.Contains(run.Description, "CVE-2024-1") {
		t.Fatalf("only the code alert should block: %s %s", run.State, run.Description)
	}
	// secrets any: three secrets now block
	if _, err := r.svc.PutPolicy(ctx(), r.tgt, adminActor, Policy{BlockMergeOn: BlockMerge{"off", "off", "any"}, BlockDeployOn: "off", MaxSuppressionDays: 180}); err != nil {
		t.Fatal(err)
	}
	run, _ = r.svc.EvaluatePull(ctx(), r.tgt, prRef(shaB))
	if run.State != "failure" || !strings.Contains(run.Description, "3 alerta") {
		t.Fatalf("secrets must block under secret=any: %s %s", run.State, run.Description)
	}
	// everything off: success
	if _, err := r.svc.PutPolicy(ctx(), r.tgt, adminActor, Policy{BlockMergeOn: BlockMerge{"off", "off", "off"}, BlockDeployOn: "off", MaxSuppressionDays: 180}); err != nil {
		t.Fatal(err)
	}
	if run, _ = r.svc.EvaluatePull(ctx(), r.tgt, prRef(shaB)); run.State != "success" {
		t.Fatalf("all off: %s %s", run.State, run.Description)
	}
}

func TestCheckFailsClosedAfterThirtyMinutesWithoutRequiredTool(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.PutPolicy(ctx(), r.tgt, adminActor, Policy{BlockMergeOn: BlockMerge{"high", "high", "any"}, BlockDeployOn: "off", MaxSuppressionDays: 180, RequiredTools: []string{"semgrep", "gitleaks"}}); err != nil {
		t.Fatal(err)
	}
	run, err := r.svc.EvaluatePull(ctx(), r.tgt, prRef(shaB))
	if err != nil || run.State != "pending" || !strings.Contains(run.Description, "semgrep") {
		t.Fatalf("waiting: %+v %v", run, err)
	}
	if c := r.forge.lastCheck(); c.State != gitcore.CheckPending {
		t.Fatalf("published: %+v", c)
	}
	// semgrep arrives, gitleaks does not
	r.advance(10 * time.Minute)
	r.upload(shaB, "refs/heads/feat", miniSarif("semgrep"), adminActor)
	r.advance(15 * time.Minute) // 25 min since the check started
	r.svc.Sweep(ctx())
	if c := r.forge.lastCheck(); c.State != gitcore.CheckPending || !strings.Contains(c.Description, "gitleaks") || strings.Contains(c.Description, "semgrep") {
		t.Fatalf("at 25 min: %+v", c)
	}
	r.advance(6 * time.Minute) // 31 min
	r.svc.Sweep(ctx())
	c := r.forge.lastCheck()
	if c.State != gitcore.CheckFailure || !strings.Contains(c.Description, "gitleaks") || !strings.Contains(c.Description, "cerrada") {
		t.Fatalf("at 31 min the check must fail closed: %+v", c)
	}
	// the late upload turns it green
	r.upload(shaB, "refs/heads/feat", miniSarif("gitleaks"), adminActor)
	if c := r.forge.lastCheck(); c.State != gitcore.CheckSuccess {
		t.Fatalf("after the tool arrived: %+v", c)
	}
}

func TestCheckPolicyBranchFilterAndSubscriber(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.PutPolicy(ctx(), r.tgt, adminActor, Policy{BlockMergeOn: BlockMerge{"high", "high", "any"}, BlockDeployOn: "off", MaxSuppressionDays: 180, AppliesToBranches: []string{"release/*"}}); err != nil {
		t.Fatal(err)
	}
	r.upload(shaB, "refs/heads/feat", miniSarif("semgrep", mini{"bad", "a.go", "b", "error"}), adminActor)
	run, _ := r.svc.EvaluatePull(ctx(), r.tgt, prRef(shaB)) // base main: not covered
	if run.State != "success" || !strings.Contains(run.Description, "no aplica") {
		t.Fatalf("branch filter: %s %s", run.State, run.Description)
	}
	run, _ = r.svc.EvaluatePull(ctx(), r.tgt, PullRef{Number: 6, Base: "release/1.2", Head: "feat", HeadSHA: shaC})
	if run.State != "success" { // release/* applies but shaC has no alerts
		t.Fatalf("release: %s", run.State)
	}

	// the A5 event of a pull request creates the check
	sub := r.svc.Subscriber()
	err := sub.Handle(ctx(), gitevents.Event{ProjectID: r.tgt.ProjectID, Name: gitevents.PROpened,
		Data: map[string]any{"pr": float64(9), "sha": shaA, "base": "main", "branch": "topic"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sub.Handle(ctx(), gitevents.Event{ProjectID: r.tgt.ProjectID, Name: gitevents.GitPush}); err != nil {
		t.Fatal(err)
	}
	if got := r.forge.checkSHAs[len(r.forge.checkSHAs)-1]; got != shaA {
		t.Fatalf("subscriber did not publish for the PR head: %v", r.forge.checkSHAs)
	}
}

func TestUploadEvaluatesThePullRequestOfThatCommit(t *testing.T) {
	r := newRig(t)
	r.forge.pulls = []gitcore.Pull{{Number: 3, Base: "main", Head: "feat", HeadSHA: shaB}}
	r.upload(shaB, "refs/heads/feat", miniSarif("semgrep", mini{"new.rule", "a.go", "x", "error"}), adminActor)
	if c := r.forge.lastCheck(); c.State != gitcore.CheckFailure || c.Context != "capsule/security" {
		t.Fatalf("check after upload: %+v", c)
	}
}

func TestDeployGateLooksAtOpenAlertsAtTheSHA(t *testing.T) {
	r := newRig(t)
	r.upload(shaA, "refs/heads/main", miniSarif("semgrep", mini{"hi", "a.go", "h", "error"}), adminActor)
	g, err := r.svc.DeployGate(ctx(), r.tgt, shaA)
	if err != nil || g.Blocked {
		t.Fatalf("default blocks deploy on critical only: %+v %v", g, err)
	}
	if _, err := r.svc.PutPolicy(ctx(), r.tgt, adminActor, Policy{BlockMergeOn: BlockMerge{"high", "high", "any"}, BlockDeployOn: "high", MaxSuppressionDays: 180, RequiredTools: []string{"gitleaks"}}); err != nil {
		t.Fatal(err)
	}
	g, _ = r.svc.DeployGate(ctx(), r.tgt, shaA)
	if !g.Blocked || len(g.Reasons) != 2 {
		t.Fatalf("gate: %+v (open high alert and the missing gitleaks upload)", g)
	}
	g, _ = r.svc.DeployGate(ctx(), r.tgt, shaB) // another commit with no data: only the missing tool
	if !g.Blocked || len(g.Reasons) != 1 || !strings.Contains(g.Reasons[0], "gitleaks") {
		t.Fatalf("gate at an unknown sha: %+v", g)
	}
	r.upload(shaA, "refs/heads/main", miniSarif("gitleaks"), adminActor)
	r.upload(shaA, "refs/heads/main", miniSarif("semgrep"), adminActor)
	g, _ = r.svc.DeployGate(ctx(), r.tgt, shaA)
	if g.Blocked {
		t.Fatalf("clean sha still blocked: %+v", g)
	}
}

func TestOverviewCountsAndPolicyBlocking(t *testing.T) {
	r := newRig(t)
	r.upload(shaA, "refs/heads/main", miniSarif("semgrep", mini{"a", "a.go", "1", "error"}, mini{"b", "b.go", "2", "warning"}), adminActor)
	r.upload(shaA, "refs/heads/main", fixtureBytes(t, "gitleaks.sarif"), adminActor)
	o, err := r.svc.Overview(ctx(), r.tgt.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	if o.Open != 5 || o.ByKind["secret"] != 3 || o.ByKind["code"] != 2 || o.BySeverity["critical"] != 1 || o.LastScanAt == nil {
		t.Fatalf("overview: %+v", o)
	}
	if !o.PolicyBlocking { // default block_deploy_on=critical and gitleaks aws is critical
		t.Fatal("policy_blocking must be true with a critical alert open")
	}
}

func TestViewersAreKeptOutOfSecretAlertsByTheQueryFlag(t *testing.T) {
	r := newRig(t)
	r.upload(shaA, "refs/heads/main", fixtureBytes(t, "gitleaks.sarif"), adminActor)
	items, _, err := r.svc.ListAlerts(ctx(), r.tgt.ProjectID, AlertQuery{})
	if err != nil || len(items) != 0 {
		t.Fatalf("without IncludeSecrets: %d %v", len(items), err)
	}
	items, _, _ = r.svc.ListAlerts(ctx(), r.tgt.ProjectID, AlertQuery{IncludeSecrets: true})
	if len(items) != 3 {
		t.Fatalf("with IncludeSecrets: %d", len(items))
	}
	if _, _, err := r.svc.ListAlerts(ctx(), r.tgt.ProjectID, AlertQuery{Severity: "urgent", Kind: "x", State: "y", Tool: "z"}); len(fieldsOf(t, err)) != 4 {
		t.Fatalf("filter validation: %v", err)
	}
}

func TestListAlertsPaginates(t *testing.T) {
	r := newRig(t)
	var ms []mini
	for i := 0; i < 7; i++ {
		ms = append(ms, mini{"r" + string(rune('a'+i)), "f.go", string(rune('a' + i)), "warning"})
	}
	r.upload(shaA, "refs/heads/main", miniSarif("semgrep", ms...), adminActor)
	seen := map[uuid.UUID]bool{}
	cursor := ""
	for page := 0; page < 10; page++ {
		items, next, err := r.svc.ListAlerts(ctx(), r.tgt.ProjectID, AlertQuery{Limit: 3, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range items {
			if seen[a.ID] {
				t.Fatal("duplicate across pages")
			}
			seen[a.ID] = true
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 7 {
		t.Fatalf("paged %d alerts, want 7", len(seen))
	}
}

// ---- scans and Renovate ----------------------------------------------------------------------

func TestScanTrigger(t *testing.T) {
	r := newRig(t)
	j, err := r.svc.TriggerScan(ctx(), r.tgt, adminActor, nil, "", "")
	if err != nil || j.Status != "queued" {
		t.Fatalf("scan: %+v %v", j, err)
	}
	if len(r.forge.dispatched) != 4 {
		t.Fatalf("dispatched %v", r.forge.dispatched)
	}
	if r.forge.dispatched[0] != "security-audit.yml@main" {
		t.Fatalf("dispatched[0] = %s", r.forge.dispatched[0])
	}
	// idempotency
	j1, _ := r.svc.TriggerScan(ctx(), r.tgt, adminActor, []string{"semgrep"}, "refs/heads/dev", "same")
	j2, _ := r.svc.TriggerScan(ctx(), r.tgt, adminActor, []string{"semgrep"}, "refs/heads/dev", "same")
	if j1.ID != j2.ID || len(r.forge.dispatched) != 5 {
		t.Fatalf("idempotency: %v %v %v", j1, j2, r.forge.dispatched)
	}
	if _, err := r.svc.TriggerScan(ctx(), r.tgt, adminActor, []string{"nmap"}, "", ""); !fieldsOf(t, err)["tools[0]"] {
		t.Fatal("unknown tool accepted")
	}
	r.forge.dispatchEr = &gitcore.Error{Code: gitcore.CodeUpstream, Message: "down"}
	if _, err := r.svc.TriggerScan(ctx(), r.tgt, adminActor, nil, "", ""); err == nil {
		t.Fatal("all dispatches failed: must be an error")
	}
	r.forge.enabled = false
	if _, err := r.svc.TriggerScan(ctx(), r.tgt, adminActor, nil, "", ""); !errors.Is(err, gitcore.ErrNotReady) {
		t.Fatalf("git off: %v", err)
	}
}

type fakeRunner struct {
	mu    sync.Mutex
	runs  []string
	block chan struct{}
	err   error
}

func (f *fakeRunner) Run(_ context.Context, repo string) error {
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append(f.runs, repo)
	return f.err
}

func TestRenovateStateOnboardingAndRun(t *testing.T) {
	r := newRig(t)
	st, err := r.svc.RenovateGet(ctx(), r.tgt)
	if err != nil || st.Enabled || st.Onboarding != "none" || st.Preset == "" {
		t.Fatalf("initial: %+v %v", st, err)
	}
	// running while disabled is refused
	_, err = r.svc.RenovateRun(ctx(), r.tgt, adminActor, "")
	var be *BusinessError
	if !errors.As(err, &be) || be.Code != "RENOVATE_DISABLED" {
		t.Fatalf("run while disabled: %v", err)
	}
	// bad inputs
	bad := "has bad chars $(x)"
	if _, err := r.svc.RenovatePut(ctx(), r.tgt, adminActor, RenovateInput{Preset: &bad, Schedule: &bad}); !fieldsOf(t, err)["preset"] {
		t.Fatalf("preset validation: %v", err)
	}
	// enabling without topic support records why
	on := true
	st, err = r.svc.RenovatePut(ctx(), r.tgt, adminActor, RenovateInput{Enabled: &on})
	if err != nil || !st.Enabled || st.TopicSynced || !strings.Contains(st.SyncError, "topic") {
		t.Fatalf("enable without topic api: %+v %v", st, err)
	}
	if !auditHas(r.store, AuditRenovateChange) {
		t.Fatal("not audited")
	}
	// with topic support the topic is set, and removed on disable
	tf := newFakeForge()
	r2 := newRig(t)
	r2.svc.forge = topicForge{tf}
	if st, err = r2.svc.RenovatePut(ctx(), r2.tgt, adminActor, RenovateInput{Enabled: &on}); err != nil || !st.TopicSynced || !tf.topics["renovate"] {
		t.Fatalf("topic set: %+v %v %v", st, err, tf.topics)
	}
	off := false
	if st, err = r2.svc.RenovatePut(ctx(), r2.tgt, adminActor, RenovateInput{Enabled: &off}); err != nil || tf.topics["renovate"] || st.Enabled {
		t.Fatalf("topic removed: %+v %v %v", st, err, tf.topics)
	}

	// onboarding: PR open, then merged (config file on the default branch)
	r.forge.pulls = []gitcore.Pull{
		{Number: 1, Head: "renovate/configure", Author: gitcore.Person{Login: "renovate-bot"}},
		{Number: 2, Head: "renovate/lodash-4.x", Author: gitcore.Person{Login: "renovate-bot"}},
		{Number: 3, Head: "feature/x", Author: gitcore.Person{Login: "ana"}},
	}
	st, _ = r.svc.RenovateGet(ctx(), r.tgt)
	if st.Onboarding != "pr_open" || st.OpenPRs != 1 {
		t.Fatalf("onboarding PR open: %+v", st)
	}
	r.advance(5 * time.Minute)
	r.forge.pulls = []gitcore.Pull{{Number: 2, Head: "renovate/lodash-4.x", Author: gitcore.Person{Login: "renovate-bot"}}, {Number: 4, Head: "x", Author: gitcore.Person{Login: "RENOVATE-BOT"}}}
	r.forge.files["renovate.json"] = true
	st, _ = r.svc.RenovateGet(ctx(), r.tgt)
	if st.Onboarding != "merged" || st.OpenPRs != 2 {
		t.Fatalf("onboarding merged: %+v", st)
	}

	// runs: not configured, then configured, then single flight
	if _, err := r.svc.RenovateRun(ctx(), r.tgt, adminActor, ""); !errors.Is(err, ErrNotReady) {
		t.Fatalf("no runner: %v", err)
	}
	fr := &fakeRunner{block: make(chan struct{})}
	r.svc.SetRunner(fr)
	j, err := r.svc.RenovateRun(ctx(), r.tgt, adminActor, "run-1")
	if err != nil || j.Status != "queued" {
		t.Fatalf("run: %+v %v", j, err)
	}
	var ce *ConflictError
	if _, err := r.svc.RenovateRun(ctx(), r.tgt, adminActor, "run-2"); !errors.As(err, &ce) || ce.Code != "RUN_IN_PROGRESS" {
		t.Fatalf("second run while running: %v", err)
	}
	if j2, err := r.svc.RenovateRun(ctx(), r.tgt, adminActor, "run-1"); err != nil || j2.ID != j.ID {
		t.Fatalf("idempotent run: %v %v", j2, err)
	}
	close(fr.block)
	deadline := time.Now().Add(2 * time.Second)
	for {
		st, _ = r.svc.RenovateGet(ctx(), r.tgt)
		if st.LastRunStatus == "success" || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st.LastRunStatus != "success" || st.LastRunAt == nil {
		t.Fatalf("last run: %+v", st)
	}
	fr.mu.Lock()
	defer fr.mu.Unlock()
	if len(fr.runs) != 1 || fr.runs[0] != "acme/app" {
		t.Fatalf("runner got %v, want a single run limited to acme/app", fr.runs)
	}
}

func TestExecRunnerBuildsDockerArgsWithoutAShell(t *testing.T) {
	id := uuid.MustParse("12345678-9abc-def0-1234-56789abcdef0")
	var gotName string
	var gotArgs []string
	run := &ExecRunner{ProjectID: id, Command: "renovate", Exec: func(_ context.Context, name string, args ...string) ([]byte, error) {
		gotName, gotArgs = name, args
		return nil, nil
	}}
	if err := run.Run(ctx(), "acme/app"); err != nil {
		t.Fatal(err)
	}
	want := []string{"exec", "-e", "RENOVATE_AUTODISCOVER=false", "-e", "RENOVATE_REPOSITORIES=acme/app", "capsule-app-123456789abc", "renovate"}
	if gotName != "docker" || strings.Join(gotArgs, " ") != strings.Join(want, " ") {
		t.Fatalf("%s %v", gotName, gotArgs)
	}
	for _, bad := range []string{"acme/app; rm -rf /", "a b/c", "acme", "../x/y", "acme/app\n--env X=1", ""} {
		if err := run.Run(ctx(), bad); err == nil {
			t.Errorf("repo %q must be refused", bad)
		}
	}
	if r := NewExecRunner(Config{}); r != nil {
		t.Error("no project configured: runner must be nil")
	}
	if r := NewExecRunner(Config{RenovateProject: id.String()}); r == nil {
		t.Error("configured runner is nil")
	}
}
