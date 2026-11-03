//go:build dbtest

package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/security"
)

// Package B7, migrations 000046-000049. Run with TEST_DATABASE_URL pointing at a throwaway Postgres:
//
//	go test -tags dbtest ./internal/repository/ -run SecurityDB

type secDB struct {
	t       *testing.T
	pool    *pgxpool.Pool
	repo    *SecurityRepository
	project uuid.UUID
	org     uuid.UUID
	user    uuid.UUID
	target  security.Target
}

func newSecDB(t *testing.T) *secDB {
	t.Helper()
	pool := freshDB(t)
	applyUpTo(t, pool, 1<<20)
	f := newFx(t, pool)
	user := f.user("", time.Now().Add(-time.Hour))
	org := f.org(user)
	project := f.project(org, "app")
	repo := NewSecurityRepository(pool)
	tgt, err := repo.ProjectTarget(context.Background(), project)
	if err != nil {
		t.Fatal(err)
	}
	return &secDB{t: t, pool: pool, repo: repo, project: project, org: org, user: user, target: tgt}
}

func (d *secDB) service() *security.Service {
	return security.New(d.repo, nil, security.Config{FingerprintKey: "db-test-key", UploadsPerMinute: 10000}, nil)
}

func secFinding(rule, fp string, sev security.Severity, kind security.Kind) security.Finding {
	return security.Finding{Kind: kind, Tool: security.ToolSemgrep, ToolName: security.ToolSemgrep, RuleID: rule, Severity: sev,
		Title: "title " + rule, Fingerprint: fp, Path: "src/" + rule + ".go", StartLine: 3}
}

func (d *secDB) upload(branch, sha string, at time.Time, fs ...security.Finding) security.ClaimedUpload {
	d.t.Helper()
	u := &security.Upload{ID: uuid.New(), ProjectID: d.project, CommitSHA: sha, Ref: branch, Branch: branch, Tool: security.ToolSemgrep,
		ToolName: security.ToolSemgrep, Status: security.UploadPending, CreatedAt: at, CreatedBy: d.user}
	payload := security.UploadPayload{Scopes: []security.Scope{{Tool: security.ToolSemgrep, ToolName: security.ToolSemgrep}}, Findings: fs}
	if _, created, err := d.repo.CreateUpload(context.Background(), u, payload, security.AuditEntry{OrgID: d.org, Action: security.AuditSarifUpload, ResourceType: "sarif_upload", ResourceID: u.ID}); err != nil || !created {
		d.t.Fatalf("create upload: %v %v", created, err)
	}
	return security.ClaimedUpload{Upload: *u, Payload: payload}
}

func (d *secDB) apply(cu security.ClaimedUpload, now time.Time) *security.ApplyResult {
	d.t.Helper()
	res, err := d.repo.ApplyUpload(context.Background(), cu, now)
	if err != nil {
		d.t.Fatalf("apply: %v", err)
	}
	return res
}

func (d *secDB) states(branch string) map[string]security.State {
	d.t.Helper()
	items, _, err := d.repo.ListAlerts(context.Background(), d.project, security.AlertQuery{Branch: branch, IncludeSecrets: true, Limit: 100})
	if err != nil {
		d.t.Fatal(err)
	}
	m := map[string]security.State{}
	for _, a := range items {
		m[a.Fingerprint] = a.State
	}
	return m
}

func TestSecurityMigrationsDB(t *testing.T) {
	d := newSecDB(t)
	ctx := context.Background()
	for _, tbl := range []string{"security_alerts", "sarif_uploads", "security_suppressions", "security_policies", "security_check_runs", "renovate_state"} {
		var n int
		if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM `+tbl).Scan(&n); err != nil {
			t.Fatalf("%s: %v", tbl, err)
		}
	}
	// down then up again with only this package's files: both directions are idempotent and leave
	// the tables usable (the earlier migrations are not re-run: they are not all idempotent)
	names := map[int]string{46: "security_suppressions_policies", 47: "security_alerts", 48: "sarif_uploads", 49: "renovate_state"}
	run := func(v int, kind string) {
		b, err := MigrationsFS.ReadFile(fmt.Sprintf("migrations/%06d_%s.%s.sql", v, names[v], kind))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if _, err := d.pool.Exec(ctx, string(b)); err != nil {
				t.Fatalf("%s %d (run %d): %v", kind, v, i+1, err)
			}
		}
	}
	for _, v := range []int{49, 48, 47, 46} {
		run(v, "down")
	}
	for _, v := range []int{46, 47, 48, 49} {
		run(v, "up")
	}
	if _, err := d.pool.Exec(ctx, `SELECT 1 FROM security_alerts LIMIT 1`); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityConstraintsDB(t *testing.T) {
	d := newSecDB(t)
	ctx := context.Background()
	ins := func(sql string, args ...any) error { _, err := d.pool.Exec(ctx, sql, args...); return err }
	base := `INSERT INTO security_alerts (project_id, kind, tool, tool_name, rule_id, severity, state, title, fingerprint, branch, evidence, dismiss_expires_at) VALUES ($1,$2,'semgrep','semgrep','r',$3,$4,'t',$5,'main',$6,$7)`
	if err := ins(base, d.project, "secret", "high", "open", "fp1", "the-secret-value", nil); err == nil {
		t.Error("a secret alert with evidence must be rejected by the database")
	}
	if err := ins(base, d.project, "secret", "high", "open", "fp2", "", nil); err != nil {
		t.Errorf("secret alert without evidence: %v", err)
	}
	if err := ins(base, d.project, "code", "severe", "open", "fp3", "", nil); err == nil {
		t.Error("unknown severity accepted")
	}
	if err := ins(base, d.project, "code", "high", "dismissed", "fp4", "", nil); err == nil {
		t.Error("a dismissed alert without expiry must be rejected")
	}
	if err := ins(base, d.project, "code", "high", "dismissed", "fp5", "", time.Now().Add(time.Hour)); err != nil {
		t.Errorf("dismissed with expiry: %v", err)
	}
	if err := ins(base, d.project, "code", "high", "open", "fp5", "", nil); err == nil {
		t.Error("(project, tool, branch, fingerprint) must be unique")
	}
	supp := `INSERT INTO security_suppressions (project_id, rule_id, fingerprint, path_glob, reason, justification, expires_at) VALUES ($1,$2,'',$3,$4,$5,now() + interval '1 day')`
	if err := ins(supp, d.project, "r", "", "wont_fix", "short"); err == nil {
		t.Error("justification under 10 characters accepted")
	}
	if err := ins(supp, d.project, "r", "", "because", "long enough justification"); err == nil {
		t.Error("reason outside the enum accepted")
	}
	if err := ins(supp, d.project, "", "", "wont_fix", "long enough justification"); err == nil {
		t.Error("a suppression that matches nothing was accepted")
	}
	for _, g := range []string{"**", "*", "**/*", "/**"} {
		if err := ins(supp, d.project, "", g, "wont_fix", "long enough justification"); err == nil {
			t.Errorf("glob %q accepted", g)
		}
	}
	if err := ins(supp, d.project, "", "src/**", "wont_fix", "long enough justification"); err != nil {
		t.Errorf("bounded glob: %v", err)
	}
	if err := ins(`INSERT INTO security_policies (project_id, max_suppression_days) VALUES ($1, 366)`, d.project); err == nil {
		t.Error("max_suppression_days over 365 accepted")
	}
}

func TestSecurityUploadCycleDB(t *testing.T) {
	d := newSecDB(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Millisecond)
	a, b := secFinding("a", "fa", security.SevHigh, security.KindCode), secFinding("b", "fb", security.SevLow, security.KindCode)

	cu := d.upload("main", "sha1", t0, a, b)
	claimed, err := d.repo.ClaimUploads(ctx, 10, time.Minute, t0.Add(time.Second))
	if err != nil || len(claimed) != 1 || claimed[0].ID != cu.ID || len(claimed[0].Payload.Findings) != 2 || claimed[0].Attempts != 1 {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	if again, _ := d.repo.ClaimUploads(ctx, 10, time.Minute, t0.Add(2*time.Second)); len(again) != 0 {
		t.Fatal("a processing upload must not be claimed again before it goes stale")
	}
	res := d.apply(claimed[0], t0.Add(time.Second))
	if len(res.Created) != 2 || res.Fixed != 0 {
		t.Fatalf("first apply: %+v", res)
	}
	up, _ := d.repo.GetUpload(ctx, d.project, cu.ID)
	if up.Status != security.UploadComplete || up.AlertsCreated != 2 || up.CompletedAt == nil {
		t.Fatalf("upload row: %+v", up)
	}
	// the findings (and any secret they could have carried) are dropped once processed
	var left *string
	if err := d.pool.QueryRow(ctx, `SELECT findings::text FROM sarif_uploads WHERE id = $1`, cu.ID).Scan(&left); err != nil || left != nil {
		t.Fatalf("findings must be NULL after processing: %v %v", left, err)
	}

	// b disappears: fixed; a stays
	d.apply(d.upload("main", "sha2", t0.Add(time.Minute), a), t0.Add(time.Minute))
	if got := d.states("main"); got["fa"] != security.StateOpen || got["fb"] != security.StateFixed {
		t.Fatalf("after second upload: %v", got)
	}
	// b comes back: open again
	res = d.apply(d.upload("main", "sha3", t0.Add(2*time.Minute), a, b), t0.Add(2*time.Minute))
	if len(res.Created) != 1 || d.states("main")["fb"] != security.StateOpen {
		t.Fatalf("reappearing: %+v %v", res, d.states("main"))
	}
	// the open alert at sha3 is what the policy looks at
	at, err := d.repo.OpenAlertsAtSHA(ctx, d.project, "sha3")
	if err != nil || len(at) != 2 {
		t.Fatalf("open alerts at sha: %d %v", len(at), err)
	}
	// a different branch has its own alerts; known fingerprints are per branch
	d.apply(d.upload("feature", "sha4", t0.Add(3*time.Minute), a), t0.Add(3*time.Minute))
	known, _ := d.repo.KnownFingerprints(ctx, d.project, "feature")
	if len(known) != 1 || !known["fa"] {
		t.Fatalf("known fingerprints: %v", known)
	}
	// the upload of tool X says nothing about tool Y
	other := secFinding("g", "fg", security.SevHigh, security.KindCode)
	other.Tool, other.ToolName = security.ToolGosec, security.ToolGosec
	u := &security.Upload{ID: uuid.New(), ProjectID: d.project, CommitSHA: "sha5", Ref: "main", Branch: "main", Tool: security.ToolGosec, ToolName: security.ToolGosec, Status: security.UploadPending, CreatedAt: t0.Add(4 * time.Minute)}
	pl := security.UploadPayload{Scopes: []security.Scope{{Tool: security.ToolGosec, ToolName: security.ToolGosec}}, Findings: []security.Finding{other}}
	if _, _, err := d.repo.CreateUpload(ctx, u, pl, security.AuditEntry{OrgID: d.org, Action: security.AuditSarifUpload, ResourceType: "sarif_upload", ResourceID: u.ID}); err != nil {
		t.Fatal(err)
	}
	d.apply(security.ClaimedUpload{Upload: *u, Payload: pl}, t0.Add(4*time.Minute))
	if got := d.states("main"); got["fa"] != security.StateOpen || got["fg"] != security.StateOpen {
		t.Fatalf("cross-tool: %v", got)
	}
	tools, _ := d.repo.ToolsUploadedAt(ctx, d.project, "sha5")
	if !tools["gosec"] || tools["semgrep"] {
		t.Fatalf("tools at sha5: %v", tools)
	}
	// the overview counts open alerts by severity and kind
	ov, err := d.repo.Overview(ctx, d.project)
	if err != nil || ov.Open != 4 || ov.BySeverity["high"] != 3 || ov.ByKind["code"] != 4 || ov.LastScanAt == nil {
		t.Fatalf("overview: %+v %v", ov, err)
	}
	// failing an upload: back to pending, then final
	u2 := d.upload("main", "sha6", t0.Add(5*time.Minute), a)
	if err := d.repo.FailUpload(ctx, u2.ID, "boom", false, t0); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.repo.GetUpload(ctx, d.project, u2.ID); got.Status != security.UploadPending || got.Error != "boom" {
		t.Fatalf("retry state: %+v", got)
	}
	if err := d.repo.FailUpload(ctx, u2.ID, "boom", true, t0); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.repo.GetUpload(ctx, d.project, u2.ID); got.Status != security.UploadFailed || got.CompletedAt == nil {
		t.Fatalf("final failure: %+v", got)
	}
}

func TestSecurityIdempotentUploadDB(t *testing.T) {
	d := newSecDB(t)
	ctx := context.Background()
	mk := func() *security.Upload {
		return &security.Upload{ID: uuid.New(), ProjectID: d.project, CommitSHA: "s", Ref: "main", Branch: "main", Tool: security.ToolSemgrep, ToolName: security.ToolSemgrep, Status: security.UploadPending, IdempotencyKey: "k-1", CreatedAt: time.Now()}
	}
	audit := security.AuditEntry{OrgID: d.org, Action: security.AuditSarifUpload, ResourceType: "sarif_upload"}
	first := mk()
	if _, created, err := d.repo.CreateUpload(ctx, first, security.UploadPayload{}, audit); err != nil || !created {
		t.Fatalf("first: %v %v", created, err)
	}
	existing, created, err := d.repo.CreateUpload(ctx, mk(), security.UploadPayload{}, audit)
	if err != nil || created || existing == nil || existing.ID != first.ID {
		t.Fatalf("replay: %+v %v %v", existing, created, err)
	}
	var n int
	_ = d.pool.QueryRow(ctx, `SELECT count(*) FROM sarif_uploads WHERE project_id = $1`, d.project).Scan(&n)
	if n != 1 {
		t.Fatalf("uploads = %d", n)
	}
}

// Two uploads of the same tool on the same branch applied at the same time (SPEC: concurrency).
func TestSecuritySimultaneousUploadsDB(t *testing.T) {
	d := newSecDB(t)
	t0 := time.Now().UTC().Truncate(time.Millisecond)
	fs := []security.Finding{
		secFinding("a", "fa", security.SevHigh, security.KindCode),
		secFinding("b", "fb", security.SevHigh, security.KindCode),
		secFinding("c", "fc", security.SevHigh, security.KindCode),
	}
	for round := 0; round < 15; round++ {
		branch := fmt.Sprintf("race-%d", round)
		// identical content: no duplicate rows and no unique violations
		var uploads []security.ClaimedUpload
		for i := 0; i < 6; i++ {
			uploads = append(uploads, d.upload(branch, fmt.Sprintf("s%d", i), t0.Add(time.Duration(i)*time.Millisecond), fs...))
		}
		var wg sync.WaitGroup
		errs := make(chan error, len(uploads))
		for _, cu := range uploads {
			wg.Add(1)
			go func(cu security.ClaimedUpload) {
				defer wg.Done()
				if _, err := d.repo.ApplyUpload(context.Background(), cu, time.Now()); err != nil {
					errs <- err
				}
			}(cu)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("round %d: concurrent apply failed: %v", round, err)
		}
		if got := d.states(branch); len(got) != 3 {
			t.Fatalf("round %d: %d alerts for 3 findings: %v", round, len(got), got)
		}
	}
	// different content: whatever the order, the NEWEST upload defines the open set
	older := d.upload("final", "o", t0, fs[0], fs[1])
	newer := d.upload("final", "n", t0.Add(time.Second), fs[2])
	for round := 0; round < 10; round++ {
		var wg sync.WaitGroup
		for _, cu := range []security.ClaimedUpload{older, newer} {
			wg.Add(1)
			go func(cu security.ClaimedUpload) {
				defer wg.Done()
				if _, err := d.repo.ApplyUpload(context.Background(), cu, time.Now()); err != nil {
					t.Error(err)
				}
			}(cu)
		}
		wg.Wait()
		got := d.states("final")
		if got["fc"] != security.StateOpen || got["fa"] == security.StateOpen || got["fb"] == security.StateOpen {
			t.Fatalf("round %d: the stale upload overwrote the newer one: %v", round, got)
		}
	}
}

func TestSecurityDismissSuppressExpireDB(t *testing.T) {
	d := newSecDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	a := secFinding("a", "fa", security.SevMedium, security.KindCode)
	d.apply(d.upload("main", "s1", now, a), now)
	d.apply(d.upload("dev", "s2", now, a), now)
	items, _, _ := d.repo.ListAlerts(ctx, d.project, security.AlertQuery{Branch: "main", Limit: 10})
	if len(items) != 1 {
		t.Fatalf("alerts: %d", len(items))
	}
	exp := now.Add(48 * time.Hour)
	dis, err := d.repo.DismissAlert(ctx, d.project, items[0].ID, security.DismissParams{Reason: security.ReasonWontFix, Justification: "accepted for now", ExpiresAt: exp, By: d.user}, now,
		security.AuditEntry{OrgID: d.org, UserID: d.user, Action: security.AuditAlertDismiss, ResourceType: "security_alert", ResourceID: items[0].ID})
	if err != nil || dis.State != security.StateDismissed || dis.Dismissal == nil || dis.Dismissal.By.Email == "" {
		t.Fatalf("dismiss: %+v %v", dis, err)
	}
	if got := d.states("dev"); got["fa"] != security.StateDismissed {
		t.Fatalf("the same fingerprint on another branch must be dismissed too: %v", got)
	}
	var ce *security.ConflictError
	if _, err := d.repo.DismissAlert(ctx, d.project, items[0].ID, security.DismissParams{Reason: security.ReasonWontFix, Justification: "again again", ExpiresAt: exp}, now, security.AuditEntry{OrgID: d.org, Action: "x", ResourceType: "x"}); !errors.As(err, &ce) {
		t.Fatalf("dismissing a dismissed alert: %v", err)
	}
	// a new upload carrying it keeps it dismissed (suppression applies)
	res := d.apply(d.upload("main", "s3", now.Add(time.Minute), a), now.Add(time.Minute))
	if len(res.Created) != 0 || d.states("main")["fa"] != security.StateDismissed {
		t.Fatalf("suppressed alert resurfaced: %+v %v", res, d.states("main"))
	}
	supps, err := d.repo.ListSuppressions(ctx, d.project)
	if err != nil || len(supps) != 1 || supps[0].Source != "alert" || supps[0].CreatedByPerson.Email == "" {
		t.Fatalf("suppressions: %+v %v", supps, err)
	}
	// the notice window: 48 h left, inside 7 days; marked once
	due, err := d.repo.DueExpiringNotices(ctx, now, 7*24*time.Hour)
	if err != nil || len(due) != 1 {
		t.Fatalf("due notices: %d %v", len(due), err)
	}
	if err := d.repo.MarkExpiringNotified(ctx, []uuid.UUID{due[0].ID}, now); err != nil {
		t.Fatal(err)
	}
	if due, _ = d.repo.DueExpiringNotices(ctx, now, 7*24*time.Hour); len(due) != 0 {
		t.Fatal("notified twice")
	}
	// expiry: the clock passes the deadline
	exps, err := d.repo.ExpireDue(ctx, exp.Add(time.Minute))
	if err != nil || len(exps) != 1 || exps[0].AlertsReopened != 2 || len(exps[0].Suppressions) != 1 {
		t.Fatalf("expire: %+v %v", exps, err)
	}
	if got := d.states("main"); got["fa"] != security.StateOpen {
		t.Fatalf("after expiry: %v", got)
	}
	if again, _ := d.repo.ExpireDue(ctx, exp.Add(time.Hour)); len(again) != 0 {
		t.Fatal("expiry is not idempotent")
	}
	supps, _ = d.repo.ListSuppressions(ctx, d.project)
	if supps[0].State != security.SuppExpired {
		t.Fatalf("suppression state %s", supps[0].State)
	}

	// manual suppression by rule + glob: applied to the open alerts it covers, revocable
	sp := &security.Suppression{ID: uuid.New(), ProjectID: d.project, Match: security.SuppressionMatch{RuleID: "a", PathGlob: "src/**"}, Reason: security.ReasonUsedInTests,
		Justification: "only used in tests", ExpiresAt: now.Add(72 * time.Hour), State: security.SuppActive, Source: "manual", CreatedBy: d.user, CreatedAt: now}
	n, err := d.repo.CreateSuppression(ctx, sp, now, security.AuditEntry{OrgID: d.org, UserID: d.user, Action: security.AuditSuppressionCreate, ResourceType: "security_suppression", ResourceID: sp.ID, NewValues: map[string]any{}})
	if err != nil || n != 2 {
		t.Fatalf("create suppression applied=%d %v", n, err)
	}
	sev, ok, err := d.repo.MaxSeverityMatching(ctx, d.project, security.SuppressionMatch{RuleID: "a"})
	_ = sev
	if err != nil || ok { // both alerts are dismissed now: nothing open matches
		t.Fatalf("max severity: %v %v %v", sev, ok, err)
	}
	// reopening one alert covered by a manual suppression is a conflict
	covered, _, _ := d.repo.ListAlerts(ctx, d.project, security.AlertQuery{State: "dismissed", Limit: 10})
	if _, err := d.repo.ReopenAlert(ctx, d.project, covered[0].ID, now, security.AuditEntry{OrgID: d.org, Action: "x", ResourceType: "x"}); !errors.As(err, &ce) || ce.Code != "SUPPRESSED_BY_RULE" {
		t.Fatalf("reopen under rule: %v", err)
	}
	re, err := d.repo.RevokeSuppression(ctx, d.project, sp.ID, d.user, now, security.AuditEntry{OrgID: d.org, UserID: d.user, Action: security.AuditSuppressionRevoke, ResourceType: "security_suppression", ResourceID: sp.ID})
	if err != nil || re != 2 {
		t.Fatalf("revoke: %d %v", re, err)
	}
	if _, err := d.repo.RevokeSuppression(ctx, d.project, sp.ID, d.user, now, security.AuditEntry{OrgID: d.org, Action: "x", ResourceType: "x"}); !errors.Is(err, security.ErrNotFound) {
		t.Fatalf("revoke twice: %v", err)
	}
	// both audited actions are in audit_logs
	var audits int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id = $1 AND action LIKE 'security.%'`, d.org).Scan(&audits); err != nil || audits < 4 {
		t.Fatalf("audit rows: %d %v", audits, err)
	}
}

func TestSecurityPolicyChecksAndRenovateDB(t *testing.T) {
	d := newSecDB(t)
	ctx := context.Background()
	if _, err := d.repo.GetPolicy(ctx, d.project); !errors.Is(err, security.ErrNoPolicy) {
		t.Fatalf("no policy: %v", err)
	}
	p := security.Policy{BlockMergeOn: security.BlockMerge{Dependency: "medium", Code: "off", Secret: "any"}, BlockDeployOn: "high", RequiredTools: []string{"semgrep"}, MaxSuppressionDays: 90, AppliesToBranches: []string{"main"}}
	audit := security.AuditEntry{OrgID: d.org, UserID: d.user, Action: security.AuditPolicyChange, ResourceType: "security_policy", ResourceID: d.project}
	if err := d.repo.PutPolicy(ctx, d.project, p, d.user, time.Now(), audit); err != nil {
		t.Fatal(err)
	}
	p.BlockDeployOn = "critical"
	p.RequiredTools, p.AppliesToBranches = nil, nil
	if err := d.repo.PutPolicy(ctx, d.project, p, d.user, time.Now(), audit); err != nil {
		t.Fatal(err)
	}
	got, err := d.repo.GetPolicy(ctx, d.project)
	if err != nil || got.BlockDeployOn != "critical" || got.BlockMergeOn.Dependency != "medium" || got.MaxSuppressionDays != 90 || got.RequiredTools == nil || len(got.RequiredTools) != 0 {
		t.Fatalf("policy: %+v %v", got, err)
	}

	// check runs: first_seen_at survives re-ensuring, concurrent ensures give one row
	t0 := time.Now().UTC().Truncate(time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := d.repo.EnsureCheckRun(ctx, security.CheckRun{ProjectID: d.project, HeadSHA: "head1", PR: 4, BaseBranch: "main", HeadBranch: "f", FirstSeenAt: t0.Add(time.Duration(i) * time.Second)}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	var rows int
	_ = d.pool.QueryRow(ctx, `SELECT count(*) FROM security_check_runs WHERE project_id = $1`, d.project).Scan(&rows)
	if rows != 1 {
		t.Fatalf("check rows = %d", rows)
	}
	run, err := d.repo.EnsureCheckRun(ctx, security.CheckRun{ProjectID: d.project, HeadSHA: "head1", FirstSeenAt: t0.Add(time.Hour)})
	if err != nil || run.PR != 4 || run.BaseBranch != "main" || run.State != "pending" || run.Final {
		t.Fatalf("ensure keeps the stored data: %+v %v", run, err)
	}
	open, err := d.repo.OpenCheckRuns(ctx, 10)
	if err != nil || len(open) != 1 {
		t.Fatalf("open runs: %d %v", len(open), err)
	}
	now := time.Now()
	run.State, run.Description, run.LastEvalAt, run.Final = "failure", "bloqueado", &now, true
	if err := d.repo.SaveCheckRun(ctx, *run); err != nil {
		t.Fatal(err)
	}
	if open, _ = d.repo.OpenCheckRuns(ctx, 10); len(open) != 0 {
		t.Fatal("a final run is still listed as open")
	}
	if recent, err := d.repo.RecentCheckRuns(ctx, d.project, time.Now().Add(-time.Hour), 10); err != nil || len(recent) != 1 || recent[0].State != "failure" {
		t.Fatalf("recent: %+v %v", recent, err)
	}

	// renovate
	if _, err := d.repo.GetRenovate(ctx, d.project); !errors.Is(err, security.ErrNotFound) {
		t.Fatalf("no state: %v", err)
	}
	st := security.RenovateState{ProjectID: d.project, Enabled: true, Preset: "local>platform/renovate-config", Schedule: "before 6am on monday", Onboarding: "none", SyncError: "topic"}
	if err := d.repo.PutRenovate(ctx, st, d.user, security.AuditEntry{OrgID: d.org, UserID: d.user, Action: security.AuditRenovateChange, ResourceType: "renovate", ResourceID: d.project}); err != nil {
		t.Fatal(err)
	}
	syncAt := time.Now().UTC()
	if err := d.repo.UpdateRenovateObserved(ctx, security.RenovateState{ProjectID: d.project, Onboarding: "pr_open", OpenPRs: 3, LastSyncAt: &syncAt}); err != nil {
		t.Fatal(err)
	}
	if err := d.repo.RecordRenovateRun(ctx, d.project, syncAt, "success"); err != nil {
		t.Fatal(err)
	}
	gs, err := d.repo.GetRenovate(ctx, d.project)
	if err != nil || !gs.Enabled || gs.Onboarding != "pr_open" || gs.OpenPRs != 3 || gs.LastRunStatus != "success" || gs.LastRunAt == nil || gs.Schedule != "before 6am on monday" || gs.SyncError != "topic" {
		t.Fatalf("renovate state: %+v %v", gs, err)
	}
}

func TestSecurityListFiltersAndPaginationDB(t *testing.T) {
	d := newSecDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	var fs []security.Finding
	for i := 0; i < 7; i++ {
		fs = append(fs, secFinding(fmt.Sprintf("r%d", i), fmt.Sprintf("f%d", i), security.SevMedium, security.KindCode))
	}
	fs = append(fs, secFinding("sec", "fsec", security.SevHigh, security.KindSecret))
	d.apply(d.upload("main", "s", now, fs...), now)
	seen := map[uuid.UUID]bool{}
	cursor := ""
	for i := 0; i < 10; i++ {
		items, next, err := d.repo.ListAlerts(ctx, d.project, security.AlertQuery{Limit: 3, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range items {
			if a.Kind == security.KindSecret {
				t.Fatal("secrets are excluded unless IncludeSecrets")
			}
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
		t.Fatalf("paged %d, want 7", len(seen))
	}
	sec, _, _ := d.repo.ListAlerts(ctx, d.project, security.AlertQuery{Kind: "secret", IncludeSecrets: true, Limit: 10})
	if len(sec) != 1 || sec[0].Evidence != "" {
		t.Fatalf("secret list: %+v", sec)
	}
	if _, _, err := d.repo.ListAlerts(ctx, d.project, security.AlertQuery{Cursor: "%%%"}); err == nil {
		t.Fatal("bad cursor accepted")
	}
}

// SPEC 5.8 / B7 acceptance: the VALUE of a detected secret is never persisted. The upload goes
// through the real parser and service with the real gitleaks fixture; afterwards EVERY table of the
// database is dumped and searched for the values.
func TestSecurityNeverPersistsSecretValuesDB(t *testing.T) {
	d := newSecDB(t)
	ctx := context.Background()
	raw, err := os.ReadFile(filepath.Join("..", "security", "testdata", "sarif", "gitleaks.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"@@SECRET_1@@": "sk_" + "live_" + "FixtureValue0123456789ab",
		"@@SECRET_2@@": "AK" + "IA" + "FIXTURE0000TEST7",
		"@@SECRET_3@@": "gh" + "p_" + "FixtureValue0123456789abcdefghijklmno",
	}
	sarif := string(raw)
	for ph, v := range values {
		sarif = strings.ReplaceAll(sarif, ph, v)
	}
	svc := d.service()
	actor := security.Actor{UserID: d.user, Login: "tester", Admin: true}
	u, err := svc.Upload(ctx, d.target, actor, security.UploadInput{CommitSHA: strings.Repeat("a", 40), Ref: "refs/heads/main", Sarif: sarif})
	if err != nil {
		t.Fatal(err)
	}
	// while the upload is still queued its stored payload must already be free of the values
	d.assertNoValue(values)
	if n, err := svc.ProcessPending(ctx, 10); err != nil || n != 1 {
		t.Fatalf("process: %d %v", n, err)
	}
	got, _ := svc.UploadStatus(ctx, d.project, u.ID)
	if got.Status != security.UploadComplete || got.AlertsCreated != 3 {
		t.Fatalf("upload: %+v", got)
	}
	// dismiss one (writes dismissal, suppression and audit rows too)
	items, _, _ := svc.ListAlerts(ctx, d.project, security.AlertQuery{Kind: "secret", IncludeSecrets: true, Limit: 10})
	if len(items) != 3 {
		t.Fatalf("secret alerts: %d", len(items))
	}
	if _, err := svc.Dismiss(ctx, d.target, actor, items[0].ID, security.DismissInput{Reason: security.ReasonFalsePositive, Justification: "fixture value in a test", ExpiresAt: time.Now().Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	d.assertNoValue(values)
	// rule, path and line ARE stored
	var path string
	var line int
	if err := d.pool.QueryRow(ctx, `SELECT path, start_line FROM security_alerts WHERE rule_id = 'github-pat'`).Scan(&path, &line); err != nil || path != "config.env" || line != 1 {
		t.Fatalf("location of the secret: %q:%d %v", path, line, err)
	}
}

// assertNoValue dumps every table of the public schema as text and fails when any value shows up.
func (d *secDB) assertNoValue(values map[string]string) {
	d.t.Helper()
	ctx := context.Background()
	rows, err := d.pool.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil {
		d.t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			d.t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	if len(tables) < 10 {
		d.t.Fatalf("only %d tables found: the dump would prove nothing", len(tables))
	}
	for _, tbl := range tables {
		r, err := d.pool.Query(ctx, `SELECT t::text FROM `+pgx.Identifier{tbl}.Sanitize()+` t`)
		if err != nil {
			d.t.Fatalf("dumping %s: %v", tbl, err)
		}
		for r.Next() {
			var row string
			if err := r.Scan(&row); err != nil {
				d.t.Fatal(err)
			}
			for ph, v := range values {
				if strings.Contains(row, v) || strings.Contains(row, ph) {
					r.Close()
					d.t.Fatalf("the value of a secret (%s...) is stored in table %s", v[:6], tbl)
				}
			}
		}
		r.Close()
		if err := r.Err(); err != nil {
			d.t.Fatal(err)
		}
	}
}
