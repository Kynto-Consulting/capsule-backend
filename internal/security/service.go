package security

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

// Service is the whole behavior of package B7 behind the HTTP handlers.
type Service struct {
	store  Store
	forge  Forge
	cfg    Config
	parser *Parser
	log    *slog.Logger
	now    func() time.Time
	pub    gitevents.Publisher
	runner RenovateRunner
	wake   chan struct{}

	mu      sync.Mutex
	buckets map[uuid.UUID][]time.Time // upload timestamps of the last minute, by project
	idem    map[string]idemEntry      // scanTrigger / renovateRun Idempotency-Key cache
	running map[uuid.UUID]bool        // renovate runs in flight
}

type idemEntry struct {
	job Job
	at  time.Time
}

// Job is the contract Job (scanTrigger, renovateRun).
type Job struct {
	ID     uuid.UUID
	Status string // queued|running|success|failed
	Detail string
}

// New builds the Service. forge may be nil (Git integration off: scans and Renovate answer
// ErrNotReady, the rest works). log may be nil.
func New(store Store, forge Forge, cfg Config, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	d := DefaultConfig()
	if cfg.WorkerEvery <= 0 {
		cfg.WorkerEvery = d.WorkerEvery
	}
	if cfg.SweepEvery <= 0 {
		cfg.SweepEvery = d.SweepEvery
	}
	if cfg.CheckTimeout <= 0 {
		cfg.CheckTimeout = d.CheckTimeout
	}
	if cfg.UploadsPerMinute <= 0 {
		cfg.UploadsPerMinute = d.UploadsPerMinute
	}
	if cfg.RenovateBotLogin == "" {
		cfg.RenovateBotLogin = d.RenovateBotLogin
	}
	if cfg.RenovatePreset == "" {
		cfg.RenovatePreset = d.RenovatePreset
	}
	if cfg.RenovateCommand == "" {
		cfg.RenovateCommand = d.RenovateCommand
	}
	return &Service{
		store: store, forge: forge, cfg: cfg, parser: &Parser{Key: []byte(cfg.FingerprintKey)},
		log: log, now: time.Now, wake: make(chan struct{}, 1),
		buckets: map[uuid.UUID][]time.Time{}, idem: map[string]idemEntry{}, running: map[uuid.UUID]bool{},
	}
}

// SetPublisher overrides the event publisher (default: gitevents.Shared()).
func (s *Service) SetPublisher(p gitevents.Publisher) { s.pub = p }

// SetRunner sets the Renovate runner.
func (s *Service) SetRunner(r RenovateRunner) { s.runner = r }

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Config returns the effective configuration.
func (s *Service) Config() Config { return s.cfg }

func (s *Service) publisher() gitevents.Publisher {
	if s.pub != nil {
		return s.pub
	}
	return gitevents.Shared()
}

func repoRef(t Target) gitcore.RepoRef { return gitcore.RepoRef{Owner: t.OrgSlug, Repo: t.ProjectSlug} }

func (s *Service) publish(ctx context.Context, t Target, name, actor string, branch string, data map[string]any) {
	err := s.publisher().Publish(ctx, gitevents.Event{
		OrgID: t.OrgID, ProjectID: t.ProjectID, Name: name, Actor: actor, Branch: branch, Data: data,
	})
	if err != nil {
		s.log.Warn("security: publishing event failed", "event", name, "project_id", t.ProjectID, "err", err)
	}
}

// ---------------------------------------------------------------------------------------------
// SARIF upload
// ---------------------------------------------------------------------------------------------

// UploadInput is the request of sarifUpload.
type UploadInput struct {
	CommitSHA      string
	Ref            string
	ToolName       string
	Sarif          string
	PR             int
	IdempotencyKey string
}

var (
	reSHA  = regexp.MustCompile(`^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)
	reTool = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$`)
	reIdem = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	rePull = regexp.MustCompile(`^refs/pull/(\d{1,9})/(?:head|merge)$`)
)

// NormalizeRef maps a git ref to the branch name alerts are keyed by (refs/heads/x -> x,
// refs/pull/N/head -> pull/N with pr=N, refs/tags/x -> tag/x, a bare name stays).
func NormalizeRef(ref string) (branch string, pr int, err error) {
	ref = strings.TrimSpace(ref)
	switch {
	case ref == "" || len(ref) > 255:
		return "", 0, errors.New("ref obligatorio (maximo 255 caracteres)")
	case strings.HasPrefix(ref, "refs/heads/"):
		branch = strings.TrimPrefix(ref, "refs/heads/")
	case rePull.MatchString(ref):
		n, _ := strconv.Atoi(rePull.FindStringSubmatch(ref)[1])
		return "pull/" + strconv.Itoa(n), n, nil
	case strings.HasPrefix(ref, "refs/tags/"):
		branch = "tag/" + strings.TrimPrefix(ref, "refs/tags/")
	case strings.HasPrefix(ref, "refs/"):
		return "", 0, errors.New("ref no soportado: usa refs/heads/<rama>, refs/pull/<n>/head o refs/tags/<etiqueta>")
	default:
		branch = ref
	}
	if branch == "" || strings.ContainsAny(branch, " \t\r\n\x00") || strings.Contains(branch, "..") {
		return "", 0, errors.New("nombre de rama no valido")
	}
	return branch, 0, nil
}

func (s *Service) allowUpload(projectID uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	cut := now.Add(-time.Minute)
	b := s.buckets[projectID][:0]
	for _, t := range s.buckets[projectID] {
		if t.After(cut) {
			b = append(b, t)
		}
	}
	if len(b) >= s.cfg.UploadsPerMinute {
		s.buckets[projectID] = b
		return false
	}
	s.buckets[projectID] = append(b, now)
	return true
}

// Upload validates and parses a SARIF upload synchronously (clear errors, nothing untrusted
// reaches the database) and queues it for the worker. The original SARIF is not stored: only the
// sanitized findings, which carry no secret values.
func (s *Service) Upload(ctx context.Context, t Target, a Actor, in UploadInput) (*Upload, error) {
	var fields []FieldError
	sha := strings.ToLower(strings.TrimSpace(in.CommitSHA))
	if !reSHA.MatchString(sha) {
		fields = append(fields, FieldError{"commit_sha", "debe ser el SHA completo (40 o 64 caracteres hexadecimales)"})
	}
	branch, prFromRef, refErr := NormalizeRef(in.Ref)
	if refErr != nil {
		fields = append(fields, FieldError{"ref", refErr.Error()})
	}
	hint := strings.TrimSpace(in.ToolName)
	if hint != "" && !reTool.MatchString(hint) {
		fields = append(fields, FieldError{"tool_name", "1 a 64 caracteres: letras, digitos, punto, guion, guion bajo y espacio"})
	}
	if in.IdempotencyKey != "" && !reIdem.MatchString(in.IdempotencyKey) {
		fields = append(fields, FieldError{"Idempotency-Key", "1 a 128 caracteres: letras, digitos y . _ : -"})
	}
	if in.PR < 0 {
		fields = append(fields, FieldError{"pr", "no puede ser negativo"})
	}
	if len(fields) > 0 {
		return nil, &ValidationError{Fields: fields}
	}
	pr := in.PR
	if pr == 0 {
		pr = prFromRef
	}
	if !s.allowUpload(t.ProjectID) {
		return nil, ErrRateLimit
	}
	parsed, err := s.parser.Parse(in.Sarif, hint, t.ProjectSlug)
	if err != nil {
		return nil, err
	}
	scopes := parsed.Scopes
	if len(scopes) == 0 {
		return nil, sarifErr("SARIF_INVALID", "el SARIF no tiene ningun run")
	}
	now := s.now()
	u := &Upload{
		ID: uuid.New(), ProjectID: t.ProjectID, CommitSHA: sha, Ref: strings.TrimSpace(in.Ref), Branch: branch, PR: pr,
		Tool: scopes[0].Tool, ToolName: scopes[0].ToolName, Status: UploadPending, IdempotencyKey: in.IdempotencyKey,
		ResultsTotal: parsed.ResultsTotal, CreatedBy: a.UserID, CreatedAt: now,
	}
	audit := AuditEntry{
		OrgID: t.OrgID, UserID: a.UserID, Action: AuditSarifUpload, ResourceType: "sarif_upload", ResourceID: u.ID, IP: a.IP,
		NewValues: map[string]any{"commit_sha": sha, "branch": branch, "tool": u.Tool, "results": parsed.ResultsTotal},
	}
	existing, created, err := s.store.CreateUpload(ctx, u, UploadPayload{Scopes: scopes, Findings: parsed.Findings}, audit)
	if err != nil {
		return nil, err
	}
	if !created {
		return existing, nil
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return u, nil
}

// UploadStatus returns one upload of the project (sarifStatus).
func (s *Service) UploadStatus(ctx context.Context, projectID, id uuid.UUID) (*Upload, error) {
	return s.store.GetUpload(ctx, projectID, id)
}

// ---------------------------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------------------------

// ListAlerts lists alerts (secrets only when q.IncludeSecrets).
func (s *Service) ListAlerts(ctx context.Context, projectID uuid.UUID, q AlertQuery) ([]Alert, string, error) {
	var fields []FieldError
	if q.Kind != "" && !Kind(q.Kind).Valid() {
		fields = append(fields, FieldError{"kind", "dependency|code|secret"})
	}
	if q.Severity != "" && !Severity(q.Severity).Valid() {
		fields = append(fields, FieldError{"severity", "critical|high|medium|low|info"})
	}
	if q.State != "" && State(q.State) != StateOpen && State(q.State) != StateFixed && State(q.State) != StateDismissed {
		fields = append(fields, FieldError{"state", "open|fixed|dismissed"})
	}
	if q.Tool != "" && !validTool(q.Tool) {
		fields = append(fields, FieldError{"tool", "herramienta desconocida"})
	}
	if len(fields) > 0 {
		return nil, "", &ValidationError{Fields: fields}
	}
	if q.Limit <= 0 {
		q.Limit = 30
	}
	if q.Limit > 100 {
		q.Limit = 100
	}
	return s.store.ListAlerts(ctx, projectID, q)
}

// GetAlert returns one alert.
func (s *Service) GetAlert(ctx context.Context, projectID, id uuid.UUID) (*Alert, error) {
	return s.store.GetAlert(ctx, projectID, id)
}

// OverviewResult is the contract SecurityOverview.
type OverviewResult struct {
	Overview
	PolicyBlocking bool
}

// Overview returns the counters and whether the deploy policy is currently blocking.
func (s *Service) Overview(ctx context.Context, projectID uuid.UUID) (*OverviewResult, error) {
	o, err := s.store.Overview(ctx, projectID)
	if err != nil {
		return nil, err
	}
	p, err := s.GetPolicy(ctx, projectID)
	if err != nil {
		return nil, err
	}
	blocking := false
	switch p.BlockDeployOn {
	case "critical":
		blocking = o.BySeverity[string(SevCritical)] > 0
	case "high":
		blocking = o.BySeverity[string(SevCritical)]+o.BySeverity[string(SevHigh)] > 0
	}
	return &OverviewResult{Overview: *o, PolicyBlocking: blocking}, nil
}

// DismissInput is the request of alertDismiss.
type DismissInput struct {
	Reason        string
	Justification string
	ExpiresAt     time.Time
}

// maxDays is the longest allowed suppression: the project's limit (<= 365), 180 for critical/high.
func (s *Service) maxDays(ctx context.Context, projectID uuid.UUID, high bool) (int, error) {
	p, err := s.GetPolicy(ctx, projectID)
	if err != nil {
		return 0, err
	}
	days := p.MaxSuppressionDays
	if days <= 0 || days > MaxSuppressionDays {
		days = MaxSuppressionDays
	}
	if high && days > MaxSuppressionDaysHi {
		days = MaxSuppressionDaysHi
	}
	return days, nil
}

func (s *Service) validateSuppressionTerms(reason, justification string, expires time.Time, days int) []FieldError {
	var fields []FieldError
	if !validReason(reason) {
		fields = append(fields, FieldError{"reason", "uno de: " + strings.Join(Reasons, ", ")})
	}
	if n := utf8.RuneCountInString(strings.TrimSpace(justification)); n < MinJustificationRunes {
		fields = append(fields, FieldError{"justification", fmt.Sprintf("minimo %d caracteres (tiene %d)", MinJustificationRunes, n)})
	} else if n > 2000 {
		fields = append(fields, FieldError{"justification", "maximo 2000 caracteres"})
	}
	now := s.now()
	switch {
	case expires.IsZero():
		fields = append(fields, FieldError{"expires_at", "obligatoria"})
	case !expires.After(now):
		fields = append(fields, FieldError{"expires_at", "debe ser futura"})
	case expires.After(now.AddDate(0, 0, days)):
		fields = append(fields, FieldError{"expires_at", fmt.Sprintf("maximo %d dias desde hoy", days)})
	}
	return fields
}

func (s *Service) actorAudit(t Target, a Actor, action, resType string, resID uuid.UUID, old, nw map[string]any) AuditEntry {
	return AuditEntry{OrgID: t.OrgID, UserID: a.UserID, Action: action, ResourceType: resType, ResourceID: resID, IP: a.IP, OldValues: old, NewValues: nw}
}

// Dismiss suppresses one alert (alertDismiss). Reason enum, justification >= 10 characters and
// expiry are mandatory; the expiry is at most the policy limit (365 days max) and 180 days for
// critical/high, which also require security.admin (a.Admin).
func (s *Service) Dismiss(ctx context.Context, t Target, a Actor, alertID uuid.UUID, in DismissInput) (*Alert, error) {
	al, err := s.store.GetAlert(ctx, t.ProjectID, alertID)
	if err != nil {
		return nil, err
	}
	high := al.Severity.HighOrAbove()
	days, err := s.maxDays(ctx, t.ProjectID, high)
	if err != nil {
		return nil, err
	}
	if fields := s.validateSuppressionTerms(in.Reason, in.Justification, in.ExpiresAt, days); len(fields) > 0 {
		return nil, &ValidationError{Fields: fields}
	}
	if high && !a.Admin {
		return nil, &ForbiddenError{Code: "ADMIN_REQUIRED", Message: "descartar una alerta critical o high exige security.admin"}
	}
	if al.State != StateOpen {
		return nil, &ConflictError{Code: "ALERT_STATE_CONFLICT", Message: "solo se puede descartar una alerta abierta (estado actual: " + string(al.State) + ")"}
	}
	now := s.now()
	out, err := s.store.DismissAlert(ctx, t.ProjectID, alertID, DismissParams{
		Reason: in.Reason, Justification: strings.TrimSpace(in.Justification), ExpiresAt: in.ExpiresAt.UTC(),
		By: a.UserID, CoversHigh: high,
	}, now, s.actorAudit(t, a, AuditAlertDismiss, "security_alert", alertID, map[string]any{"state": "open"},
		map[string]any{"state": "dismissed", "reason": in.Reason, "expires_at": in.ExpiresAt.UTC().Format(time.RFC3339), "severity": string(al.Severity), "kind": string(al.Kind)}))
	if err != nil {
		return nil, err
	}
	if out.Dismissal != nil && out.Dismissal.By.Name == "" && out.Dismissal.By.Email == "" && a.UserID != uuid.Nil {
		uid := a.UserID
		out.Dismissal.By = Person{UserID: &uid, Name: a.Login}
	}
	s.publish(ctx, t, gitevents.SecurityAlertDismiss, a.Login, out.Branch, map[string]any{
		"alert_id": out.ID.String(), "kind": string(out.Kind), "severity": string(out.Severity), "rule_id": out.RuleID,
		"path": out.Path, "reason": in.Reason, "expires_at": in.ExpiresAt.UTC().Format(time.RFC3339),
	})
	s.ReevaluateRecent(ctx, t)
	return out, nil
}

// Reopen reopens a dismissed alert (alertReopen).
func (s *Service) Reopen(ctx context.Context, t Target, a Actor, alertID uuid.UUID) (*Alert, error) {
	al, err := s.store.GetAlert(ctx, t.ProjectID, alertID)
	if err != nil {
		return nil, err
	}
	// Dismissing critical/high needs security.admin; reopening is the safe direction, so
	// security.triage is enough.
	out, err := s.store.ReopenAlert(ctx, t.ProjectID, alertID, s.now(),
		s.actorAudit(t, a, AuditAlertReopen, "security_alert", alertID, map[string]any{"state": string(al.State)}, map[string]any{"state": "open"}))
	if err != nil {
		return nil, err
	}
	s.ReevaluateRecent(ctx, t)
	return out, nil
}

// ---------------------------------------------------------------------------------------------
// Suppressions
// ---------------------------------------------------------------------------------------------

// SuppressionInput is the request of suppressionCreate.
type SuppressionInput struct {
	Match         SuppressionMatch
	Reason        string
	Justification string
	ExpiresAt     time.Time
}

var reFingerprint = regexp.MustCompile(`^[0-9a-f]{16,64}$`)

// ListSuppressions lists active, expired and revoked suppressions.
func (s *Service) ListSuppressions(ctx context.Context, projectID uuid.UUID) ([]Suppression, error) {
	return s.store.ListSuppressions(ctx, projectID)
}

// CreateSuppression creates a rule/fingerprint/path suppression. If it currently covers a
// critical/high alert it needs security.admin and lasts at most 180 days and may keep covering
// critical/high alerts; otherwise it only ever suppresses medium and lower.
func (s *Service) CreateSuppression(ctx context.Context, t Target, a Actor, in SuppressionInput) (*Suppression, int, error) {
	var fields []FieldError
	m := SuppressionMatch{
		RuleID: plain(in.Match.RuleID, 255), Fingerprint: strings.ToLower(strings.TrimSpace(in.Match.Fingerprint)),
		PathGlob: strings.TrimSpace(in.Match.PathGlob),
	}
	if m.RuleID == "" && m.Fingerprint == "" && m.PathGlob == "" {
		fields = append(fields, FieldError{"match", "indica al menos rule_id, fingerprint o path_glob"})
	}
	if m.Fingerprint != "" && !reFingerprint.MatchString(m.Fingerprint) {
		fields = append(fields, FieldError{"match.fingerprint", "huella hexadecimal de 16 a 64 caracteres"})
	}
	if m.PathGlob != "" {
		switch {
		case globMatchesEverything(m.PathGlob):
			fields = append(fields, FieldError{"match.path_glob", "el glob no puede cubrir todo el repositorio (**, *, **/*): acota la ruta"})
		case len(m.PathGlob) > 512 || strings.Contains(m.PathGlob, "..") || strings.ContainsAny(m.PathGlob, "\x00\r\n"):
			fields = append(fields, FieldError{"match.path_glob", "glob no valido"})
		default:
			if _, err := globToRegexp(m.PathGlob); err != nil {
				fields = append(fields, FieldError{"match.path_glob", "glob no valido"})
			}
		}
	}
	sev, found, err := s.store.MaxSeverityMatching(ctx, t.ProjectID, m)
	if err != nil {
		return nil, 0, err
	}
	high := found && sev.HighOrAbove()
	days, err := s.maxDays(ctx, t.ProjectID, high)
	if err != nil {
		return nil, 0, err
	}
	fields = append(fields, s.validateSuppressionTerms(in.Reason, in.Justification, in.ExpiresAt, days)...)
	if len(fields) > 0 {
		return nil, 0, &ValidationError{Fields: fields}
	}
	if high && !a.Admin {
		return nil, 0, &ForbiddenError{Code: "ADMIN_REQUIRED", Message: "la supresion cubre alertas critical o high: exige security.admin"}
	}
	now := s.now()
	sp := &Suppression{
		ID: uuid.New(), ProjectID: t.ProjectID, Match: m, Reason: in.Reason, Justification: strings.TrimSpace(in.Justification),
		ExpiresAt: in.ExpiresAt.UTC(), State: SuppActive, Source: "manual", CoversHigh: high && a.Admin,
		CreatedBy: a.UserID, CreatedAt: now,
	}
	applied, err := s.store.CreateSuppression(ctx, sp, now, s.actorAudit(t, a, AuditSuppressionCreate, "security_suppression", sp.ID, nil,
		map[string]any{"rule_id": m.RuleID, "fingerprint": m.Fingerprint, "path_glob": m.PathGlob, "reason": in.Reason, "expires_at": sp.ExpiresAt.Format(time.RFC3339), "alerts": 0}))
	if err != nil {
		return nil, 0, err
	}
	s.ReevaluateRecent(ctx, t)
	return sp, applied, nil
}

// RevokeSuppression revokes a suppression; the alerts it covered go back to open.
func (s *Service) RevokeSuppression(ctx context.Context, t Target, a Actor, id uuid.UUID) error {
	_, err := s.store.RevokeSuppression(ctx, t.ProjectID, id, a.UserID, s.now(),
		s.actorAudit(t, a, AuditSuppressionRevoke, "security_suppression", id, map[string]any{"state": "active"}, map[string]any{"state": "revoked"}))
	if err != nil {
		return err
	}
	s.ReevaluateRecent(ctx, t)
	return nil
}

// ---------------------------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------------------------

// GetPolicy returns the stored policy or the default one.
func (s *Service) GetPolicy(ctx context.Context, projectID uuid.UUID) (*Policy, error) {
	p, err := s.store.GetPolicy(ctx, projectID)
	if errors.Is(err, ErrNoPolicy) {
		d := DefaultPolicy()
		return &d, nil
	}
	if err != nil {
		return nil, err
	}
	return normalizePolicy(p), nil
}

func normalizePolicy(p *Policy) *Policy {
	if p.RequiredTools == nil {
		p.RequiredTools = []string{}
	}
	if p.AppliesToBranches == nil {
		p.AppliesToBranches = []string{}
	}
	return p
}

var reToolReq = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidatePolicy checks a policy and returns the normalized copy.
func ValidatePolicy(in Policy) (Policy, error) {
	var fields []FieldError
	sevs := map[string]bool{"off": true, "critical": true, "high": true, "medium": true, "low": true}
	if !sevs[in.BlockMergeOn.Dependency] {
		fields = append(fields, FieldError{"block_merge_on.dependency", "off|critical|high|medium|low"})
	}
	if !sevs[in.BlockMergeOn.Code] {
		fields = append(fields, FieldError{"block_merge_on.code", "off|critical|high|medium|low"})
	}
	if in.BlockMergeOn.Secret != "off" && in.BlockMergeOn.Secret != "any" {
		fields = append(fields, FieldError{"block_merge_on.secret", "off|any"})
	}
	if in.BlockDeployOn != "off" && in.BlockDeployOn != "critical" && in.BlockDeployOn != "high" {
		fields = append(fields, FieldError{"block_deploy_on", "off|critical|high"})
	}
	if in.MaxSuppressionDays < 1 || in.MaxSuppressionDays > MaxSuppressionDays {
		fields = append(fields, FieldError{"max_suppression_days", fmt.Sprintf("entre 1 y %d", MaxSuppressionDays)})
	}
	if len(in.RequiredTools) > 20 {
		fields = append(fields, FieldError{"required_tools", "maximo 20"})
	}
	tools := make([]string, 0, len(in.RequiredTools))
	seen := map[string]bool{}
	for i, t := range in.RequiredTools {
		t = strings.ToLower(strings.TrimSpace(t))
		if !reToolReq.MatchString(t) {
			fields = append(fields, FieldError{fmt.Sprintf("required_tools[%d]", i), "nombre de herramienta no valido"})
			continue
		}
		if !seen[t] {
			seen[t] = true
			tools = append(tools, t)
		}
	}
	if len(in.AppliesToBranches) > 50 {
		fields = append(fields, FieldError{"applies_to_branches", "maximo 50"})
	}
	branches := make([]string, 0, len(in.AppliesToBranches))
	for i, b := range in.AppliesToBranches {
		b = strings.TrimSpace(b)
		if b == "" || len(b) > 255 || strings.ContainsAny(b, " \t\r\n\x00") {
			fields = append(fields, FieldError{fmt.Sprintf("applies_to_branches[%d]", i), "patron de rama no valido"})
			continue
		}
		branches = append(branches, b)
	}
	if len(fields) > 0 {
		return Policy{}, &ValidationError{Fields: fields}
	}
	in.RequiredTools, in.AppliesToBranches = tools, branches
	return in, nil
}

// PutPolicy validates and stores the policy (security.admin is checked by the handler).
func (s *Service) PutPolicy(ctx context.Context, t Target, a Actor, in Policy) (*Policy, error) {
	p, err := ValidatePolicy(in)
	if err != nil {
		return nil, err
	}
	old, _ := s.GetPolicy(ctx, t.ProjectID)
	var oldV map[string]any
	if old != nil {
		oldV = policyMap(*old)
	}
	if err := s.store.PutPolicy(ctx, t.ProjectID, p, a.UserID, s.now(),
		s.actorAudit(t, a, AuditPolicyChange, "security_policy", t.ProjectID, oldV, policyMap(p))); err != nil {
		return nil, err
	}
	s.ReevaluateRecent(ctx, t)
	return &p, nil
}

func policyMap(p Policy) map[string]any {
	return map[string]any{
		"block_merge_dependency": p.BlockMergeOn.Dependency, "block_merge_code": p.BlockMergeOn.Code,
		"block_merge_secret": p.BlockMergeOn.Secret, "block_deploy_on": p.BlockDeployOn,
		"required_tools": p.RequiredTools, "max_suppression_days": p.MaxSuppressionDays,
		"applies_to_branches": p.AppliesToBranches,
	}
}

// ---------------------------------------------------------------------------------------------
// Scans (scanTrigger)
// ---------------------------------------------------------------------------------------------

// ScanWorkflows maps a scan tool to the workflow template that runs it and uploads its SARIF.
var ScanWorkflows = map[string]string{
	ToolOSV:      "security-audit.yml",
	ToolSemgrep:  "sast.yml",
	ToolGitleaks: "gitleaks.yml",
	ToolTrivy:    "trivy.yml",
}

// TriggerScan dispatches the workflows of the requested tools (default: all four) on ref
// (default: the repository's default branch). The workflows publish their SARIF to
// /security/sarif when they finish; the Job only says they were queued.
func (s *Service) TriggerScan(ctx context.Context, t Target, a Actor, tools []string, ref, idemKey string) (*Job, error) {
	if s.forge == nil || !s.forge.Enabled() {
		return nil, gitcore.ErrNotReady
	}
	if job := s.idempotent("scan:"+t.ProjectID.String()+":"+idemKey, idemKey); job != nil {
		return job, nil
	}
	if len(tools) == 0 {
		tools = []string{ToolOSV, ToolSemgrep, ToolGitleaks, ToolTrivy}
	}
	var fields []FieldError
	seen := map[string]bool{}
	var list []string
	for i, tl := range tools {
		if _, ok := ScanWorkflows[tl]; !ok {
			fields = append(fields, FieldError{fmt.Sprintf("tools[%d]", i), "osv-scanner|semgrep|gitleaks|trivy"})
			continue
		}
		if !seen[tl] {
			seen[tl] = true
			list = append(list, tl)
		}
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		def, err := s.store.DefaultBranchOf(ctx, t.ProjectID)
		if err != nil || def == "" {
			def = "main"
			if r, gerr := s.forge.GetRepo(ctx, repoRef(t)); gerr == nil && r.DefaultBranch != "" {
				def = r.DefaultBranch
			}
		}
		ref = def
	} else if b, _, err := NormalizeRef(ref); err != nil {
		fields = append(fields, FieldError{"ref", err.Error()})
	} else {
		ref = b
	}
	if len(fields) > 0 {
		return nil, &ValidationError{Fields: fields}
	}
	var ok, failed []string
	var firstErr error
	for _, tl := range list {
		if err := s.forge.DispatchWorkflow(ctx, repoRef(t), ScanWorkflows[tl], ref, nil); err != nil {
			failed = append(failed, tl)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ok = append(ok, tl)
	}
	if len(ok) == 0 {
		return nil, firstErr
	}
	job := Job{ID: uuid.New(), Status: "queued", Detail: "queued: " + strings.Join(ok, ", ")}
	if len(failed) > 0 {
		job.Detail += "; not dispatched: " + strings.Join(failed, ", ")
	}
	_ = s.store.WriteAudit(ctx, s.actorAudit(t, a, AuditScanTrigger, "security_scan", job.ID, nil,
		map[string]any{"tools": ok, "ref": ref}))
	s.rememberIdem("scan:"+t.ProjectID.String()+":"+idemKey, idemKey, job)
	return &job, nil
}

func (s *Service) idempotent(key, raw string) *Job {
	if raw == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.idem[key]
	if !ok || s.now().Sub(e.at) > 10*time.Minute {
		return nil
	}
	j := e.job
	return &j
}

func (s *Service) rememberIdem(key, raw string, j Job) {
	if raw == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.idem {
		if s.now().Sub(e.at) > 10*time.Minute {
			delete(s.idem, k)
		}
	}
	s.idem[key] = idemEntry{job: j, at: s.now()}
}
