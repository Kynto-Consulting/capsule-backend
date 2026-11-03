package security

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemStore is an in-memory Store for tests of this package and of the handlers. It follows the
// same rules as the Postgres store (Reconcile, suppression semantics) but is not meant for
// production.
type MemStore struct {
	mu          sync.Mutex
	Targets     map[uuid.UUID]Target
	Defaults    map[uuid.UUID]string
	Alerts      map[uuid.UUID]*Alert
	Supps       map[uuid.UUID]*Suppression
	Policies    map[uuid.UUID]Policy
	Uploads     map[uuid.UUID]*Upload
	Payloads    map[uuid.UUID]UploadPayload
	Checks      map[string]*CheckRun
	Renovate    map[uuid.UUID]*RenovateState
	Audits      []AuditEntry
	applied     map[string]time.Time // scope key -> created_at of the latest applied upload
	FailApplyN  int                  // fail the next N ApplyUpload calls (tests)
	UploadsDone []uuid.UUID
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{
		Targets: map[uuid.UUID]Target{}, Defaults: map[uuid.UUID]string{}, Alerts: map[uuid.UUID]*Alert{},
		Supps: map[uuid.UUID]*Suppression{}, Policies: map[uuid.UUID]Policy{}, Uploads: map[uuid.UUID]*Upload{},
		Payloads: map[uuid.UUID]UploadPayload{}, Checks: map[string]*CheckRun{}, Renovate: map[uuid.UUID]*RenovateState{},
		applied: map[string]time.Time{},
	}
}

// AddProject registers a project target (default branch main).
func (m *MemStore) AddProject(t Target) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Targets[t.ProjectID] = t
	m.Defaults[t.ProjectID] = "main"
}

var _ Store = (*MemStore)(nil)

func (m *MemStore) audit(a AuditEntry) { m.Audits = append(m.Audits, a) }

func (m *MemStore) WriteAudit(_ context.Context, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit(a)
	return nil
}

func (m *MemStore) CreateUpload(_ context.Context, u *Upload, p UploadPayload, a AuditEntry) (*Upload, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u.IdempotencyKey != "" {
		for _, e := range m.Uploads {
			if e.ProjectID == u.ProjectID && e.IdempotencyKey == u.IdempotencyKey {
				c := *e
				return &c, false, nil
			}
		}
	}
	c := *u
	m.Uploads[u.ID] = &c
	m.Payloads[u.ID] = p
	m.audit(a)
	return nil, true, nil
}

func (m *MemStore) GetUpload(_ context.Context, projectID, id uuid.UUID) (*Upload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.Uploads[id]
	if !ok || u.ProjectID != projectID {
		return nil, ErrNotFound
	}
	c := *u
	return &c, nil
}

func (m *MemStore) ClaimUploads(_ context.Context, limit int, stale time.Duration, now time.Time) ([]ClaimedUpload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []*Upload
	for _, u := range m.Uploads {
		if u.Status == UploadPending || (u.Status == UploadProcessing && u.StartedAt != nil && now.Sub(*u.StartedAt) > stale) {
			ids = append(ids, u)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].CreatedAt.Before(ids[j].CreatedAt) })
	var out []ClaimedUpload
	for _, u := range ids {
		if len(out) >= limit {
			break
		}
		u.Status, u.Attempts = UploadProcessing, u.Attempts+1
		t := now
		u.StartedAt = &t
		out = append(out, ClaimedUpload{Upload: *u, Payload: m.Payloads[u.ID]})
	}
	return out, nil
}

func (m *MemStore) suppList(projectID uuid.UUID) []Suppression {
	var out []Suppression
	for _, s := range m.Supps {
		if s.ProjectID == projectID {
			out = append(out, *s)
		}
	}
	return out
}

func (m *MemStore) ApplyUpload(_ context.Context, cu ClaimedUpload, now time.Time) (*ApplyResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailApplyN > 0 {
		m.FailApplyN--
		return nil, context.DeadlineExceeded
	}
	res := &ApplyResult{}
	up := m.Uploads[cu.ID]
	set := NewSuppressionSet(m.suppList(cu.ProjectID), now)
	superseded := true
	for _, sc := range cu.Payload.Scopes {
		key := cu.ProjectID.String() + "|" + cu.Branch + "|" + sc.ToolName
		if last, ok := m.applied[key]; ok && last.After(cu.CreatedAt) {
			continue
		}
		superseded = false
		m.applied[key] = cu.CreatedAt
		var existing []Alert
		for _, a := range m.Alerts {
			if a.ProjectID == cu.ProjectID && a.Branch == cu.Branch && a.ToolName == sc.ToolName {
				existing = append(existing, *a)
			}
		}
		var fs []Finding
		for _, f := range cu.Payload.Findings {
			if f.ToolName == sc.ToolName {
				fs = append(fs, f)
			}
		}
		plan := Reconcile(ReconcileInput{ProjectID: cu.ProjectID, Branch: cu.Branch, SHA: cu.CommitSHA, UploadID: cu.ID,
			Scope: sc, Findings: fs, Existing: existing, Supp: set, Now: now})
		for i := range plan.Insert {
			a := plan.Insert[i]
			m.Alerts[a.ID] = &a
		}
		for i := range plan.Update {
			a := plan.Update[i]
			m.Alerts[a.ID] = &a
		}
		res.Created = append(res.Created, plan.Created...)
		res.Fixed += plan.Fixed
	}
	res.Superseded = superseded
	up.Status, up.Superseded, up.AlertsFixed, up.AlertsCreated = UploadComplete, superseded, res.Fixed, len(res.Created)
	t := now
	up.CompletedAt = &t
	delete(m.Payloads, cu.ID)
	m.UploadsDone = append(m.UploadsDone, cu.ID)
	return res, nil
}

func (m *MemStore) FailUpload(_ context.Context, id uuid.UUID, msg string, final bool, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.Uploads[id]
	if !ok {
		return ErrNotFound
	}
	u.Error = msg
	if final {
		u.Status = UploadFailed
		delete(m.Payloads, id)
	} else {
		u.Status = UploadPending
	}
	return nil
}

func (m *MemStore) ListAlerts(_ context.Context, projectID uuid.UUID, q AlertQuery) ([]Alert, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []Alert
	for _, a := range m.Alerts {
		if a.ProjectID != projectID {
			continue
		}
		if a.Kind == KindSecret && !q.IncludeSecrets {
			continue
		}
		if (q.Kind != "" && string(a.Kind) != q.Kind) || (q.Severity != "" && string(a.Severity) != q.Severity) ||
			(q.State != "" && string(a.State) != q.State) || (q.Branch != "" && a.Branch != q.Branch) ||
			(q.Tool != "" && a.Tool != q.Tool) {
			continue
		}
		all = append(all, *a)
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.After(all[j].CreatedAt)
		}
		return all[i].ID.String() > all[j].ID.String()
	})
	start := 0
	if q.Cursor != "" {
		n, err := strconv.Atoi(q.Cursor)
		if err != nil || n < 0 {
			return nil, "", &ValidationError{Fields: []FieldError{{"cursor", "cursor no valido"}}}
		}
		start = n
	}
	if start > len(all) {
		start = len(all)
	}
	end := start + q.Limit
	next := ""
	if end < len(all) {
		next = strconv.Itoa(end)
	} else {
		end = len(all)
	}
	return all[start:end], next, nil
}

func (m *MemStore) GetAlert(_ context.Context, projectID, id uuid.UUID) (*Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.Alerts[id]
	if !ok || a.ProjectID != projectID {
		return nil, ErrNotFound
	}
	c := *a
	if a.Dismissal != nil {
		d := *a.Dismissal
		c.Dismissal = &d
	}
	return &c, nil
}

func (m *MemStore) Overview(_ context.Context, projectID uuid.UUID) (*Overview, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := &Overview{BySeverity: map[string]int{}, ByKind: map[string]int{}}
	for _, a := range m.Alerts {
		if a.ProjectID != projectID {
			continue
		}
		switch a.State {
		case StateOpen:
			o.Open++
			o.BySeverity[string(a.Severity)]++
			o.ByKind[string(a.Kind)]++
		case StateDismissed:
			o.Dismissed++
		}
	}
	for _, u := range m.Uploads {
		if u.ProjectID == projectID && u.Status == UploadComplete && u.CompletedAt != nil && (o.LastScanAt == nil || u.CompletedAt.After(*o.LastScanAt)) {
			t := *u.CompletedAt
			o.LastScanAt = &t
		}
	}
	return o, nil
}

func (m *MemStore) DismissAlert(_ context.Context, projectID, id uuid.UUID, p DismissParams, now time.Time, a AuditEntry) (*Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	al, ok := m.Alerts[id]
	if !ok || al.ProjectID != projectID {
		return nil, ErrNotFound
	}
	if al.State != StateOpen {
		return nil, &ConflictError{Code: "ALERT_STATE_CONFLICT", Message: "solo se puede descartar una alerta abierta"}
	}
	sp := &Suppression{
		ID: uuid.New(), ProjectID: projectID, Match: SuppressionMatch{Fingerprint: al.Fingerprint}, Reason: p.Reason,
		Justification: p.Justification, ExpiresAt: p.ExpiresAt, State: SuppActive, Source: "alert", AlertID: id,
		CoversHigh: p.CoversHigh, CreatedBy: p.By, CreatedAt: now,
	}
	m.Supps[sp.ID] = sp
	for _, o := range m.Alerts {
		if o.ProjectID == projectID && o.State == StateOpen && o.Fingerprint == al.Fingerprint {
			dismissInto(o, sp, now)
		}
	}
	m.audit(a)
	c := *al
	d := *al.Dismissal
	c.Dismissal = &d
	return &c, nil
}

func dismissInto(a *Alert, sp *Suppression, now time.Time) {
	a.State = StateDismissed
	a.SuppressionID = sp.ID
	a.Dismissal = &Dismissal{Reason: sp.Reason, Justification: sp.Justification, ByUserID: sp.CreatedBy, ExpiresAt: sp.ExpiresAt, At: now}
	a.UpdatedAt = now
}

func (m *MemStore) reopenCovered(suppID uuid.UUID, now time.Time) int {
	n := 0
	for _, o := range m.Alerts {
		if o.State == StateDismissed && o.SuppressionID == suppID {
			o.State, o.Dismissal, o.SuppressionID, o.UpdatedAt = StateOpen, nil, uuid.Nil, now
			n++
		}
	}
	return n
}

func (m *MemStore) ReopenAlert(_ context.Context, projectID, id uuid.UUID, now time.Time, a AuditEntry) (*Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	al, ok := m.Alerts[id]
	if !ok || al.ProjectID != projectID {
		return nil, ErrNotFound
	}
	if al.State != StateDismissed {
		return nil, &ConflictError{Code: "ALERT_STATE_CONFLICT", Message: "solo se puede reabrir una alerta descartada"}
	}
	sp := m.Supps[al.SuppressionID]
	if sp != nil && sp.Source == "manual" && sp.State == SuppActive {
		return nil, &ConflictError{Code: "SUPPRESSED_BY_RULE", Message: "la alerta esta cubierta por una supresion: revocala"}
	}
	if sp != nil {
		sp.State = SuppRevoked
		t := now
		sp.RevokedAt = &t
		m.reopenCovered(sp.ID, now)
	}
	if al.State == StateDismissed { // dismissed without a suppression row
		al.State, al.Dismissal, al.SuppressionID, al.UpdatedAt = StateOpen, nil, uuid.Nil, now
	}
	m.audit(a)
	c := *al
	return &c, nil
}

func (m *MemStore) ListSuppressions(_ context.Context, projectID uuid.UUID) ([]Suppression, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.suppList(projectID)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemStore) MaxSeverityMatching(_ context.Context, projectID uuid.UUID, mt SuppressionMatch) (Severity, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	probe := Suppression{Match: mt}
	best, found := Severity(""), false
	for _, a := range m.Alerts {
		if a.ProjectID == projectID && a.State == StateOpen && MatchesIgnoringSeverity(probe, a) {
			if !found || a.Severity.Rank() > best.Rank() {
				best, found = a.Severity, true
			}
		}
	}
	return best, found, nil
}

func (m *MemStore) CreateSuppression(_ context.Context, s *Suppression, now time.Time, a AuditEntry) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *s
	m.Supps[s.ID] = &c
	set := NewSuppressionSet([]Suppression{c}, now)
	n := 0
	for _, o := range m.Alerts {
		if o.ProjectID == s.ProjectID && o.State == StateOpen && set.MatchAlert(o) != nil {
			dismissInto(o, &c, now)
			n++
		}
	}
	a.NewValues["alerts"] = n
	m.audit(a)
	return n, nil
}

func (m *MemStore) RevokeSuppression(_ context.Context, projectID, id, by uuid.UUID, now time.Time, a AuditEntry) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.Supps[id]
	if !ok || s.ProjectID != projectID || s.State != SuppActive {
		return 0, ErrNotFound
	}
	s.State = SuppRevoked
	t := now
	s.RevokedAt = &t
	n := m.reopenCovered(id, now)
	m.audit(a)
	return n, nil
}

func (m *MemStore) ExpireDue(_ context.Context, now time.Time) ([]ExpiryResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	by := map[uuid.UUID]*ExpiryResult{}
	get := func(p uuid.UUID) *ExpiryResult {
		if by[p] == nil {
			by[p] = &ExpiryResult{Target: m.Targets[p]}
		}
		return by[p]
	}
	for _, s := range m.Supps {
		if s.State == SuppActive && !s.ExpiresAt.After(now) {
			s.State = SuppExpired
			r := get(s.ProjectID)
			r.Suppressions = append(r.Suppressions, s.ID)
			r.AlertsReopened += m.reopenCovered(s.ID, now)
		}
	}
	for _, a := range m.Alerts {
		if a.State == StateDismissed && a.Dismissal != nil && !a.Dismissal.ExpiresAt.After(now) {
			a.State, a.Dismissal, a.SuppressionID, a.UpdatedAt = StateOpen, nil, uuid.Nil, now
			get(a.ProjectID).AlertsReopened++
		}
	}
	var out []ExpiryResult
	for _, r := range by {
		out = append(out, *r)
	}
	return out, nil
}

func (m *MemStore) DueExpiringNotices(_ context.Context, now time.Time, window time.Duration) ([]Suppression, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Suppression
	for _, s := range m.Supps {
		if s.State == SuppActive && s.NotifiedExpiringAt == nil && s.ExpiresAt.After(now) && !s.ExpiresAt.After(now.Add(window)) {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (m *MemStore) MarkExpiringNotified(_ context.Context, ids []uuid.UUID, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		if s := m.Supps[id]; s != nil {
			t := now
			s.NotifiedExpiringAt = &t
		}
	}
	return nil
}

func (m *MemStore) GetPolicy(_ context.Context, projectID uuid.UUID) (*Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.Policies[projectID]
	if !ok {
		return nil, ErrNoPolicy
	}
	return &p, nil
}

func (m *MemStore) PutPolicy(_ context.Context, projectID uuid.UUID, p Policy, _ uuid.UUID, _ time.Time, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Policies[projectID] = p
	m.audit(a)
	return nil
}

func (m *MemStore) OpenAlertsAtSHA(_ context.Context, projectID uuid.UUID, sha string) ([]Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Alert
	for _, a := range m.Alerts {
		if a.ProjectID == projectID && a.State == StateOpen && a.LastSeenSHA == sha {
			out = append(out, *a)
		}
	}
	return out, nil
}

func (m *MemStore) KnownFingerprints(_ context.Context, projectID uuid.UUID, branch string) (map[string]bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for _, a := range m.Alerts {
		if a.ProjectID == projectID && a.Branch == branch && (a.State == StateOpen || a.State == StateDismissed) {
			out[a.Fingerprint] = true
		}
	}
	return out, nil
}

func (m *MemStore) ToolsUploadedAt(_ context.Context, projectID uuid.UUID, sha string) (map[string]bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for _, u := range m.Uploads {
		if u.ProjectID == projectID && u.CommitSHA == sha && u.Status == UploadComplete {
			out[u.ToolName] = true
			out[u.Tool] = true
		}
	}
	return out, nil
}

func checkKey(p uuid.UUID, sha string) string { return p.String() + "|" + sha }

func (m *MemStore) EnsureCheckRun(_ context.Context, c CheckRun) (*CheckRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := checkKey(c.ProjectID, c.HeadSHA)
	if e, ok := m.Checks[k]; ok {
		x := *e
		return &x, nil
	}
	x := c
	m.Checks[k] = &x
	y := x
	return &y, nil
}

func (m *MemStore) SaveCheckRun(_ context.Context, c CheckRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	x := c
	m.Checks[checkKey(c.ProjectID, c.HeadSHA)] = &x
	return nil
}

func (m *MemStore) OpenCheckRuns(_ context.Context, limit int) ([]CheckRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []CheckRun
	for _, c := range m.Checks {
		if !c.Final && len(out) < limit {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (m *MemStore) RecentCheckRuns(_ context.Context, projectID uuid.UUID, since time.Time, limit int) ([]CheckRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []CheckRun
	for _, c := range m.Checks {
		last := c.FirstSeenAt
		if c.LastEvalAt != nil && c.LastEvalAt.After(last) {
			last = *c.LastEvalAt
		}
		if c.ProjectID == projectID && last.After(since) && len(out) < limit {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (m *MemStore) ProjectTarget(_ context.Context, projectID uuid.UUID) (Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Targets[projectID]
	if !ok {
		return Target{}, ErrNotFound
	}
	return t, nil
}

func (m *MemStore) DefaultBranchOf(_ context.Context, projectID uuid.UUID) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Defaults[projectID], nil
}

func (m *MemStore) GetRenovate(_ context.Context, projectID uuid.UUID) (*RenovateState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.Renovate[projectID]
	if !ok {
		return nil, ErrNotFound
	}
	c := *s
	return &c, nil
}

func (m *MemStore) PutRenovate(_ context.Context, s RenovateState, _ uuid.UUID, a AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := s
	m.Renovate[s.ProjectID] = &c
	m.audit(a)
	return nil
}

func (m *MemStore) UpdateRenovateObserved(_ context.Context, s RenovateState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.Renovate[s.ProjectID]; e != nil {
		e.Onboarding, e.OpenPRs, e.LastSyncAt = s.Onboarding, s.OpenPRs, s.LastSyncAt
	}
	return nil
}

func (m *MemStore) RecordRenovateRun(_ context.Context, projectID uuid.UUID, at time.Time, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.Renovate[projectID]; e != nil {
		t := at
		e.LastRunAt, e.LastRunStatus = &t, status
	}
	return nil
}

// Reset puts an alert back to open and drops its dismissal (tests that dismiss the same alert
// several times).
func (m *MemStore) Reset(id uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.Alerts[id]; ok {
		a.State, a.Dismissal, a.SuppressionID = StateOpen, nil, uuid.Nil
	}
}
