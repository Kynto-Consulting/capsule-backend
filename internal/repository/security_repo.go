package repository

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/security"
)

// SecurityRepository persists the Git Capsule B7 tables (security_alerts, sarif_uploads,
// security_suppressions, security_policies, security_check_runs, renovate_state) and implements
// security.Store.
type SecurityRepository struct{ pool *pgxpool.Pool }

func NewSecurityRepository(pool *pgxpool.Pool) *SecurityRepository {
	return &SecurityRepository{pool: pool}
}

var _ security.Store = (*SecurityRepository)(nil)

type secRow interface{ Scan(...any) error }

type secExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// ---- columns and scans (each scan has a test of its destination count) -----------------------

const securityAlertCols = `id, project_id, kind, tool, tool_name, rule_id, severity, state, title, description, fingerprint, branch, path,
	start_line, end_line, package_name, package_version, fixed_version, advisory, evidence, trace, first_seen_sha, last_seen_sha,
	last_upload_id, suppression_id, dismiss_reason, dismiss_justification, dismissed_by, dismiss_expires_at, dismissed_at, fixed_at,
	created_at, updated_at`

// alertSelect prefixes the columns with the alias a and appends the dismissing user's name and email.
func secPrefixed(cols, alias string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

var securityAlertSelect = secPrefixed(securityAlertCols, "a") + `, u.name, u.email`

const securityAlertFrom = ` FROM security_alerts a LEFT JOIN users u ON u.id = a.dismissed_by`

func scanSecurityAlert(row secRow, a *security.Alert, withUser bool) error {
	var (
		trace                            []byte
		lastUpload, suppID, dismissedBy  *uuid.UUID
		dismissExp, dismissedAt, fixedAt *time.Time
		kind, severity, state            string
		reason, justification            string
		userName, userEmail              *string
	)
	dest := []any{&a.ID, &a.ProjectID, &kind, &a.Tool, &a.ToolName, &a.RuleID, &severity, &state, &a.Title, &a.Description,
		&a.Fingerprint, &a.Branch, &a.Path, &a.StartLine, &a.EndLine, &a.Package, &a.Version, &a.FixedVersion, &a.Advisory,
		&a.Evidence, &trace, &a.FirstSeenSHA, &a.LastSeenSHA, &lastUpload, &suppID, &reason, &justification, &dismissedBy,
		&dismissExp, &dismissedAt, &fixedAt, &a.CreatedAt, &a.UpdatedAt}
	if withUser {
		dest = append(dest, &userName, &userEmail)
	}
	if err := row.Scan(dest...); err != nil {
		return err
	}
	a.Kind, a.Severity, a.State = security.Kind(kind), security.Severity(severity), security.State(state)
	a.Trace = nil
	if len(trace) > 0 {
		if err := json.Unmarshal(trace, &a.Trace); err != nil {
			return fmt.Errorf("decoding alert trace: %w", err)
		}
	}
	a.LastUploadID, a.SuppressionID = uuid.Nil, uuid.Nil
	if lastUpload != nil {
		a.LastUploadID = *lastUpload
	}
	if suppID != nil {
		a.SuppressionID = *suppID
	}
	a.FixedAt = fixedAt
	a.Dismissal = nil
	if a.State == security.StateDismissed && dismissExp != nil {
		d := &security.Dismissal{Reason: reason, Justification: justification, ExpiresAt: *dismissExp}
		if dismissedAt != nil {
			d.At = *dismissedAt
		}
		if dismissedBy != nil {
			d.ByUserID = *dismissedBy
			id := *dismissedBy
			d.By.UserID = &id
			if userName != nil {
				d.By.Name = *userName
			}
			if userEmail != nil {
				d.By.Email = *userEmail
			}
		}
		a.Dismissal = d
	}
	return nil
}

const securitySuppressionCols = `id, project_id, rule_id, fingerprint, path_glob, reason, justification, expires_at, state, source, alert_id,
	covers_high, created_by, created_at, revoked_at, notified_expiring_at`

var securitySuppressionSelect = secPrefixed(securitySuppressionCols, "s") + `, u.name, u.email`

const securitySuppressionFrom = ` FROM security_suppressions s LEFT JOIN users u ON u.id = s.created_by`

func scanSecuritySuppression(row secRow, s *security.Suppression, withUser bool) error {
	var alertID, createdBy *uuid.UUID
	var name, email *string
	dest := []any{&s.ID, &s.ProjectID, &s.Match.RuleID, &s.Match.Fingerprint, &s.Match.PathGlob, &s.Reason, &s.Justification,
		&s.ExpiresAt, &s.State, &s.Source, &alertID, &s.CoversHigh, &createdBy, &s.CreatedAt, &s.RevokedAt, &s.NotifiedExpiringAt}
	if withUser {
		dest = append(dest, &name, &email)
	}
	if err := row.Scan(dest...); err != nil {
		return err
	}
	s.AlertID, s.CreatedBy = uuid.Nil, uuid.Nil
	if alertID != nil {
		s.AlertID = *alertID
	}
	if createdBy != nil {
		s.CreatedBy = *createdBy
		id := *createdBy
		s.CreatedByPerson.UserID = &id
	}
	if name != nil {
		s.CreatedByPerson.Name = *name
	}
	if email != nil {
		s.CreatedByPerson.Email = *email
	}
	return nil
}

const securityUploadCols = `id, project_id, commit_sha, ref, branch, pr, tool, tool_name, status, error, idempotency_key, results_total,
	alerts_created, alerts_fixed, superseded, attempts, created_by, created_at, started_at, completed_at`

func scanSecurityUpload(row secRow, u *security.Upload, extra ...any) error {
	var pr *int
	var idem *string
	var createdBy *uuid.UUID
	dest := []any{&u.ID, &u.ProjectID, &u.CommitSHA, &u.Ref, &u.Branch, &pr, &u.Tool, &u.ToolName, &u.Status, &u.Error, &idem,
		&u.ResultsTotal, &u.AlertsCreated, &u.AlertsFixed, &u.Superseded, &u.Attempts, &createdBy, &u.CreatedAt, &u.StartedAt, &u.CompletedAt}
	if err := row.Scan(append(dest, extra...)...); err != nil {
		return err
	}
	u.PR = 0
	if pr != nil {
		u.PR = *pr
	}
	u.IdempotencyKey = ""
	if idem != nil {
		u.IdempotencyKey = *idem
	}
	u.CreatedBy = uuid.Nil
	if createdBy != nil {
		u.CreatedBy = *createdBy
	}
	return nil
}

const securityCheckCols = `project_id, head_sha, pr_number, base_branch, head_branch, state, description, first_seen_at, last_eval_at, final`

func scanSecurityCheck(row secRow, c *security.CheckRun) error {
	return row.Scan(&c.ProjectID, &c.HeadSHA, &c.PR, &c.BaseBranch, &c.HeadBranch, &c.State, &c.Description, &c.FirstSeenAt, &c.LastEvalAt, &c.Final)
}

const securityRenovateCols = `project_id, enabled, preset, schedule, onboarding, open_prs, last_run_at, last_run_status, dashboard_issue_url,
	topic_synced, sync_error, last_sync_at, updated_at`

func scanSecurityRenovate(row secRow, s *security.RenovateState) error {
	return row.Scan(&s.ProjectID, &s.Enabled, &s.Preset, &s.Schedule, &s.Onboarding, &s.OpenPRs, &s.LastRunAt, &s.LastRunStatus,
		&s.DashboardIssueURL, &s.TopicSynced, &s.SyncError, &s.LastSyncAt, &s.UpdatedAt)
}

const securityPolicyCols = `block_merge_dependency, block_merge_code, block_merge_secret, block_deploy_on, required_tools, max_suppression_days, applies_to_branches`

func scanSecurityPolicy(row secRow, p *security.Policy) error {
	return row.Scan(&p.BlockMergeOn.Dependency, &p.BlockMergeOn.Code, &p.BlockMergeOn.Secret, &p.BlockDeployOn, &p.RequiredTools,
		&p.MaxSuppressionDays, &p.AppliesToBranches)
}

func secNonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func secNullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func secInsertAudit(ctx context.Context, q secExecer, e security.AuditEntry) error {
	var ip any
	if e.IP != "" {
		ip = e.IP
	}
	_, err := q.Exec(ctx, `
		INSERT INTO audit_logs (user_id, org_id, action, resource_type, resource_id, ip_address, old_values, new_values)
		VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8)`,
		secNullUUID(e.UserID), e.OrgID, e.Action, e.ResourceType, secNullUUID(e.ResourceID), ip, e.OldValues, e.NewValues)
	if err != nil {
		return fmt.Errorf("writing audit log: %w", err)
	}
	return nil
}

func (r *SecurityRepository) WriteAudit(ctx context.Context, a security.AuditEntry) error {
	return secInsertAudit(ctx, r.pool, a)
}

func (r *SecurityRepository) inTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---- uploads ---------------------------------------------------------------------------------

func (r *SecurityRepository) CreateUpload(ctx context.Context, u *security.Upload, payload security.UploadPayload, a security.AuditEntry) (*security.Upload, bool, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, false, fmt.Errorf("encoding upload payload: %w", err)
	}
	var existing *security.Upload
	err = r.inTx(ctx, func(tx pgx.Tx) error {
		var idem any
		var pr any
		if u.IdempotencyKey != "" {
			idem = u.IdempotencyKey
		}
		if u.PR > 0 {
			pr = u.PR
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO sarif_uploads (id, project_id, commit_sha, ref, branch, pr, tool, tool_name, status, idempotency_key, results_total, findings, created_by, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10,$11,$12,$13)
			ON CONFLICT (project_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING`,
			u.ID, u.ProjectID, u.CommitSHA, u.Ref, u.Branch, pr, u.Tool, u.ToolName, idem, u.ResultsTotal, body, secNullUUID(u.CreatedBy), u.CreatedAt)
		if err != nil {
			return fmt.Errorf("creating sarif upload: %w", err)
		}
		if tag.RowsAffected() == 0 {
			var e security.Upload
			if err := scanSecurityUpload(tx.QueryRow(ctx, `SELECT `+securityUploadCols+` FROM sarif_uploads WHERE project_id = $1 AND idempotency_key = $2`, u.ProjectID, u.IdempotencyKey), &e); err != nil {
				return fmt.Errorf("loading idempotent upload: %w", err)
			}
			existing = &e
			return nil
		}
		return secInsertAudit(ctx, tx, a)
	})
	if err != nil {
		return nil, false, err
	}
	return existing, existing == nil, nil
}

func (r *SecurityRepository) GetUpload(ctx context.Context, projectID, id uuid.UUID) (*security.Upload, error) {
	var u security.Upload
	err := scanSecurityUpload(r.pool.QueryRow(ctx, `SELECT `+securityUploadCols+` FROM sarif_uploads WHERE id = $1 AND project_id = $2`, id, projectID), &u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, security.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading sarif upload: %w", err)
	}
	return &u, nil
}

func (r *SecurityRepository) ClaimUploads(ctx context.Context, limit int, stale time.Duration, now time.Time) ([]security.ClaimedUpload, error) {
	rows, err := r.pool.Query(ctx, `
		WITH c AS (
			SELECT id FROM sarif_uploads
			WHERE status = 'pending' OR (status = 'processing' AND started_at < $2)
			ORDER BY created_at LIMIT $1 FOR UPDATE SKIP LOCKED)
		UPDATE sarif_uploads u SET status = 'processing', started_at = $3, attempts = u.attempts + 1
		FROM c WHERE u.id = c.id
		RETURNING `+secPrefixed(securityUploadCols, "u")+`, u.findings`,
		limit, now.Add(-stale), now)
	if err != nil {
		return nil, fmt.Errorf("claiming sarif uploads: %w", err)
	}
	defer rows.Close()
	var out []security.ClaimedUpload
	for rows.Next() {
		var cu security.ClaimedUpload
		var findings []byte
		if err := scanSecurityUpload(rows, &cu.Upload, &findings); err != nil {
			return nil, fmt.Errorf("scanning sarif upload: %w", err)
		}
		if len(findings) > 0 {
			if err := json.Unmarshal(findings, &cu.Payload); err != nil {
				return nil, fmt.Errorf("decoding upload payload: %w", err)
			}
		}
		out = append(out, cu)
	}
	return out, rows.Err()
}

func (r *SecurityRepository) FailUpload(ctx context.Context, id uuid.UUID, msg string, final bool, now time.Time) error {
	status, clear := security.UploadPending, ""
	if final {
		status, clear = security.UploadFailed, ", findings = NULL, completed_at = $4"
	}
	args := []any{id, status, msg}
	if final {
		args = append(args, now)
	}
	_, err := r.pool.Exec(ctx, `UPDATE sarif_uploads SET status = $2, error = left($3, 500)`+clear+` WHERE id = $1`, args...)
	if err != nil {
		return fmt.Errorf("failing sarif upload: %w", err)
	}
	return nil
}

func (r *SecurityRepository) loadActiveSuppressions(ctx context.Context, q secExecer, projectID uuid.UUID) ([]security.Suppression, error) {
	rows, err := q.Query(ctx, `SELECT `+securitySuppressionCols+` FROM security_suppressions WHERE project_id = $1 AND state = 'active'`, projectID)
	if err != nil {
		return nil, fmt.Errorf("loading suppressions: %w", err)
	}
	defer rows.Close()
	var out []security.Suppression
	for rows.Next() {
		var s security.Suppression
		if err := scanSecuritySuppression(rows, &s, false); err != nil {
			return nil, fmt.Errorf("scanning suppression: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *SecurityRepository) ApplyUpload(ctx context.Context, cu security.ClaimedUpload, now time.Time) (*security.ApplyResult, error) {
	res := &security.ApplyResult{}
	err := r.inTx(ctx, func(tx pgx.Tx) error {
		*res = security.ApplyResult{}
		scopes := append([]security.Scope(nil), cu.Payload.Scopes...)
		sort.Slice(scopes, func(i, j int) bool { return scopes[i].ToolName < scopes[j].ToolName })
		// one advisory lock per (project, branch, tool): simultaneous uploads of the same tool queue up here
		for _, sc := range scopes {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, cu.ProjectID.String()+"|"+cu.Branch+"|"+sc.ToolName); err != nil {
				return fmt.Errorf("locking scope: %w", err)
			}
		}
		supps, err := r.loadActiveSuppressions(ctx, tx, cu.ProjectID)
		if err != nil {
			return err
		}
		set := security.NewSuppressionSet(supps, now)
		applied := 0
		for _, sc := range scopes {
			if sc.ToolName == cu.ToolName {
				var newer bool
				if err := tx.QueryRow(ctx, `
					SELECT EXISTS (SELECT 1 FROM sarif_uploads WHERE project_id = $1 AND branch = $2 AND tool_name = $3
						AND status = 'complete' AND superseded = false AND created_at > $4 AND id <> $5)`,
					cu.ProjectID, cu.Branch, sc.ToolName, cu.CreatedAt, cu.ID).Scan(&newer); err != nil {
					return fmt.Errorf("checking newer uploads: %w", err)
				}
				if newer {
					continue // an upload that arrived later was already applied: this one is stale
				}
			}
			applied++
			rows, err := tx.Query(ctx, `SELECT `+securityAlertSelect+securityAlertFrom+` WHERE a.project_id = $1 AND a.branch = $2 AND a.tool_name = $3`,
				cu.ProjectID, cu.Branch, sc.ToolName)
			if err != nil {
				return fmt.Errorf("loading alerts: %w", err)
			}
			var existing []security.Alert
			for rows.Next() {
				var a security.Alert
				if err := scanSecurityAlert(rows, &a, true); err != nil {
					rows.Close()
					return fmt.Errorf("scanning alert: %w", err)
				}
				existing = append(existing, a)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			var fs []security.Finding
			for _, f := range cu.Payload.Findings {
				if f.ToolName == sc.ToolName {
					fs = append(fs, f)
				}
			}
			plan := security.Reconcile(security.ReconcileInput{ProjectID: cu.ProjectID, Branch: cu.Branch, SHA: cu.CommitSHA, UploadID: cu.ID,
				Scope: sc, Findings: fs, Existing: existing, Supp: set, Now: now})
			if err := r.writePlan(ctx, tx, plan); err != nil {
				return err
			}
			res.Created = append(res.Created, plan.Created...)
			res.Fixed += plan.Fixed
		}
		res.Superseded = applied == 0
		_, err = tx.Exec(ctx, `UPDATE sarif_uploads SET status = 'complete', superseded = $2, alerts_created = $3, alerts_fixed = $4,
			error = '', findings = NULL, completed_at = $5 WHERE id = $1`, cu.ID, res.Superseded, len(res.Created), res.Fixed, now)
		if err != nil {
			return fmt.Errorf("completing upload: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

const securityInsertAlertSQL = `INSERT INTO security_alerts (id, project_id, kind, tool, tool_name, rule_id, severity, state, title, description,
	fingerprint, branch, path, start_line, end_line, package_name, package_version, fixed_version, advisory, evidence, trace,
	first_seen_sha, last_seen_sha, last_upload_id, suppression_id, dismiss_reason, dismiss_justification, dismissed_by,
	dismiss_expires_at, dismissed_at, fixed_at, created_at, updated_at)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33)`

const securityUpdateAlertSQL = `UPDATE security_alerts SET severity=$2, state=$3, title=$4, description=$5, path=$6, start_line=$7, end_line=$8,
	package_name=$9, package_version=$10, fixed_version=$11, advisory=$12, evidence=$13, trace=$14, last_seen_sha=$15, last_upload_id=$16,
	suppression_id=$17, dismiss_reason=$18, dismiss_justification=$19, dismissed_by=$20, dismiss_expires_at=$21, dismissed_at=$22,
	fixed_at=$23, updated_at=$24 WHERE id=$1`

func alertDismissArgs(a security.Alert) (reason, justification string, by any, exp, at any) {
	if a.Dismissal == nil {
		return "", "", nil, nil, nil
	}
	return a.Dismissal.Reason, a.Dismissal.Justification, secNullUUID(a.Dismissal.ByUserID), a.Dismissal.ExpiresAt, a.Dismissal.At
}

func (r *SecurityRepository) writePlan(ctx context.Context, tx pgx.Tx, plan security.ReconcilePlan) error {
	b := &pgx.Batch{}
	for _, a := range plan.Insert {
		trace, err := json.Marshal(secTrace(a.Trace))
		if err != nil {
			return err
		}
		reason, just, by, exp, at := alertDismissArgs(a)
		b.Queue(securityInsertAlertSQL, a.ID, a.ProjectID, string(a.Kind), a.Tool, a.ToolName, a.RuleID, string(a.Severity), string(a.State),
			a.Title, a.Description, a.Fingerprint, a.Branch, a.Path, a.StartLine, a.EndLine, a.Package, a.Version, a.FixedVersion,
			a.Advisory, a.Evidence, trace, a.FirstSeenSHA, a.LastSeenSHA, secNullUUID(a.LastUploadID), secNullUUID(a.SuppressionID),
			reason, just, by, exp, at, a.FixedAt, a.CreatedAt, a.UpdatedAt)
	}
	for _, a := range plan.Update {
		trace, err := json.Marshal(secTrace(a.Trace))
		if err != nil {
			return err
		}
		reason, just, by, exp, at := alertDismissArgs(a)
		b.Queue(securityUpdateAlertSQL, a.ID, string(a.Severity), string(a.State), a.Title, a.Description, a.Path, a.StartLine, a.EndLine,
			a.Package, a.Version, a.FixedVersion, a.Advisory, a.Evidence, trace, a.LastSeenSHA, secNullUUID(a.LastUploadID),
			secNullUUID(a.SuppressionID), reason, just, by, exp, at, a.FixedAt, a.UpdatedAt)
	}
	if b.Len() == 0 {
		return nil
	}
	br := tx.SendBatch(ctx, b)
	for i := 0; i < b.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return fmt.Errorf("writing alerts: %w", err)
		}
	}
	return br.Close()
}

func secTrace(t []security.TraceStep) []security.TraceStep {
	if t == nil {
		return []security.TraceStep{}
	}
	return t
}

// ---- alerts ----------------------------------------------------------------------------------

func secEncodeCursor(t time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

func secDecodeCursor(c string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, uuid.Nil, errors.New("bad cursor")
	}
	ts, ids, ok := strings.Cut(string(raw), "|")
	if !ok {
		return time.Time{}, uuid.Nil, errors.New("bad cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, uuid.Nil, errors.New("bad cursor")
	}
	id, err := uuid.Parse(ids)
	if err != nil {
		return time.Time{}, uuid.Nil, errors.New("bad cursor")
	}
	return t, id, nil
}

func (r *SecurityRepository) ListAlerts(ctx context.Context, projectID uuid.UUID, q security.AlertQuery) ([]security.Alert, string, error) {
	where := []string{"a.project_id = $1"}
	args := []any{projectID}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.Replace(cond, "?", fmt.Sprintf("$%d", len(args)), 1))
	}
	if !q.IncludeSecrets {
		where = append(where, "a.kind <> 'secret'")
	}
	if q.Kind != "" {
		add("a.kind = ?", q.Kind)
	}
	if q.Severity != "" {
		add("a.severity = ?", q.Severity)
	}
	if q.State != "" {
		add("a.state = ?", q.State)
	}
	if q.Branch != "" {
		add("a.branch = ?", q.Branch)
	}
	if q.Tool != "" {
		add("a.tool = ?", q.Tool)
	}
	if q.Cursor != "" {
		ct, cid, err := secDecodeCursor(q.Cursor)
		if err != nil {
			return nil, "", &security.ValidationError{Fields: []security.FieldError{{Field: "cursor", Message: "cursor no valido"}}}
		}
		args = append(args, ct, cid)
		where = append(where, fmt.Sprintf("(a.created_at, a.id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	limit := q.Limit
	if limit <= 0 || limit > 100 {
		limit = 30
	}
	args = append(args, limit+1)
	rows, err := r.pool.Query(ctx, `SELECT `+securityAlertSelect+securityAlertFrom+` WHERE `+strings.Join(where, " AND ")+
		fmt.Sprintf(` ORDER BY a.created_at DESC, a.id DESC LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, "", fmt.Errorf("listing security alerts: %w", err)
	}
	defer rows.Close()
	var out []security.Alert
	for rows.Next() {
		var a security.Alert
		if err := scanSecurityAlert(rows, &a, true); err != nil {
			return nil, "", fmt.Errorf("scanning security alert: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = secEncodeCursor(last.CreatedAt, last.ID)
	}
	return out, next, nil
}

func (r *SecurityRepository) getAlert(ctx context.Context, q secExecer, projectID, id uuid.UUID, lock bool) (*security.Alert, error) {
	sql := `SELECT ` + securityAlertSelect + securityAlertFrom + ` WHERE a.id = $1 AND a.project_id = $2`
	if lock {
		sql += ` FOR UPDATE OF a`
	}
	var a security.Alert
	err := scanSecurityAlert(q.QueryRow(ctx, sql, id, projectID), &a, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, security.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading security alert: %w", err)
	}
	return &a, nil
}

func (r *SecurityRepository) GetAlert(ctx context.Context, projectID, id uuid.UUID) (*security.Alert, error) {
	return r.getAlert(ctx, r.pool, projectID, id, false)
}

func (r *SecurityRepository) Overview(ctx context.Context, projectID uuid.UUID) (*security.Overview, error) {
	o := &security.Overview{BySeverity: map[string]int{}, ByKind: map[string]int{}}
	rows, err := r.pool.Query(ctx, `SELECT state, severity, kind, count(*) FROM security_alerts WHERE project_id = $1 AND state IN ('open','dismissed') GROUP BY state, severity, kind`, projectID)
	if err != nil {
		return nil, fmt.Errorf("security overview: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var state, sev, kind string
		var n int
		if err := rows.Scan(&state, &sev, &kind, &n); err != nil {
			return nil, err
		}
		switch state {
		case "open":
			o.Open += n
			o.BySeverity[sev] += n
			o.ByKind[kind] += n
		case "dismissed":
			o.Dismissed += n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if err := r.pool.QueryRow(ctx, `SELECT max(completed_at) FROM sarif_uploads WHERE project_id = $1 AND status = 'complete'`, projectID).Scan(&o.LastScanAt); err != nil {
		return nil, fmt.Errorf("security overview last scan: %w", err)
	}
	return o, nil
}

const secDismissSQL = `UPDATE security_alerts SET state = 'dismissed', suppression_id = $1, dismiss_reason = $2, dismiss_justification = $3,
	dismissed_by = $4, dismiss_expires_at = $5, dismissed_at = $6, updated_at = $6`

const secReopenSQL = `UPDATE security_alerts SET state = 'open', suppression_id = NULL, dismiss_reason = '', dismiss_justification = '',
	dismissed_by = NULL, dismiss_expires_at = NULL, dismissed_at = NULL, updated_at = $1`

func (r *SecurityRepository) DismissAlert(ctx context.Context, projectID, id uuid.UUID, p security.DismissParams, now time.Time, a security.AuditEntry) (*security.Alert, error) {
	var out *security.Alert
	err := r.inTx(ctx, func(tx pgx.Tx) error {
		al, err := r.getAlert(ctx, tx, projectID, id, true)
		if err != nil {
			return err
		}
		if al.State != security.StateOpen {
			return &security.ConflictError{Code: "ALERT_STATE_CONFLICT", Message: "solo se puede descartar una alerta abierta (estado actual: " + string(al.State) + ")"}
		}
		suppID := uuid.New()
		if _, err := tx.Exec(ctx, `
			INSERT INTO security_suppressions (id, project_id, fingerprint, reason, justification, expires_at, state, source, alert_id, covers_high, created_by, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,'active','alert',$7,$8,$9,$10)`,
			suppID, projectID, al.Fingerprint, p.Reason, p.Justification, p.ExpiresAt, id, p.CoversHigh, secNullUUID(p.By), now); err != nil {
			return fmt.Errorf("creating suppression: %w", err)
		}
		// the same fingerprint on other branches is dismissed with it (SPEC 5.8)
		if _, err := tx.Exec(ctx, secDismissSQL+` WHERE project_id = $7 AND fingerprint = $8 AND state = 'open'`,
			suppID, p.Reason, p.Justification, secNullUUID(p.By), p.ExpiresAt, now, projectID, al.Fingerprint); err != nil {
			return fmt.Errorf("dismissing alerts: %w", err)
		}
		if err := secInsertAudit(ctx, tx, a); err != nil {
			return err
		}
		out, err = r.getAlert(ctx, tx, projectID, id, false)
		return err
	})
	return out, err
}

func (r *SecurityRepository) ReopenAlert(ctx context.Context, projectID, id uuid.UUID, now time.Time, a security.AuditEntry) (*security.Alert, error) {
	var out *security.Alert
	err := r.inTx(ctx, func(tx pgx.Tx) error {
		al, err := r.getAlert(ctx, tx, projectID, id, true)
		if err != nil {
			return err
		}
		if al.State != security.StateDismissed {
			return &security.ConflictError{Code: "ALERT_STATE_CONFLICT", Message: "solo se puede reabrir una alerta descartada (estado actual: " + string(al.State) + ")"}
		}
		if al.SuppressionID != uuid.Nil {
			var source, state string
			if err := tx.QueryRow(ctx, `SELECT source, state FROM security_suppressions WHERE id = $1 FOR UPDATE`, al.SuppressionID).Scan(&source, &state); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("loading suppression: %w", err)
			} else if err == nil && source == "manual" && state == security.SuppActive {
				return &security.ConflictError{Code: "SUPPRESSED_BY_RULE", Message: "la alerta esta cubierta por una supresion por regla o ruta: revoca la supresion"}
			}
			if _, err := tx.Exec(ctx, `UPDATE security_suppressions SET state = 'revoked', revoked_at = $2 WHERE id = $1 AND state = 'active'`, al.SuppressionID, now); err != nil {
				return fmt.Errorf("revoking suppression: %w", err)
			}
			if _, err := tx.Exec(ctx, secReopenSQL+` WHERE suppression_id = $2 AND state = 'dismissed'`, now, al.SuppressionID); err != nil {
				return fmt.Errorf("reopening alerts: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, secReopenSQL+` WHERE id = $2 AND state = 'dismissed'`, now, id); err != nil {
			return fmt.Errorf("reopening alert: %w", err)
		}
		if err := secInsertAudit(ctx, tx, a); err != nil {
			return err
		}
		out, err = r.getAlert(ctx, tx, projectID, id, false)
		return err
	})
	return out, err
}

// ---- suppressions ----------------------------------------------------------------------------

func (r *SecurityRepository) ListSuppressions(ctx context.Context, projectID uuid.UUID) ([]security.Suppression, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+securitySuppressionSelect+securitySuppressionFrom+` WHERE s.project_id = $1 ORDER BY s.created_at DESC, s.id DESC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing suppressions: %w", err)
	}
	defer rows.Close()
	var out []security.Suppression
	for rows.Next() {
		var s security.Suppression
		if err := scanSecuritySuppression(rows, &s, true); err != nil {
			return nil, fmt.Errorf("scanning suppression: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// openAlertsMatching loads the project's open alerts that the match can select (SQL prefilter on
// rule and fingerprint, the glob is applied by the caller).
func (r *SecurityRepository) openAlertsMatching(ctx context.Context, q secExecer, projectID uuid.UUID, m security.SuppressionMatch) ([]security.Alert, error) {
	where, args := []string{"a.project_id = $1", "a.state = 'open'"}, []any{projectID}
	if m.RuleID != "" {
		args = append(args, m.RuleID)
		where = append(where, fmt.Sprintf("a.rule_id = $%d", len(args)))
	}
	if m.Fingerprint != "" {
		args = append(args, m.Fingerprint)
		where = append(where, fmt.Sprintf("a.fingerprint = $%d", len(args)))
	}
	rows, err := q.Query(ctx, `SELECT `+securityAlertSelect+securityAlertFrom+` WHERE `+strings.Join(where, " AND "), args...)
	if err != nil {
		return nil, fmt.Errorf("loading alerts: %w", err)
	}
	defer rows.Close()
	var out []security.Alert
	for rows.Next() {
		var a security.Alert
		if err := scanSecurityAlert(rows, &a, true); err != nil {
			return nil, fmt.Errorf("scanning alert: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *SecurityRepository) MaxSeverityMatching(ctx context.Context, projectID uuid.UUID, m security.SuppressionMatch) (security.Severity, bool, error) {
	alerts, err := r.openAlertsMatching(ctx, r.pool, projectID, m)
	if err != nil {
		return "", false, err
	}
	probe := security.Suppression{Match: m}
	best, found := security.Severity(""), false
	for i := range alerts {
		if security.MatchesIgnoringSeverity(probe, &alerts[i]) && (!found || alerts[i].Severity.Rank() > best.Rank()) {
			best, found = alerts[i].Severity, true
		}
	}
	return best, found, nil
}

func (r *SecurityRepository) CreateSuppression(ctx context.Context, s *security.Suppression, now time.Time, a security.AuditEntry) (int, error) {
	applied := 0
	err := r.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO security_suppressions (id, project_id, rule_id, fingerprint, path_glob, reason, justification, expires_at, state, source, alert_id, covers_high, created_by, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			s.ID, s.ProjectID, s.Match.RuleID, s.Match.Fingerprint, s.Match.PathGlob, s.Reason, s.Justification, s.ExpiresAt, s.State,
			s.Source, secNullUUID(s.AlertID), s.CoversHigh, secNullUUID(s.CreatedBy), s.CreatedAt); err != nil {
			return fmt.Errorf("creating suppression: %w", err)
		}
		alerts, err := r.openAlertsMatching(ctx, tx, s.ProjectID, s.Match)
		if err != nil {
			return err
		}
		set := security.NewSuppressionSet([]security.Suppression{*s}, now)
		var ids []uuid.UUID
		for i := range alerts {
			if set.MatchAlert(&alerts[i]) != nil {
				ids = append(ids, alerts[i].ID)
			}
		}
		if len(ids) > 0 {
			if _, err := tx.Exec(ctx, secDismissSQL+` WHERE id = ANY($7) AND state = 'open'`,
				s.ID, s.Reason, s.Justification, secNullUUID(s.CreatedBy), s.ExpiresAt, now, ids); err != nil {
				return fmt.Errorf("dismissing covered alerts: %w", err)
			}
		}
		applied = len(ids)
		if a.NewValues != nil {
			a.NewValues["alerts"] = applied
		}
		return secInsertAudit(ctx, tx, a)
	})
	return applied, err
}

func (r *SecurityRepository) RevokeSuppression(ctx context.Context, projectID, id, by uuid.UUID, now time.Time, a security.AuditEntry) (int, error) {
	reopened := 0
	err := r.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE security_suppressions SET state = 'revoked', revoked_at = $3, revoked_by = $4 WHERE id = $1 AND project_id = $2 AND state = 'active'`,
			id, projectID, now, secNullUUID(by))
		if err != nil {
			return fmt.Errorf("revoking suppression: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return security.ErrNotFound
		}
		t2, err := tx.Exec(ctx, secReopenSQL+` WHERE suppression_id = $2 AND state = 'dismissed'`, now, id)
		if err != nil {
			return fmt.Errorf("reopening alerts: %w", err)
		}
		reopened = int(t2.RowsAffected())
		return secInsertAudit(ctx, tx, a)
	})
	return reopened, err
}

func (r *SecurityRepository) ExpireDue(ctx context.Context, now time.Time) ([]security.ExpiryResult, error) {
	type acc struct {
		supps    []uuid.UUID
		reopened int
	}
	by := map[uuid.UUID]*acc{}
	get := func(p uuid.UUID) *acc {
		if by[p] == nil {
			by[p] = &acc{}
		}
		return by[p]
	}
	err := r.inTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE security_suppressions SET state = 'expired' WHERE state = 'active' AND expires_at <= $1 RETURNING id, project_id`, now)
		if err != nil {
			return fmt.Errorf("expiring suppressions: %w", err)
		}
		var ids []uuid.UUID
		for rows.Next() {
			var id, pid uuid.UUID
			if err := rows.Scan(&id, &pid); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
			get(pid).supps = append(get(pid).supps, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		reopen := func(cond string, args ...any) error {
			rows, err := tx.Query(ctx, secReopenSQL+` WHERE state = 'dismissed' AND `+cond+` RETURNING project_id`, append([]any{now}, args...)...)
			if err != nil {
				return fmt.Errorf("reopening expired alerts: %w", err)
			}
			defer rows.Close()
			for rows.Next() {
				var pid uuid.UUID
				if err := rows.Scan(&pid); err != nil {
					return err
				}
				get(pid).reopened++
			}
			return rows.Err()
		}
		if len(ids) > 0 {
			if err := reopen(`suppression_id = ANY($2)`, ids); err != nil {
				return err
			}
		}
		// dismissals without a suppression row whose own expiry passed
		return reopen(`dismiss_expires_at <= $2`, now)
	})
	if err != nil {
		return nil, err
	}
	var out []security.ExpiryResult
	for pid, a := range by {
		t, err := r.ProjectTarget(ctx, pid)
		if err != nil {
			continue
		}
		out = append(out, security.ExpiryResult{Target: t, Suppressions: a.supps, AlertsReopened: a.reopened})
		_ = secInsertAudit(ctx, r.pool, security.AuditEntry{
			OrgID: t.OrgID, Action: security.AuditSuppressionExpire, ResourceType: "security_suppression", ResourceID: t.ProjectID,
			NewValues: map[string]any{"suppressions": len(a.supps), "alerts_reopened": a.reopened},
		})
	}
	return out, nil
}

func (r *SecurityRepository) DueExpiringNotices(ctx context.Context, now time.Time, window time.Duration) ([]security.Suppression, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+securitySuppressionSelect+securitySuppressionFrom+`
		WHERE s.state = 'active' AND s.notified_expiring_at IS NULL AND s.expires_at > $1 AND s.expires_at <= $2 ORDER BY s.expires_at LIMIT 500`,
		now, now.Add(window))
	if err != nil {
		return nil, fmt.Errorf("loading expiring suppressions: %w", err)
	}
	defer rows.Close()
	var out []security.Suppression
	for rows.Next() {
		var s security.Suppression
		if err := scanSecuritySuppression(rows, &s, true); err != nil {
			return nil, fmt.Errorf("scanning suppression: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *SecurityRepository) MarkExpiringNotified(ctx context.Context, ids []uuid.UUID, now time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := r.pool.Exec(ctx, `UPDATE security_suppressions SET notified_expiring_at = $2 WHERE id = ANY($1)`, ids, now)
	if err != nil {
		return fmt.Errorf("marking suppression notices: %w", err)
	}
	return nil
}

// ---- policy ----------------------------------------------------------------------------------

func (r *SecurityRepository) GetPolicy(ctx context.Context, projectID uuid.UUID) (*security.Policy, error) {
	var p security.Policy
	err := scanSecurityPolicy(r.pool.QueryRow(ctx, `SELECT `+securityPolicyCols+` FROM security_policies WHERE project_id = $1`, projectID), &p)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, security.ErrNoPolicy
	}
	if err != nil {
		return nil, fmt.Errorf("loading security policy: %w", err)
	}
	p.RequiredTools, p.AppliesToBranches = secNonNil(p.RequiredTools), secNonNil(p.AppliesToBranches)
	return &p, nil
}

func (r *SecurityRepository) PutPolicy(ctx context.Context, projectID uuid.UUID, p security.Policy, by uuid.UUID, now time.Time, a security.AuditEntry) error {
	return r.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO security_policies (project_id, block_merge_dependency, block_merge_code, block_merge_secret, block_deploy_on,
				required_tools, max_suppression_days, applies_to_branches, updated_by, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (project_id) DO UPDATE SET block_merge_dependency = EXCLUDED.block_merge_dependency,
				block_merge_code = EXCLUDED.block_merge_code, block_merge_secret = EXCLUDED.block_merge_secret,
				block_deploy_on = EXCLUDED.block_deploy_on, required_tools = EXCLUDED.required_tools,
				max_suppression_days = EXCLUDED.max_suppression_days, applies_to_branches = EXCLUDED.applies_to_branches,
				updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
			projectID, p.BlockMergeOn.Dependency, p.BlockMergeOn.Code, p.BlockMergeOn.Secret, p.BlockDeployOn,
			secNonNil(p.RequiredTools), p.MaxSuppressionDays, secNonNil(p.AppliesToBranches), secNullUUID(by), now); err != nil {
			return fmt.Errorf("saving security policy: %w", err)
		}
		return secInsertAudit(ctx, tx, a)
	})
}

// ---- evaluation inputs -----------------------------------------------------------------------

func (r *SecurityRepository) OpenAlertsAtSHA(ctx context.Context, projectID uuid.UUID, sha string) ([]security.Alert, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+securityAlertSelect+securityAlertFrom+` WHERE a.project_id = $1 AND a.state = 'open' AND a.last_seen_sha = $2`, projectID, sha)
	if err != nil {
		return nil, fmt.Errorf("loading alerts at sha: %w", err)
	}
	defer rows.Close()
	var out []security.Alert
	for rows.Next() {
		var a security.Alert
		if err := scanSecurityAlert(rows, &a, true); err != nil {
			return nil, fmt.Errorf("scanning alert: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *SecurityRepository) KnownFingerprints(ctx context.Context, projectID uuid.UUID, branch string) (map[string]bool, error) {
	rows, err := r.pool.Query(ctx, `SELECT DISTINCT fingerprint FROM security_alerts WHERE project_id = $1 AND branch = $2 AND state IN ('open','dismissed')`, projectID, branch)
	if err != nil {
		return nil, fmt.Errorf("loading fingerprints: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out[fp] = true
	}
	return out, rows.Err()
}

func (r *SecurityRepository) ToolsUploadedAt(ctx context.Context, projectID uuid.UUID, sha string) (map[string]bool, error) {
	rows, err := r.pool.Query(ctx, `SELECT DISTINCT tool, tool_name FROM sarif_uploads WHERE project_id = $1 AND commit_sha = $2 AND status = 'complete'`, projectID, sha)
	if err != nil {
		return nil, fmt.Errorf("loading uploaded tools: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var tool, name string
		if err := rows.Scan(&tool, &name); err != nil {
			return nil, err
		}
		out[tool], out[name] = true, true
	}
	return out, rows.Err()
}

// ---- check runs ------------------------------------------------------------------------------

func (r *SecurityRepository) EnsureCheckRun(ctx context.Context, c security.CheckRun) (*security.CheckRun, error) {
	var out security.CheckRun
	err := scanSecurityCheck(r.pool.QueryRow(ctx, `
		INSERT INTO security_check_runs (project_id, head_sha, pr_number, base_branch, head_branch, state, description, first_seen_at)
		VALUES ($1,$2,$3,$4,$5,'pending',$6,$7)
		ON CONFLICT (project_id, head_sha) DO UPDATE SET
			pr_number = CASE WHEN EXCLUDED.pr_number <> 0 THEN EXCLUDED.pr_number ELSE security_check_runs.pr_number END,
			base_branch = COALESCE(NULLIF(EXCLUDED.base_branch, ''), security_check_runs.base_branch),
			head_branch = COALESCE(NULLIF(EXCLUDED.head_branch, ''), security_check_runs.head_branch)
		RETURNING `+securityCheckCols, c.ProjectID, c.HeadSHA, c.PR, c.BaseBranch, c.HeadBranch, c.Description, c.FirstSeenAt), &out)
	if err != nil {
		return nil, fmt.Errorf("ensuring check run: %w", err)
	}
	return &out, nil
}

func (r *SecurityRepository) SaveCheckRun(ctx context.Context, c security.CheckRun) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE security_check_runs SET pr_number = $3, base_branch = $4, head_branch = $5, state = $6, description = $7,
			last_eval_at = $8, final = $9 WHERE project_id = $1 AND head_sha = $2`,
		c.ProjectID, c.HeadSHA, c.PR, c.BaseBranch, c.HeadBranch, c.State, c.Description, c.LastEvalAt, c.Final)
	if err != nil {
		return fmt.Errorf("saving check run: %w", err)
	}
	return nil
}

func (r *SecurityRepository) scanChecks(rows pgx.Rows) ([]security.CheckRun, error) {
	defer rows.Close()
	var out []security.CheckRun
	for rows.Next() {
		var c security.CheckRun
		if err := scanSecurityCheck(rows, &c); err != nil {
			return nil, fmt.Errorf("scanning check run: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *SecurityRepository) OpenCheckRuns(ctx context.Context, limit int) ([]security.CheckRun, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+securityCheckCols+` FROM security_check_runs WHERE final = false AND first_seen_at > now() - interval '14 days' ORDER BY first_seen_at LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("loading open check runs: %w", err)
	}
	return r.scanChecks(rows)
}

func (r *SecurityRepository) RecentCheckRuns(ctx context.Context, projectID uuid.UUID, since time.Time, limit int) ([]security.CheckRun, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+securityCheckCols+` FROM security_check_runs WHERE project_id = $1
		AND GREATEST(first_seen_at, COALESCE(last_eval_at, first_seen_at)) > $2 ORDER BY first_seen_at DESC LIMIT $3`, projectID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("loading recent check runs: %w", err)
	}
	return r.scanChecks(rows)
}

// ---- project ---------------------------------------------------------------------------------

func (r *SecurityRepository) ProjectTarget(ctx context.Context, projectID uuid.UUID) (security.Target, error) {
	var t security.Target
	err := r.pool.QueryRow(ctx, `SELECT p.id, o.id, o.slug, p.slug FROM projects p JOIN organizations o ON o.id = p.org_id WHERE p.id = $1`, projectID).
		Scan(&t.ProjectID, &t.OrgID, &t.OrgSlug, &t.ProjectSlug)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, security.ErrNotFound
	}
	if err != nil {
		return t, fmt.Errorf("loading project target: %w", err)
	}
	return t, nil
}

func (r *SecurityRepository) DefaultBranchOf(ctx context.Context, projectID uuid.UUID) (string, error) {
	var b *string
	err := r.pool.QueryRow(ctx, `SELECT branch FROM projects WHERE id = $1`, projectID).Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", security.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("loading project branch: %w", err)
	}
	if b == nil {
		return "", nil
	}
	return *b, nil
}

// ---- renovate --------------------------------------------------------------------------------

func (r *SecurityRepository) GetRenovate(ctx context.Context, projectID uuid.UUID) (*security.RenovateState, error) {
	var s security.RenovateState
	err := scanSecurityRenovate(r.pool.QueryRow(ctx, `SELECT `+securityRenovateCols+` FROM renovate_state WHERE project_id = $1`, projectID), &s)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, security.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading renovate state: %w", err)
	}
	return &s, nil
}

func (r *SecurityRepository) PutRenovate(ctx context.Context, s security.RenovateState, by uuid.UUID, a security.AuditEntry) error {
	return r.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO renovate_state (project_id, enabled, preset, schedule, onboarding, open_prs, topic_synced, sync_error, updated_by, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())
			ON CONFLICT (project_id) DO UPDATE SET enabled = EXCLUDED.enabled, preset = EXCLUDED.preset, schedule = EXCLUDED.schedule,
				topic_synced = EXCLUDED.topic_synced, sync_error = EXCLUDED.sync_error, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			s.ProjectID, s.Enabled, s.Preset, s.Schedule, s.Onboarding, s.OpenPRs, s.TopicSynced, s.SyncError, secNullUUID(by)); err != nil {
			return fmt.Errorf("saving renovate state: %w", err)
		}
		return secInsertAudit(ctx, tx, a)
	})
}

func (r *SecurityRepository) UpdateRenovateObserved(ctx context.Context, s security.RenovateState) error {
	_, err := r.pool.Exec(ctx, `UPDATE renovate_state SET onboarding = $2, open_prs = $3, dashboard_issue_url = $4, last_sync_at = $5 WHERE project_id = $1`,
		s.ProjectID, s.Onboarding, s.OpenPRs, s.DashboardIssueURL, s.LastSyncAt)
	if err != nil {
		return fmt.Errorf("updating renovate state: %w", err)
	}
	return nil
}

func (r *SecurityRepository) RecordRenovateRun(ctx context.Context, projectID uuid.UUID, at time.Time, status string) error {
	_, err := r.pool.Exec(ctx, `UPDATE renovate_state SET last_run_at = $2, last_run_status = $3 WHERE project_id = $1`, projectID, at, status)
	if err != nil {
		return fmt.Errorf("recording renovate run: %w", err)
	}
	return nil
}
