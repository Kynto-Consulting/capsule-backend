package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/environments"
)

// EnvironmentRepository persists environments, promotions, approvals and history (A6).
type EnvironmentRepository struct{ pool *pgxpool.Pool }

func NewEnvironmentRepository(pool *pgxpool.Pool) *EnvironmentRepository {
	return &EnvironmentRepository{pool: pool}
}

var _ environments.Store = (*EnvironmentRepository)(nil)

// querier is what pool and tx share.
type envQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

const envCols = `id, project_id, name, kind, target_project_id, branch_patterns, tag_patterns, auto_deploy, reviewers,
	required_approvals, allow_self_approval, wait_minutes, windows, require_checks_on_sha, require_source_environment,
	require_security_policy, rollback_requires_approval, created_by, created_at, updated_at`

func scanEnvironment(row pgx.Row, e *environments.Environment) error {
	var reviewers, windows []byte
	var src string
	err := row.Scan(&e.ID, &e.ProjectID, &e.Name, &e.Kind, &e.TargetProjectID, &e.BranchPatterns, &e.TagPatterns,
		&e.AutoDeploy, &reviewers, &e.RequiredApprovals, &e.AllowSelfApproval, &e.WaitMinutes, &windows,
		&e.RequireChecksOnSHA, &src, &e.RequireSecurityPolicy, &e.RollbackRequiresApproval, &e.CreatedBy,
		&e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return err
	}
	e.RequireSourceEnvironment = nil
	if src != "" {
		e.RequireSourceEnvironment = &src
	}
	e.Reviewers, e.Windows = nil, nil
	if err := json.Unmarshal(reviewers, &e.Reviewers); err != nil {
		return fmt.Errorf("decoding reviewers: %w", err)
	}
	if err := json.Unmarshal(windows, &e.Windows); err != nil {
		return fmt.Errorf("decoding windows: %w", err)
	}
	if e.Reviewers == nil {
		e.Reviewers = []environments.Reviewer{}
	}
	if e.Windows == nil {
		e.Windows = []environments.Window{}
	}
	if e.BranchPatterns == nil {
		e.BranchPatterns = []string{}
	}
	if e.TagPatterns == nil {
		e.TagPatterns = []string{}
	}
	return nil
}

const promoCols = `p.id, p.project_id, p.environment_id, e.name, p.sha, p.branch, p.from_environment, p.comment, p.status,
	p.status_reason, p.requested_by, p.required_approvals, p.quorum_at, p.not_before, p.expires_at, p.idempotency_key,
	p.source_deployment_id, p.deployment_id, p.checks, p.conditions, p.started_at, p.finished_at, p.created_at, p.updated_at`

const promoFrom = ` FROM promotions p JOIN environments e ON e.id = p.environment_id `

func scanPromotion(row pgx.Row, p *environments.Promotion) error {
	var checks, conds []byte
	err := row.Scan(&p.ID, &p.ProjectID, &p.EnvironmentID, &p.Environment, &p.SHA, &p.Branch, &p.FromEnvironment,
		&p.Comment, &p.Status, &p.StatusReason, &p.RequestedBy, &p.RequiredApprovals, &p.QuorumAt, &p.NotBefore,
		&p.ExpiresAt, &p.IdempotencyKey, &p.SourceDeploymentID, &p.DeploymentID, &checks, &conds, &p.StartedAt,
		&p.FinishedAt, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return err
	}
	p.Checks, p.Conditions = environments.CheckSnapshot{}, nil
	if len(checks) > 0 {
		_ = json.Unmarshal(checks, &p.Checks)
	}
	if len(conds) > 0 {
		_ = json.Unmarshal(conds, &p.Conditions)
	}
	if p.Checks.Items == nil {
		p.Checks.Items = []environments.CheckItem{}
	}
	if p.Conditions == nil {
		p.Conditions = []environments.Condition{}
	}
	p.Approvals = []environments.Approval{}
	return nil
}

const approvalCols = `promotion_id, user_id, decision, comment, self_approval, role_at_decision, created_at`

const envDepCols = `id, environment_id, promotion_id, sha, deployment_id, status, health_status, created_at, finished_at`

func scanEnvDeployment(row pgx.Row, d *environments.EnvDeployment) error {
	return row.Scan(&d.ID, &d.EnvironmentID, &d.PromotionID, &d.SHA, &d.DeploymentID, &d.Status, &d.HealthStatus,
		&d.CreatedAt, &d.FinishedAt)
}

const artifactCols = `id, source_key, COALESCE(git_sha, ''), COALESCE(build_strategy, ''), COALESCE(container_port, 0)`

func scanArtifact(row pgx.Row, a *environments.Artifact) error {
	return row.Scan(&a.DeploymentID, &a.SourceKey, &a.SHA, &a.BuildStrategy, &a.ContainerPort)
}

func envInsertAudit(ctx context.Context, q envQuerier, e environments.AuditEntry) error {
	var user, res, ip any
	if e.UserID != uuid.Nil {
		user = e.UserID
	}
	if e.ResourceID != uuid.Nil {
		res = e.ResourceID
	}
	if e.IP != "" {
		ip = e.IP
	}
	_, err := q.Exec(ctx, `
		INSERT INTO audit_logs (user_id, org_id, action, resource_type, resource_id, ip_address, old_values, new_values)
		VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8)`,
		user, e.OrgID, e.Action, e.ResourceType, res, ip, e.OldValues, e.NewValues)
	if err != nil {
		return fmt.Errorf("writing audit log: %w", err)
	}
	return nil
}

func (r *EnvironmentRepository) WriteAudit(ctx context.Context, a environments.AuditEntry) error {
	return envInsertAudit(ctx, r.pool, a)
}

func isUnique(err error, constraint string) bool {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return constraint == "" || pe.ConstraintName == constraint
	}
	return false
}

// ---- targets ----------------------------------------------------------------------------------

func (r *EnvironmentRepository) Target(ctx context.Context, projectID uuid.UUID) (environments.Target, error) {
	var t environments.Target
	err := r.pool.QueryRow(ctx, `
		SELECT p.id, p.org_id, o.slug, p.slug FROM projects p JOIN organizations o ON o.id = p.org_id
		WHERE p.id = $1 AND p.deleted_at IS NULL`, projectID).Scan(&t.ProjectID, &t.OrgID, &t.OrgSlug, &t.ProjectSlug)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, environments.ErrNotFound
	}
	return t, err
}

// ---- environments -------------------------------------------------------------------------------

func (r *EnvironmentRepository) ListEnvs(ctx context.Context, projectID uuid.UUID) ([]environments.Environment, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+envCols+` FROM environments WHERE project_id = $1 ORDER BY created_at, name`, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing environments: %w", err)
	}
	defer rows.Close()
	out := []environments.Environment{}
	for rows.Next() {
		var e environments.Environment
		if err := scanEnvironment(rows, &e); err != nil {
			return nil, fmt.Errorf("scanning environment: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *EnvironmentRepository) GetEnv(ctx context.Context, projectID uuid.UUID, name string) (*environments.Environment, error) {
	var e environments.Environment
	err := scanEnvironment(r.pool.QueryRow(ctx, `SELECT `+envCols+` FROM environments WHERE project_id = $1 AND name = $2`, projectID, name), &e)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, environments.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting environment: %w", err)
	}
	return &e, nil
}

func (r *EnvironmentRepository) GetEnvByID(ctx context.Context, id uuid.UUID) (*environments.Environment, error) {
	var e environments.Environment
	err := scanEnvironment(r.pool.QueryRow(ctx, `SELECT `+envCols+` FROM environments WHERE id = $1`, id), &e)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, environments.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting environment: %w", err)
	}
	return &e, nil
}

func envJSON(e *environments.Environment) (reviewers, windows []byte, src string) {
	rv := e.Reviewers
	if rv == nil {
		rv = []environments.Reviewer{}
	}
	wn := e.Windows
	if wn == nil {
		wn = []environments.Window{}
	}
	reviewers, _ = json.Marshal(rv)
	windows, _ = json.Marshal(wn)
	if e.RequireSourceEnvironment != nil {
		src = *e.RequireSourceEnvironment
	}
	return
}

func (r *EnvironmentRepository) CreateEnv(ctx context.Context, e *environments.Environment, a environments.AuditEntry) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("creating environment: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	rv, wn, src := envJSON(e)
	err = tx.QueryRow(ctx, `
		INSERT INTO environments (id, project_id, name, kind, target_project_id, branch_patterns, tag_patterns, auto_deploy,
			reviewers, required_approvals, allow_self_approval, wait_minutes, windows, require_checks_on_sha,
			require_source_environment, require_security_policy, rollback_requires_approval, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13::jsonb,$14,$15,$16,$17,$18)
		RETURNING created_at, updated_at`,
		e.ID, e.ProjectID, e.Name, e.Kind, e.TargetProjectID, e.BranchPatterns, e.TagPatterns, e.AutoDeploy, rv,
		e.RequiredApprovals, e.AllowSelfApproval, e.WaitMinutes, wn, e.RequireChecksOnSHA, src,
		e.RequireSecurityPolicy, e.RollbackRequiresApproval, e.CreatedBy).Scan(&e.CreatedAt, &e.UpdatedAt)
	if isUnique(err, "uq_environments_name") {
		return environments.ErrDuplicate
	}
	if err != nil {
		return fmt.Errorf("creating environment: %w", err)
	}
	if err := envInsertAudit(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *EnvironmentRepository) UpdateEnv(ctx context.Context, e *environments.Environment, a environments.AuditEntry) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("updating environment: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	rv, wn, src := envJSON(e)
	err = tx.QueryRow(ctx, `
		UPDATE environments SET kind=$3, target_project_id=$4, branch_patterns=$5, tag_patterns=$6, auto_deploy=$7,
			reviewers=$8::jsonb, required_approvals=$9, allow_self_approval=$10, wait_minutes=$11, windows=$12::jsonb,
			require_checks_on_sha=$13, require_source_environment=$14, require_security_policy=$15,
			rollback_requires_approval=$16, updated_at=now()
		WHERE id=$1 AND project_id=$2 RETURNING updated_at`,
		e.ID, e.ProjectID, e.Kind, e.TargetProjectID, e.BranchPatterns, e.TagPatterns, e.AutoDeploy, rv,
		e.RequiredApprovals, e.AllowSelfApproval, e.WaitMinutes, wn, e.RequireChecksOnSHA, src,
		e.RequireSecurityPolicy, e.RollbackRequiresApproval).Scan(&e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return environments.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("updating environment: %w", err)
	}
	if err := envInsertAudit(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *EnvironmentRepository) DeleteEnv(ctx context.Context, projectID, id uuid.UUID, a environments.AuditEntry) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("deleting environment: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `DELETE FROM environments WHERE id=$1 AND project_id=$2`, id, projectID)
	if err != nil {
		return fmt.Errorf("deleting environment: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return environments.ErrNotFound
	}
	if err := envInsertAudit(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---- history --------------------------------------------------------------------------------------

func (r *EnvironmentRepository) CurrentDeployment(ctx context.Context, envID uuid.UUID) (*environments.EnvDeployment, error) {
	var d environments.EnvDeployment
	err := scanEnvDeployment(r.pool.QueryRow(ctx, `SELECT `+envDepCols+` FROM environment_deployments
		WHERE environment_id=$1 AND status='success' ORDER BY COALESCE(finished_at, created_at) DESC, id DESC LIMIT 1`, envID), &d)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("current deployment: %w", err)
	}
	return &d, nil
}

func (r *EnvironmentRepository) ListEnvDeployments(ctx context.Context, envID uuid.UUID, cursor string, limit int) ([]environments.EnvDeployment, string, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if cursor == "" {
		rows, err = r.pool.Query(ctx, `SELECT `+envDepCols+` FROM environment_deployments WHERE environment_id=$1
			ORDER BY created_at DESC, id DESC LIMIT $2`, envID, limit+1)
	} else {
		ts, id, derr := environments.DecodeCursor(cursor)
		if derr != nil {
			return nil, "", derr
		}
		rows, err = r.pool.Query(ctx, `SELECT `+envDepCols+` FROM environment_deployments WHERE environment_id=$1
			AND (created_at, id) < ($2, $3) ORDER BY created_at DESC, id DESC LIMIT $4`, envID, ts, id, limit+1)
	}
	if err != nil {
		return nil, "", fmt.Errorf("listing environment deployments: %w", err)
	}
	defer rows.Close()
	out := []environments.EnvDeployment{}
	for rows.Next() {
		var d environments.EnvDeployment
		if err := scanEnvDeployment(rows, &d); err != nil {
			return nil, "", fmt.Errorf("scanning environment deployment: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = environments.EncodeCursor(out[limit-1].CreatedAt, out[limit-1].ID)
	}
	return out, next, nil
}

func (r *EnvironmentRepository) SuccessfulSHA(ctx context.Context, envID uuid.UUID, sha string) (*environments.EnvDeployment, *environments.Artifact, error) {
	var d environments.EnvDeployment
	err := scanEnvDeployment(r.pool.QueryRow(ctx, `SELECT `+envDepCols+` FROM environment_deployments
		WHERE environment_id=$1 AND sha=$2 AND status='success' AND deployment_id IS NOT NULL
		ORDER BY created_at DESC LIMIT 1`, envID, sha), &d)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("successful sha: %w", err)
	}
	art, err := r.ArtifactOf(ctx, *d.DeploymentID)
	if err != nil || art == nil {
		return nil, nil, err
	}
	return &d, art, nil
}

func (r *EnvironmentRepository) FindArtifact(ctx context.Context, projectID uuid.UUID, sha string) (*environments.Artifact, error) {
	var a environments.Artifact
	err := scanArtifact(r.pool.QueryRow(ctx, `SELECT `+artifactCols+` FROM deployments
		WHERE project_id=$1 AND git_sha=$2 AND status='success' AND source_key IS NOT NULL AND source_key <> ''
		ORDER BY created_at DESC LIMIT 1`, projectID, sha), &a)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("finding artifact: %w", err)
	}
	return &a, nil
}

func (r *EnvironmentRepository) ArtifactOf(ctx context.Context, id uuid.UUID) (*environments.Artifact, error) {
	var a environments.Artifact
	err := scanArtifact(r.pool.QueryRow(ctx, `SELECT `+artifactCols+` FROM deployments
		WHERE id=$1 AND source_key IS NOT NULL AND source_key <> ''`, id), &a)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading artifact: %w", err)
	}
	return &a, nil
}

// ---- promotions -----------------------------------------------------------------------------------

func (r *EnvironmentRepository) loadPromotion(ctx context.Context, q envQuerier, id uuid.UUID) (*environments.Promotion, error) {
	var p environments.Promotion
	err := scanPromotion(q.QueryRow(ctx, `SELECT `+promoCols+promoFrom+`WHERE p.id = $1`, id), &p)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, environments.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading promotion: %w", err)
	}
	if err := r.attachApprovals(ctx, q, []*environments.Promotion{&p}); err != nil {
		return nil, err
	}
	return &p, nil
}

func scanApproval(row pgx.Row, promo *uuid.UUID, a *environments.Approval) error {
	return row.Scan(promo, &a.UserID, &a.Decision, &a.Comment, &a.SelfApproval, &a.Role, &a.At)
}

func (r *EnvironmentRepository) attachApprovals(ctx context.Context, q envQuerier, ps []*environments.Promotion) error {
	if len(ps) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, len(ps))
	by := map[uuid.UUID]*environments.Promotion{}
	for i, p := range ps {
		ids[i] = p.ID
		by[p.ID] = p
	}
	rows, err := q.Query(ctx, `SELECT `+approvalCols+` FROM promotion_approvals WHERE promotion_id = ANY($1) ORDER BY created_at, id`, ids)
	if err != nil {
		return fmt.Errorf("loading approvals: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var pid uuid.UUID
		var a environments.Approval
		if err := scanApproval(rows, &pid, &a); err != nil {
			return fmt.Errorf("scanning approval: %w", err)
		}
		if p := by[pid]; p != nil {
			p.Approvals = append(p.Approvals, a)
		}
	}
	return rows.Err()
}

func (r *EnvironmentRepository) GetPromotion(ctx context.Context, id uuid.UUID) (*environments.Promotion, error) {
	return r.loadPromotion(ctx, r.pool, id)
}

func (r *EnvironmentRepository) queryPromotions(ctx context.Context, sql string, args ...any) ([]environments.Promotion, error) {
	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("listing promotions: %w", err)
	}
	defer rows.Close()
	var out []environments.Promotion
	for rows.Next() {
		var p environments.Promotion
		if err := scanPromotion(rows, &p); err != nil {
			return nil, fmt.Errorf("scanning promotion: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ptrs := make([]*environments.Promotion, len(out))
	for i := range out {
		ptrs[i] = &out[i]
	}
	return out, r.attachApprovals(ctx, r.pool, ptrs)
}

func (r *EnvironmentRepository) ListPromotions(ctx context.Context, envID uuid.UUID, activeOnly bool) ([]environments.Promotion, error) {
	q := `SELECT ` + promoCols + promoFrom + `WHERE p.environment_id = $1`
	if activeOnly {
		q += ` AND p.status IN ('pending_approval','waiting','approved','deploying')`
	}
	return r.queryPromotions(ctx, q+` ORDER BY p.created_at, p.id`, envID)
}

func (r *EnvironmentRepository) ListActive(ctx context.Context, limit int) ([]environments.Promotion, error) {
	return r.queryPromotions(ctx, `SELECT `+promoCols+promoFrom+`
		WHERE p.status IN ('pending_approval','waiting','approved','deploying') ORDER BY p.created_at, p.id LIMIT $1`, limit)
}

func (r *EnvironmentRepository) FindByIdempotency(ctx context.Context, projectID, requestedBy uuid.UUID, key string) (*environments.Promotion, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, `SELECT id FROM promotions WHERE project_id=$1 AND requested_by=$2 AND idempotency_key=$3`,
		projectID, requestedBy, key).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("finding promotion by key: %w", err)
	}
	return r.loadPromotion(ctx, r.pool, id)
}

func (r *EnvironmentRepository) CreatePromotion(ctx context.Context, p *environments.Promotion, a environments.AuditEntry) error {
	checks, _ := json.Marshal(p.Checks)
	conds, _ := json.Marshal(p.Conditions)
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("creating promotion: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	_, err = tx.Exec(ctx, `
		INSERT INTO promotions (id, project_id, environment_id, sha, branch, from_environment, comment, status,
			requested_by, required_approvals, quorum_at, not_before, expires_at, idempotency_key, source_deployment_id,
			checks, conditions)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17::jsonb)`,
		p.ID, p.ProjectID, p.EnvironmentID, p.SHA, p.Branch, p.FromEnvironment, p.Comment, p.Status, p.RequestedBy,
		p.RequiredApprovals, p.QuorumAt, p.NotBefore, p.ExpiresAt, p.IdempotencyKey, p.SourceDeploymentID, checks, conds)
	if err != nil {
		_ = tx.Rollback(ctx)
		switch {
		case isUnique(err, "uq_promotions_idempotency") && p.RequestedBy != nil:
			old, ferr := r.FindByIdempotency(ctx, p.ProjectID, *p.RequestedBy, p.IdempotencyKey)
			if ferr == nil && old != nil {
				return &environments.ExistingError{Kind: "idempotency", Promotion: old}
			}
		case isUnique(err, "uq_promotions_active_sha"):
			var id uuid.UUID
			if ferr := r.pool.QueryRow(ctx, `SELECT id FROM promotions WHERE environment_id=$1 AND sha=$2
				AND status IN ('pending_approval','waiting','approved','deploying') LIMIT 1`, p.EnvironmentID, p.SHA).Scan(&id); ferr == nil {
				if old, lerr := r.loadPromotion(ctx, r.pool, id); lerr == nil {
					return &environments.ExistingError{Kind: "active", Promotion: old}
				}
			}
		}
		return fmt.Errorf("creating promotion: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO environment_deployments (environment_id, promotion_id, sha, status)
		VALUES ($1,$2,$3,$4)`, p.EnvironmentID, p.ID, p.SHA, environments.EnvDeploymentStatus(p.Status)); err != nil {
		return fmt.Errorf("creating environment deployment: %w", err)
	}
	if err := envInsertAudit(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// syncHistory mirrors the promotion status into its history row.
func syncHistory(ctx context.Context, q envQuerier, id uuid.UUID, status string, finished *time.Time, health string) error {
	_, err := q.Exec(ctx, `UPDATE environment_deployments SET status=$2, finished_at=COALESCE($3, finished_at),
		health_status=CASE WHEN $4::text <> '' THEN $4::text ELSE health_status END,
		deployment_id=COALESCE(deployment_id, (SELECT deployment_id FROM promotions WHERE id=$1))
		WHERE promotion_id=$1`, id, environments.EnvDeploymentStatus(status), finished, health)
	if err != nil {
		return fmt.Errorf("updating environment deployment: %w", err)
	}
	return nil
}

func (r *EnvironmentRepository) AddDecision(ctx context.Context, d environments.Decision, a environments.AuditEntry) (*environments.Promotion, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("recording decision: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// the row lock serializes simultaneous decisions on the same promotion
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM promotions WHERE id=$1 FOR UPDATE`, d.PromotionID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, environments.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("locking promotion: %w", err)
	}
	approve := d.Approval.Decision == "approved"
	switch {
	case approve && status != environments.StatusPending:
		return nil, environments.ErrInvalidState
	case !approve && status != environments.StatusPending && status != environments.StatusWaiting && status != environments.StatusApproved:
		return nil, environments.ErrInvalidState
	}
	_, err = tx.Exec(ctx, `INSERT INTO promotion_approvals (promotion_id, user_id, decision, comment, self_approval, role_at_decision, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, d.PromotionID, d.Approval.UserID, d.Approval.Decision, d.Approval.Comment,
		d.Approval.SelfApproval, d.Approval.Role, d.Approval.At)
	if isUnique(err, "uq_promotion_approvals_user") {
		return nil, environments.ErrAlreadyDecided
	}
	if err != nil {
		return nil, fmt.Errorf("inserting approval: %w", err)
	}
	newStatus, reason := "", ""
	var nb *time.Time
	var finished *time.Time
	if !approve {
		newStatus, reason, finished = environments.StatusRejected, d.RejectReason, &d.RejectedAt
	} else {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM promotion_approvals WHERE promotion_id=$1 AND decision='approved'
			AND ($2 OR NOT self_approval)`, d.PromotionID, d.AllowSelf).Scan(&n); err != nil {
			return nil, fmt.Errorf("counting approvals: %w", err)
		}
		if n >= d.Required {
			newStatus, nb = d.QuorumStatus, d.QuorumNotBefore
		}
	}
	if newStatus != "" {
		if _, err := tx.Exec(ctx, `UPDATE promotions SET status=$2::text, status_reason=$3, not_before=$4,
			quorum_at=CASE WHEN $2::text IN ('waiting','approved') THEN $5 ELSE quorum_at END,
			finished_at=COALESCE($6, finished_at), required_approvals=$7, updated_at=now() WHERE id=$1`,
			d.PromotionID, newStatus, reason, nb, d.QuorumAt, finished, d.Required); err != nil {
			return nil, fmt.Errorf("updating promotion: %w", err)
		}
		if err := syncHistory(ctx, tx, d.PromotionID, newStatus, finished, ""); err != nil {
			return nil, err
		}
	}
	if err := envInsertAudit(ctx, tx, a); err != nil {
		return nil, err
	}
	p, err := r.loadPromotion(ctx, tx, d.PromotionID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("recording decision: %w", err)
	}
	return p, nil
}

func (r *EnvironmentRepository) Transition(ctx context.Context, id uuid.UUID, from []string, to string, pt environments.Patch, a *environments.AuditEntry) (bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("transition: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var got uuid.UUID
	err = tx.QueryRow(ctx, `UPDATE promotions SET status=$3, status_reason=$4, not_before=$5,
		quorum_at=COALESCE($6, quorum_at), started_at=COALESCE($7, started_at), finished_at=COALESCE($8, finished_at),
		required_approvals=COALESCE($9, required_approvals), updated_at=now()
		WHERE id=$1 AND status = ANY($2) RETURNING id`,
		id, from, to, pt.Reason, pt.NotBefore, pt.QuorumAt, pt.StartedAt, pt.FinishedAt, pt.Required).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if isUnique(err, "uq_promotions_one_deploying") {
		return false, nil // the environment already has a deploying promotion: stay queued
	}
	if err != nil {
		return false, fmt.Errorf("transition: %w", err)
	}
	if err := syncHistory(ctx, tx, id, to, pt.FinishedAt, pt.Health); err != nil {
		return false, err
	}
	if a != nil {
		if err := envInsertAudit(ctx, tx, *a); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("transition: %w", err)
	}
	return true, nil
}

func (r *EnvironmentRepository) SetDeployment(ctx context.Context, id, deploymentID uuid.UUID) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("saving deployment: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `UPDATE promotions SET deployment_id=$2, updated_at=now() WHERE id=$1`, id, deploymentID); err != nil {
		return fmt.Errorf("saving deployment: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE environment_deployments SET deployment_id=$2 WHERE promotion_id=$1`, id, deploymentID); err != nil {
		return fmt.Errorf("saving deployment: %w", err)
	}
	return tx.Commit(ctx)
}

func (r *EnvironmentRepository) ExpireOverdue(ctx context.Context, now time.Time) ([]environments.Promotion, error) {
	rows, err := r.pool.Query(ctx, `UPDATE promotions SET status='expired', status_reason='expired without a decision (72 h)',
		finished_at=$1, updated_at=now()
		WHERE status IN ('pending_approval','waiting','approved') AND expires_at <= $1 RETURNING id`, now)
	if err != nil {
		return nil, fmt.Errorf("expiring promotions: %w", err)
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []environments.Promotion
	for _, id := range ids {
		p, err := r.loadPromotion(ctx, r.pool, id)
		if err != nil {
			return nil, err
		}
		if err := syncHistory(ctx, r.pool, id, environments.StatusExpired, &now, ""); err != nil {
			return nil, err
		}
		_ = envInsertAudit(ctx, r.pool, environments.AuditEntry{OrgID: orgOf(ctx, r.pool, p.ProjectID), Action: "promotion.expire",
			ResourceType: "promotion", ResourceID: id, NewValues: map[string]any{"environment": p.Environment, "sha": p.SHA}})
		out = append(out, *p)
	}
	return out, nil
}

func orgOf(ctx context.Context, q envQuerier, projectID uuid.UUID) uuid.UUID {
	var org uuid.UUID
	_ = q.QueryRow(ctx, `SELECT org_id FROM projects WHERE id=$1`, projectID).Scan(&org)
	return org
}

func (r *EnvironmentRepository) PendingForOrg(ctx context.Context, orgID uuid.UUID, cursor string, limit int) ([]environments.PendingRow, error) {
	q := `SELECT ` + promoCols + `, ` + envColsPrefixed + promoFrom + `
		WHERE p.status = 'pending_approval' AND p.project_id IN (SELECT id FROM projects WHERE org_id = $1 AND deleted_at IS NULL)`
	args := []any{orgID}
	if cursor != "" {
		ts, id, err := environments.DecodeCursor(cursor)
		if err != nil {
			return nil, err
		}
		q += ` AND (p.created_at, p.id) > ($2, $3)`
		args = append(args, ts, id)
	}
	q += fmt.Sprintf(` ORDER BY p.created_at, p.id LIMIT %d`, limit)
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing pending approvals: %w", err)
	}
	defer rows.Close()
	var out []environments.PendingRow
	for rows.Next() {
		var pr environments.PendingRow
		if err := scanPendingRow(rows, &pr); err != nil {
			return nil, fmt.Errorf("scanning pending approval: %w", err)
		}
		out = append(out, pr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ptrs := make([]*environments.Promotion, len(out))
	for i := range out {
		ptrs[i] = &out[i].Promotion
	}
	return out, r.attachApprovals(ctx, r.pool, ptrs)
}

const envColsPrefixed = `e.id, e.project_id, e.name, e.kind, e.target_project_id, e.branch_patterns, e.tag_patterns, e.auto_deploy,
	e.reviewers, e.required_approvals, e.allow_self_approval, e.wait_minutes, e.windows, e.require_checks_on_sha,
	e.require_source_environment, e.require_security_policy, e.rollback_requires_approval, e.created_by, e.created_at, e.updated_at`

func scanPendingRow(row pgx.Row, pr *environments.PendingRow) error {
	var checks, conds, reviewers, windows []byte
	var src string
	p, e := &pr.Promotion, &pr.Env
	err := row.Scan(&p.ID, &p.ProjectID, &p.EnvironmentID, &p.Environment, &p.SHA, &p.Branch, &p.FromEnvironment,
		&p.Comment, &p.Status, &p.StatusReason, &p.RequestedBy, &p.RequiredApprovals, &p.QuorumAt, &p.NotBefore,
		&p.ExpiresAt, &p.IdempotencyKey, &p.SourceDeploymentID, &p.DeploymentID, &checks, &conds, &p.StartedAt,
		&p.FinishedAt, &p.CreatedAt, &p.UpdatedAt,
		&e.ID, &e.ProjectID, &e.Name, &e.Kind, &e.TargetProjectID, &e.BranchPatterns, &e.TagPatterns,
		&e.AutoDeploy, &reviewers, &e.RequiredApprovals, &e.AllowSelfApproval, &e.WaitMinutes, &windows,
		&e.RequireChecksOnSHA, &src, &e.RequireSecurityPolicy, &e.RollbackRequiresApproval, &e.CreatedBy,
		&e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return err
	}
	_ = json.Unmarshal(checks, &p.Checks)
	_ = json.Unmarshal(conds, &p.Conditions)
	if p.Checks.Items == nil {
		p.Checks.Items = []environments.CheckItem{}
	}
	if p.Conditions == nil {
		p.Conditions = []environments.Condition{}
	}
	p.Approvals = []environments.Approval{}
	if src != "" {
		e.RequireSourceEnvironment = &src
	}
	if err := json.Unmarshal(reviewers, &e.Reviewers); err != nil {
		return fmt.Errorf("decoding reviewers: %w", err)
	}
	_ = json.Unmarshal(windows, &e.Windows)
	return nil
}
