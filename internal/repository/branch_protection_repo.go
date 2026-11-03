package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/gitprotect"
)

// BranchProtectionRepository persists branch_protection_rules and branch_protection_sync
// (Git Capsule A4) and implements gitprotect.Store.
type BranchProtectionRepository struct{ pool *pgxpool.Pool }

func NewBranchProtectionRepository(pool *pgxpool.Pool) *BranchProtectionRepository {
	return &BranchProtectionRepository{pool: pool}
}

var _ gitprotect.Store = (*BranchProtectionRepository)(nil)

const branchProtectionCols = `id, project_id, pattern, require_pull_request, required_approvals, dismiss_stale_approvals,
	block_on_rejected_reviews, require_code_owner_review, required_checks, require_up_to_date, require_signed_commits,
	require_linear_history, block_force_push, block_deletion, push_allow_roles, merge_allow_roles, enforce_for_admins,
	block_on_security_policy, delete_branch_on_merge, created_by, created_at, updated_at`

const branchProtectionSyncCols = `rule_id, project_id, status, forgejo_rule_name, stale_rule_names, spec_hash, attempts,
	last_error, last_synced_at, last_drift_at, drift_count, updated_at`

const branchProtectionTargetCols = `p.id, o.id, o.slug, p.slug`

func scanBranchProtection(row interface{ Scan(...any) error }, r *gitprotect.Rule) error {
	return row.Scan(&r.ID, &r.ProjectID, &r.Pattern, &r.RequirePullRequest, &r.RequiredApprovals, &r.DismissStaleApprovals,
		&r.BlockOnRejectedReviews, &r.RequireCodeOwnerReview, &r.RequiredChecks, &r.RequireUpToDate, &r.RequireSignedCommits,
		&r.RequireLinearHistory, &r.BlockForcePush, &r.BlockDeletion, &r.PushAllowRoles, &r.MergeAllowRoles, &r.EnforceForAdmins,
		&r.BlockOnSecurityPolicy, &r.DeleteBranchOnMerge, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
}

func scanBranchProtectionSync(row interface{ Scan(...any) error }, s *gitprotect.SyncState) error {
	return row.Scan(&s.RuleID, &s.ProjectID, &s.Status, &s.ForgejoRuleName, &s.StaleRuleNames, &s.SpecHash, &s.Attempts,
		&s.LastError, &s.LastSyncedAt, &s.LastDriftAt, &s.DriftCount, &s.UpdatedAt)
}

func scanBranchProtectionTarget(row interface{ Scan(...any) error }, t *gitprotect.Target) error {
	return row.Scan(&t.ProjectID, &t.OrgID, &t.OrgSlug, &t.ProjectSlug)
}

func bpNonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func bpIsUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (r *BranchProtectionRepository) ListRules(ctx context.Context, projectID uuid.UUID) ([]gitprotect.Rule, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+branchProtectionCols+` FROM branch_protection_rules WHERE project_id = $1 ORDER BY created_at, id`, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing branch protection rules: %w", err)
	}
	defer rows.Close()
	var out []gitprotect.Rule
	for rows.Next() {
		var x gitprotect.Rule
		if err := scanBranchProtection(rows, &x); err != nil {
			return nil, fmt.Errorf("scanning branch protection rule: %w", err)
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (r *BranchProtectionRepository) GetRule(ctx context.Context, projectID, ruleID uuid.UUID) (*gitprotect.Rule, error) {
	var x gitprotect.Rule
	err := scanBranchProtection(r.pool.QueryRow(ctx, `SELECT `+branchProtectionCols+` FROM branch_protection_rules WHERE id = $1 AND project_id = $2`, ruleID, projectID), &x)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, gitprotect.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading branch protection rule: %w", err)
	}
	return &x, nil
}

type bpExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func bpInsertAudit(ctx context.Context, q bpExecer, e gitprotect.AuditEntry) error {
	var user, res any
	if e.UserID != uuid.Nil {
		user = e.UserID
	}
	if e.ResourceID != uuid.Nil {
		res = e.ResourceID
	}
	var ip any
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

func (r *BranchProtectionRepository) CreateRule(ctx context.Context, x *gitprotect.Rule, a gitprotect.AuditEntry) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("creating branch protection rule: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	err = tx.QueryRow(ctx, `
		INSERT INTO branch_protection_rules (id, project_id, pattern, require_pull_request, required_approvals, dismiss_stale_approvals,
			block_on_rejected_reviews, require_code_owner_review, required_checks, require_up_to_date, require_signed_commits,
			require_linear_history, block_force_push, block_deletion, push_allow_roles, merge_allow_roles, enforce_for_admins,
			block_on_security_policy, delete_branch_on_merge, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
		RETURNING created_at, updated_at`,
		x.ID, x.ProjectID, x.Pattern, x.RequirePullRequest, x.RequiredApprovals, x.DismissStaleApprovals,
		x.BlockOnRejectedReviews, x.RequireCodeOwnerReview, bpNonNil(x.RequiredChecks), x.RequireUpToDate, x.RequireSignedCommits,
		x.RequireLinearHistory, x.BlockForcePush, x.BlockDeletion, bpNonNil(x.PushAllowRoles), bpNonNil(x.MergeAllowRoles), x.EnforceForAdmins,
		x.BlockOnSecurityPolicy, x.DeleteBranchOnMerge, x.CreatedBy).Scan(&x.CreatedAt, &x.UpdatedAt)
	if bpIsUnique(err) {
		return gitprotect.ErrDuplicate
	}
	if err != nil {
		return fmt.Errorf("creating branch protection rule: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO branch_protection_sync (rule_id, project_id, status) VALUES ($1, $2, 'pending')`, x.ID, x.ProjectID); err != nil {
		return fmt.Errorf("creating branch protection sync row: %w", err)
	}
	if err := bpInsertAudit(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *BranchProtectionRepository) UpdateRule(ctx context.Context, x *gitprotect.Rule, a gitprotect.AuditEntry) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("updating branch protection rule: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	err = tx.QueryRow(ctx, `
		UPDATE branch_protection_rules SET pattern=$3, require_pull_request=$4, required_approvals=$5, dismiss_stale_approvals=$6,
			block_on_rejected_reviews=$7, require_code_owner_review=$8, required_checks=$9, require_up_to_date=$10, require_signed_commits=$11,
			require_linear_history=$12, block_force_push=$13, block_deletion=$14, push_allow_roles=$15, merge_allow_roles=$16,
			enforce_for_admins=$17, block_on_security_policy=$18, delete_branch_on_merge=$19, updated_at=now()
		WHERE id=$1 AND project_id=$2
		RETURNING created_at, updated_at`,
		x.ID, x.ProjectID, x.Pattern, x.RequirePullRequest, x.RequiredApprovals, x.DismissStaleApprovals,
		x.BlockOnRejectedReviews, x.RequireCodeOwnerReview, bpNonNil(x.RequiredChecks), x.RequireUpToDate, x.RequireSignedCommits,
		x.RequireLinearHistory, x.BlockForcePush, x.BlockDeletion, bpNonNil(x.PushAllowRoles), bpNonNil(x.MergeAllowRoles), x.EnforceForAdmins,
		x.BlockOnSecurityPolicy, x.DeleteBranchOnMerge).Scan(&x.CreatedAt, &x.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return gitprotect.ErrNotFound
	}
	if bpIsUnique(err) {
		return gitprotect.ErrDuplicate
	}
	if err != nil {
		return fmt.Errorf("updating branch protection rule: %w", err)
	}
	if err := bpInsertAudit(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *BranchProtectionRepository) DeleteRule(ctx context.Context, projectID, ruleID uuid.UUID, a gitprotect.AuditEntry) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("deleting branch protection rule: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `DELETE FROM branch_protection_rules WHERE id = $1 AND project_id = $2`, ruleID, projectID)
	if err != nil {
		return fmt.Errorf("deleting branch protection rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return gitprotect.ErrNotFound
	}
	if err := bpInsertAudit(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *BranchProtectionRepository) ListSync(ctx context.Context, projectID uuid.UUID) (map[uuid.UUID]gitprotect.SyncState, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+branchProtectionSyncCols+` FROM branch_protection_sync WHERE project_id = $1`, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing branch protection sync: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]gitprotect.SyncState{}
	for rows.Next() {
		var s gitprotect.SyncState
		if err := scanBranchProtectionSync(rows, &s); err != nil {
			return nil, fmt.Errorf("scanning branch protection sync: %w", err)
		}
		out[s.RuleID] = s
	}
	return out, rows.Err()
}

func (r *BranchProtectionRepository) PutSync(ctx context.Context, s gitprotect.SyncState) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO branch_protection_sync (rule_id, project_id, status, forgejo_rule_name, stale_rule_names, spec_hash, attempts,
			last_error, last_synced_at, last_drift_at, drift_count, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, now())
		ON CONFLICT (rule_id) DO UPDATE SET
			status = EXCLUDED.status, forgejo_rule_name = EXCLUDED.forgejo_rule_name, stale_rule_names = EXCLUDED.stale_rule_names,
			spec_hash = EXCLUDED.spec_hash, attempts = EXCLUDED.attempts, last_error = EXCLUDED.last_error,
			last_synced_at = EXCLUDED.last_synced_at, last_drift_at = EXCLUDED.last_drift_at, drift_count = EXCLUDED.drift_count,
			updated_at = now()`,
		s.RuleID, s.ProjectID, s.Status, s.ForgejoRuleName, bpNonNil(s.StaleRuleNames), s.SpecHash, s.Attempts,
		s.LastError, s.LastSyncedAt, s.LastDriftAt, s.DriftCount)
	if err != nil {
		return fmt.Errorf("saving branch protection sync: %w", err)
	}
	return nil
}

func (r *BranchProtectionRepository) ProjectsWithRules(ctx context.Context) ([]gitprotect.Target, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT `+branchProtectionTargetCols+`
		FROM branch_protection_rules br
		JOIN projects p      ON p.id = br.project_id AND p.deleted_at IS NULL
		JOIN organizations o ON o.id = p.org_id AND o.deleted_at IS NULL
		JOIN git_core_state s ON s.project_id = p.id AND s.status = 'ready'
		ORDER BY p.id`)
	if err != nil {
		return nil, fmt.Errorf("listing projects with protection rules: %w", err)
	}
	defer rows.Close()
	var out []gitprotect.Target
	for rows.Next() {
		var t gitprotect.Target
		if err := scanBranchProtectionTarget(rows, &t); err != nil {
			return nil, fmt.Errorf("scanning protection target: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *BranchProtectionRepository) WriteAudit(ctx context.Context, a gitprotect.AuditEntry) error {
	return bpInsertAudit(ctx, r.pool, a)
}
