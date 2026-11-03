// Package gitprotect is Git Capsule package A4: branch protection rules.
//
// Capsule owns the rules (table branch_protection_rules, the source of truth) and projects them
// onto Forgejo through gitcore.Protections. It also explains which rule applies to a branch
// (Evaluate, with Forgejo's glob semantics and precedence), reconciles drift (somebody edits a
// rule in Forgejo), restricts merge styles for "linear history", protects tags and keeps an audit
// trail of every change.
//
// Depends only on gitcore (A1) and the standard library; persistence goes through Store, which
// internal/repository implements.
package gitprotect

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Roles that can be named in push_allow_roles / merge_allow_roles.
const (
	RoleAdmin    = "admin"
	RoleDeployer = "deployer"
)

// Sync states of a rule.
const (
	SyncPending = "pending"
	SyncSynced  = "synced"
	SyncError   = "error"
)

// Audit actions (SPEC 5.3 / 6: git.protection.change, repo.settings.change).
const (
	ActionProtectionChange = "git.protection.change"
	ActionProtectionDrift  = "git.protection.drift"
	ActionRepoSettings     = "repo.settings.change"
	ActionTagChange        = "git.tag.change"
	ResourceProtection     = "branch_protection"
	ResourceRepo           = "git_repo"
	ResourceTag            = "git_tag"
)

// Capsule contexts published as commit statuses (SPEC 5.3). They can be used as required checks.
const (
	CtxPreview  = "capsule/preview"
	CtxSecurity = "capsule/security"
	CtxPolicy   = "capsule/policy"
	CtxEnvPref  = "capsule/env:"
)

var (
	ErrNotFound  = errors.New("gitprotect: not found")
	ErrDuplicate = errors.New("gitprotect: a rule with that pattern already exists")
)

// Rule is one protection rule as Capsule stores it. JSON names follow ProtectionInput.
type Rule struct {
	ID        uuid.UUID `json:"id"`
	ProjectID uuid.UUID `json:"-"`

	Pattern                string   `json:"pattern"`
	RequirePullRequest     bool     `json:"require_pull_request"`
	RequiredApprovals      int      `json:"required_approvals"`
	DismissStaleApprovals  bool     `json:"dismiss_stale_approvals"`
	BlockOnRejectedReviews bool     `json:"block_on_rejected_reviews"`
	RequireCodeOwnerReview bool     `json:"require_code_owner_review"`
	RequiredChecks         []string `json:"required_checks"`
	RequireUpToDate        bool     `json:"require_up_to_date"`
	RequireSignedCommits   bool     `json:"require_signed_commits"`
	RequireLinearHistory   bool     `json:"require_linear_history"`
	BlockForcePush         bool     `json:"block_force_push"`
	BlockDeletion          bool     `json:"block_deletion"`
	PushAllowRoles         []string `json:"push_allow_roles"`
	MergeAllowRoles        []string `json:"merge_allow_roles"`
	EnforceForAdmins       bool     `json:"enforce_for_admins"`
	BlockOnSecurityPolicy  bool     `json:"block_on_security_policy"`
	DeleteBranchOnMerge    bool     `json:"delete_branch_on_merge"`

	CreatedBy *uuid.UUID `json:"-"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// SyncState is the projection state of one rule (table branch_protection_sync).
type SyncState struct {
	RuleID          uuid.UUID
	ProjectID       uuid.UUID
	Status          string
	ForgejoRuleName string
	StaleRuleNames  []string
	SpecHash        string
	Attempts        int
	LastError       string
	LastSyncedAt    *time.Time
	LastDriftAt     *time.Time
	DriftCount      int
	UpdatedAt       time.Time
}

// Protection is the API view: ProtectionInput fields + id/created_at + sync information.
type Protection struct {
	Rule
	ForgejoSynced bool       `json:"forgejo_synced"`
	SyncError     string     `json:"sync_error,omitempty"`
	SyncStatus    string     `json:"sync_status"`
	LastSyncedAt  *time.Time `json:"last_synced_at,omitempty"`
	DriftCount    int        `json:"drift_count"`
	Warnings      []string   `json:"warnings,omitempty"`
}

// Input is the request body of create/put. Pointers tell "omitted" (safe default) from false.
type Input struct {
	Pattern                string   `json:"pattern"`
	RequirePullRequest     *bool    `json:"require_pull_request"`
	RequiredApprovals      *int     `json:"required_approvals"`
	DismissStaleApprovals  *bool    `json:"dismiss_stale_approvals"`
	BlockOnRejectedReviews *bool    `json:"block_on_rejected_reviews"`
	RequireCodeOwnerReview *bool    `json:"require_code_owner_review"`
	RequiredChecks         []string `json:"required_checks"`
	RequireUpToDate        *bool    `json:"require_up_to_date"`
	RequireSignedCommits   *bool    `json:"require_signed_commits"`
	RequireLinearHistory   *bool    `json:"require_linear_history"`
	BlockForcePush         *bool    `json:"block_force_push"`
	BlockDeletion          *bool    `json:"block_deletion"`
	PushAllowRoles         []string `json:"push_allow_roles"`
	MergeAllowRoles        []string `json:"merge_allow_roles"`
	EnforceForAdmins       *bool    `json:"enforce_for_admins"`
	BlockOnSecurityPolicy  *bool    `json:"block_on_security_policy"`
	DeleteBranchOnMerge    *bool    `json:"delete_branch_on_merge"`
}

// Target identifies the project a call acts on (the handler resolves it from the URL).
type Target struct {
	ProjectID   uuid.UUID
	OrgID       uuid.UUID
	OrgSlug     string // Forgejo owner
	ProjectSlug string // Forgejo repo (also the prefix of the <slug>-admin / -deployer teams)
}

// Actor is who performs a change (for audit and Sudo). Zero value = the system (reconciler).
type Actor struct {
	UserID uuid.UUID
	IP     string
}

// AuditEntry is written to audit_logs (same shape as authz.AuditEntry; UserID may be Nil).
type AuditEntry struct {
	OrgID        uuid.UUID
	UserID       uuid.UUID
	Action       string
	ResourceType string
	ResourceID   uuid.UUID
	IP           string
	OldValues    map[string]any
	NewValues    map[string]any
}

// FieldError is one validation problem.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError groups FieldErrors (handler answers 422 VALIDATION_ERROR).
type ValidationError struct{ Fields []FieldError }

func (e *ValidationError) Error() string {
	if len(e.Fields) == 0 {
		return "invalid protection rule"
	}
	return "invalid protection rule: " + e.Fields[0].Field + ": " + e.Fields[0].Message
}

// PolicyError is a business-rule refusal (handler answers 422 with Code).
type PolicyError struct{ Code, Message string }

func (e *PolicyError) Error() string { return e.Code + ": " + e.Message }

// ConflictError is a 409 (duplicate pattern, limit reached).
type ConflictError struct{ Code, Message string }

func (e *ConflictError) Error() string { return e.Code + ": " + e.Message }

// ForbiddenError is a 403 decided by Capsule (e.g. PROTECTED_TAG).
type ForbiddenError struct{ Code, Message string }

func (e *ForbiddenError) Error() string { return e.Code + ": " + e.Message }
