package gitaudit

import "regexp"

// Audit actions of Git Capsule. audit_logs.action is varchar(50) and resource_type varchar(50).
// Actions already written by other packages keep their names (git_token.*, git_ssh_key.*, the
// member and org actions of authz); these are the ones the product spec adds (SPEC 5.9).
const (
	ActProtectionChange   = "git.protection.change"
	ActRepoSettingsChange = "repo.settings.change"
	ActMemberRoleChange   = "member.role.change"
	ActTeamDrift          = "git.team_drift" // written with user_id NULL and actor_label "system"
	ActApprovalDecide     = "env.approval.decide"
	ActPromotionRequest   = "env.promotion.request"
	ActEnvironmentChange  = "env.config.change"
	ActAlertDismiss       = "security.alert.dismiss"
	ActSuppressionCreate  = "security.suppression.create"
	ActSuppressionExpire  = "security.suppression.expire"
	ActSecurityPolicy     = "security.policy.change"
	ActWebhookCreate      = "webhook.create"
	ActWebhookUpdate      = "webhook.update"
	ActWebhookDelete      = "webhook.delete"
	ActWebhookRotate      = "webhook.rotate_secret"
	ActMirrorChange       = "git.mirror.change"
	ActImportStart        = "git.import.start"
	ActImportFinish       = "git.import.finish"
	ActRecoveryRun        = "recovery.run"
	ActAuditExport        = "audit.export"
)

// ResourceTypes used by the actions above.
const (
	ResProject     = "project"
	ResProtection  = "branch_protection"
	ResMember      = "project_member"
	ResEnvironment = "environment"
	ResPromotion   = "promotion"
	ResAlert       = "security_alert"
	ResSuppression = "security_suppression"
	ResWebhook     = "webhook"
	ResMirror      = "git_mirror"
	ResImport      = "git_import"
	ResRecovery    = "recovery_run"
	ResAuditLog    = "audit_log"
)

// Actions lists the actions above (tests and docs).
var Actions = []string{
	ActProtectionChange, ActRepoSettingsChange, ActMemberRoleChange, ActTeamDrift, ActApprovalDecide,
	ActPromotionRequest, ActEnvironmentChange, ActAlertDismiss, ActSuppressionCreate, ActSuppressionExpire,
	ActSecurityPolicy, ActWebhookCreate, ActWebhookUpdate, ActWebhookDelete, ActWebhookRotate,
	ActMirrorChange, ActImportStart, ActImportFinish, ActRecoveryRun, ActAuditExport,
}

var actionRE = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)
var resourceRE = regexp.MustCompile(`^[a-z0-9_]+$`)

// ValidAction reports whether s is a well formed action name ("area.thing[.verb]", max 50).
func ValidAction(s string) bool { return len(s) <= 50 && actionRE.MatchString(s) }

// ValidResourceType reports whether s is a well formed resource type (max 50).
func ValidResourceType(s string) bool { return len(s) <= 50 && resourceRE.MatchString(s) }
