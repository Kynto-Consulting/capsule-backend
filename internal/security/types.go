// Package security is Git Capsule package B7: security alerts for repositories.
//
// It ingests SARIF 2.1.0 produced by osv-scanner, Semgrep, gosec, Bandit, gitleaks, trivy and any
// other tool, turns every result into an Alert with a stable fingerprint (open -> fixed cycle),
// applies suppressions (enumerated reason, justification >= 10 characters, mandatory expiry),
// evaluates the per-project policy (check capsule/security on pull requests, deploy gate) and
// keeps the Renovate state of each repository.
//
// SARIF is untrusted input: it is parsed with hard limits (compressed size, decompressed size,
// nesting depth, number of results), every text is sanitized and HTML/Markdown escaped before it
// is stored, and the VALUE of a detected secret is never stored, returned, logged or published:
// only an HMAC fingerprint, the path, the line and the rule.
package security

import (
	"time"

	"github.com/google/uuid"
)

// Kind is the alert family (SPEC 5.8).
type Kind string

const (
	KindDependency Kind = "dependency"
	KindCode       Kind = "code"
	KindSecret     Kind = "secret"
)

// Valid reports whether k is one of the three kinds.
func (k Kind) Valid() bool { return k == KindDependency || k == KindCode || k == KindSecret }

// Severity of an alert.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Rank orders severities: critical 4 ... info 0 (unknown -1).
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	case SevInfo:
		return 0
	}
	return -1
}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { return s.Rank() >= 0 }

// HighOrAbove is true for critical and high (they need security.admin to dismiss, 180 days max).
func (s Severity) HighOrAbove() bool { return s.Rank() >= SevHigh.Rank() }

// State of an alert.
type State string

const (
	StateOpen      State = "open"
	StateFixed     State = "fixed"
	StateDismissed State = "dismissed"
)

// Tool names (enum of the contract).
const (
	ToolOSV      = "osv-scanner"
	ToolRenovate = "renovate"
	ToolSemgrep  = "semgrep"
	ToolGosec    = "gosec"
	ToolBandit   = "bandit"
	ToolESLint   = "eslint-security"
	ToolGitleaks = "gitleaks"
	ToolTrivy    = "trivy"
	ToolOther    = "sarif-other"
)

// KnownTools lists the tool enum in contract order.
var KnownTools = []string{ToolOSV, ToolRenovate, ToolSemgrep, ToolGosec, ToolBandit, ToolESLint, ToolGitleaks, ToolTrivy, ToolOther}

func validTool(t string) bool {
	for _, k := range KnownTools {
		if k == t {
			return true
		}
	}
	return false
}

// Dismissal reasons (enum of DismissRequest / SuppressionInput).
const (
	ReasonFalsePositive = "false_positive"
	ReasonWontFix       = "wont_fix"
	ReasonUsedInTests   = "used_in_tests"
	ReasonRiskAccepted  = "risk_accepted"
)

// Reasons is the enum, in contract order.
var Reasons = []string{ReasonFalsePositive, ReasonWontFix, ReasonUsedInTests, ReasonRiskAccepted}

func validReason(r string) bool {
	for _, k := range Reasons {
		if k == r {
			return true
		}
	}
	return false
}

// Limits of suppressions (SPEC 5.8).
const (
	MinJustificationRunes = 10
	MaxSuppressionDays    = 365
	MaxSuppressionDaysHi  = 180 // critical/high
	ExpiryNoticeDays      = 7
)

// TraceStep is one hop of a data-flow trace (SARIF codeFlows), already escaped.
type TraceStep struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Message string `json:"message,omitempty"`
}

// Person is a Capsule user as shown in dismissals and suppressions.
type Person struct {
	UserID    *uuid.UUID `json:"user_id"`
	Login     string     `json:"login,omitempty"`
	Name      string     `json:"name,omitempty"`
	Email     string     `json:"email,omitempty"`
	AvatarURL string     `json:"avatar_url,omitempty"`
}

// Dismissal is the dismissal data of an alert.
type Dismissal struct {
	Reason        string
	Justification string
	ByUserID      uuid.UUID // uuid.Nil when unknown (user deleted)
	By            Person    // filled on reads
	ExpiresAt     time.Time
	At            time.Time
}

// Alert is one security alert as stored. Text fields are already sanitized and escaped.
type Alert struct {
	ID            uuid.UUID
	ProjectID     uuid.UUID
	Kind          Kind
	Tool          string
	ToolName      string
	RuleID        string
	Severity      Severity
	State         State
	Title         string
	Description   string
	Fingerprint   string
	Branch        string
	Path          string
	StartLine     int
	EndLine       int
	Package       string
	Version       string
	FixedVersion  string
	Advisory      string
	Evidence      string // never set for secrets
	Trace         []TraceStep
	FirstSeenSHA  string
	LastSeenSHA   string
	LastUploadID  uuid.UUID
	SuppressionID uuid.UUID // uuid.Nil when none
	Dismissal     *Dismissal
	FixedAt       *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Finding is a normalized SARIF result, before it becomes an Alert. It is what is persisted in
// sarif_uploads.findings until the upload is processed; secrets carry no value at all.
type Finding struct {
	Kind         Kind        `json:"kind"`
	Tool         string      `json:"tool"`
	ToolName     string      `json:"tool_name"`
	RuleID       string      `json:"rule_id"`
	Severity     Severity    `json:"severity"`
	Title        string      `json:"title"`
	Description  string      `json:"description,omitempty"`
	Fingerprint  string      `json:"fingerprint"`
	Path         string      `json:"path,omitempty"`
	StartLine    int         `json:"start_line,omitempty"`
	EndLine      int         `json:"end_line,omitempty"`
	Package      string      `json:"package,omitempty"`
	Version      string      `json:"version,omitempty"`
	FixedVersion string      `json:"fixed_version,omitempty"`
	Advisory     string      `json:"advisory,omitempty"`
	Evidence     string      `json:"evidence,omitempty"`
	Trace        []TraceStep `json:"trace,omitempty"`
}

// Scope is the (tool) a run of an upload speaks for; the open -> fixed cycle is applied per scope,
// including runs that produced zero results.
type Scope struct {
	Tool     string `json:"tool"`
	ToolName string `json:"tool_name"`
}

// UploadPayload is the sanitized content of an upload awaiting processing.
type UploadPayload struct {
	Scopes   []Scope   `json:"scopes"`
	Findings []Finding `json:"findings"`
}

// Upload statuses.
const (
	UploadPending    = "pending"
	UploadProcessing = "processing"
	UploadComplete   = "complete"
	UploadFailed     = "failed"
)

// Upload is the row of sarif_uploads.
type Upload struct {
	ID             uuid.UUID
	ProjectID      uuid.UUID
	CommitSHA      string
	Ref            string
	Branch         string
	PR             int
	Tool           string
	ToolName       string
	Status         string
	Error          string
	IdempotencyKey string
	ResultsTotal   int
	AlertsCreated  int
	AlertsFixed    int
	Superseded     bool
	Attempts       int
	CreatedBy      uuid.UUID
	CreatedAt      time.Time
	StartedAt      *time.Time
	CompletedAt    *time.Time
}

// SuppressionMatch selects alerts. Every non-empty field must match (AND).
type SuppressionMatch struct {
	RuleID      string `json:"rule_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	PathGlob    string `json:"path_glob,omitempty"`
}

// Suppression states.
const (
	SuppActive  = "active"
	SuppExpired = "expired"
	SuppRevoked = "revoked"
)

// Suppression is a rule/fingerprint/path suppression (or the one created by dismissing an alert).
type Suppression struct {
	ID                 uuid.UUID
	ProjectID          uuid.UUID
	Match              SuppressionMatch
	Reason             string
	Justification      string
	ExpiresAt          time.Time
	State              string
	Source             string // manual | alert
	AlertID            uuid.UUID
	CoversHigh         bool // may suppress critical/high alerts (created by an admin that covered one)
	CreatedBy          uuid.UUID
	CreatedByPerson    Person
	CreatedAt          time.Time
	RevokedAt          *time.Time
	NotifiedExpiringAt *time.Time
}

// Policy is the per-project security policy (contract SecurityPolicy).
type Policy struct {
	BlockMergeOn       BlockMerge `json:"block_merge_on"`
	BlockDeployOn      string     `json:"block_deploy_on"` // off|critical|high
	RequiredTools      []string   `json:"required_tools"`
	MaxSuppressionDays int        `json:"max_suppression_days"`
	AppliesToBranches  []string   `json:"applies_to_branches"`
}

// BlockMerge is the minimum severity that blocks a merge, by kind. Secret: off|any.
type BlockMerge struct {
	Dependency string `json:"dependency"` // off|critical|high|medium|low
	Code       string `json:"code"`
	Secret     string `json:"secret"`
}

// DefaultPolicy is what a project without a stored policy gets.
func DefaultPolicy() Policy {
	return Policy{
		BlockMergeOn:       BlockMerge{Dependency: "high", Code: "high", Secret: "any"},
		BlockDeployOn:      "critical",
		RequiredTools:      []string{},
		MaxSuppressionDays: MaxSuppressionDaysHi,
		AppliesToBranches:  []string{},
	}
}

// Overview is the contract SecurityOverview.
type Overview struct {
	BySeverity map[string]int
	ByKind     map[string]int
	Open       int
	Dismissed  int
	LastScanAt *time.Time
}

// AlertQuery filters alert lists. Empty fields do not filter. Secrets are excluded unless
// IncludeSecrets (viewers only see counters of secret alerts).
type AlertQuery struct {
	Kind           string
	Severity       string
	State          string
	Branch         string
	Tool           string
	Cursor         string
	Limit          int
	IncludeSecrets bool
}

// Target identifies a project and its repository.
type Target struct {
	ProjectID   uuid.UUID
	OrgID       uuid.UUID
	OrgSlug     string
	ProjectSlug string
}

// Actor is who performs a change (audit). Zero value = the system.
type Actor struct {
	UserID uuid.UUID
	Login  string
	IP     string
	// Admin is true when the user holds security.admin (decided by the handler through authz).
	Admin bool
}

// AuditEntry is written to audit_logs.
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

// Audit actions.
const (
	AuditAlertDismiss      = "security.alert.dismiss"
	AuditAlertReopen       = "security.alert.reopen"
	AuditSuppressionCreate = "security.suppression.create"
	AuditSuppressionRevoke = "security.suppression.revoke"
	AuditSuppressionExpire = "security.suppression.expire"
	AuditPolicyChange      = "security.policy.change"
	AuditSarifUpload       = "security.sarif.upload"
	AuditScanTrigger       = "security.scan.trigger"
	AuditRenovateChange    = "security.renovate.change"
	AuditRenovateRun       = "security.renovate.run"
)

// CheckContext is the commit status published on pull requests.
const CheckContext = "capsule/security"

// CheckRun is the state of capsule/security for one head SHA.
type CheckRun struct {
	ProjectID   uuid.UUID
	HeadSHA     string
	PR          int
	BaseBranch  string
	HeadBranch  string
	State       string // pending|success|failure|error
	Description string
	FirstSeenAt time.Time
	LastEvalAt  *time.Time
	Final       bool
}

// RenovateState is the Renovate row of a repository.
type RenovateState struct {
	ProjectID         uuid.UUID
	Enabled           bool
	Preset            string
	Schedule          string
	Onboarding        string // none|pr_open|merged
	OpenPRs           int
	LastRunAt         *time.Time
	LastRunStatus     string
	DashboardIssueURL string
	TopicSynced       bool
	SyncError         string
	LastSyncAt        *time.Time
	UpdatedAt         time.Time
}
