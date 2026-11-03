// Package environments implements Git Capsule package A6 (docs/git-capsule/SPEC.md 5.7):
// deployment environments, promotions and approvals.
package environments

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
)

// Promotion states.
const (
	StatusPending   = "pending_approval"
	StatusWaiting   = "waiting"
	StatusApproved  = "approved"
	StatusDeploying = "deploying"
	StatusSuccess   = "success"
	StatusFailed    = "failed"
	StatusRejected  = "rejected"
	StatusCancelled = "cancelled"
	StatusExpired   = "expired"
)

// ExpiryAfter is how long a promotion may wait for a decision or a window.
const ExpiryAfter = 72 * time.Hour

// CheckPrefix prefixes the commit status Capsule publishes per environment.
const CheckPrefix = "capsule/env:"

// IsActive reports whether the promotion has not reached a final state.
func IsActive(s string) bool {
	switch s {
	case StatusPending, StatusWaiting, StatusApproved, StatusDeploying:
		return true
	}
	return false
}

// Reviewer is one entry of the approver list: a user or a project role.
type Reviewer struct {
	Type   string     `json:"type"`
	UserID *uuid.UUID `json:"user_id,omitempty"`
	Role   string     `json:"role,omitempty"`
}

// Window is a deployment window: days (empty = every day), local from/to (HH:MM) and zone.
type Window struct {
	Days []string `json:"days"`
	From string   `json:"from"`
	To   string   `json:"to"`
	TZ   string   `json:"tz"`
}

// Environment is the stored policy.
type Environment struct {
	ID                       uuid.UUID  `json:"id"`
	ProjectID                uuid.UUID  `json:"-"`
	Name                     string     `json:"name"`
	Kind                     string     `json:"kind"`
	TargetProjectID          uuid.UUID  `json:"target_project_id"`
	BranchPatterns           []string   `json:"branch_patterns"`
	TagPatterns              []string   `json:"tag_patterns"`
	AutoDeploy               bool       `json:"auto_deploy"`
	Reviewers                []Reviewer `json:"reviewers"`
	RequiredApprovals        int        `json:"required_approvals"`
	AllowSelfApproval        bool       `json:"allow_self_approval"`
	WaitMinutes              int        `json:"wait_minutes"`
	Windows                  []Window   `json:"windows"`
	RequireChecksOnSHA       bool       `json:"require_checks_on_sha"`
	RequireSourceEnvironment *string    `json:"require_source_environment"`
	RequireSecurityPolicy    bool       `json:"require_security_policy"`
	RollbackRequiresApproval bool       `json:"rollback_requires_approval"`
	CreatedBy                *uuid.UUID `json:"-"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"-"`
}

// Input is the body of envCreate / envPut. Absent pointer fields take the kind's default.
type Input struct {
	Name                     string     `json:"name"`
	Kind                     string     `json:"kind"`
	TargetProjectID          *uuid.UUID `json:"target_project_id"`
	BranchPatterns           []string   `json:"branch_patterns"`
	TagPatterns              []string   `json:"tag_patterns"`
	AutoDeploy               *bool      `json:"auto_deploy"`
	Reviewers                []Reviewer `json:"reviewers"`
	RequiredApprovals        *int       `json:"required_approvals"`
	AllowSelfApproval        *bool      `json:"allow_self_approval"`
	WaitMinutes              *int       `json:"wait_minutes"`
	Windows                  []Window   `json:"windows"`
	RequireChecksOnSHA       *bool      `json:"require_checks_on_sha"`
	RequireSourceEnvironment *string    `json:"require_source_environment"`
	RequireSecurityPolicy    *bool      `json:"require_security_policy"`
	RollbackRequiresApproval *bool      `json:"rollback_requires_approval"`
}

// Person is a user as shown in responses.
type Person struct {
	UserID    *uuid.UUID `json:"user_id"`
	Login     string     `json:"login"`
	Name      string     `json:"name"`
	Email     string     `json:"email"`
	AvatarURL string     `json:"avatar_url"`
}

// Approval is one decision.
type Approval struct {
	UserID       *uuid.UUID
	Decision     string // approved|rejected
	Comment      string
	SelfApproval bool
	Role         string
	At           time.Time
}

// Condition is one evaluated gate of a promotion.
type Condition struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// CheckItem is one commit status captured when the promotion was requested.
type CheckItem struct {
	Context     string `json:"context"`
	State       string `json:"state"`
	TargetURL   string `json:"target_url,omitempty"`
	Description string `json:"description,omitempty"`
}

// CheckSnapshot is the SHA's checks at request time (Capsule's own capsule/env:* excluded).
type CheckSnapshot struct {
	State string      `json:"state"`
	Items []CheckItem `json:"items"`
}

// Promotion is the stored request.
type Promotion struct {
	ID                 uuid.UUID
	ProjectID          uuid.UUID
	EnvironmentID      uuid.UUID
	Environment        string
	SHA                string
	Branch             string
	FromEnvironment    string
	Comment            string
	Status             string
	StatusReason       string
	RequestedBy        *uuid.UUID
	RequiredApprovals  int
	QuorumAt           *time.Time
	NotBefore          *time.Time
	ExpiresAt          time.Time
	IdempotencyKey     string
	SourceDeploymentID *uuid.UUID
	DeploymentID       *uuid.UUID
	Checks             CheckSnapshot
	Conditions         []Condition
	StartedAt          *time.Time
	FinishedAt         *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
	Approvals          []Approval
}

// EnvDeployment is one history row.
type EnvDeployment struct {
	ID            uuid.UUID  `json:"id"`
	EnvironmentID uuid.UUID  `json:"-"`
	SHA           string     `json:"sha"`
	DeploymentID  *uuid.UUID `json:"deployment_id"`
	Status        string     `json:"status"`
	PromotionID   uuid.UUID  `json:"promotion_id"`
	HealthStatus  string     `json:"health_status,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
}

// EnvDeploymentStatus maps a promotion status to the history vocabulary.
func EnvDeploymentStatus(promo string) string {
	if promo == StatusApproved {
		return "queued"
	}
	return promo
}

// Artifact is a successful deployment whose stored source can be redeployed without building again.
type Artifact struct {
	DeploymentID  uuid.UUID
	SourceKey     string
	SHA           string
	BuildStrategy string
	ContainerPort int
}

// Target identifies a project and its organization.
type Target struct {
	ProjectID   uuid.UUID
	OrgID       uuid.UUID
	OrgSlug     string
	ProjectSlug string
}

// Actor is the authenticated caller; Role is their effective role on the project ("" = none).
type Actor struct {
	UserID uuid.UUID
	Role   authz.Role
	IP     string
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

// Errors.
var (
	ErrNotFound       = errors.New("environments: not found")
	ErrDuplicate      = errors.New("environments: an environment with that name already exists")
	ErrInvalidState   = errors.New("environments: the promotion is not in a state that allows this")
	ErrAlreadyDecided = errors.New("environments: this user already decided")
)

// FieldError is one validation problem.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError carries field problems (422 VALIDATION_ERROR).
type ValidationError struct{ Fields []FieldError }

func (e *ValidationError) Error() string {
	if len(e.Fields) == 0 {
		return "invalid input"
	}
	return fmt.Sprintf("invalid %s: %s", e.Fields[0].Field, e.Fields[0].Message)
}

// PolicyError is a 422 business rule (POLICY_BLOCKED, ARTIFACT_NOT_FOUND...).
type PolicyError struct{ Code, Message string }

func (e *PolicyError) Error() string { return e.Code + ": " + e.Message }

// ConflictError is a 409 (PROTECTED_BRANCH, CHECKS_REQUIRED, IDEMPOTENCY_CONFLICT...).
type ConflictError struct{ Code, Message string }

func (e *ConflictError) Error() string { return e.Code + ": " + e.Message }

// ForbiddenError is a 403 (SELF_APPROVAL_FORBIDDEN, NOT_AN_APPROVER).
type ForbiddenError struct{ Code, Message string }

func (e *ForbiddenError) Error() string { return e.Code + ": " + e.Message }

// ExistingError is returned by Store.CreatePromotion when the request collides with a stored one.
type ExistingError struct {
	Kind      string // idempotency|active
	Promotion *Promotion
}

func (e *ExistingError) Error() string { return "environments: existing promotion (" + e.Kind + ")" }
