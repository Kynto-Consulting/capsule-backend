package environments

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

// Config tunes the background loop.
type Config struct {
	Tick          time.Duration // advance/expiry/queue loop (default 30 s)
	DeployTimeout time.Duration // a deploying promotion older than this fails (default 60 min)
}

// ConfigFromEnv reads ENVIRONMENTS_TICK_SECONDS and ENVIRONMENTS_DEPLOY_TIMEOUT_MINUTES.
func ConfigFromEnv() Config {
	c := Config{Tick: 30 * time.Second, DeployTimeout: 60 * time.Minute}
	if n, err := strconv.Atoi(os.Getenv("ENVIRONMENTS_TICK_SECONDS")); err == nil && n > 0 {
		c.Tick = time.Duration(n) * time.Second
	}
	if n, err := strconv.Atoi(os.Getenv("ENVIRONMENTS_DEPLOY_TIMEOUT_MINUTES")); err == nil && n > 0 {
		c.DeployTimeout = time.Duration(n) * time.Minute
	}
	return c
}

// Service implements A6. Safe for concurrent use.
type Service struct {
	store    Store
	forge    Forge
	deployer Deployer
	sec      SecurityGate
	dir      Directory
	pub      Publisher
	cfg      Config
	log      *slog.Logger
	now      func() time.Time

	tickMu sync.Mutex
}

// New builds a Service. pub and log may be nil.
func New(store Store, forge Forge, deployer Deployer, dir Directory, pub Publisher, cfg Config, log *slog.Logger) *Service {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if pub == nil {
		pub = gitevents.Discard
	}
	if cfg.Tick <= 0 {
		cfg.Tick = 30 * time.Second
	}
	if cfg.DeployTimeout <= 0 {
		cfg.DeployTimeout = 60 * time.Minute
	}
	return &Service{store: store, forge: forge, deployer: deployer, dir: dir, pub: pub, cfg: cfg, log: log, now: time.Now}
}

// WithSecurity sets the security-policy gate (package B7).
func (s *Service) WithSecurity(g SecurityGate) *Service { s.sec = g; return s }

func bg(ctx context.Context) context.Context { return context.WithoutCancel(ctx) }

func ref(t Target) gitcore.RepoRef { return gitcore.RepoRef{Owner: t.OrgSlug, Repo: t.ProjectSlug} }

// ---- views ---------------------------------------------------------------------------------

// EnvView is an environment with its current deployment.
type EnvView struct {
	Environment
	Current *EnvDeployment `json:"current"`
}

// ProjectRef is the project of a promotion (the UI needs it to decide from the org inbox).
type ProjectRef struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
}

// ApprovalView is one decision in a response.
type ApprovalView struct {
	User         Person    `json:"user"`
	Decision     string    `json:"decision"`
	Comment      string    `json:"comment"`
	At           time.Time `json:"at"`
	SelfApproved bool      `json:"self_approved"`
}

// PromotionView is the response shape of a promotion.
type PromotionView struct {
	ID                uuid.UUID      `json:"id"`
	Project           ProjectRef     `json:"project"`
	Environment       string         `json:"environment"`
	SHA               string         `json:"sha"`
	Branch            string         `json:"branch"`
	FromEnvironment   string         `json:"from_environment"`
	Comment           string         `json:"comment"`
	Status            string         `json:"status"`
	StatusReason      string         `json:"status_reason"`
	RequestedBy       *Person        `json:"requested_by"`
	Approvals         []ApprovalView `json:"approvals"`
	RequiredApprovals int            `json:"required_approvals"`
	NotBefore         *time.Time     `json:"not_before"`
	ExpiresAt         time.Time      `json:"expires_at"`
	Checks            CheckSnapshot  `json:"checks"`
	Conditions        []Condition    `json:"conditions"`
	DeploymentID      *uuid.UUID     `json:"deployment_id"`
	CanDecide         bool           `json:"can_decide"`
	CreatedAt         time.Time      `json:"created_at"`
}

type people struct {
	s *Service
	m map[uuid.UUID]Person
}

func (s *Service) newPeople() *people { return &people{s: s, m: map[uuid.UUID]Person{}} }

func (p *people) get(ctx context.Context, id *uuid.UUID) Person {
	if id == nil {
		return Person{Name: "Git Capsule"}
	}
	if v, ok := p.m[*id]; ok {
		return v
	}
	v, err := p.s.dir.Person(ctx, *id)
	if err != nil {
		v = Person{}
	}
	u := *id
	v.UserID = &u
	p.m[u] = v
	return v
}

func (s *Service) view(ctx context.Context, pp *people, p Promotion, env Environment, actor *Actor) (PromotionView, error) {
	t, err := s.store.Target(ctx, p.ProjectID)
	if err != nil {
		return PromotionView{}, err
	}
	now := s.now()
	required := p.RequiredApprovals
	conds := append([]Condition{}, p.Conditions...)
	if IsActive(p.Status) {
		required = env.RequiredApprovals
		pc := p
		pc.RequiredApprovals = required
		conds = append(conds, DynamicConditions(env, pc, now)...)
	}
	v := PromotionView{
		ID: p.ID, Project: ProjectRef{ID: t.ProjectID, Slug: t.ProjectSlug}, Environment: p.Environment,
		SHA: p.SHA, Branch: p.Branch, FromEnvironment: p.FromEnvironment, Comment: p.Comment,
		Status: p.Status, StatusReason: p.StatusReason, RequiredApprovals: required,
		NotBefore: p.NotBefore, ExpiresAt: p.ExpiresAt, Checks: p.Checks, Conditions: conds,
		DeploymentID: p.DeploymentID, CreatedAt: p.CreatedAt, Approvals: []ApprovalView{},
	}
	if v.Checks.Items == nil {
		v.Checks.Items = []CheckItem{}
	}
	if p.RequestedBy != nil {
		per := pp.get(ctx, p.RequestedBy)
		v.RequestedBy = &per
	}
	for _, a := range p.Approvals {
		v.Approvals = append(v.Approvals, ApprovalView{User: pp.get(ctx, a.UserID), Decision: a.Decision,
			Comment: a.Comment, At: a.At, SelfApproved: a.SelfApproval})
	}
	if actor != nil {
		v.CanDecide = canDecide(env, p, *actor, true) == nil
	}
	return v, nil
}

// ---- helpers ---------------------------------------------------------------------------------

func encodeCursor(t time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

// DecodeCursor parses a cursor produced by encodeCursor.
func DecodeCursor(c string) (time.Time, uuid.UUID, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, uuid.Nil, errors.New("invalid cursor")
	}
	ts, idStr, ok := strings.Cut(string(b), "|")
	if !ok {
		return time.Time{}, uuid.Nil, errors.New("invalid cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, uuid.Nil, errors.New("invalid cursor")
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return time.Time{}, uuid.Nil, errors.New("invalid cursor")
	}
	return t, id, nil
}

// EncodeCursor is exported for the Store implementations.
func EncodeCursor(t time.Time, id uuid.UUID) string { return encodeCursor(t, id) }

func describeErr(err error) string {
	if e, ok := gitcore.AsError(err); ok {
		if e.Message == "" {
			return string(e.Code)
		}
		return string(e.Code) + ": " + e.Message
	}
	return "internal error"
}

// isGate reports whether err is a business-rule failure (not an infrastructure one).
func isGate(err error) bool {
	var pe *PolicyError
	var ce *ConflictError
	return errors.As(err, &pe) || errors.As(err, &ce)
}

// canDecide checks the approver rules for approve (or reject when approve=false). The list of
// the environment decides; the role only matters for production (admins) and for being a member.
func canDecide(env Environment, p Promotion, a Actor, approve bool) error {
	if !IsActive(p.Status) || p.Status == StatusDeploying {
		return ErrInvalidState
	}
	if approve && p.Status != StatusPending {
		return ErrInvalidState
	}
	if a.Role == "" || !IsApprover(env, a.UserID, string(a.Role)) {
		return &ForbiddenError{"NOT_AN_APPROVER", "you are not on the approver list of this environment"}
	}
	if env.Kind == "production" && a.Role != authz.RoleAdmin {
		return &ForbiddenError{"NOT_AN_APPROVER", "production approvals require a project admin"}
	}
	if approve && p.RequestedBy != nil && *p.RequestedBy == a.UserID && !env.AllowSelfApproval {
		return &ForbiddenError{"SELF_APPROVAL_FORBIDDEN", "the requester cannot approve their own promotion"}
	}
	for _, x := range p.Approvals {
		if x.UserID != nil && *x.UserID == a.UserID {
			return ErrAlreadyDecided
		}
	}
	return nil
}

// ---- environments ------------------------------------------------------------------------------

func (s *Service) envView(ctx context.Context, e Environment) (EnvView, error) {
	cur, err := s.store.CurrentDeployment(ctx, e.ID)
	if err != nil {
		return EnvView{}, err
	}
	return EnvView{Environment: e, Current: cur}, nil
}

// ListEnvs lists the environments of the project.
func (s *Service) ListEnvs(ctx context.Context, t Target) ([]EnvView, error) {
	es, err := s.store.ListEnvs(ctx, t.ProjectID)
	if err != nil {
		return nil, err
	}
	out := make([]EnvView, 0, len(es))
	for _, e := range es {
		v, err := s.envView(ctx, e)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// GetEnv returns one environment by name.
func (s *Service) GetEnv(ctx context.Context, t Target, name string) (*EnvView, error) {
	e, err := s.store.GetEnv(ctx, t.ProjectID, name)
	if err != nil {
		return nil, err
	}
	v, err := s.envView(ctx, *e)
	return &v, err
}

// checkEnvRefs validates what Normalize cannot know: target project, source environment and approvers.
func (s *Service) checkEnvRefs(ctx context.Context, t Target, e Environment) error {
	var fe []FieldError
	if e.TargetProjectID != t.ProjectID {
		tt, err := s.store.Target(ctx, e.TargetProjectID)
		if err != nil || tt.OrgID != t.OrgID {
			fe = append(fe, FieldError{"target_project_id", "must be a project of the same organization"})
		}
	}
	if e.RequireSourceEnvironment != nil {
		if _, err := s.store.GetEnv(ctx, t.ProjectID, *e.RequireSourceEnvironment); err != nil {
			fe = append(fe, FieldError{"require_source_environment", "that environment does not exist in this project"})
		}
	}
	for i, r := range e.Reviewers {
		if r.Type != "user" || r.UserID == nil {
			continue
		}
		role, err := s.dir.Role(ctx, *r.UserID, t.OrgID, t.ProjectID)
		if err != nil {
			return err
		}
		f := fmt.Sprintf("reviewers[%d].user_id", i)
		switch {
		case role == "":
			fe = append(fe, FieldError{f, "that user has no access to the project"})
		case e.Kind == "production" && role != authz.RoleAdmin:
			fe = append(fe, FieldError{f, "production approvers must be project admins"})
		}
	}
	if len(fe) > 0 {
		return &ValidationError{Fields: fe}
	}
	return nil
}

func envValues(e Environment) map[string]any {
	return map[string]any{
		"name": e.Name, "kind": e.Kind, "target_project_id": e.TargetProjectID.String(),
		"branch_patterns": e.BranchPatterns, "tag_patterns": e.TagPatterns,
		"required_approvals": e.RequiredApprovals, "allow_self_approval": e.AllowSelfApproval,
		"wait_minutes": e.WaitMinutes, "reviewers": len(e.Reviewers), "windows": len(e.Windows),
		"require_checks_on_sha": e.RequireChecksOnSHA, "require_security_policy": e.RequireSecurityPolicy,
		"auto_deploy": e.AutoDeploy,
	}
}

// CreateEnv creates an environment.
func (s *Service) CreateEnv(ctx context.Context, t Target, a Actor, in Input) (*EnvView, error) {
	e, err := Normalize(in, t.ProjectID)
	if err != nil {
		return nil, err
	}
	if err := s.checkEnvRefs(ctx, t, e); err != nil {
		return nil, err
	}
	e.ID, e.ProjectID = uuid.New(), t.ProjectID
	uid := a.UserID
	e.CreatedBy = &uid
	au := AuditEntry{OrgID: t.OrgID, UserID: a.UserID, Action: "environment.create", ResourceType: "environment",
		ResourceID: e.ID, IP: a.IP, NewValues: envValues(e)}
	if err := s.store.CreateEnv(ctx, &e, au); err != nil {
		return nil, err
	}
	s.auditSelfApproval(ctx, t, a, e, false)
	return s.GetEnv(ctx, t, e.Name)
}

// auditSelfApproval records that an environment now allows self-approval (owner decision: only
// when configured explicitly, and always audited).
func (s *Service) auditSelfApproval(ctx context.Context, t Target, a Actor, e Environment, was bool) {
	if !e.AllowSelfApproval || was {
		return
	}
	_ = s.store.WriteAudit(bg(ctx), AuditEntry{OrgID: t.OrgID, UserID: a.UserID, Action: "environment.self_approval_enabled",
		ResourceType: "environment", ResourceID: e.ID, IP: a.IP, NewValues: map[string]any{"name": e.Name, "kind": e.Kind}})
}

// PutEnv replaces the policies of an environment (the name cannot change).
func (s *Service) PutEnv(ctx context.Context, t Target, a Actor, name string, in Input) (*EnvView, error) {
	old, err := s.store.GetEnv(ctx, t.ProjectID, name)
	if err != nil {
		return nil, err
	}
	if in.Name == "" {
		in.Name = name
	}
	if in.Name != name {
		return nil, &ValidationError{Fields: []FieldError{{"name", "an environment cannot be renamed"}}}
	}
	e, err := Normalize(in, t.ProjectID)
	if err != nil {
		return nil, err
	}
	if err := s.checkEnvRefs(ctx, t, e); err != nil {
		return nil, err
	}
	e.ID, e.ProjectID, e.CreatedAt, e.CreatedBy = old.ID, old.ProjectID, old.CreatedAt, old.CreatedBy
	au := AuditEntry{OrgID: t.OrgID, UserID: a.UserID, Action: "environment.update", ResourceType: "environment",
		ResourceID: e.ID, IP: a.IP, OldValues: envValues(*old), NewValues: envValues(e)}
	if err := s.store.UpdateEnv(ctx, &e, au); err != nil {
		return nil, err
	}
	s.auditSelfApproval(ctx, t, a, e, old.AllowSelfApproval)
	s.reevaluate(bg(ctx), t, e)
	return s.GetEnv(ctx, t, e.Name)
}

// DeleteEnv removes an environment (never the target project). It refuses while promotions are active.
func (s *Service) DeleteEnv(ctx context.Context, t Target, a Actor, name string) error {
	e, err := s.store.GetEnv(ctx, t.ProjectID, name)
	if err != nil {
		return err
	}
	act, err := s.store.ListPromotions(ctx, e.ID, true)
	if err != nil {
		return err
	}
	if len(act) > 0 {
		return &ConflictError{"ENV_HAS_ACTIVE_PROMOTIONS", "cancel or finish the active promotions before deleting the environment"}
	}
	return s.store.DeleteEnv(ctx, t.ProjectID, e.ID, AuditEntry{OrgID: t.OrgID, UserID: a.UserID, Action: "environment.delete",
		ResourceType: "environment", ResourceID: e.ID, IP: a.IP, OldValues: envValues(*e)})
}

// EnvDeployments lists the history of an environment (newest first).
func (s *Service) EnvDeployments(ctx context.Context, t Target, name, cursor string, limit int) ([]EnvDeployment, string, error) {
	e, err := s.store.GetEnv(ctx, t.ProjectID, name)
	if err != nil {
		return nil, "", err
	}
	if limit < 1 || limit > 100 {
		limit = 30
	}
	return s.store.ListEnvDeployments(ctx, e.ID, cursor, limit)
}
