package environments

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

var shaRE = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// PromotionRequest is the body of promotionCreate.
type PromotionRequest struct {
	Environment     string `json:"environment"`
	SHA             string `json:"sha"`
	FromEnvironment string `json:"from_environment"`
	Comment         string `json:"comment"`
}

// gateResult is the outcome of the request-time conditions.
type gateResult struct {
	Branch   string
	Snapshot CheckSnapshot
	Conds    []Condition
	Artifact *Artifact
	Source   *uuid.UUID
}

// refOf finds the allowed branch (or tag) that contains sha. With no patterns configured only the
// default branch is allowed (never "everything").
func (s *Service) refOf(ctx context.Context, t Target, env Environment, sha string) (string, error) {
	r := ref(t)
	noPatterns := len(env.BranchPatterns) == 0 && len(env.TagPatterns) == 0
	compares := 0
	cursor := ""
	for page := 0; page < 5; page++ {
		l, err := s.forge.ListBranches(ctx, r, gitcore.Page{Cursor: cursor, Limit: gitcore.MaxLimit})
		if err != nil {
			return "", err
		}
		for _, b := range l.Items {
			if !((noPatterns && b.Default) || MatchAny(env.BranchPatterns, b.Name)) {
				continue
			}
			if b.SHA == sha {
				return b.Name, nil
			}
			if compares >= 10 {
				continue
			}
			compares++
			// sha is an ancestor of the branch when it has no commit the branch lacks
			c, err := s.forge.Compare(ctx, r, b.Name, sha)
			if err != nil {
				if e, ok := gitcore.AsError(err); ok && e.Code == gitcore.CodeNotFound {
					continue
				}
				return "", err
			}
			if c.AheadBy == 0 && len(c.Commits) == 0 && !c.Truncated {
				return b.Name, nil
			}
		}
		if l.NextCursor == "" {
			break
		}
		cursor = l.NextCursor
	}
	if len(env.TagPatterns) > 0 {
		cursor = ""
		for page := 0; page < 3; page++ {
			l, err := s.forge.ListTags(ctx, r, gitcore.Page{Cursor: cursor, Limit: gitcore.MaxLimit})
			if err != nil {
				return "", err
			}
			for _, tg := range l.Items {
				if tg.SHA == sha && MatchAny(env.TagPatterns, tg.Name) {
					return "tag:" + tg.Name, nil
				}
			}
			if l.NextCursor == "" {
				break
			}
			cursor = l.NextCursor
		}
	}
	return "", &ConflictError{"PROTECTED_BRANCH", "the commit is not on a branch or tag allowed to deploy to " + env.Name}
}

// checkStatic evaluates the conditions that depend on the commit and the repository (branch,
// checks, security policy, source environment, artifact). It is run at request time, again when a
// policy changes and again right before deploying. Business failures are *ConflictError or
// *PolicyError; anything else is an infrastructure problem.
func (s *Service) checkStatic(ctx context.Context, t Target, env Environment, sha, from string) (*gateResult, error) {
	res := &gateResult{}
	branch, err := s.refOf(ctx, t, env, sha)
	if err != nil {
		return nil, err
	}
	res.Branch = branch
	res.Conds = append(res.Conds, Condition{Name: "branch", OK: true, Detail: branch + " is allowed for " + env.Name})

	cs, err := s.forge.ListChecks(ctx, ref(t), sha)
	if err != nil {
		return nil, err
	}
	res.Snapshot = snapshotChecks(cs)
	if env.RequireChecksOnSHA {
		if len(res.Snapshot.Items) == 0 {
			return nil, &ConflictError{"CHECKS_REQUIRED", "the commit has no checks and " + env.Name + " requires them"}
		}
		if res.Snapshot.State != "success" {
			return nil, &ConflictError{"CHECKS_REQUIRED", "the commit checks are " + res.Snapshot.State}
		}
		res.Conds = append(res.Conds, Condition{Name: "checks", OK: true, Detail: "all checks of the commit passed"})
	}
	if env.RequireSecurityPolicy && s.sec != nil {
		blocked, why, err := s.sec.Blocked(ctx, env.ProjectID, sha)
		if err != nil {
			return nil, err
		}
		if blocked {
			return nil, &PolicyError{"POLICY_BLOCKED", "the security policy blocks this commit: " + why}
		}
		res.Conds = append(res.Conds, Condition{Name: "security", OK: true, Detail: "security policy satisfied"})
	}

	src := from
	if env.RequireSourceEnvironment != nil {
		if from != "" && from != *env.RequireSourceEnvironment {
			return nil, &PolicyError{"SOURCE_ENVIRONMENT_MISMATCH", env.Name + " only accepts commits promoted from " + *env.RequireSourceEnvironment}
		}
		src = *env.RequireSourceEnvironment
	}
	if src != "" {
		se, err := s.store.GetEnv(ctx, env.ProjectID, src)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, &PolicyError{"SOURCE_ENVIRONMENT_REQUIRED", "environment " + src + " does not exist"}
			}
			return nil, err
		}
		ed, art, err := s.store.SuccessfulSHA(ctx, se.ID, sha)
		if err != nil {
			return nil, err
		}
		if ed == nil || art == nil {
			return nil, &PolicyError{"SOURCE_ENVIRONMENT_REQUIRED", "the commit has not been deployed successfully to " + src}
		}
		res.Artifact = art
		res.Conds = append(res.Conds, Condition{Name: "source_environment", OK: true, Detail: "succeeded in " + src})
	} else {
		for _, pid := range []uuid.UUID{env.ProjectID, env.TargetProjectID} {
			art, err := s.store.FindArtifact(ctx, pid, sha)
			if err != nil {
				return nil, err
			}
			if art != nil {
				res.Artifact = art
				break
			}
		}
	}
	if res.Artifact == nil {
		return nil, &PolicyError{"ARTIFACT_NOT_FOUND", "no successful deployment of this commit exists to promote; deploy it first (for example to staging)"}
	}
	id := res.Artifact.DeploymentID
	res.Source = &id
	return res, nil
}

func snapshotChecks(cs *gitcore.CheckSet) CheckSnapshot {
	out := CheckSnapshot{State: "success", Items: []CheckItem{}}
	failed, pending := false, false
	for _, c := range cs.Items {
		if strings.HasPrefix(c.Context, CheckPrefix) {
			continue // our own status must not gate another environment
		}
		out.Items = append(out.Items, CheckItem{Context: c.Context, State: string(c.State), TargetURL: c.TargetURL, Description: c.Description})
		switch c.State {
		case gitcore.CheckFailure, gitcore.CheckError:
			failed = true
		case gitcore.CheckSuccess, gitcore.CheckSkipped:
		default:
			pending = true
		}
	}
	switch {
	case failed:
		out.State = "failure"
	case pending:
		out.State = "pending"
	case len(out.Items) == 0:
		out.State = "pending"
	}
	return out
}

// hasEligibleApprover guards the single-admin trap: with no self-approval, a request nobody else
// can approve would only wait 72 h and expire.
func (s *Service) hasEligibleApprover(ctx context.Context, t Target, env Environment, requester *uuid.UUID) (bool, error) {
	if env.RequiredApprovals == 0 || env.AllowSelfApproval {
		return true, nil
	}
	for _, r := range env.Reviewers {
		switch {
		case r.Type == "user" && r.UserID != nil:
			if requester != nil && *r.UserID == *requester {
				continue
			}
			role, err := s.dir.Role(ctx, *r.UserID, t.OrgID, t.ProjectID)
			if err != nil {
				return false, err
			}
			if role != "" {
				return true, nil
			}
		case r.Type == "role" && r.Role == "admin":
			n, err := s.dir.CountAdmins(ctx, t.OrgID, t.ProjectID)
			if err != nil {
				return false, err
			}
			if requester != nil {
				if role, err := s.dir.Role(ctx, *requester, t.OrgID, t.ProjectID); err == nil && role == authz.RoleAdmin {
					n--
				}
			}
			if n > 0 {
				return true, nil
			}
		case r.Type == "role":
			return true, nil // deployers: cannot count them cheaply; assume somebody else exists
		}
	}
	return false, nil
}

// CreatePromotion requests deploying sha to an environment. created is false when the
// Idempotency-Key matched an earlier identical request (the stored one is returned).
func (s *Service) CreatePromotion(ctx context.Context, t Target, a Actor, req PromotionRequest, key string) (PromotionView, bool, error) {
	var fe []FieldError
	req.SHA = strings.ToLower(strings.TrimSpace(req.SHA))
	if !shaRE.MatchString(req.SHA) {
		fe = append(fe, FieldError{"sha", "must be a hexadecimal commit id (7 to 64 characters)"})
	}
	if len(key) > 128 {
		fe = append(fe, FieldError{"Idempotency-Key", "at most 128 characters"})
	}
	if len(req.Comment) > 2000 {
		fe = append(fe, FieldError{"comment", "at most 2000 characters"})
	}
	if len(fe) > 0 {
		return PromotionView{}, false, &ValidationError{Fields: fe}
	}
	env, err := s.store.GetEnv(ctx, t.ProjectID, req.Environment)
	if err != nil {
		return PromotionView{}, false, err
	}
	uid := a.UserID
	if key != "" {
		if old, err := s.store.FindByIdempotency(ctx, t.ProjectID, uid, key); err != nil {
			return PromotionView{}, false, err
		} else if old != nil {
			return s.replay(ctx, a, *old, *env, req)
		}
	}
	p, err := s.create(ctx, t, *env, &uid, a.IP, req, key)
	var ex *ExistingError
	if errors.As(err, &ex) {
		if ex.Kind == "idempotency" {
			return s.replay(ctx, a, *ex.Promotion, *env, req)
		}
		return PromotionView{}, false, &ConflictError{"PROMOTION_ACTIVE", "this commit already has an active promotion to " + env.Name + " (" + ex.Promotion.ID.String() + ")"}
	}
	if err != nil {
		return PromotionView{}, false, err
	}
	v, err := s.view(ctx, s.newPeople(), *p, *env, &a)
	return v, true, err
}

func (s *Service) replay(ctx context.Context, a Actor, old Promotion, env Environment, req PromotionRequest) (PromotionView, bool, error) {
	if old.EnvironmentID != env.ID || !strings.HasPrefix(old.SHA, req.SHA) || old.FromEnvironment != req.FromEnvironment {
		return PromotionView{}, false, &ConflictError{"IDEMPOTENCY_CONFLICT", "that Idempotency-Key was used with a different request"}
	}
	v, err := s.view(ctx, s.newPeople(), old, env, &a)
	return v, false, err
}

// create runs the conditions and stores the promotion. requestedBy nil = Capsule itself (auto_deploy).
func (s *Service) create(ctx context.Context, t Target, env Environment, requestedBy *uuid.UUID, ip string, req PromotionRequest, key string) (*Promotion, error) {
	if s.forge == nil || !s.forge.Enabled() {
		return nil, &gitcore.Error{Code: gitcore.CodeNotReady, Message: "git integration is not configured"}
	}
	commit, err := s.forge.GetCommit(ctx, ref(t), req.SHA)
	if err != nil {
		return nil, err
	}
	sha := strings.ToLower(commit.SHA)
	res, err := s.checkStatic(ctx, t, env, sha, req.FromEnvironment)
	if err != nil {
		return nil, err
	}
	ok, err := s.hasEligibleApprover(ctx, t, env, requestedBy)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &PolicyError{"NO_ELIGIBLE_APPROVER", "nobody else can approve in " + env.Name + ": name a second approver, or enable self-approval in the environment (it will be audited)"}
	}
	now := s.now()
	p := &Promotion{
		ID: uuid.New(), ProjectID: t.ProjectID, EnvironmentID: env.ID, Environment: env.Name, SHA: sha,
		Branch: res.Branch, FromEnvironment: req.FromEnvironment, Comment: req.Comment,
		Status: StatusPending, RequestedBy: requestedBy, RequiredApprovals: env.RequiredApprovals,
		ExpiresAt: now.Add(ExpiryAfter), IdempotencyKey: key, SourceDeploymentID: res.Source,
		Checks: res.Snapshot, Conditions: res.Conds, CreatedAt: now, UpdatedAt: now, Approvals: []Approval{},
	}
	if env.RequiredApprovals == 0 {
		q := now
		st, nb := NextAfterQuorum(env, q, now)
		p.Status, p.NotBefore, p.QuorumAt = st, nb, &q
	}
	au := AuditEntry{OrgID: t.OrgID, Action: "promotion.request", ResourceType: "promotion", ResourceID: p.ID, IP: ip,
		NewValues: map[string]any{"environment": env.Name, "sha": sha, "branch": res.Branch, "status": p.Status,
			"required_approvals": p.RequiredApprovals, "checks": res.Snapshot.State, "comment": req.Comment}}
	if requestedBy != nil {
		au.UserID = *requestedBy
	}
	if err := s.store.CreatePromotion(ctx, p, au); err != nil {
		return nil, err
	}
	s.after(bg(ctx), env, *p)
	if p.Status == StatusPending {
		s.publish(bg(ctx), env, *p, gitevents.ApprovalRequested, "", s.approverRecipients(env, requestedBy), nil)
	}
	return p, nil
}

func (s *Service) approverRecipients(env Environment, requester *uuid.UUID) []uuid.UUID {
	var out []uuid.UUID
	for _, r := range env.Reviewers {
		if r.Type == "user" && r.UserID != nil && (requester == nil || *r.UserID != *requester) {
			out = append(out, *r.UserID)
		}
	}
	return out
}

// GetPromotion returns a promotion of the project.
func (s *Service) GetPromotion(ctx context.Context, t Target, a Actor, id uuid.UUID) (PromotionView, error) {
	p, env, err := s.load(ctx, t, id)
	if err != nil {
		return PromotionView{}, err
	}
	return s.view(ctx, s.newPeople(), *p, *env, &a)
}

func (s *Service) load(ctx context.Context, t Target, id uuid.UUID) (*Promotion, *Environment, error) {
	p, err := s.store.GetPromotion(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if p.ProjectID != t.ProjectID {
		return nil, nil, ErrNotFound
	}
	env, err := s.store.GetEnvByID(ctx, p.EnvironmentID)
	if err != nil {
		return nil, nil, err
	}
	return p, env, nil
}

// Approve records an approval. The approver list decides (not the role); the requester cannot
// approve unless the environment explicitly allows it, and then the approval is audited as such.
func (s *Service) Approve(ctx context.Context, t Target, a Actor, id uuid.UUID, comment string) (PromotionView, error) {
	return s.decide(ctx, t, a, id, comment, "approved")
}

// Reject vetoes a promotion that has not started deploying.
func (s *Service) Reject(ctx context.Context, t Target, a Actor, id uuid.UUID, comment string) (PromotionView, error) {
	return s.decide(ctx, t, a, id, comment, "rejected")
}

func (s *Service) decide(ctx context.Context, t Target, a Actor, id uuid.UUID, comment, decision string) (PromotionView, error) {
	if len(comment) > 2000 {
		return PromotionView{}, &ValidationError{Fields: []FieldError{{"comment", "at most 2000 characters"}}}
	}
	p, env, err := s.load(ctx, t, id)
	if err != nil {
		return PromotionView{}, err
	}
	if err := canDecide(*env, *p, a, decision == "approved"); err != nil {
		return PromotionView{}, s.mapDecideErr(err)
	}
	now := s.now()
	self := p.RequestedBy != nil && *p.RequestedBy == a.UserID
	uid := a.UserID
	st, nb := NextAfterQuorum(*env, now, now)
	action := "promotion." + map[string]string{"approved": "approve", "rejected": "reject"}[decision]
	if self && decision == "approved" {
		action = "promotion.self_approve"
	}
	d := Decision{
		PromotionID: id, Required: env.RequiredApprovals, AllowSelf: env.AllowSelfApproval,
		Approval:     Approval{UserID: &uid, Decision: decision, Comment: comment, SelfApproval: self && decision == "approved", Role: string(a.Role), At: now},
		QuorumStatus: st, QuorumNotBefore: nb, QuorumAt: now, RejectReason: "rejected: " + comment, RejectedAt: now,
	}
	au := AuditEntry{OrgID: t.OrgID, UserID: a.UserID, Action: action, ResourceType: "promotion", ResourceID: id, IP: a.IP,
		NewValues: map[string]any{"environment": env.Name, "sha": p.SHA, "decision": decision, "comment": comment, "self_approval": self && decision == "approved"}}
	np, err := s.store.AddDecision(ctx, d, au)
	if err != nil {
		return PromotionView{}, s.mapDecideErr(err)
	}
	s.after(bg(ctx), *env, *np)
	s.publish(bg(ctx), *env, *np, gitevents.ApprovalDecided, decision, nil, &a.UserID)
	return s.view(ctx, s.newPeople(), *np, *env, &a)
}

func (s *Service) mapDecideErr(err error) error {
	switch {
	case errors.Is(err, ErrInvalidState):
		return &ConflictError{"INVALID_STATE", "the promotion is not waiting for a decision"}
	case errors.Is(err, ErrAlreadyDecided):
		return &ConflictError{"ALREADY_DECIDED", "you already decided on this promotion"}
	}
	return err
}

// Cancel cancels a promotion that has not started deploying: the requester or an environment admin.
func (s *Service) Cancel(ctx context.Context, t Target, a Actor, id uuid.UUID) (PromotionView, error) {
	p, env, err := s.load(ctx, t, id)
	if err != nil {
		return PromotionView{}, err
	}
	isReq := p.RequestedBy != nil && *p.RequestedBy == a.UserID
	if !isReq && !authz.RoleAllows(a.Role, authz.EnvAdmin) {
		return PromotionView{}, &ForbiddenError{"FORBIDDEN", "only the requester or an environment admin can cancel"}
	}
	now := s.now()
	au := AuditEntry{OrgID: t.OrgID, UserID: a.UserID, Action: "promotion.cancel", ResourceType: "promotion", ResourceID: id, IP: a.IP,
		NewValues: map[string]any{"environment": env.Name, "sha": p.SHA}}
	ok, err := s.store.Transition(ctx, id, []string{StatusPending, StatusWaiting, StatusApproved}, StatusCancelled,
		Patch{Reason: "cancelled by the user", FinishedAt: &now}, &au)
	if err != nil {
		return PromotionView{}, err
	}
	if !ok {
		return PromotionView{}, &ConflictError{"INVALID_STATE", "the promotion can no longer be cancelled"}
	}
	np, err := s.store.GetPromotion(ctx, id)
	if err != nil {
		return PromotionView{}, err
	}
	s.after(bg(ctx), *env, *np)
	return s.view(ctx, s.newPeople(), *np, *env, &a)
}

// Pending lists the promotions awaiting a decision that the user may take, across the organization.
func (s *Service) Pending(ctx context.Context, orgID, userID uuid.UUID, cursor string, limit int) ([]PromotionView, string, error) {
	if limit < 1 || limit > 100 {
		limit = 30
	}
	pp := s.newPeople()
	roles := map[uuid.UUID]authz.Role{}
	var out []PromotionView
	next := ""
	cur := cursor
	for iter := 0; iter < 20; iter++ {
		rows, err := s.store.PendingForOrg(ctx, orgID, cur, limit*3)
		if err != nil {
			return nil, "", err
		}
		for i, r := range rows {
			cur = encodeCursor(r.Promotion.CreatedAt, r.Promotion.ID)
			role, seen := roles[r.Promotion.ProjectID]
			if !seen {
				if role, err = s.dir.Role(ctx, userID, orgID, r.Promotion.ProjectID); err != nil {
					return nil, "", err
				}
				roles[r.Promotion.ProjectID] = role
			}
			act := Actor{UserID: userID, Role: role}
			if canDecide(r.Env, r.Promotion, act, true) != nil {
				continue
			}
			v, err := s.view(ctx, pp, r.Promotion, r.Env, &act)
			if err != nil {
				return nil, "", err
			}
			out = append(out, v)
			if len(out) == limit {
				if i < len(rows)-1 || len(rows) == limit*3 {
					next = cur
				}
				return out, next, nil
			}
		}
		if len(rows) < limit*3 {
			return out, "", nil
		}
	}
	return out, cur, nil
}

// AutoPromote creates promotions (requested by Capsule itself) for the environments of the project
// with auto_deploy whose branch patterns match. Per-environment failures are logged and skipped.
func (s *Service) AutoPromote(ctx context.Context, t Target, branch, sha string) {
	envs, err := s.store.ListEnvs(ctx, t.ProjectID)
	if err != nil {
		s.log.Error("environments: auto promote list failed", "err", err)
		return
	}
	for _, e := range envs {
		if !e.AutoDeploy || !MatchAny(e.BranchPatterns, branch) {
			continue
		}
		if _, err := s.create(ctx, t, e, nil, "", PromotionRequest{Environment: e.Name, SHA: sha, Comment: "auto_deploy"}, ""); err != nil {
			s.log.Info("environments: auto promote skipped", "environment", e.Name, "reason", err.Error())
		}
	}
}
