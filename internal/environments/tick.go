package environments

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

// ---- side effects: commit status and events -----------------------------------------------------

// after publishes the capsule/env:<name> status and, for final states, promotion.completed.
func (s *Service) after(ctx context.Context, env Environment, p Promotion) {
	s.publishCheck(ctx, env, p)
	switch p.Status {
	case StatusSuccess, StatusFailed, StatusExpired, StatusCancelled:
		s.publish(ctx, env, p, gitevents.PromotionCompleted, "", nil, nil)
	}
}

func (s *Service) publishCheck(ctx context.Context, env Environment, p Promotion) {
	if s.forge == nil || !s.forge.Enabled() {
		return
	}
	t, err := s.store.Target(ctx, env.ProjectID)
	if err != nil {
		return
	}
	state, desc := gitcore.CheckPending, "promotion "+p.Status
	switch p.Status {
	case StatusSuccess:
		state, desc = gitcore.CheckSuccess, "deployed to "+env.Name
	case StatusFailed, StatusRejected, StatusCancelled, StatusExpired:
		state, desc = gitcore.CheckFailure, "promotion to "+env.Name+" "+p.Status
	case StatusPending:
		desc = "waiting for approval to deploy to " + env.Name
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := s.forge.SetCheck(rctx, ref(t), p.SHA, gitcore.CheckInput{Context: CheckPrefix + env.Name, State: state, Description: desc}); err != nil {
		s.log.Warn("environments: publishing the environment check failed", "environment", env.Name, "err", describeErr(err))
	}
}

func (s *Service) publish(ctx context.Context, env Environment, p Promotion, name, decision string, recipients []uuid.UUID, actor *uuid.UUID) {
	data := map[string]any{"environment": env.Name, "promotion_id": p.ID.String(), "sha": p.SHA, "status": p.Status}
	if decision != "" {
		data["decision"] = decision
	}
	if p.RequestedBy != nil {
		data["requested_by"] = p.RequestedBy.String()
	}
	ev := gitevents.Event{ProjectID: env.ProjectID, Name: name, Branch: p.Branch, Data: data, Recipients: recipients, Actor: "Git Capsule"}
	if actor != nil {
		ev.ActorUserID = *actor
		if per, err := s.dir.Person(ctx, *actor); err == nil && per.Name != "" {
			ev.Actor = per.Name
		}
	}
	if err := s.pub.Publish(ctx, ev); err != nil {
		s.log.Warn("environments: publishing event failed", "event", name, "err", err)
	}
}

// ---- policy changes --------------------------------------------------------------------------------

// reevaluate applies a new policy to the promotions that have not started deploying: those that
// no longer satisfy the commit conditions are cancelled with the reason; the rest are advanced.
func (s *Service) reevaluate(ctx context.Context, t Target, env Environment) {
	ps, err := s.store.ListPromotions(ctx, env.ID, true)
	if err != nil {
		s.log.Error("environments: reevaluate list failed", "err", err)
		return
	}
	now := s.now()
	for _, p := range ps {
		if p.Status == StatusDeploying {
			continue
		}
		if _, err := s.checkStatic(ctx, t, env, p.SHA, p.FromEnvironment); err != nil {
			if !isGate(err) {
				continue // infrastructure trouble: keep it, the next change or tick decides
			}
			au := AuditEntry{OrgID: t.OrgID, Action: "promotion.cancel", ResourceType: "promotion", ResourceID: p.ID,
				NewValues: map[string]any{"reason": "policy_changed", "detail": err.Error()}}
			ok, terr := s.store.Transition(ctx, p.ID, []string{p.Status}, StatusCancelled,
				Patch{Reason: "policy_changed: " + err.Error(), FinishedAt: &now}, &au)
			if terr == nil && ok {
				p.Status = StatusCancelled
				s.after(ctx, env, p)
			}
			continue
		}
		s.advance(ctx, env, p, now)
	}
}

// advance applies Advance to one promotion and persists the change.
func (s *Service) advance(ctx context.Context, env Environment, p Promotion, now time.Time) Promotion {
	req := env.RequiredApprovals
	st, nb, q, changed := Advance(env, p, now)
	if !changed && p.RequiredApprovals == req {
		return p
	}
	ok, err := s.store.Transition(ctx, p.ID, []string{p.Status}, st, Patch{NotBefore: nb, QuorumAt: q, Required: &req}, nil)
	if err != nil || !ok {
		return p
	}
	was := p.Status
	p.Status, p.NotBefore, p.QuorumAt, p.RequiredApprovals = st, nb, q, req
	if was != st {
		s.after(ctx, env, p)
	}
	return p
}

// ---- the loop ----------------------------------------------------------------------------------------

// RunLoop runs Tick every cfg.Tick until ctx ends.
func (s *Service) RunLoop(ctx context.Context) {
	t := time.NewTicker(s.cfg.Tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}

// Tick expires overdue promotions, advances waiting ones, starts the next approved promotion of
// each environment (one deploying promotion per environment: the queue) and follows deployments.
func (s *Service) Tick(ctx context.Context) {
	s.tickMu.Lock()
	defer s.tickMu.Unlock()
	now := s.now()
	envs := map[uuid.UUID]*Environment{}
	getEnv := func(id uuid.UUID) *Environment {
		if e, ok := envs[id]; ok {
			return e
		}
		e, err := s.store.GetEnvByID(ctx, id)
		if err != nil {
			e = nil
		}
		envs[id] = e
		return e
	}
	expired, err := s.store.ExpireOverdue(ctx, now)
	if err != nil {
		s.log.Error("environments: expiring promotions failed", "err", err)
	}
	for _, p := range expired {
		if env := getEnv(p.EnvironmentID); env != nil {
			s.after(bg(ctx), *env, p)
		}
	}
	active, err := s.store.ListActive(ctx, 500)
	if err != nil {
		s.log.Error("environments: listing promotions failed", "err", err)
		return
	}
	busy := map[uuid.UUID]bool{}
	ready := map[uuid.UUID][]Promotion{}
	var order []uuid.UUID
	for _, p := range active {
		env := getEnv(p.EnvironmentID)
		if env == nil {
			continue
		}
		if p.Status == StatusDeploying {
			if np := s.poll(ctx, *env, p, now); np.Status == StatusDeploying {
				busy[env.ID] = true
			}
			continue
		}
		p = s.advance(ctx, *env, p, now)
		if p.Status == StatusApproved {
			if _, seen := ready[env.ID]; !seen {
				order = append(order, env.ID)
			}
			ready[env.ID] = append(ready[env.ID], p)
		}
	}
	for _, id := range order {
		if busy[id] {
			continue
		}
		for _, p := range ready[id] { // oldest first: ListActive is ordered by created_at
			if s.start(ctx, *envs[id], p, now) {
				break
			}
		}
	}
}

// start claims the queue slot and creates the deployment reusing the stored source. It returns
// true when the environment is now busy (claimed) so the next candidate waits.
func (s *Service) start(ctx context.Context, env Environment, p Promotion, now time.Time) bool {
	t, err := s.store.Target(ctx, env.ProjectID)
	if err != nil {
		return false
	}
	res, err := s.checkStatic(ctx, t, env, p.SHA, p.FromEnvironment)
	if err != nil {
		if !isGate(err) {
			s.log.Warn("environments: pre-deploy check could not run", "promotion", p.ID, "err", describeErr(err))
			return false
		}
		au := AuditEntry{OrgID: t.OrgID, Action: "promotion.cancel", ResourceType: "promotion", ResourceID: p.ID,
			NewValues: map[string]any{"reason": "conditions_no_longer_met", "detail": err.Error()}}
		if ok, _ := s.store.Transition(ctx, p.ID, []string{StatusApproved}, StatusCancelled,
			Patch{Reason: "conditions no longer met: " + err.Error(), FinishedAt: &now}, &au); ok {
			p.Status = StatusCancelled
			s.after(bg(ctx), env, p)
		}
		return false
	}
	art := *res.Artifact
	if p.SourceDeploymentID != nil { // deploy exactly what was approved
		if a, err := s.store.ArtifactOf(ctx, *p.SourceDeploymentID); err == nil && a != nil {
			art = *a
		}
	}
	au := AuditEntry{OrgID: t.OrgID, Action: "promotion.deploy", ResourceType: "promotion", ResourceID: p.ID,
		NewValues: map[string]any{"environment": env.Name, "sha": p.SHA, "source_deployment": art.DeploymentID.String()}}
	ok, err := s.store.Transition(ctx, p.ID, []string{StatusApproved}, StatusDeploying, Patch{StartedAt: &now}, &au)
	if err != nil {
		s.log.Warn("environments: claiming the queue failed", "promotion", p.ID, "err", err)
		return false
	}
	if !ok {
		return true // somebody else holds the environment
	}
	p.Status = StatusDeploying
	s.after(bg(ctx), env, p)
	s.launch(ctx, env, p, art)
	return true
}

func (s *Service) launch(ctx context.Context, env Environment, p Promotion, art Artifact) {
	meta := map[string]string{"source": "promotion", "promotion_id": p.ID.String(), "environment": env.Name,
		"sha": p.SHA, "ref": p.Branch, "promoted_from": art.DeploymentID.String()}
	depID, err := s.deployer.Deploy(ctx, env.TargetProjectID, art, p.RequestedBy, meta)
	if err != nil {
		s.finish(ctx, env, p, StatusFailed, "could not create the deployment", "")
		return
	}
	if err := s.store.SetDeployment(ctx, p.ID, depID); err != nil {
		s.log.Error("environments: saving the deployment id failed", "promotion", p.ID, "err", err)
	}
}

func (s *Service) finish(ctx context.Context, env Environment, p Promotion, to, reason, health string) Promotion {
	now := s.now()
	t, _ := s.store.Target(ctx, env.ProjectID)
	au := AuditEntry{OrgID: t.OrgID, Action: "promotion.complete", ResourceType: "promotion", ResourceID: p.ID,
		NewValues: map[string]any{"environment": env.Name, "sha": p.SHA, "status": to, "reason": reason}}
	ok, err := s.store.Transition(ctx, p.ID, []string{StatusDeploying}, to, Patch{Reason: reason, FinishedAt: &now, Health: health}, &au)
	if err != nil || !ok {
		return p
	}
	p.Status, p.StatusReason = to, reason
	s.after(bg(ctx), env, p)
	return p
}

// poll follows the deployment of a deploying promotion.
func (s *Service) poll(ctx context.Context, env Environment, p Promotion, now time.Time) Promotion {
	if p.DeploymentID == nil {
		// crashed between claiming and creating the deployment: retry after a grace period
		if p.StartedAt != nil && now.Sub(*p.StartedAt) > 2*time.Minute && p.SourceDeploymentID != nil {
			if a, err := s.store.ArtifactOf(ctx, *p.SourceDeploymentID); err == nil && a != nil {
				s.launch(ctx, env, p, *a)
				return p
			}
			return s.finish(ctx, env, p, StatusFailed, "the stored source is no longer available", "")
		}
		return p
	}
	status, health, err := s.deployer.Status(ctx, *p.DeploymentID)
	if err != nil {
		s.log.Warn("environments: reading the deployment failed", "promotion", p.ID, "err", err)
		return p
	}
	switch status {
	case "success":
		return s.finish(ctx, env, p, StatusSuccess, "", health)
	case "failed", "cancelled":
		return s.finish(ctx, env, p, StatusFailed, "the deployment "+status, health)
	}
	if p.StartedAt != nil && now.Sub(*p.StartedAt) > s.cfg.DeployTimeout {
		return s.finish(ctx, env, p, StatusFailed, "the deployment did not finish in time", health)
	}
	return p
}
