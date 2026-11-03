package gitsync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

// RetryInterval is when users that do not exist in Forgejo yet are tried again.
const RetryInterval = 2 * time.Minute

// Reconciler makes the Forgejo teams of a project match the effective Capsule roles.
// All operations are idempotent and safe to repeat; a per-project lock serializes them.
type Reconciler struct {
	Forge   Forge
	Dir     Directory
	IDs     *Identities
	States  StateStore    // nil = state and drift are not recorded
	Pending PendingStore  // nil = pending users are not queued
	Janitor ReviewJanitor // nil = pending reviews are not discarded
	// Keep are logins never removed from a team (the service account).
	Keep   []string
	Logger *slog.Logger
	Now    func() time.Time

	mu    sync.Mutex
	locks map[uuid.UUID]*sync.Mutex
}

// Report is the outcome of reconciling one project.
type Report struct {
	ProjectID       uuid.UUID
	Added           []string // logins added to a team
	Removed         []string // logins removed from a team
	Pending         []uuid.UUID
	PermissionDrift []string // team names whose Forgejo permission differs from the spec
	ReviewsDropped  int
	Drift           bool // a non-event pass had to correct something
}

func (r *Reconciler) log() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.Default()
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reconciler) lock(id uuid.UUID) func() {
	r.mu.Lock()
	if r.locks == nil {
		r.locks = map[uuid.UUID]*sync.Mutex{}
	}
	m := r.locks[id]
	if m == nil {
		m = &sync.Mutex{}
		r.locks[id] = m
	}
	r.mu.Unlock()
	m.Lock()
	return m.Unlock
}

func clip(s string) string {
	if len(s) > 300 {
		return s[:300]
	}
	return s
}

// SyncProject is the event-driven entry point (role added/changed/removed, org change, retry of
// pending users, right after provisioning). It also is forgejo's team sync delegate.
func (r *Reconciler) SyncProject(ctx context.Context, projectID uuid.UUID) error {
	_, err := r.Reconcile(ctx, projectID, TriggerEvent)
	return err
}

// Reconcile syncs one project. A project that does not exist or is not linked to Forgejo is a
// no-op (nil report). User-level failures are collected and the pass continues, so one broken
// user never blocks the removal of another; the joined error is returned at the end.
func (r *Reconciler) Reconcile(ctx context.Context, projectID uuid.UUID, trig Trigger) (*Report, error) {
	if r == nil || r.Forge == nil || !r.Forge.Enabled() {
		return nil, nil
	}
	defer r.lock(projectID)()

	p, err := r.Dir.Project(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	members, err := r.Dir.Members(ctx, p.OrgID)
	if err != nil {
		return nil, err
	}
	mode, explicit, err := r.Dir.Access(ctx, p.OrgID, projectID)
	if err != nil {
		return nil, err
	}
	if err := r.Forge.EnsureOrg(ctx, p.Repo.Owner); err != nil {
		return nil, err
	}

	rep := &Report{ProjectID: projectID}
	var errs []error
	specs := TeamSpecs(p.Slug)
	teams := map[authz.Role]*gitcore.Team{}
	current := map[authz.Role]map[string]bool{}
	for _, role := range Roles {
		spec := specs[role]
		t, err := r.Forge.EnsureTeam(ctx, p.Repo.Owner, spec)
		if err != nil {
			return nil, fmt.Errorf("team %s: %w", spec.Name, err)
		}
		if err := r.Forge.AddTeamRepo(ctx, t.ID, p.Repo); err != nil {
			return nil, fmt.Errorf("team %s repo: %w", spec.Name, err)
		}
		logins, err := r.Forge.TeamMembers(ctx, t.ID)
		if err != nil {
			return nil, fmt.Errorf("team %s members: %w", spec.Name, err)
		}
		set := map[string]bool{}
		for _, l := range logins {
			set[strings.ToLower(l)] = true
		}
		teams[role], current[role] = t, set
		if t.Permission != "" && t.Permission != spec.Permission {
			rep.PermissionDrift = append(rep.PermissionDrift, spec.Name)
			if pt, ok := r.Forge.(TeamPatcher); ok {
				if perr := pt.PatchTeam(ctx, p.Repo.Owner, t.ID, spec); perr != nil {
					errs = append(errs, fmt.Errorf("patching team %s: %w", spec.Name, perr))
				}
			}
		}
	}

	// Desired state: login -> role, from authz.Resolve (the same function every permission uses).
	desired := map[string]authz.Role{}
	userOf := map[string]uuid.UUID{}
	identOf := map[string]*Identity{}
	var pending []uuid.UUID
	pendingMsg := "forgejo user does not exist yet (first OIDC login pending)"
	for _, m := range members {
		role := authz.Resolve(m.OrgRole, mode, explicit[m.UserID]).Role
		if role == "" {
			continue // hidden or not a member: in no team
		}
		id, ierr := r.IDs.Resolve(ctx, m.UserID, m.Email)
		if ierr != nil {
			pending = append(pending, m.UserID)
			pendingMsg = clip(ierr.Error())
			errs = append(errs, fmt.Errorf("identity of %s: %w", m.UserID, ierr))
			continue
		}
		login := strings.ToLower(id.ForgejoUsername)
		desired[login], userOf[login], identOf[login] = role, m.UserID, id
	}

	// Add first (a role change never leaves a gap), remove afterwards.
	logins := make([]string, 0, len(desired))
	for l := range desired {
		logins = append(logins, l)
	}
	sort.Strings(logins)
	addedTo := map[authz.Role]int{}
	for _, login := range logins {
		role := desired[login]
		if current[role][login] {
			r.markLinked(ctx, userOf[login], identOf[login], login)
			continue
		}
		exists, err := r.Forge.UserExists(ctx, login)
		if err != nil {
			errs = append(errs, fmt.Errorf("checking %s: %w", login, err))
			pending = append(pending, userOf[login])
			pendingMsg = clip(err.Error())
			continue
		}
		if !exists {
			pending = append(pending, userOf[login])
			continue
		}
		if err := r.Forge.AddTeamMember(ctx, teams[role].ID, login); err != nil {
			errs = append(errs, fmt.Errorf("adding %s to %s: %w", login, specs[role].Name, err))
			pending = append(pending, userOf[login])
			pendingMsg = clip(err.Error())
			continue
		}
		current[role][login] = true
		addedTo[role]++
		rep.Added = append(rep.Added, login)
		r.markLinked(ctx, userOf[login], identOf[login], login)
	}

	keep := map[string]bool{}
	for _, k := range r.Keep {
		keep[strings.ToLower(k)] = true
	}
	removedFrom := map[authz.Role]int{}
	removedOK := map[string]bool{}
	for _, role := range Roles {
		var extra []string
		for login := range current[role] {
			if desired[login] != role && !keep[login] {
				extra = append(extra, login)
			}
		}
		sort.Strings(extra)
		for _, login := range extra {
			if err := r.Forge.RemoveTeamMember(ctx, teams[role].ID, login); err != nil {
				errs = append(errs, fmt.Errorf("removing %s from %s: %w", login, specs[role].Name, err))
				continue
			}
			delete(current[role], login)
			removedFrom[role]++
			removedOK[login] = true
			rep.Removed = append(rep.Removed, login)
		}
	}

	// Whoever lost a role that could review loses the pending review requests too.
	if r.Janitor != nil {
		dropped := make([]string, 0, len(removedOK))
		for login := range removedOK {
			dropped = append(dropped, login)
		}
		sort.Strings(dropped)
		for _, login := range dropped {
			if nr, ok := desired[login]; ok && authz.RoleAllows(nr, authz.GitReview) {
				continue
			}
			n, err := r.Janitor.DropPendingReviews(ctx, p.Repo, login)
			if err != nil {
				errs = append(errs, fmt.Errorf("discarding pending reviews of %s: %w", login, err))
				continue
			}
			rep.ReviewsDropped += n
		}
	}

	rep.Pending = pending
	rep.Drift = trig != TriggerEvent && (len(rep.Added) > 0 || len(rep.Removed) > 0 || len(rep.PermissionDrift) > 0)

	if r.Pending != nil {
		if err := r.Pending.ReplaceTeamSync(ctx, projectID, pending, pendingMsg, r.now().Add(RetryInterval)); err != nil {
			errs = append(errs, err)
		}
	}
	if r.States != nil {
		now := r.now()
		lastErr := ""
		if len(errs) > 0 {
			lastErr = clip(errors.Join(errs...).Error())
		}
		for _, role := range Roles {
			st := TeamState{
				ProjectID: projectID, Role: role, TeamID: teams[role].ID, TeamName: specs[role].Name,
				Permission: teams[role].Permission, Members: len(current[role]), LastSyncedAt: now, LastError: lastErr,
				LastDriftAdded: addedTo[role], LastDriftRemoved: removedFrom[role],
			}
			if st.Permission == "" {
				st.Permission = specs[role].Permission
			}
			drift := rep.Drift && (addedTo[role] > 0 || removedFrom[role] > 0 || containsStr(rep.PermissionDrift, specs[role].Name))
			if drift {
				t := now
				st.LastDriftAt = &t
			}
			if err := r.States.PutTeamState(ctx, st, drift); err != nil {
				errs = append(errs, err)
			}
		}
		if rep.Drift {
			vals := map[string]any{
				"trigger": string(trig), "added": rep.Added, "removed": rep.Removed, "permission_drift": rep.PermissionDrift,
			}
			if err := r.States.AuditDrift(ctx, p.OrgID, projectID, "git.team_drift", vals); err != nil {
				errs = append(errs, err)
			}
			r.log().Warn("git team drift corrected", "project_id", projectID, "added", len(rep.Added), "removed", len(rep.Removed), "trigger", string(trig))
		}
	}
	return rep, errors.Join(errs...)
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// markLinked records that the Forgejo user exists (once per identity).
func (r *Reconciler) markLinked(ctx context.Context, userID uuid.UUID, id *Identity, login string) {
	if id == nil || id.LinkedAt != nil {
		return
	}
	var fid int64
	if ur, ok := r.Forge.(UserResolver); ok {
		if v, found, err := ur.ForgejoUserID(ctx, login); err == nil && found {
			fid = v
		}
	}
	if err := r.IDs.Store.MarkLinked(ctx, userID, fid); err != nil {
		r.log().Warn("git identity: marking linked failed", "user_id", userID, "error", err)
		return
	}
	now := r.now()
	id.LinkedAt = &now
}

// ---- whole-platform reconciliation ---------------------------------------------------------

// Summary is the result of reconciling every Forgejo-linked project.
type Summary struct {
	Projects int `json:"projects"`
	Failed   int `json:"failed"`
	Added    int `json:"added"`
	Removed  int `json:"removed"`
	Drifted  int `json:"drifted"`
}

// ReconcileAll walks every Forgejo-linked project (keyset pages) and reconciles it. One failing
// project does not stop the pass.
func (r *Reconciler) ReconcileAll(ctx context.Context, trig Trigger) (Summary, error) {
	var sum Summary
	if r == nil || r.States == nil {
		return sum, errors.New("gitsync: reconciler without a state store cannot enumerate projects")
	}
	after := uuid.Nil
	for {
		ids, err := r.States.ListForgejoProjects(ctx, after, 100)
		if err != nil {
			return sum, err
		}
		for _, id := range ids {
			if ctx.Err() != nil {
				return sum, ctx.Err()
			}
			pctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			rep, err := r.Reconcile(pctx, id, trig)
			cancel()
			sum.Projects++
			if err != nil {
				sum.Failed++
				r.log().Warn("git reconcile failed", "project_id", id, "error", err)
			}
			if rep != nil {
				sum.Added += len(rep.Added)
				sum.Removed += len(rep.Removed)
				if rep.Drift {
					sum.Drifted++
				}
			}
		}
		if len(ids) < 100 {
			return sum, nil
		}
		after = ids[len(ids)-1]
	}
}

// Run reconciles everything every `every` (default 15 min) until ctx ends. The first pass waits
// one interval so a restart does not stampede Forgejo.
func (r *Reconciler) Run(ctx context.Context, every time.Duration) {
	if r == nil || r.Forge == nil || !r.Forge.Enabled() {
		return
	}
	if every <= 0 {
		every = 15 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := r.ReconcileAll(ctx, TriggerPeriodic); err != nil {
				r.log().Warn("git periodic reconcile failed", "error", err)
			}
		}
	}
}
