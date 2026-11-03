package gitimport

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

// MirrorForge is the part of gitcore the mirror uses. *gitcore.Service satisfies it.
type MirrorForge interface {
	gitcore.Mirrors
	GetRepo(ctx context.Context, r gitcore.RepoRef) (*gitcore.Repository, error)
	Enabled() bool
}

// MirrorDeps wires the mirror service.
type MirrorDeps struct {
	Store MirrorStore
	Forge MirrorForge
	// SyncForge runs the (slow) manual synchronization; nil = Forge. The wiring gives it a client with a
	// long per-call timeout (Forgejo answers when the push finished).
	SyncForge gitcore.Mirrors
	// PollEvery and PollTimeout bound the wait for Forgejo to report the outcome of a queued push
	// (defaults 1 s and 2 min).
	PollEvery, PollTimeout time.Duration
	Policy                 gitsource.Policy
	Audit                  Auditor
	Logger                 *slog.Logger
	Now                    func() time.Time
}

// MirrorService manages the push mirror of a project (T17: code leaves to a third party; the callers
// require git.admin, every change is audited and the view carries the notice the UI must show).
type MirrorService struct {
	cfg  Config
	d    MirrorDeps
	base context.Context
	wg   sync.WaitGroup
}

// NewMirrors builds the mirror service. base bounds the background synchronizations.
func NewMirrors(base context.Context, cfg Config, d MirrorDeps) *MirrorService {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if base == nil {
		base = context.Background()
	}
	return &MirrorService{cfg: cfg.withDefaults(), d: d, base: base}
}

// Wait blocks until every background synchronization finished.
func (m *MirrorService) Wait() { m.wg.Wait() }

// Target identifies the project a mirror belongs to.
type Target struct {
	OrgID     uuid.UUID
	ProjectID uuid.UUID
	Repo      gitcore.RepoRef // Forgejo owner/repo
}

// Actor is who changed the mirror (audit).
type Actor struct {
	UserID uuid.UUID
	IP     string
}

// MirrorInput is a validated-by-the-service mirrorPut request. Credential nil keeps the stored one.
type MirrorInput struct {
	RemoteURL  string
	Credential *string
	Branches   []string
	Interval   string
}

// MirrorView is what the API returns. The credential is never part of it.
type MirrorView struct {
	Mirror
	RemoteHost string
	Syncing    bool
	Notice     string
}

// MirrorUsername is the user name sent with the credential: GitHub accepts any non-empty name when
// the secret is a personal access token.
const MirrorUsername = "x-access-token"

var branchRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/*-]{0,199}$`)

func intervalSpec(iv string) (every string, onCommit bool, ok bool) {
	switch iv {
	case IntervalOnPush:
		return "0", true, true // no periodic push; push on every commit
	case IntervalHourly:
		return "1h0m0s", false, true
	case IntervalDaily:
		return "24h0m0s", false, true
	}
	return "", false, false
}

// BranchFilter encodes branch names/globs the way Forgejo 15 reads branch_filter (comma separated;
// verified against a real instance).
func BranchFilter(branches []string) string { return strings.Join(branches, ",") }

func validRemote(ctx context.Context, p gitsource.Policy, raw string) (host string, clean string, err error) {
	raw = strings.TrimSpace(raw)
	u, perr := url.Parse(raw)
	if perr != nil || u.Scheme != "https" || u.Host == "" {
		return "", "", invalid("remote_url must be an https:// address")
	}
	if u.User != nil {
		return "", "", invalid("remote_url must not contain credentials: send the credential field instead")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", "", invalid("remote_url must not contain a query or a fragment")
	}
	ref, _, verr := p.ValidateRepoURL(ctx, raw) // T2: public hosts only, optional allow-list, resolved now
	if verr != nil {
		return "", "", invalid("remote_url is not allowed: " + verr.Error())
	}
	return ref.Host, raw, nil
}

func normBranches(in []string, def string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, b := range in {
		b = strings.TrimSpace(b)
		if b == "" || seen[b] {
			continue
		}
		if !branchRe.MatchString(b) || strings.Contains(b, "..") || strings.HasSuffix(b, "/") {
			return nil, invalid("invalid branch name " + clip(b, 60))
		}
		seen[b] = true
		out = append(out, b)
	}
	if len(out) > 20 {
		return nil, invalid("at most 20 branches")
	}
	if len(out) == 0 {
		if def == "" {
			return nil, invalid("at least one branch is required")
		}
		out = []string{def} // never "all branches" by default: only what is configured leaves
	}
	return out, nil
}

func (m *MirrorService) view(mr *Mirror) *MirrorView {
	v := &MirrorView{Mirror: *mr}
	if u, err := url.Parse(mr.RemoteURL); err == nil {
		v.RemoteHost = u.Hostname()
	}
	if mr.SyncingSince != nil && m.d.Now().Sub(*mr.SyncingSince) < m.cfg.SyncTimeout {
		v.Syncing = true
	}
	v.Notice = "El codigo de este proyecto sale de Git Capsule hacia " + v.RemoteHost + ", un tercero fuera de nuestro control. Solo se envian las ramas configuradas; los pull requests y las revisiones no se sincronizan."
	if v.Branches == nil {
		v.Branches = []string{}
	}
	return v
}

func (m *MirrorService) audit(ctx context.Context, t Target, a Actor, action string, vals map[string]any) {
	if m.d.Audit == nil {
		return
	}
	rec := AuditRecord{OrgID: t.OrgID, Action: action, ResourceType: "git_mirror", ResourceID: &t.ProjectID, IP: a.IP, Values: vals}
	vals["project_id"] = t.ProjectID.String()
	if a.UserID != uuid.Nil {
		u := a.UserID
		rec.UserID = &u
	}
	if err := m.d.Audit.Audit(ctx, rec); err != nil {
		m.d.Logger.Warn("git mirror: audit failed", "action", action, "error", Redact(err.Error()))
	}
}

// Get returns the stored mirror refreshed with what Forgejo knows (last push, last error). ErrNotFound
// when the project has none.
func (m *MirrorService) Get(ctx context.Context, t Target) (*MirrorView, error) {
	mr, err := m.d.Store.GetMirror(ctx, t.ProjectID)
	if err != nil {
		return nil, err
	}
	if m.d.Forge.Enabled() && mr.ForgejoRemoteName != "" {
		list, lerr := m.d.Forge.ListPushMirrors(ctx, t.Repo)
		if lerr != nil {
			m.d.Logger.Warn("git mirror: reading the live state failed", "project_id", t.ProjectID, "error", Redact(gitErrText(lerr)))
		} else {
			found := false
			for _, pm := range list {
				if pm.RemoteName != mr.ForgejoRemoteName {
					continue
				}
				found = true
				var at *time.Time
				if pm.LastUpdate.Year() > 2000 {
					x := pm.LastUpdate.UTC()
					at = &x
				}
				if at == nil {
					continue // Forgejo has never pushed it: keep what Capsule recorded
				}
				lastErr := clip(Redact(pm.LastError), 500)
				if mr.LastSyncAt == nil || at.After(*mr.LastSyncAt) { // only a NEWER Forgejo verdict replaces what Capsule recorded
					if rerr := m.d.Store.RecordSync(ctx, t.ProjectID, at, lastErr); rerr == nil {
						mr.LastSyncAt, mr.LastError = at, lastErr
					}
				}
			}
			if !found {
				mr.LastError = "the mirror is missing in the Git service: save the configuration again"
			}
		}
	}
	return m.view(mr), nil
}

// Put creates or replaces the mirror.
func (m *MirrorService) Put(ctx context.Context, t Target, a Actor, in MirrorInput) (*MirrorView, error) {
	if !m.d.Forge.Enabled() {
		return nil, ErrNotConfigured
	}
	host, remote, err := validRemote(ctx, m.d.Policy, in.RemoteURL)
	if err != nil {
		return nil, err
	}
	iv := in.Interval
	if iv == "" {
		iv = IntervalDaily
	}
	every, onCommit, ok := intervalSpec(iv)
	if !ok {
		return nil, invalid("interval must be on_push, hourly or daily")
	}
	repo, err := m.d.Forge.GetRepo(ctx, t.Repo)
	if err != nil {
		return nil, err
	}
	branches, err := normBranches(in.Branches, repo.DefaultBranch)
	if err != nil {
		return nil, err
	}
	old, err := m.d.Store.GetMirror(ctx, t.ProjectID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if errors.Is(err, ErrNotFound) {
		old = nil
	}

	cred := ""
	switch {
	case in.Credential != nil:
		cred = strings.TrimSpace(*in.Credential)
	case old != nil && old.HasCredential:
		if cred, err = m.d.Store.Credential(ctx, t.ProjectID); err != nil {
			return nil, err
		}
	}

	spec := gitcore.PushMirrorSpec{RemoteAddress: remote, Interval: every, SyncOnCommit: onCommit, BranchFilter: BranchFilter(branches)}
	if cred != "" {
		spec.RemoteUsername, spec.RemotePassword = MirrorUsername, cred
	}
	pm, err := m.d.Forge.AddPushMirror(ctx, t.Repo, spec)
	if err != nil {
		// Forgejo answers 401 "Permission denied" for private/loopback remotes (verified on 15.0.11):
		// that is a bad address, not a broken service token.
		if ge, ok := gitcore.AsError(err); ok && ge.Status == 401 {
			return nil, invalid("the Git service refuses that remote address (private and loopback addresses are not allowed)")
		}
		return nil, err
	}

	mr := &Mirror{ProjectID: t.ProjectID, OrgID: t.OrgID, RemoteURL: remote, Branches: branches, Interval: iv,
		ForgejoRemoteName: pm.RemoteName}
	if a.UserID != uuid.Nil {
		u := a.UserID
		mr.CreatedBy = &u
	}
	var credPtr *string
	if in.Credential != nil {
		credPtr = &cred
	}
	if err := m.d.Store.PutMirror(ctx, mr, credPtr); err != nil {
		_ = m.d.Forge.DeletePushMirror(context.WithoutCancel(ctx), t.Repo, pm.RemoteName) // do not leave it orphaned
		return nil, err
	}
	if old != nil && old.ForgejoRemoteName != "" && old.ForgejoRemoteName != pm.RemoteName {
		if derr := m.d.Forge.DeletePushMirror(ctx, t.Repo, old.ForgejoRemoteName); derr != nil && !errors.Is(derr, gitcore.ErrNotFound) {
			m.d.Logger.Warn("git mirror: removing the replaced remote failed", "project_id", t.ProjectID, "error", gitErrText(derr))
		}
	}
	m.audit(ctx, t, a, AuditMirrorSet, map[string]any{"remote_host": host, "remote_url": remote, "branches": branches, "interval": iv,
		"credential_set": cred != "", "credential_changed": in.Credential != nil, "replaced": old != nil})
	return m.Get(ctx, t)
}

// Delete removes the mirror from Forgejo and from Capsule (ErrNotFound when there is none).
func (m *MirrorService) Delete(ctx context.Context, t Target, a Actor) error {
	mr, err := m.d.Store.GetMirror(ctx, t.ProjectID)
	if err != nil {
		return err
	}
	if mr.ForgejoRemoteName != "" && m.d.Forge.Enabled() {
		if derr := m.d.Forge.DeletePushMirror(ctx, t.Repo, mr.ForgejoRemoteName); derr != nil && !errors.Is(derr, gitcore.ErrNotFound) {
			return derr
		}
	}
	if err := m.d.Store.DeleteMirror(ctx, t.ProjectID); err != nil {
		return err
	}
	m.audit(ctx, t, a, AuditMirrorDelete, map[string]any{"remote_url": mr.RemoteURL})
	return nil
}

// SyncJob is the answer of mirrorSync.
type SyncJob struct {
	ID     uuid.UUID
	Status string
	Detail string
}

// Sync pushes now. Forgejo answers when the push is done (it can take minutes), so it runs in the
// background; the result lands in last_sync_at / last_error, which mirrorGet returns.
func (m *MirrorService) Sync(ctx context.Context, t Target, a Actor) (*SyncJob, error) {
	if !m.d.Forge.Enabled() {
		return nil, ErrNotConfigured
	}
	mr, err := m.d.Store.GetMirror(ctx, t.ProjectID)
	if err != nil {
		return nil, err
	}
	got, err := m.d.Store.BeginSync(ctx, t.ProjectID, m.d.Now().Add(-m.cfg.SyncTimeout))
	if err != nil {
		return nil, err
	}
	if !got {
		return nil, ErrBusy
	}
	job := &SyncJob{ID: uuid.New(), Status: StatusQueued, Detail: "synchronization started"}
	m.audit(ctx, t, a, AuditMirrorSync, map[string]any{"remote_url": mr.RemoteURL, "job_id": job.ID.String()})
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		bg, cancel := context.WithTimeout(m.base, m.cfg.SyncTimeout)
		defer cancel()
		defer func() { _ = m.d.Store.EndSync(context.WithoutCancel(m.base), t.ProjectID) }()
		syncer := m.d.SyncForge
		if syncer == nil {
			syncer = m.d.Forge
		}
		before := m.remoteUpdate(bg, t, mr.ForgejoRemoteName)
		serr := syncer.SyncPushMirrors(bg, t.Repo)
		bgc := context.WithoutCancel(m.base)
		if serr != nil {
			var at *time.Time
			if cur, gerr := m.d.Store.GetMirror(bgc, t.ProjectID); gerr == nil {
				at = cur.LastSyncAt
			}
			_ = m.d.Store.RecordSync(bgc, t.ProjectID, at, clip(Redact(gitErrText(serr)), 500))
			return
		}
		// Forgejo only QUEUES the push (verified on 15.0.11): the verdict is what it reports afterwards.
		if at, lastErr, ok := m.awaitPush(bg, t, mr.ForgejoRemoteName, before); ok {
			if err := m.d.Store.RecordSync(bgc, t.ProjectID, at, lastErr); err != nil {
				m.d.Logger.Warn("git mirror: recording the synchronization failed", "project_id", t.ProjectID, "error", Redact(err.Error()))
			}
		}
	}()
	return job, nil
}

// remoteUpdate returns the last_update Forgejo reports for the remote (zero when unknown).
func (m *MirrorService) remoteUpdate(ctx context.Context, t Target, name string) time.Time {
	list, err := m.d.Forge.ListPushMirrors(ctx, t.Repo)
	if err != nil {
		return time.Time{}
	}
	for _, pm := range list {
		if pm.RemoteName == name {
			return pm.LastUpdate
		}
	}
	return time.Time{}
}

// awaitPush polls until Forgejo reports a last_update different from before (the queued push ran, with
// or without error) or PollTimeout passes. ok=false means "no verdict yet": mirrorGet keeps showing
// whatever Forgejo reports later.
func (m *MirrorService) awaitPush(ctx context.Context, t Target, name string, before time.Time) (at *time.Time, lastErr string, ok bool) {
	every, limit := m.d.PollEvery, m.d.PollTimeout
	if every <= 0 {
		every = time.Second
	}
	if limit <= 0 {
		limit = 2 * time.Minute
	}
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, "", false
		case <-deadline.C:
			return nil, "", false
		case <-tick.C:
			list, err := m.d.Forge.ListPushMirrors(ctx, t.Repo)
			if err != nil {
				continue
			}
			for _, pm := range list {
				if pm.RemoteName == name && pm.LastUpdate.Year() > 2000 && !pm.LastUpdate.Equal(before) {
					u := pm.LastUpdate.UTC()
					return &u, clip(Redact(pm.LastError), 500), true
				}
			}
		}
	}
}
