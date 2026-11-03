package security

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// RenovateTopic is the repository topic the self-hosted bot autodiscovers
// (deploy/forgejo/renovate/config.js: autodiscoverTopics).
const RenovateTopic = "renovate"

const renovateObserveEvery = 2 * time.Minute

// onboardingBranch is the branch Renovate uses for its "Configure Renovate" pull request.
const onboardingBranch = "renovate/configure"

var renovateConfigFiles = []string{
	"renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json",
	".forgejo/renovate.json", ".gitea/renovate.json", ".github/renovate.json",
}

// BusinessError is a 422 with a stable code.
type BusinessError struct{ Code, Message string }

func (e *BusinessError) Error() string { return e.Code + ": " + e.Message }

// RenovateInput is the request of renovatePut; nil fields stay as they are.
type RenovateInput struct {
	Enabled  *bool
	Preset   *string
	Schedule *string
}

var (
	rePreset   = regexp.MustCompile(`^[A-Za-z0-9:_>./@+-]{1,255}$`)
	reSchedule = regexp.MustCompile(`^[A-Za-z0-9 :,*/_-]{0,255}$`)
)

func (s *Service) defaultRenovate(projectID uuid.UUID) RenovateState {
	return RenovateState{ProjectID: projectID, Preset: s.cfg.RenovatePreset, Onboarding: "none"}
}

// RenovateGet returns the Renovate state of the repository, refreshing what Forgejo says
// (onboarding pull request, open update pull requests) at most every two minutes. A Forgejo
// failure never fails the read: the last known state is returned.
func (s *Service) RenovateGet(ctx context.Context, t Target) (*RenovateState, error) {
	st, err := s.store.GetRenovate(ctx, t.ProjectID)
	if errors.Is(err, ErrNotFound) {
		d := s.defaultRenovate(t.ProjectID)
		st = &d
	} else if err != nil {
		return nil, err
	}
	if st.Enabled && s.forge != nil && s.forge.Enabled() && (st.LastSyncAt == nil || s.now().Sub(*st.LastSyncAt) > renovateObserveEvery) {
		if obs, oerr := s.observeRenovate(ctx, t, *st); oerr != nil {
			s.log.Warn("security: observing Renovate failed", "project_id", t.ProjectID, "err", oerr)
		} else {
			if uerr := s.store.UpdateRenovateObserved(ctx, obs); uerr != nil {
				s.log.Warn("security: storing Renovate state failed", "project_id", t.ProjectID, "err", uerr)
			}
			st = &obs
		}
	}
	return st, nil
}

func (s *Service) observeRenovate(ctx context.Context, t Target, st RenovateState) (RenovateState, error) {
	r := repoRef(t)
	repo, err := s.forge.GetRepo(ctx, r)
	if err != nil {
		return st, err
	}
	onboardingOpen, open := false, 0
	var cursor string
	for page := 0; page < 3; page++ {
		l, err := s.forge.ListPulls(ctx, r, gitcore.PullQuery{State: "open"}, gitcore.Page{Cursor: cursor, Limit: 100})
		if err != nil {
			return st, err
		}
		for _, p := range l.Items {
			switch {
			case p.Head == onboardingBranch:
				onboardingOpen = true
			case strings.EqualFold(p.Author.Login, s.cfg.RenovateBotLogin) || strings.HasPrefix(p.Head, "renovate/"):
				open++
			}
		}
		if l.NextCursor == "" {
			break
		}
		cursor = l.NextCursor
	}
	onboarding := "none"
	if onboardingOpen {
		onboarding = "pr_open"
	} else if repo.DefaultBranch != "" && !repo.Empty {
		for _, f := range renovateConfigFiles {
			_, err := s.forge.GetFile(ctx, r, repo.DefaultBranch, f)
			if err == nil {
				onboarding = "merged"
				break
			}
			if !errors.Is(err, gitcore.ErrNotFound) {
				return st, err
			}
		}
	}
	now := s.now()
	st.Onboarding, st.OpenPRs, st.LastSyncAt = onboarding, open, &now
	return st, nil
}

// RenovatePut enables or disables Renovate for the repository and records the preset and schedule.
// Enabling marks the repository with the "renovate" topic (the bot autodiscovers by topic) when
// the Git core can set topics; otherwise TopicSynced stays false and SyncError tells the admin to
// add the topic in Forgejo.
func (s *Service) RenovatePut(ctx context.Context, t Target, a Actor, in RenovateInput) (*RenovateState, error) {
	var fields []FieldError
	if in.Preset != nil && !rePreset.MatchString(strings.TrimSpace(*in.Preset)) && strings.TrimSpace(*in.Preset) != "" {
		fields = append(fields, FieldError{"preset", "preset de Renovate no valido (por ejemplo local>org/repo o config:recommended)"})
	}
	if in.Schedule != nil && !reSchedule.MatchString(strings.TrimSpace(*in.Schedule)) {
		fields = append(fields, FieldError{"schedule", "horario no valido (texto de Renovate o cron: letras, digitos, espacio y : , * / - _)"})
	}
	if len(fields) > 0 {
		return nil, &ValidationError{Fields: fields}
	}
	st, err := s.store.GetRenovate(ctx, t.ProjectID)
	if errors.Is(err, ErrNotFound) {
		d := s.defaultRenovate(t.ProjectID)
		st = &d
	} else if err != nil {
		return nil, err
	}
	old := map[string]any{"enabled": st.Enabled, "preset": st.Preset, "schedule": st.Schedule}
	next := *st
	if in.Enabled != nil {
		next.Enabled = *in.Enabled
	}
	if in.Preset != nil {
		next.Preset = strings.TrimSpace(*in.Preset)
		if next.Preset == "" {
			next.Preset = s.cfg.RenovatePreset
		}
	}
	if in.Schedule != nil {
		next.Schedule = strings.TrimSpace(*in.Schedule)
	}
	if next.Enabled != st.Enabled || (next.Enabled && !st.TopicSynced) {
		next.TopicSynced, next.SyncError = s.syncTopic(ctx, t, next.Enabled)
	}
	err = s.store.PutRenovate(ctx, next, a.UserID, s.actorAudit(t, a, AuditRenovateChange, "renovate", t.ProjectID, old,
		map[string]any{"enabled": next.Enabled, "preset": next.Preset, "schedule": next.Schedule, "topic_synced": next.TopicSynced}))
	if err != nil {
		return nil, err
	}
	return &next, nil
}

func (s *Service) syncTopic(ctx context.Context, t Target, present bool) (synced bool, errText string) {
	if s.forge == nil || !s.forge.Enabled() {
		return false, "Git no esta configurado: el topic se sincroniza al activarlo de nuevo"
	}
	ts, ok := s.forge.(TopicSetter)
	if !ok {
		return false, "el nucleo Git no expone topics: agrega o quita el topic \"renovate\" del repositorio en Forgejo"
	}
	if err := ts.SetRepoTopic(ctx, repoRef(t), RenovateTopic, present); err != nil {
		s.log.Warn("security: setting the renovate topic failed", "project_id", t.ProjectID, "err", err)
		return false, "no se pudo actualizar el topic en Forgejo; reintenta"
	}
	return true, ""
}

// RenovateRun forces a Renovate run limited to this repository. It answers immediately with a
// queued Job; the run happens in the background and its result is recorded in the state.
func (s *Service) RenovateRun(ctx context.Context, t Target, a Actor, idemKey string) (*Job, error) {
	key := "renovate:" + t.ProjectID.String() + ":" + idemKey
	if job := s.idempotent(key, idemKey); job != nil {
		return job, nil
	}
	st, err := s.store.GetRenovate(ctx, t.ProjectID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if st == nil || !st.Enabled {
		return nil, &BusinessError{Code: "RENOVATE_DISABLED", Message: "Renovate no esta activado en este repositorio"}
	}
	if s.runner == nil {
		return nil, ErrNotReady
	}
	s.mu.Lock()
	if s.running[t.ProjectID] {
		s.mu.Unlock()
		return nil, &ConflictError{Code: "RUN_IN_PROGRESS", Message: "ya hay una ejecucion de Renovate en curso para este repositorio"}
	}
	s.running[t.ProjectID] = true
	s.mu.Unlock()

	job := Job{ID: uuid.New(), Status: "queued", Detail: "Renovate se ejecutara solo para " + t.OrgSlug + "/" + t.ProjectSlug}
	now := s.now()
	_ = s.store.RecordRenovateRun(ctx, t.ProjectID, now, "queued")
	_ = s.store.WriteAudit(ctx, s.actorAudit(t, a, AuditRenovateRun, "renovate", t.ProjectID, nil, map[string]any{"job_id": job.ID.String()}))
	s.rememberIdem(key, idemKey, job)
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		status := "success"
		if err := s.runner.Run(bg, t.OrgSlug+"/"+t.ProjectSlug); err != nil {
			status = "failed"
			s.log.Warn("security: Renovate run failed", "project_id", t.ProjectID, "err", err)
		}
		_ = s.store.RecordRenovateRun(bg, t.ProjectID, s.now(), status)
		s.mu.Lock()
		delete(s.running, t.ProjectID)
		s.mu.Unlock()
	}()
	return &job, nil
}

// ---- runner ----------------------------------------------------------------------------------

var reRepoName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$`)

// ExecRunner runs the Renovate container of the Capsule project that hosts the bot, exactly like
// a manual cron trigger does (docker exec on capsule-app-<first 12 of the project id>), limited to
// one repository through RENOVATE_REPOSITORIES. No shell is involved: the repo name is validated
// and passed as an argument.
type ExecRunner struct {
	ProjectID uuid.UUID
	Command   string
	Exec      func(ctx context.Context, name string, args ...string) ([]byte, error) // nil = os/exec
}

// NewExecRunner returns the runner for cfg, or nil when no Renovate project is configured.
func NewExecRunner(cfg Config) RenovateRunner {
	id, err := uuid.Parse(cfg.RenovateProject)
	if err != nil {
		return nil
	}
	return &ExecRunner{ProjectID: id, Command: cfg.RenovateCommand}
}

// Run implements RenovateRunner.
func (r *ExecRunner) Run(ctx context.Context, repo string) error {
	if !reRepoName.MatchString(repo) {
		return fmt.Errorf("security: repository name %q is not valid", repo)
	}
	cmd := strings.Fields(r.Command)
	if len(cmd) == 0 {
		cmd = []string{"renovate"}
	}
	container := "capsule-app-" + strings.ReplaceAll(r.ProjectID.String(), "-", "")[:12]
	args := append([]string{"exec", "-e", "RENOVATE_AUTODISCOVER=false", "-e", "RENOVATE_REPOSITORIES=" + repo, container}, cmd...)
	run := r.Exec
	if run == nil {
		run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	if out, err := run(ctx, "docker", args...); err != nil {
		return fmt.Errorf("security: renovate run failed: %w (%s)", err, plain(string(out), 300))
	}
	return nil
}
