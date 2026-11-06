package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

// InvalidError is a validation failure (maps to HTTP 400).
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return e.Msg }

type ProjectGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Project, error)
}

type DBLister interface {
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]*domain.Database, error)
}

type Service struct {
	cfg        Config
	repo       Repo
	store      Store
	dock       Docker
	projects   ProjectGetter
	dbs        DBLister
	objects    ObjectSource
	secret     string
	log        *slog.Logger
	now        func() time.Time
	sem        chan struct{} // global concurrency cap (1)
	retryDelay time.Duration
	baseCtx    context.Context
	tick       time.Duration
}

func New(cfg Config, repo Repo, store Store, dock Docker, projects ProjectGetter, dbs DBLister, secret string, log *slog.Logger) *Service {
	cfg.defaults()
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		cfg: cfg, repo: repo, store: store, dock: dock, projects: projects, dbs: dbs, secret: secret, log: log,
		now: time.Now, sem: make(chan struct{}, 1), retryDelay: 30 * time.Second,
		baseCtx: context.Background(), tick: time.Minute,
	}
}

// SetContext sets the parent context of asynchronous runs (cancelled on shutdown).
func (s *Service) SetContext(ctx context.Context) { s.baseCtx = ctx }

// Enabled reports whether backups are on for this installation.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled && s.store != nil && s.repo != nil }

// Capability is the value of the "backups" platform capability.
func (s *Service) Capability() any {
	def := "daily"
	if s != nil {
		def = s.cfg.DefaultSchedule
	}
	return map[string]any{"enabled": s.Enabled(), "default_schedule": def}
}

// ── views ───────────────────────────────────────────────────────────────────

type RunView struct {
	ID         uuid.UUID  `json:"id"`
	Kind       string     `json:"kind"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	SizeBytes  int64      `json:"size_bytes"`
	Error      string     `json:"error"`
}

type IncludeView struct {
	Databases bool `json:"databases"`
	Volumes   bool `json:"volumes"`
}

type View struct {
	Enabled       bool        `json:"enabled"`
	Schedule      string      `json:"schedule"`
	RetentionDays int         `json:"retention_days"`
	Include       IncludeView `json:"include"`
	LastRuns      []RunView   `json:"last_runs"`
	NextRun       *time.Time  `json:"next_run"`
}

type SnapshotView struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	SizeBytes int64     `json:"size_bytes"`
	Kind      string    `json:"kind"`
	Source    string    `json:"source"`
}

func runViews(rs []Run) []RunView {
	out := make([]RunView, 0, len(rs))
	for _, r := range rs {
		out = append(out, RunView{ID: r.ID, Kind: r.Kind, Status: r.Status, StartedAt: r.StartedAt,
			FinishedAt: r.FinishedAt, SizeBytes: r.SizeBytes, Error: r.Error})
	}
	return out
}

func (s *Service) defaultSettings(projectID uuid.UUID) Settings {
	return Settings{ProjectID: projectID, Enabled: s.cfg.DefaultOn, Schedule: s.cfg.DefaultSchedule,
		RetentionDays: s.cfg.DefaultRetentionDays, IncludeDatabases: true, IncludeVolumes: false}
}

// effective resolves the stored settings or the platform defaults. Without a stored row a
// project is enabled by default only when it has databases.
func (s *Service) effective(ctx context.Context, projectID uuid.UUID) (Settings, error) {
	st, err := s.repo.GetSettings(ctx, projectID)
	if err != nil {
		return Settings{}, err
	}
	if st != nil {
		st.Configured = true
		return *st, nil
	}
	d := s.defaultSettings(projectID)
	if d.Enabled {
		dbs, err := s.dbs.ListByProject(ctx, projectID)
		if err != nil {
			return Settings{}, err
		}
		d.Enabled = len(dbs) > 0
	}
	return d, nil
}

func (s *Service) view(ctx context.Context, projectID uuid.UUID) (*View, error) {
	st, err := s.effective(ctx, projectID)
	if err != nil {
		return nil, err
	}
	runs, err := s.repo.ListRuns(ctx, &projectID, 10)
	if err != nil {
		return nil, err
	}
	v := &View{Enabled: st.Enabled && s.Enabled(), Schedule: st.Schedule, RetentionDays: st.RetentionDays,
		Include: IncludeView{Databases: st.IncludeDatabases, Volumes: st.IncludeVolumes}, LastRuns: runViews(runs)}
	if v.Enabled {
		last, err := s.repo.LastBackupStart(ctx, &projectID)
		if err != nil {
			return nil, err
		}
		n := NextRun(st.Schedule, last, s.now())
		v.NextRun = &n
	}
	return v, nil
}

// Get returns GET .../backups.
func (s *Service) Get(ctx context.Context, projectID uuid.UUID) (*View, error) {
	return s.view(ctx, projectID)
}

// Patch is a partial settings update.
type Patch struct {
	Enabled          *bool
	Schedule         *string
	RetentionDays    *int
	IncludeDatabases *bool
	IncludeVolumes   *bool
}

// Update validates and stores settings (PUT .../backups).
func (s *Service) Update(ctx context.Context, projectID uuid.UUID, p Patch) (*View, error) {
	if !s.Enabled() {
		return nil, ErrDisabled
	}
	st, err := s.effective(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if p.Enabled != nil {
		st.Enabled = *p.Enabled
	}
	if p.Schedule != nil {
		if !ValidSchedule(*p.Schedule) {
			return nil, &InvalidError{"schedule must be one of hourly, 6h, 12h, daily, weekly"}
		}
		st.Schedule = *p.Schedule
	}
	if p.RetentionDays != nil {
		if *p.RetentionDays < 1 || *p.RetentionDays > s.cfg.BucketRetentionDays {
			return nil, &InvalidError{fmt.Sprintf("retention_days must be between 1 and %d (the bucket retention)", s.cfg.BucketRetentionDays)}
		}
		st.RetentionDays = *p.RetentionDays
	}
	if p.IncludeDatabases != nil {
		st.IncludeDatabases = *p.IncludeDatabases
	}
	if p.IncludeVolumes != nil {
		st.IncludeVolumes = *p.IncludeVolumes
	}
	if st.RetentionDays > s.cfg.BucketRetentionDays {
		st.RetentionDays = s.cfg.BucketRetentionDays
	}
	if err := s.repo.UpsertSettings(ctx, &st); err != nil {
		return nil, err
	}
	return s.view(ctx, projectID)
}

// Snapshots lists a project's stored backups (data and manifests).
func (s *Service) Snapshots(ctx context.Context, projectID uuid.UUID) ([]SnapshotView, error) {
	sn, err := s.repo.ListSnapshots(ctx, &projectID)
	if err != nil {
		return nil, err
	}
	out := make([]SnapshotView, 0, len(sn))
	for _, x := range sn {
		out = append(out, SnapshotView{ID: x.ID, CreatedAt: x.CreatedAt, SizeBytes: x.SizeBytes, Kind: x.Kind, Source: x.Source})
	}
	return out, nil
}

// PlatformView returns the platform-level runs and snapshots.
func (s *Service) PlatformView(ctx context.Context) (map[string]any, error) {
	runs, err := s.repo.ListRuns(ctx, nil, 10)
	if err != nil {
		return nil, err
	}
	sn, err := s.repo.ListSnapshots(ctx, nil)
	if err != nil {
		return nil, err
	}
	sv := make([]SnapshotView, 0, len(sn))
	for _, x := range sn {
		sv = append(sv, SnapshotView{ID: x.ID, CreatedAt: x.CreatedAt, SizeBytes: x.SizeBytes, Kind: x.Kind, Source: x.Source})
	}
	var next *time.Time
	if s.Enabled() {
		last, err := s.repo.LastBackupStart(ctx, nil)
		if err != nil {
			return nil, err
		}
		n := NextRun(s.cfg.DefaultSchedule, last, s.now())
		next = &n
	}
	return map[string]any{"enabled": s.Enabled(), "schedule": s.cfg.DefaultSchedule,
		"last_runs": runViews(runs), "snapshots": sv, "next_run": next}, nil
}

// ── starting jobs ───────────────────────────────────────────────────────────

func (s *Service) newRun(projectID *uuid.UUID, orgID *uuid.UUID, kind, trigger string, user *uuid.UUID) Run {
	return Run{ID: uuid.New(), ProjectID: projectID, OrgID: orgID, Kind: kind, Trigger: trigger,
		Status: "running", StartedAt: s.now().UTC(), UserID: user}
}

func (s *Service) project(ctx context.Context, id uuid.UUID) (*domain.Project, error) {
	p, err := s.projects.GetByID(ctx, id)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrNotFound
	}
	return p, err
}

// StartBackup runs a backup now in the background and returns the run id.
func (s *Service) StartBackup(ctx context.Context, projectID uuid.UUID, user *uuid.UUID) (uuid.UUID, error) {
	if !s.Enabled() {
		return uuid.Nil, ErrDisabled
	}
	proj, err := s.project(ctx, projectID)
	if err != nil {
		return uuid.Nil, err
	}
	st, err := s.effective(ctx, projectID)
	if err != nil {
		return uuid.Nil, err
	}
	run := s.newRun(&projectID, &proj.OrgID, "backup", "manual", user)
	if err := s.repo.CreateRun(ctx, &run); err != nil {
		return uuid.Nil, err
	}
	go s.execute(run, st)
	return run.ID, nil
}

// StartVerify checks the latest backups of a project without touching any data.
func (s *Service) StartVerify(ctx context.Context, projectID uuid.UUID, user *uuid.UUID) (uuid.UUID, error) {
	if !s.Enabled() {
		return uuid.Nil, ErrDisabled
	}
	proj, err := s.project(ctx, projectID)
	if err != nil {
		return uuid.Nil, err
	}
	run := s.newRun(&projectID, &proj.OrgID, "verify", "manual", user)
	if err := s.repo.CreateRun(ctx, &run); err != nil {
		return uuid.Nil, err
	}
	go s.execute(run, Settings{ProjectID: projectID})
	return run.ID, nil
}

// StartPlatformBackup / StartPlatformVerify are the platform-level counterparts.
func (s *Service) StartPlatformBackup(ctx context.Context, user *uuid.UUID) (uuid.UUID, error) {
	return s.startPlatform(ctx, "backup", user)
}

func (s *Service) StartPlatformVerify(ctx context.Context, user *uuid.UUID) (uuid.UUID, error) {
	return s.startPlatform(ctx, "verify", user)
}

func (s *Service) startPlatform(ctx context.Context, kind string, user *uuid.UUID) (uuid.UUID, error) {
	if !s.Enabled() {
		return uuid.Nil, ErrDisabled
	}
	run := s.newRun(nil, nil, kind, "manual", user)
	if err := s.repo.CreateRun(ctx, &run); err != nil {
		return uuid.Nil, err
	}
	go s.execute(run, Settings{})
	return run.ID, nil
}

// ErrUnsupported marks an operation the engine/snapshot cannot do (HTTP 400).
var ErrUnsupported = errors.New("unsupported")

// StartRestore validates synchronously, then restores in the background. Confirmation is the
// caller's job (the API acts on an explicit request; CLI/dashboard ask twice).
func (s *Service) StartRestore(ctx context.Context, projectID, snapshotID uuid.UUID, target string, user *uuid.UUID) (uuid.UUID, error) {
	if !s.Enabled() {
		return uuid.Nil, ErrDisabled
	}
	proj, err := s.project(ctx, projectID)
	if err != nil {
		return uuid.Nil, err
	}
	snap, err := s.repo.GetSnapshot(ctx, &projectID, snapshotID)
	if err != nil {
		return uuid.Nil, err
	}
	switch snap.Kind {
	case "database":
		eng, err := engineFor(snap.Engine)
		if err != nil {
			return uuid.Nil, &InvalidError{err.Error()}
		}
		if eng.restore == nil {
			return uuid.Nil, &InvalidError{fmt.Sprintf("restoring %s snapshots through Capsule is not supported (download and load the .rdb manually)", snap.Engine)}
		}
		if target != "" {
			if !ValidTargetName(target) {
				return uuid.Nil, &InvalidError{"target must be a valid database name (letters, digits, underscore)"}
			}
			if eng.create == nil && snap.Engine != "mongodb" {
				return uuid.Nil, &InvalidError{"this engine cannot restore into a new database"}
			}
		}
	case "volume", "objects":
		if target != "" {
			return uuid.Nil, &InvalidError{"target is only supported for database snapshots"}
		}
	default:
		return uuid.Nil, &InvalidError{"only database, volume and object storage snapshots can be restored"}
	}
	run := s.newRun(&projectID, &proj.OrgID, "restore", "manual", user)
	if err := s.repo.CreateRun(ctx, &run); err != nil {
		return uuid.Nil, err
	}
	go s.executeRestore(run, snap, target)
	return run.ID, nil
}

// ── scheduler ───────────────────────────────────────────────────────────────

// Run is the in-process scheduler. It marks orphaned runs failed, then ticks every minute.
// Only one instance claims work at a time (Postgres advisory lock inside ClaimDue).
func (s *Service) Run(ctx context.Context) {
	if !s.Enabled() {
		s.log.Info("backups disabled: scheduler not started")
		return
	}
	s.SetContext(ctx)
	if n, err := s.repo.FailOrphans(ctx, s.now()); err != nil {
		s.log.Warn("backups: recovering orphaned runs failed", "error", err)
	} else if n > 0 {
		s.log.Warn("backups: marked orphaned running runs as failed", "count", n)
	}
	t := time.NewTicker(s.tick)
	defer t.Stop()
	s.Tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}

// decide is the scheduling rule: enabled, nothing running, and the next run is due.
func (s *Service) decide(c Candidate) bool {
	if !c.Settings.Enabled || c.Running {
		return false
	}
	return !NextRun(c.Settings.Schedule, c.LastStart, s.now()).After(s.now())
}

// Tick claims due runs and executes them one after another.
func (s *Service) Tick(ctx context.Context) {
	runs, err := s.repo.ClaimDue(ctx, true, s.defaultSettings(uuid.Nil), s.decide)
	if err != nil {
		s.log.Warn("backups: claiming due runs failed", "error", err)
		return
	}
	for _, run := range runs {
		if ctx.Err() != nil {
			return
		}
		st := Settings{}
		if run.ProjectID != nil {
			if st, err = s.effective(ctx, *run.ProjectID); err != nil {
				_ = s.repo.FinishRun(ctx, run.ID, "failed", 0, "loading settings: "+err.Error(), s.now())
				continue
			}
		}
		s.execute(run, st)
	}
}

// ── execution ───────────────────────────────────────────────────────────────

func (s *Service) finish(run Run, size int64, err error, notes []string) {
	status, msg := "success", strings.Join(notes, "; ")
	if err != nil {
		status, msg = "failed", err.Error()
		if len(notes) > 0 {
			msg += "; " + strings.Join(notes, "; ")
		}
	}
	if len(msg) > 4000 {
		msg = msg[:4000]
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(s.baseCtx), 30*time.Second)
	defer cancel()
	if ferr := s.repo.FinishRun(ctx, run.ID, status, size, msg, s.now().UTC()); ferr != nil {
		s.log.Error("backups: finishing run failed", "run", run.ID, "error", ferr)
	}
	s.audit(ctx, run, "backup."+run.Kind+".finished", map[string]any{"run_id": run.ID.String(), "status": status, "size_bytes": size, "error": msg})
}

func (s *Service) audit(ctx context.Context, run Run, action string, extra map[string]any) {
	e := AuditEntry{OrgID: run.OrgID, UserID: run.UserID, Action: action, ResourceType: "backup", ResourceID: run.ProjectID, NewValues: extra}
	if err := s.repo.Audit(ctx, e); err != nil {
		s.log.Warn("backups: audit failed", "error", err)
	}
}

func (s *Service) acquire(ctx context.Context) bool {
	select {
	case s.sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Service) execute(run Run, st Settings) {
	ctx, cancel := context.WithTimeout(s.baseCtx, s.cfg.RunTimeout)
	defer cancel()
	if !s.acquire(ctx) {
		s.finish(run, 0, errors.New("cancelled before start"), nil)
		return
	}
	defer func() { <-s.sem }()
	s.audit(ctx, run, "backup."+run.Kind+".start", map[string]any{"run_id": run.ID.String(), "trigger": run.Trigger})
	defer func() {
		if r := recover(); r != nil {
			s.finish(run, 0, fmt.Errorf("internal error: %v", r), nil)
		}
	}()
	switch {
	case run.Kind == "verify":
		size, err := s.verify(ctx, run)
		s.finish(run, size, err, nil)
	case run.ProjectID == nil:
		rs := &runState{done: map[string]bool{}}
		err := s.withRetry(ctx, rs, func() []string { return s.platformOnce(ctx, run, rs) })
		if err == nil {
			s.retainPlatform(ctx)
		}
		s.finish(run, rs.size, err, rs.notes)
	default:
		rs := &runState{done: map[string]bool{}}
		err := s.withRetry(ctx, rs, func() []string { return s.projectOnce(ctx, run, st, rs) })
		if err == nil {
			s.retain(ctx, run.ProjectID, st.RetentionDays)
		}
		s.finish(run, rs.size, err, rs.notes)
	}
}

type runState struct {
	done  map[string]bool // sources already stored (not repeated on retry)
	size  int64
	notes []string
	data  int // data snapshots created (databases, volumes, platform files)
}

// withRetry runs fn, and once more after a pause when it reported errors.
func (s *Service) withRetry(ctx context.Context, rs *runState, fn func() []string) error {
	var errs []string
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(s.retryDelay):
			case <-ctx.Done():
				return fmt.Errorf("%s; cancelled before retry", strings.Join(errs, "; "))
			}
		}
		if errs = fn(); len(errs) == 0 {
			return nil
		}
		s.log.Warn("backups: attempt failed", "attempt", attempt+1, "errors", len(errs))
	}
	return errors.New(strings.Join(errs, "; "))
}

// retain deletes objects older than retentionDays and marks their snapshots deleted.
func (s *Service) retain(ctx context.Context, projectID *uuid.UUID, retentionDays int) {
	cutoff := s.now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	old, err := s.repo.ExpiredSnapshots(ctx, projectID, cutoff)
	if err != nil {
		s.log.Warn("backups: listing expired snapshots failed", "error", err)
		return
	}
	for _, sn := range old {
		if err := s.store.Delete(ctx, sn.ObjectKey); err != nil {
			s.log.Warn("backups: deleting expired object failed", "key", sn.ObjectKey, "error", err)
			continue
		}
		if err := s.repo.MarkSnapshotDeleted(ctx, sn.ID); err != nil {
			s.log.Warn("backups: marking snapshot deleted failed", "id", sn.ID, "error", err)
		}
	}
}

// Audit writes an audit_logs row; failures are logged, never fatal.
func (s *Service) Audit(ctx context.Context, e AuditEntry) {
	if err := s.repo.Audit(ctx, e); err != nil {
		s.log.Warn("backups: audit failed", "error", err)
	}
}

// retainPlatform only forgets platform snapshots whose object the bucket lifecycle has already
// expired: the API's IAM user may delete under projects/* only, never under platform/.
func (s *Service) retainPlatform(ctx context.Context) {
	cutoff := s.now().UTC().Add(-time.Duration(s.cfg.BucketRetentionDays) * 24 * time.Hour)
	old, err := s.repo.ExpiredSnapshots(ctx, nil, cutoff)
	if err != nil {
		s.log.Warn("backups: listing expired platform snapshots failed", "error", err)
		return
	}
	for _, sn := range old {
		if err := s.repo.MarkSnapshotDeleted(ctx, sn.ID); err != nil {
			s.log.Warn("backups: marking platform snapshot deleted failed", "id", sn.ID, "error", err)
		}
	}
}
