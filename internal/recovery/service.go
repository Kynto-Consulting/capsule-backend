package recovery

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/backup"
)

// Config is read from CAPSULE_RECOVERY_* by ConfigFromEnv (it lives here, not in config.go).
type Config struct {
	Enabled       bool          // CAPSULE_RECOVERY_ENABLED
	WorkDir       string        // CAPSULE_RECOVERY_WORKDIR: where ephemeral restores land (default /var/lib/capsule/recovery)
	ScriptsDir    string        // CAPSULE_RECOVERY_SCRIPTS_DIR: deploy/recovery on the host
	ScriptsOn     bool          // CAPSULE_RECOVERY_SCRIPTS: let the server run git/smoke scripts (network/core/dns stay bootstrap-only)
	ForgejoBucket string        // CAPSULE_RECOVERY_FORGEJO_BUCKET: bucket with forgejo/ dumps ("" = same bucket as backups)
	ReportPrefix  string        // CAPSULE_RECOVERY_REPORT_PREFIX: drills/ (ephemeral) or recoveries/
	RunTimeout    time.Duration // CAPSULE_RECOVERY_TIMEOUT (default 8h: the worst-case RTO)
}

func ConfigFromEnv() Config {
	c := Config{
		Enabled:       os.Getenv("CAPSULE_RECOVERY_ENABLED") == "true",
		WorkDir:       envOr("CAPSULE_RECOVERY_WORKDIR", "/var/lib/capsule/recovery"),
		ScriptsDir:    envOr("CAPSULE_RECOVERY_SCRIPTS_DIR", "/opt/capsule/deploy/recovery"),
		ScriptsOn:     os.Getenv("CAPSULE_RECOVERY_SCRIPTS") == "true",
		ForgejoBucket: os.Getenv("CAPSULE_RECOVERY_FORGEJO_BUCKET"),
		RunTimeout:    8 * time.Hour,
	}
	if h, err := strconv.Atoi(os.Getenv("CAPSULE_RECOVERY_TIMEOUT_HOURS")); err == nil && h > 0 {
		c.RunTimeout = time.Duration(h) * time.Hour
	}
	return c
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// Service orchestrates plan / apply / verify for the HTTP handlers and the CLI.
type Service struct {
	cfg     Config
	src     Source
	v       *Verifier
	forgejo backup.Store // may be nil
	journal Journal
	runner  Runner
	log     *slog.Logger
	now     func() time.Time
	baseCtx context.Context
	mu      sync.Mutex
	inPlace Restorer
	rebuild interface {
		Rebuild(ctx context.Context, projectID uuid.UUID, m *backup.Manifest) error
	}
}

func New(cfg Config, src Source, v *Verifier, forgejo backup.Store, j Journal, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{cfg: cfg, src: src, v: v, forgejo: forgejo, journal: j, runner: OSRunner{}, log: log, now: time.Now, baseCtx: context.Background()}
}

func (s *Service) SetContext(ctx context.Context) { s.baseCtx = ctx }
func (s *Service) SetClock(f func() time.Time)    { s.now = f }
func (s *Service) SetRunner(r Runner)             { s.runner = r }

// SetInPlace enables in-place data restores (ServiceRestorer over backup.Service) and the project
// rebuilder. Without it, in-place database/volume steps are reported as skipped, not faked.
func (s *Service) SetInPlace(r Restorer, rb interface {
	Rebuild(ctx context.Context, projectID uuid.UUID, m *backup.Manifest) error
}) {
	s.inPlace, s.rebuild = r, rb
}

func (s *Service) Enabled() bool {
	return s != nil && s.cfg.Enabled && s.src != nil && s.v != nil && s.journal != nil
}

// Plan resolves what would be restored (read only; creates nothing).
func (s *Service) Plan(ctx context.Context, req Request) (Plan, error) {
	req.Mode = ModePlan
	if _, err := req.Normalize(); err != nil {
		return Plan{}, err
	}
	cat, err := LoadCatalog(ctx, s.src, s.v, s.forgejo, s.now())
	if err != nil {
		return Plan{}, err
	}
	return BuildPlan(req, cat)
}

// Start plans and, for apply/verify, creates the run and executes it in the background.
// For plan mode the returned run is the planned (unstored) view.
func (s *Service) Start(ctx context.Context, req Request, user *uuid.UUID, idemKey string) (*Run, error) {
	nreq, err := req.Normalize()
	if err != nil {
		return nil, err
	}
	cat, err := LoadCatalog(ctx, s.src, s.v, s.forgejo, s.now())
	if err != nil {
		return nil, err
	}
	plan, err := BuildPlan(nreq, cat)
	if err != nil {
		return nil, err
	}
	run := &Run{ID: uuid.New(), Mode: nreq.Mode, Status: RunPlanned, Request: nreq, PlanID: plan.PlanID,
		Steps: InitSteps(plan), IdempotencyKey: idemKey, RequestedBy: user, StartedAt: s.now().UTC()}
	if nreq.Mode == ModePlan {
		return run, nil
	}
	if nreq.Mode == ModeApply && !plan.Ready && !nreq.ContinueOnErr {
		return nil, ErrBlocked
	}
	existing, created, err := s.journal.Begin(ctx, run)
	if err != nil {
		return nil, err
	}
	if !created {
		return existing, nil
	}
	run.Status = RunRunning
	go s.execute(plan, run, cat)
	return run, nil
}

// Resume re-executes a stored run: steps already ok are skipped, the first not ok is run again.
func (s *Service) Resume(ctx context.Context, id uuid.UUID) (*Run, error) {
	run, err := s.journal.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	cat, err := LoadCatalog(ctx, s.src, s.v, s.forgejo, s.now())
	if err != nil {
		return nil, err
	}
	plan, err := BuildPlan(run.Request, cat)
	if err != nil {
		return nil, err
	}
	if plan.PlanID != run.PlanID {
		return nil, ErrPlanChanged
	}
	go s.execute(plan, run, cat)
	return run, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*Run, error) { return s.journal.Get(ctx, id) }

func (s *Service) execute(plan Plan, run *Run, cat Catalog) {
	ctx, cancel := context.WithTimeout(s.baseCtx, s.cfg.RunTimeout)
	defer cancel()
	var reportKey string
	eng := &Engine{Journal: s.journal, Execs: s.execs(plan, cat, run, &reportKey), Now: s.now}
	if err := eng.Execute(ctx, plan, run); err != nil {
		s.log.Error("recovery run failed to persist", "run", run.ID, "error", err)
	}
	if reportKey != "" {
		run.ReportURL = reportKey
		_ = s.journal.Save(context.WithoutCancel(ctx), run)
	}
}

func (s *Service) execs(plan Plan, cat Catalog, run *Run, reportKey *string) map[Kind]Exec {
	m := map[Kind]Exec{}
	var rest Restorer
	if plan.Request.Target == TargetEphemeral {
		rest = &DirRestorer{V: s.v, Dir: s.cfg.WorkDir}
	} else if s.inPlace != nil {
		rest = s.inPlace
	}
	probe := probeSnapshot(plan)
	tools := []string(nil)
	m[KindPreflight] = PreflightExec{V: s.v, Probe: probe, Tools: tools}
	if rest != nil {
		m[KindDatabase], m[KindVolume] = DataExec{R: rest}, DataExec{R: rest}
		if plan.Request.Target == TargetEphemeral {
			m[KindPlatform] = DataExec{R: rest}
		}
	}
	m[KindProject] = ProjectExec{V: s.v, Dir: s.cfg.WorkDir, Rebuilder: func() interface {
		Rebuild(context.Context, uuid.UUID, *backup.Manifest) error
	} {
		if plan.Request.Target == TargetInPlace {
			return s.rebuild
		}
		return nil
	}()}
	if s.cfg.ScriptsOn {
		for k, name := range map[Kind]string{KindGit: "git-restore.sh", KindSmoke: "smoke.sh"} {
			m[k] = ScriptExec{Runner: s.runner, Dir: s.cfg.ScriptsDir, Script: name}
		}
	}
	prefix := s.cfg.ReportPrefix
	if prefix == "" {
		prefix = "recoveries/"
		if plan.Request.Target == TargetEphemeral {
			prefix = "drills/"
		}
	}
	m[KindReport] = ReportExec{Build: func(ctx context.Context, rc RunCtx) (string, error) {
		cur, err := s.journal.Get(ctx, rc.RunID)
		if err != nil {
			return "", err
		}
		rep := BuildReport(cur, plan, s.now(), time.Time{}, nil)
		st := s.reportStore()
		if st == nil {
			return "report not stored (no object store)", nil
		}
		key, err := WriteReport(ctx, st, prefix, rep)
		if err != nil {
			return "", err
		}
		*reportKey = key
		return key, nil
	}}
	return m
}

func (s *Service) reportStore() backup.Store {
	if s.v != nil {
		return s.v.Store
	}
	return nil
}

func probeSnapshot(plan Plan) *SnapshotRef {
	var best *SnapshotRef
	for _, st := range plan.Steps {
		if st.Snapshot == nil {
			continue
		}
		if best == nil || st.Snapshot.Size < best.Size {
			c := *st.Snapshot
			best = &c
		}
	}
	return best
}
