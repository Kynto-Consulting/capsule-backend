package security

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

const (
	maxUploadAttempts = 3
	staleProcessing   = 2 * time.Minute
	maxCreatedEvents  = 20
)

// RunLoop processes queued uploads and runs the periodic sweeps until ctx ends.
func (s *Service) RunLoop(ctx context.Context) {
	worker := time.NewTicker(s.cfg.WorkerEvery)
	sweep := time.NewTicker(s.cfg.SweepEvery)
	defer worker.Stop()
	defer sweep.Stop()
	s.drain(ctx)
	s.Sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			s.drain(ctx)
		case <-worker.C:
			s.drain(ctx)
		case <-sweep.C:
			s.Sweep(ctx)
		}
	}
}

func (s *Service) drain(ctx context.Context) {
	for ctx.Err() == nil {
		n, err := s.ProcessPending(ctx, 10)
		if err != nil {
			s.log.Warn("security: processing uploads failed", "err", err)
			return
		}
		if n == 0 {
			return
		}
	}
}

// ProcessPending claims and processes up to limit uploads and returns how many it handled.
func (s *Service) ProcessPending(ctx context.Context, limit int) (int, error) {
	claimed, err := s.store.ClaimUploads(ctx, limit, staleProcessing, s.now())
	if err != nil {
		return 0, err
	}
	for _, cu := range claimed {
		s.processOne(ctx, cu)
	}
	return len(claimed), nil
}

func (s *Service) processOne(ctx context.Context, cu ClaimedUpload) {
	now := s.now()
	res, err := s.store.ApplyUpload(ctx, cu, now)
	if err != nil {
		final := cu.Attempts >= maxUploadAttempts
		s.log.Warn("security: applying upload failed", "upload_id", cu.ID, "attempt", cu.Attempts, "err", err)
		if ferr := s.store.FailUpload(ctx, cu.ID, "no se pudo procesar la subida: "+plain(err.Error(), 200), final, now); ferr != nil {
			s.log.Error("security: recording upload failure failed", "upload_id", cu.ID, "err", ferr)
		}
		return
	}
	t, err := s.store.ProjectTarget(ctx, cu.ProjectID)
	if err != nil {
		s.log.Warn("security: project of upload not found", "upload_id", cu.ID, "err", err)
		return
	}
	if res.Superseded {
		return
	}
	s.publishCreated(ctx, t, cu, res.Created)
	// pull requests whose head is this commit get their check (it also creates the pending run)
	s.evaluatePullsAt(ctx, t, cu.CommitSHA)
	s.ReevaluateRecent(ctx, t)
}

func (s *Service) publishCreated(ctx context.Context, t Target, cu ClaimedUpload, created []Alert) {
	var open []Alert
	for _, a := range created {
		if a.State == StateOpen {
			open = append(open, a)
		}
	}
	sort.SliceStable(open, func(i, j int) bool { return open[i].Severity.Rank() > open[j].Severity.Rank() })
	for i, a := range open {
		if i >= maxCreatedEvents {
			break
		}
		// never the value of a secret: rule, path and line are all that exists
		s.publish(ctx, t, gitevents.SecurityAlertCreated, "", a.Branch, map[string]any{
			"alert_id": a.ID.String(), "kind": string(a.Kind), "severity": string(a.Severity), "tool": a.Tool,
			"rule_id": a.RuleID, "path": a.Path, "line": a.StartLine, "title": a.Title, "total_new": len(open),
		})
	}
}

func (s *Service) evaluatePullsAt(ctx context.Context, t Target, sha string) {
	if s.forge == nil || !s.forge.Enabled() {
		return
	}
	var cursor string
	for page := 0; page < 3; page++ {
		l, err := s.forge.ListPulls(ctx, repoRef(t), gitcore.PullQuery{State: "open"}, gitcore.Page{Cursor: cursor, Limit: 100})
		if err != nil {
			s.log.Warn("security: listing pull requests failed", "project_id", t.ProjectID, "err", err)
			return
		}
		for _, p := range l.Items {
			if strings.EqualFold(p.HeadSHA, sha) {
				if _, err := s.EvaluatePull(ctx, t, PullRef{Number: p.Number, Base: p.Base, Head: p.Head, HeadSHA: p.HeadSHA}); err != nil {
					s.log.Warn("security: evaluating pull request failed", "project_id", t.ProjectID, "pr", p.Number, "err", err)
				}
			}
		}
		if l.NextCursor == "" {
			return
		}
		cursor = l.NextCursor
	}
}

// Sweep expires suppressions, sends the 7-day notices and re-evaluates checks that wait for a
// required tool (so they fail closed after the timeout even if nobody touches the project).
func (s *Service) Sweep(ctx context.Context) {
	now := s.now()
	expired, err := s.store.ExpireDue(ctx, now)
	if err != nil {
		s.log.Warn("security: expiring suppressions failed", "err", err)
	}
	for _, e := range expired {
		s.ReevaluateRecent(ctx, e.Target)
	}

	notices, err := s.store.DueExpiringNotices(ctx, now, ExpiryNoticeDays*24*time.Hour)
	if err != nil {
		s.log.Warn("security: loading expiring suppressions failed", "err", err)
	}
	var notified []uuid.UUID
	targets := map[uuid.UUID]Target{}
	for _, sp := range notices {
		t, ok := targets[sp.ProjectID]
		if !ok {
			if t, err = s.store.ProjectTarget(ctx, sp.ProjectID); err != nil {
				continue
			}
			targets[sp.ProjectID] = t
		}
		days := int(sp.ExpiresAt.Sub(now).Hours()/24 + 0.999)
		data := map[string]any{
			"suppression_id": sp.ID.String(), "expires_at": sp.ExpiresAt.UTC().Format(time.RFC3339), "days_left": days,
			"reason": sp.Reason, "rule_id": sp.Match.RuleID, "path_glob": sp.Match.PathGlob, "source": sp.Source,
		}
		var rec []uuid.UUID
		if sp.CreatedBy != uuid.Nil {
			rec = []uuid.UUID{sp.CreatedBy}
		}
		if err := s.publisher().Publish(ctx, gitevents.Event{
			OrgID: t.OrgID, ProjectID: t.ProjectID, Name: gitevents.SecuritySuppExpiring, Data: data, Recipients: rec,
		}); err != nil {
			s.log.Warn("security: expiring notice failed", "suppression_id", sp.ID, "err", err)
			continue
		}
		notified = append(notified, sp.ID)
	}
	if len(notified) > 0 {
		if err := s.store.MarkExpiringNotified(ctx, notified, now); err != nil {
			s.log.Warn("security: marking notices failed", "err", err)
		}
	}

	runs, err := s.store.OpenCheckRuns(ctx, 200)
	if err != nil {
		s.log.Warn("security: loading open checks failed", "err", err)
		return
	}
	for i := range runs {
		t, ok := targets[runs[i].ProjectID]
		if !ok {
			if t, err = s.store.ProjectTarget(ctx, runs[i].ProjectID); err != nil {
				continue
			}
			targets[runs[i].ProjectID] = t
		}
		if _, err := s.evaluateRun(ctx, t, &runs[i]); err != nil {
			s.log.Warn("security: re-evaluating check failed", "project_id", t.ProjectID, "sha", runs[i].HeadSHA, "err", err)
		}
	}
}

// ---- inbound pull request events -------------------------------------------------------------

// Subscriber adapts the Service to the A5 event bus: when a pull request opens or gets new
// commits the capsule/security check is created (pending) and evaluated, so a head that already
// has alerts is reported at once and one that is waiting for a tool starts its 30 minute clock.
type Subscriber struct{ s *Service }

// Subscriber returns the bus subscriber (register it with gitevents.Bus.Subscribe).
func (s *Service) Subscriber() *Subscriber { return &Subscriber{s: s} }

// Name implements gitevents.Subscriber.
func (b *Subscriber) Name() string { return "security" }

// Handle implements gitevents.Subscriber (idempotent: re-evaluating the same head is harmless).
func (b *Subscriber) Handle(ctx context.Context, e gitevents.Event) error {
	switch e.Name {
	case gitevents.PROpened, gitevents.PRUpdated, gitevents.PRReadyForReview:
	default:
		return nil
	}
	sha, _ := e.Data["sha"].(string)
	if sha == "" {
		return nil
	}
	pr := dataInt(e.Data["pr"])
	base, _ := e.Data["base"].(string)
	head, _ := e.Data["branch"].(string)
	t, err := b.s.store.ProjectTarget(ctx, e.ProjectID)
	if err != nil {
		return err
	}
	_, err = b.s.EvaluatePull(ctx, t, PullRef{Number: pr, Base: base, Head: head, HeadSHA: sha})
	return err
}

func dataInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	}
	return 0
}

var _ gitevents.Subscriber = (*Subscriber)(nil)

// String is for logs.
func (c CheckRun) String() string {
	return fmt.Sprintf("%s@%s %s", CheckContext, c.HeadSHA, c.State)
}
