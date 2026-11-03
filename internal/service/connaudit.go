package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/connaudit"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

// connAuditState is the optional connection-audit wiring of the worker.
type connAuditState struct {
	store      connaudit.Store
	classifier func(ctx context.Context, w *DeployWorker, projectID uuid.UUID) *connaudit.Classifier
}

// SetConnAudit enables the deploy connection report (nil store: disabled).
func (w *DeployWorker) SetConnAudit(store connaudit.Store) {
	if store == nil {
		w.connAudit = nil
		return
	}
	w.connAudit = &connAuditState{store: store}
}

// connClassifier builds the classifier for a project: Capsule hosts/ports from
// the environment plus the project's own container names.
func (w *DeployWorker) connClassifier(ctx context.Context, projectID uuid.UUID) *connaudit.Classifier {
	c := connaudit.ClassifierFromEnv()
	c.OwnShort = strings.ReplaceAll(projectID.String(), "-", "")[:12]
	c.OwnNames = map[string]bool{}
	if w.pool != nil {
		if rows, err := w.pool.Query(ctx, `SELECT id FROM databases WHERE project_id = $1`, projectID); err == nil {
			for rows.Next() {
				var id uuid.UUID
				if rows.Scan(&id) == nil {
					c.OwnNames["capsule-db-"+id.String()] = true
				}
			}
			rows.Close()
		}
	}
	if w.extraPorts != nil {
		if ports, err := w.extraPorts(ctx, projectID); err == nil {
			set := map[int]bool{}
			for _, m := range ports {
				set[m.HostPort] = true
			}
			c.Published = func(p int) bool { return set[p] }
		}
	}
	return c
}

// connAuditGate analyses the env layers and the extracted source, stores the
// findings on the deployment, publishes the event and applies the project
// policy. It returns false (after failing the deployment) when strict blocks.
// Any internal error degrades to "continue": the audit never breaks a deploy.
func (w *DeployWorker) connAuditGate(ctx context.Context, id, projectID uuid.UUID, buildDir string) bool {
	st := w.connAudit
	if st == nil {
		return true
	}
	mode, err := st.store.Mode(ctx, projectID)
	if err != nil {
		mode = connaudit.ModeWarn
	}
	if mode == connaudit.ModeOff {
		return true
	}
	cls := w.connClassifier(ctx, projectID)
	var found []connaudit.Finding
	if m, err := w.resolveEnv(ctx, id, projectID); err == nil {
		env := make(map[string]string, len(m))
		for k, e := range m {
			env[k] = e.Value // analysed in memory only
		}
		found = connaudit.AnalyzeEnv(env, cls)
	} else {
		w.logger.Warn("connection audit: could not load env", "id", id)
	}
	scanned, stats := connaudit.ScanDir(ctx, buildDir, cls, connaudit.ScanLimits{})
	found = connaudit.Merge(found, scanned)
	if stats.Truncated {
		w.appendLog(ctx, id, "Connection audit: scan limits reached, the source report may be partial")
	}
	return w.connAuditApply(ctx, id, projectID, mode, found)
}

// connAuditApply stores the findings, reports them and enforces the policy.
func (w *DeployWorker) connAuditApply(ctx context.Context, id, projectID uuid.UUID, mode connaudit.Mode, found []connaudit.Finding) bool {
	st := w.connAudit
	connaudit.Sort(found)
	if err := st.store.SaveFindings(ctx, id, found); err != nil {
		w.logger.Warn("connection audit: could not store findings", "id", id, "error", err)
	}
	sups, _ := st.store.Suppressions(ctx, projectID)
	applied := connaudit.Apply(found, sups, time.Now())
	cnt := connaudit.Count(applied)
	if len(found) > 0 {
		w.appendLog(ctx, id, fmt.Sprintf("Connection audit: %d critical, %d warning, %d info, %d suppressed (see connection_warnings)", cnt.Critical, cnt.Warning, cnt.Info, cnt.Suppressed))
		if cnt.Critical+cnt.Warning > 0 {
			gitevents.Shared().Publish(ctx, gitevents.Event{
				ProjectID: projectID, Name: gitevents.DeploymentConnWarn, Actor: "capsule",
				Data: map[string]any{
					"deployment_id": id.String(),
					"critical":      cnt.Critical, "warning": cnt.Warning,
					"summary": fmt.Sprintf("%d critica(s), %d advertencia(s)", cnt.Critical, cnt.Warning),
				},
			})
		}
	}
	if blocked := connaudit.Blocking(applied, mode); len(blocked) > 0 {
		var parts []string
		for _, b := range blocked {
			parts = append(parts, b.Source+" -> "+b.Endpoint+" ["+b.ID+"]")
		}
		w.failDeployment(ctx, id, connaudit.BlockedCode+": strict connection policy blocked this deployment: "+strings.Join(parts, "; ")+
			". Route them through the gateway or suppress them with a reason.", nil)
		return false
	}
	return true
}

// connAuditRuntime (CAPSULE_CONNAUDIT_RUNTIME=true) observes the running
// container after CAPSULE_CONNAUDIT_RUNTIME_DELAY seconds (default 30) and merges
// the live connections into the stored findings. Best effort and asynchronous.
func (w *DeployWorker) connAuditRuntime(id, projectID uuid.UUID, container string) {
	st := w.connAudit
	if st == nil || container == "" || os.Getenv("CAPSULE_CONNAUDIT_RUNTIME") != "true" {
		return
	}
	delay := 30 * time.Second
	if n, err := strconv.Atoi(os.Getenv("CAPSULE_CONNAUDIT_RUNTIME_DELAY")); err == nil && n >= 0 {
		delay = time.Duration(n) * time.Second
	}
	go func() {
		time.Sleep(delay)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if mode, err := st.store.Mode(ctx, projectID); err == nil && mode == connaudit.ModeOff {
			return
		}
		run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		}
		live, err := connaudit.Observe(ctx, run, os.ReadFile, container, w.connClassifier(ctx, projectID))
		if err != nil {
			w.appendLog(ctx, id, "Connection audit: runtime observation unavailable for this image (no shell or no access to the container); static report only")
			return
		}
		prev, err := st.store.FindingsFor(ctx, []uuid.UUID{id})
		if err != nil {
			return
		}
		merged := connaudit.Merge(prev[id], live)
		connaudit.Sort(merged)
		if err := st.store.SaveFindings(ctx, id, merged); err != nil {
			w.logger.Warn("connection audit: could not store runtime findings", "id", id, "error", err)
			return
		}
		if len(live) > 0 {
			w.appendLog(ctx, id, fmt.Sprintf("Connection audit: %d live connection(s) to non-routed internal endpoints", len(live)))
		}
	}()
}
