package service

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/connaudit"
	"github.com/kynto/capsule/backend/internal/domain"
)

type auditStore struct {
	mu    sync.Mutex
	sups  []connaudit.Suppression
	saved []connaudit.Finding
}

func (s *auditStore) Mode(context.Context, uuid.UUID) (connaudit.Mode, error) {
	return connaudit.ModeWarn, nil
}
func (s *auditStore) SetMode(context.Context, uuid.UUID, connaudit.Mode) error { return nil }
func (s *auditStore) Suppressions(context.Context, uuid.UUID) ([]connaudit.Suppression, error) {
	return s.sups, nil
}
func (s *auditStore) PutSuppression(context.Context, uuid.UUID, connaudit.Suppression) error {
	return nil
}
func (s *auditStore) DeleteSuppression(context.Context, uuid.UUID, string) error { return nil }
func (s *auditStore) SaveFindings(_ context.Context, _ uuid.UUID, f []connaudit.Finding) error {
	s.saved = f
	return nil
}
func (s *auditStore) FindingsFor(context.Context, []uuid.UUID) (map[uuid.UUID][]connaudit.Finding, error) {
	return nil, nil
}

type auditDeployments struct {
	domain.DeploymentRepository
	status string
	logs   []string
}

func (d *auditDeployments) UpdateStatus(_ context.Context, _ uuid.UUID, s string) error {
	d.status = s
	return nil
}
func (d *auditDeployments) AppendLog(_ context.Context, l *domain.BuildLog) error {
	d.logs = append(d.logs, l.Message)
	return nil
}

func auditWorker(st *auditStore) (*DeployWorker, *auditDeployments) {
	dep := &auditDeployments{}
	w := &DeployWorker{deployments: dep, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w.SetConnAudit(st)
	return w, dep
}

func TestConnAuditStrictBlocksCritical(t *testing.T) {
	cls := &connaudit.Classifier{}
	found := connaudit.AnalyzeEnv(map[string]string{"X": "http://169.254.169.254/latest", "DB_HOST": "127.0.0.1"}, cls)
	st := &auditStore{}
	w, dep := auditWorker(st)
	if !w.connAuditApply(context.Background(), uuid.New(), uuid.New(), connaudit.ModeWarn, found) || dep.status == "failed" {
		t.Fatal("warn must not block")
	}
	if len(st.saved) != 2 {
		t.Fatalf("saved %v", st.saved)
	}
	w, dep = auditWorker(st)
	if w.connAuditApply(context.Background(), uuid.New(), uuid.New(), connaudit.ModeStrict, found) || dep.status != "failed" {
		t.Fatal("strict must block a critical finding")
	}
	if !strings.Contains(strings.Join(dep.logs, "\n"), connaudit.BlockedCode) {
		t.Fatalf("logs %v", dep.logs)
	}
	// a live suppression lifts the block; an expired one does not
	past := time.Now().Add(-time.Hour)
	var critID string
	for _, f := range found {
		if f.Severity == connaudit.SevCritical {
			critID = f.ID
		}
	}
	st.sups = []connaudit.Suppression{{FindingID: critID, Reason: "motivo valido", ExpiresAt: &past}}
	w, _ = auditWorker(st)
	if w.connAuditApply(context.Background(), uuid.New(), uuid.New(), connaudit.ModeStrict, found) {
		t.Fatal("expired suppression must not lift the block")
	}
	st.sups = []connaudit.Suppression{{FindingID: critID, Reason: "motivo valido"}}
	w, _ = auditWorker(st)
	if !w.connAuditApply(context.Background(), uuid.New(), uuid.New(), connaudit.ModeStrict, found) {
		t.Fatal("active suppression must lift the block")
	}
}
