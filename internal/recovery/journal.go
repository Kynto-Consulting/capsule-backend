package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
)

// Journal stores recovery runs. Implementations: MemJournal (tests), FileJournal (bootstrap mode,
// before the database exists: same JSON as recovery_runs) and repository.RecoveryRepository.
type Journal interface {
	// Begin stores a new run. When run.IdempotencyKey is set and a run with the same key and
	// requester exists, that run is returned with created=false and nothing is stored. An apply
	// run fails with ErrActive while another apply run is running (one recovery at a time).
	Begin(ctx context.Context, run *Run) (existing *Run, created bool, err error)
	Save(ctx context.Context, run *Run) error
	Get(ctx context.Context, id uuid.UUID) (*Run, error)
}

func clone(r *Run) *Run {
	b, _ := json.Marshal(r)
	var c Run
	_ = json.Unmarshal(b, &c)
	c.IdempotencyKey, c.RequestedBy = r.IdempotencyKey, r.RequestedBy
	return &c
}

// MemJournal is an in-memory Journal.
type MemJournal struct {
	mu   sync.Mutex
	runs map[uuid.UUID]*Run
	// order keeps insertion order for deterministic scans
	order []uuid.UUID
}

func NewMemJournal() *MemJournal { return &MemJournal{runs: map[uuid.UUID]*Run{}} }

func (m *MemJournal) Begin(_ context.Context, run *Run) (*Run, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.order {
		r := m.runs[id]
		if run.IdempotencyKey != "" && r.IdempotencyKey == run.IdempotencyKey && sameUser(r.RequestedBy, run.RequestedBy) {
			return clone(r), false, nil
		}
		if run.Mode == ModeApply && r.Mode == ModeApply && r.Status == RunRunning {
			return nil, false, ErrActive
		}
	}
	m.runs[run.ID] = clone(run)
	m.order = append(m.order, run.ID)
	return nil, true, nil
}

func (m *MemJournal) Save(_ context.Context, run *Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.runs[run.ID]; !ok {
		return ErrNotFound
	}
	m.runs[run.ID] = clone(run)
	return nil
}

func (m *MemJournal) Get(_ context.Context, id uuid.UUID) (*Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return clone(r), nil
}

func sameUser(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// FileJournal keeps one JSON file per run in Dir (bootstrap mode). The file has the same shape as
// the recovery_runs row, so it can be loaded into the database once it exists.
type FileJournal struct {
	Dir string
	mu  sync.Mutex
}

func (f *FileJournal) path(id uuid.UUID) string { return filepath.Join(f.Dir, id.String()+".json") }

func (f *FileJournal) all() ([]*Run, error) {
	ents, err := os.ReadDir(f.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Run
	for _, e := range ents {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(f.Dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var r Run
		if json.Unmarshal(b, &r) == nil {
			out = append(out, &r)
		}
	}
	return out, nil
}

func (f *FileJournal) write(run *Run) error {
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(struct {
		*Run
		IdempotencyKey string `json:"idempotency_key,omitempty"`
	}{run, run.IdempotencyKey}, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path(run.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path(run.ID))
}

func (f *FileJournal) Begin(_ context.Context, run *Run) (*Run, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs, err := f.all()
	if err != nil {
		return nil, false, err
	}
	for _, r := range rs {
		if run.Mode == ModeApply && r.Mode == ModeApply && r.Status == RunRunning {
			return nil, false, ErrActive
		}
	}
	return nil, true, f.write(run)
}

func (f *FileJournal) Save(_ context.Context, run *Run) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.write(run)
}

func (f *FileJournal) Get(_ context.Context, id uuid.UUID) (*Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := os.ReadFile(f.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var r Run
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
