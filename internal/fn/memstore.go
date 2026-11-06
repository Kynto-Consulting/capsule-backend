package fn

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemStore is an in-memory Store for tests and local use.
type MemStore struct {
	mu     sync.Mutex
	fns    map[uuid.UUID]*Function
	runs   map[uuid.UUID]*Run
	tokens map[string]*RunToken
	Nodes  map[string]string // hash -> node name
	seen   map[string]time.Time
	builds map[uuid.UUID]*Build
}

// NewMemStore creates an empty store.
func NewMemStore() *MemStore {
	return &MemStore{fns: map[uuid.UUID]*Function{}, runs: map[uuid.UUID]*Run{}, tokens: map[string]*RunToken{}, Nodes: map[string]string{}, seen: map[string]time.Time{}}
}

func (m *MemStore) CreateFunction(_ context.Context, f *Function) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.fns {
		if o.ProjectID == f.ProjectID && o.Name == f.Name {
			return ErrConflict
		}
	}
	c := *f
	m.fns[f.ID] = &c
	return nil
}
func (m *MemStore) GetFunction(_ context.Context, p uuid.UUID, name string) (*Function, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.fns {
		if o.ProjectID == p && o.Name == name {
			c := *o
			return &c, nil
		}
	}
	return nil, ErrNotFound
}
func (m *MemStore) GetFunctionByID(_ context.Context, id uuid.UUID) (*Function, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if o, ok := m.fns[id]; ok {
		c := *o
		return &c, nil
	}
	return nil, ErrNotFound
}
func (m *MemStore) ListFunctions(_ context.Context, p uuid.UUID) ([]*Function, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Function
	for _, o := range m.fns {
		if o.ProjectID == p {
			c := *o
			out = append(out, &c)
		}
	}
	return out, nil
}
func (m *MemStore) CronFunctions(_ context.Context) ([]*Function, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Function
	for _, o := range m.fns {
		if o.Cron != "" {
			c := *o
			out = append(out, &c)
		}
	}
	return out, nil
}
func (m *MemStore) DeleteFunction(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.fns, id)
	for bid, b := range m.builds { // ON DELETE CASCADE, like fn_builds
		if b.FunctionID == id {
			delete(m.builds, bid)
		}
	}
	return nil
}
func (m *MemStore) CASLastCron(_ context.Context, id uuid.UUID, old *time.Time, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.fns[id]
	if !ok {
		return false, nil
	}
	if (f.LastCronAt == nil) != (old == nil) || (old != nil && !f.LastCronAt.Equal(*old)) {
		return false, nil
	}
	f.LastCronAt = &now
	return true, nil
}
func (m *MemStore) EnqueueRun(_ context.Context, r *Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *r
	m.runs[r.ID] = &c
	return nil
}
func (m *MemStore) byStatus(st string) []*Run {
	var out []*Run
	for _, r := range m.runs {
		if r.Status == st {
			c := *r
			out = append(out, &c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].QueuedAt.Before(out[j].QueuedAt) })
	return out
}
func (m *MemStore) QueuedRuns(_ context.Context, limit int) ([]*Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	q := m.byStatus(RunQueued)
	if len(q) > limit {
		q = q[:limit]
	}
	return q, nil
}
func (m *MemStore) RunningRuns(_ context.Context) ([]*Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.byStatus(RunRunning), nil
}
func (m *MemStore) TryStart(_ context.Context, id uuid.UUID, node string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok || r.Status != RunQueued {
		return false, nil
	}
	f := m.fns[r.FunctionID]
	n := 0
	for _, o := range m.runs {
		if o.FunctionID == r.FunctionID && o.Status == RunRunning {
			n++
		}
	}
	if f == nil || n >= f.MaxConcurrency {
		return false, nil
	}
	r.Status, r.NodeID, r.StartedAt = RunRunning, node, &now
	return true, nil
}
func (m *MemStore) FinishRun(_ context.Context, id uuid.UUID, st string, exit *int, in, out int64, tail string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok {
		return ErrNotFound
	}
	r.Status, r.ExitCode, r.BytesIn, r.BytesOut, r.LogTail, r.FinishedAt = st, exit, in, out, tail, &now
	return nil
}
func (m *MemStore) GetRun(_ context.Context, id uuid.UUID) (*Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.runs[id]; ok {
		c := *r
		return &c, nil
	}
	return nil, ErrNotFound
}
func (m *MemStore) ListRuns(_ context.Context, fid uuid.UUID, limit int) ([]*Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Run
	for _, r := range m.runs {
		if r.FunctionID == fid {
			c := *r
			out = append(out, &c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].QueuedAt.After(out[j].QueuedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (m *MemStore) PutToken(_ context.Context, t RunToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.Hash] = &t
	return nil
}
func (m *MemStore) GetToken(_ context.Context, h string) (*RunToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tokens[h]; ok {
		c := *t
		return &c, nil
	}
	return nil, ErrNotFound
}
func (m *MemStore) RevokeRunTokens(_ context.Context, run uuid.UUID, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tokens {
		if t.RunID == run && t.RevokedAt == nil {
			n := now
			t.RevokedAt = &n
		}
	}
	return nil
}
func (m *MemStore) NodeByHash(_ context.Context, h string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n, ok := m.Nodes[h]; ok {
		m.seen[n] = time.Now()
		return n, nil
	}
	return "", ErrNotFound
}

// LiveNode returns the node seen since the given time.
func (m *MemStore) LiveNode(_ context.Context, since time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	best, bt := "", since
	for n, t := range m.seen {
		if t.After(bt) {
			best, bt = n, t
		}
	}
	if best == "" {
		return "", ErrNotFound
	}
	return best, nil
}
