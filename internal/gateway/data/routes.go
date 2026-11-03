package data

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Table is an immutable, indexed route table. Lookups never lock: the manager swaps whole tables atomically.
type Table struct {
	Rev       int64
	Leases    []Lease
	UDP       []Route // transport=udp routes (served in phase F3)
	byHost    map[string]*Route
	wildcards []wildRoute
	byService map[string]*Route // "project/service"
	byID      map[string]*Route
	udpBySvc  map[string]*Route // "project/service" of UDP routes (udp_support.go)
	udpByID   map[string]*Route
	bySvcID   map[string][]*Route // every usable route of a service, by id
}

type wildRoute struct {
	suffix string // ".apps.example.test" (with leading dot)
	route  *Route
}

// NewTable indexes a snapshot. Only TCP routes are indexed for the TCP data plane.
func NewTable(s *Snapshot) *Table {
	t := &Table{
		Rev:       s.Rev,
		Leases:    s.Leases,
		byHost:    make(map[string]*Route, len(s.Routes)),
		byService: make(map[string]*Route),
		byID:      make(map[string]*Route, len(s.Routes)),
	}
	for i := range s.Routes {
		r := s.Routes[i]
		r.Host = strings.TrimSuffix(strings.ToLower(r.Host), ".")
		if r.Transport == "udp" {
			t.UDP = append(t.UDP, r)
			continue
		}
		if r.DestHost == "" || r.DestPort <= 0 || r.DestPort > 65535 || r.ID == "" {
			continue // unusable row: never route to a half-defined destination
		}
		rp := &r
		t.byID[r.ID] = rp
		if r.Host != "" {
			if strings.HasPrefix(r.Host, "*.") {
				t.wildcards = append(t.wildcards, wildRoute{suffix: r.Host[1:], route: rp})
			} else {
				t.byHost[r.Host] = rp
			}
		}
		if r.Project == "" {
			r.Project = r.ProjectSlug
		}
		if r.Project != "" && r.Service != "" {
			t.byService[r.Project+"/"+r.Service] = rp
		}
	}
	t.indexExtra()
	return t
}

// LookupHost resolves an SNI/Host name: exact match first, then the longest wildcard suffix.
func (t *Table) LookupHost(host string) *Route {
	if t == nil || host == "" {
		return nil
	}
	if r, ok := t.byHost[host]; ok {
		return r
	}
	var best *Route
	bl := 0
	for _, w := range t.wildcards {
		if strings.HasSuffix(host, w.suffix) && len(w.suffix) > bl && len(host) > len(w.suffix) {
			best, bl = w.route, len(w.suffix)
		}
	}
	return best
}

// LookupService resolves a capsule/1 project/service pair.
func (t *Table) LookupService(project, service string) *Route {
	if t == nil {
		return nil
	}
	return t.byService[project+"/"+service]
}

// Len is the number of TCP routes.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return len(t.byID)
}

// Routes lists the indexed TCP routes (for metrics cleanup and diagnostics).
func (t *Table) Routes() []*Route {
	if t == nil {
		return nil
	}
	out := make([]*Route, 0, len(t.byID))
	for _, r := range t.byID {
		out = append(out, r)
	}
	return out
}

// RouteManager keeps the current table in sync with the control plane (long-poll) and degrades safely: when the
// control plane stops answering, the last known table keeps being served until it is older than MaxAge.
type RouteManager struct {
	CP        ControlPlane
	Log       *slog.Logger
	Wait      time.Duration // long-poll wait sent to the control plane (default 25 s)
	MaxAge    time.Duration // 0 = serve the last table forever
	CacheFile string        // optional on-disk copy so a restart during an outage still has routes
	OnChange  func(old, new *Table)
	Now       func() time.Time

	cur      atomic.Pointer[Table]
	lastOK   atomic.Int64 // unix nanos of the last successful contact (200 or 304)
	ctlUp    atomic.Bool
	failures atomic.Int64
}

func (m *RouteManager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Table returns the table in force, or nil if none was ever loaded or it is older than MaxAge.
func (m *RouteManager) Table() *Table {
	t := m.cur.Load()
	if t == nil {
		return nil
	}
	if m.MaxAge > 0 && m.now().Sub(time.Unix(0, m.lastOK.Load())) > m.MaxAge {
		return nil
	}
	return t
}

// Age is the time since the last successful contact with the control plane (0 if never).
func (m *RouteManager) Age() time.Duration {
	l := m.lastOK.Load()
	if l == 0 {
		return 0
	}
	return m.now().Sub(time.Unix(0, l))
}

// ControlUp reports whether the last attempt reached the control plane.
func (m *RouteManager) ControlUp() bool { return m.ctlUp.Load() }

// Ready is true when a usable table is being served.
func (m *RouteManager) Ready() bool { return m.Table() != nil }

// Rev is the revision in force (0 when none).
func (m *RouteManager) Rev() int64 {
	if t := m.cur.Load(); t != nil {
		return t.Rev
	}
	return 0
}

// Set installs a snapshot (used by Run and by tests).
func (m *RouteManager) Set(s *Snapshot) {
	nt := NewTable(s)
	old := m.cur.Swap(nt)
	m.lastOK.Store(m.now().UnixNano())
	if m.OnChange != nil {
		m.OnChange(old, nt)
	}
}

type cacheDoc struct {
	SavedAt  time.Time `json:"saved_at"`
	Snapshot Snapshot  `json:"snapshot"`
}

func (m *RouteManager) saveCache(s *Snapshot) {
	if m.CacheFile == "" {
		return
	}
	b, err := json.Marshal(cacheDoc{SavedAt: m.now().UTC(), Snapshot: *s})
	if err != nil {
		return
	}
	tmp := m.CacheFile + ".tmp"
	if err := os.MkdirAll(filepath.Dir(m.CacheFile), 0o700); err != nil {
		return
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		m.Log.Warn("routes cache write failed", "err", err)
		return
	}
	if err := os.Rename(tmp, m.CacheFile); err != nil {
		m.Log.Warn("routes cache rename failed", "err", err)
	}
}

// LoadCache installs the on-disk copy if it is younger than MaxAge. It reports whether a table was installed.
func (m *RouteManager) LoadCache() bool {
	if m.CacheFile == "" {
		return false
	}
	b, err := os.ReadFile(m.CacheFile)
	if err != nil {
		return false
	}
	var d cacheDoc
	if json.Unmarshal(b, &d) != nil {
		return false
	}
	if m.MaxAge > 0 && m.now().Sub(d.SavedAt) > m.MaxAge {
		return false
	}
	nt := NewTable(&d.Snapshot)
	m.cur.Store(nt)
	m.lastOK.Store(d.SavedAt.UnixNano())
	if m.OnChange != nil {
		m.OnChange(nil, nt)
	}
	m.Log.Info("routes loaded from cache", "rev", d.Snapshot.Rev, "routes", nt.Len(), "saved_at", d.SavedAt)
	return true
}

// Run synchronises until ctx ends. The first request does not wait (wait=0) so startup is immediate.
func (m *RouteManager) Run(ctx context.Context) {
	if m.Wait <= 0 {
		m.Wait = 25 * time.Second
	}
	wait := time.Duration(0)
	backoff := time.Second
	for ctx.Err() == nil {
		since := m.Rev()
		if m.cur.Load() == nil {
			since = 0
		}
		rctx, cancel := context.WithTimeout(ctx, wait+20*time.Second)
		snap, err := m.CP.Routes(rctx, since, wait)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			m.ctlUp.Store(false)
			n := m.failures.Add(1)
			if n == 1 || n%20 == 0 {
				m.Log.Warn("routes poll failed; serving last known table", "err", errString(err), "failures", n, "age", m.Age().Round(time.Second))
			}
			sleepCtx(ctx, jitter(backoff))
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		m.failures.Store(0)
		backoff = time.Second
		m.ctlUp.Store(true)
		if snap == nil { // 304
			m.lastOK.Store(m.now().UnixNano())
			if m.cur.Load() == nil { // revision 0 and nothing yet: an empty table is a valid answer
				m.Set(&Snapshot{})
			}
		} else {
			m.Set(snap)
			m.saveCache(snap)
			m.Log.Info("routes reloaded", "rev", snap.Rev, "routes", len(snap.Routes))
		}
		wait = m.Wait
	}
}

func errString(err error) string {
	switch {
	case errors.Is(err, ErrControlUnauthorized):
		return "control plane rejected the gateway secret"
	default:
		return err.Error()
	}
}

func jitter(d time.Duration) time.Duration {
	return d - d/5 + time.Duration(rand.Int64N(int64(d)/5*2+1))
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
