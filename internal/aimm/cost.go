package aimm

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"
)

// Cost estimates, in US dollars, from the catalog's price table. They are estimates, not invoices: AWS bills the real usage.

// EstimateTokens prices a chat or embedding call.
func EstimateTokens(m Model, in, out int) float64 {
	return roundUSD(float64(in)/1000*m.Price.Input + float64(out)/1000*m.Price.Output)
}

// EstimateImages prices n images.
func EstimateImages(m Model, n int) float64 { return roundUSD(float64(n) * m.Price.Per) }

// EstimateSpeech prices a Polly call by characters.
func EstimateSpeech(m Model, chars int) float64 { return roundUSD(float64(chars) / 1e6 * m.Price.Per) }

// EstimateMinutes prices audio by duration (transcription, speech to speech).
func EstimateMinutes(m Model, minutes float64) float64 { return roundUSD(minutes * m.Price.Per) }

// EstimateRerank prices a rerank call: one search per 100 documents.
func EstimateRerank(m Model, docs int) float64 {
	searches := math.Ceil(float64(docs) / 100)
	return roundUSD(searches * m.Price.Per / 1000)
}

// ErrQuota means the daily budget of the scope is spent.
var ErrQuota = errors.New("daily AI budget exceeded")

// QuotaError carries the numbers for the response.
type QuotaError struct {
	UsedUSD, LimitUSD, NeededUSD float64
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("daily AI budget exceeded: used $%.4f of $%.2f, this call needs about $%.4f", e.UsedUSD, e.LimitUSD, e.NeededUSD)
}
func (e *QuotaError) Is(t error) bool { return t == ErrQuota }

// KV is the persistence the quota needs (the platform cache).
type KV interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, ttlSeconds int) error
}

// Quota enforces a daily spend per scope (a project, or a user for calls outside a project). It is process-local in its
// read-modify-write: with several API replicas the cap can be exceeded by one call per replica, which the estimate-before-call
// check keeps within a few cents.
type Quota struct {
	KV       KV
	DailyUSD float64 // 0 = unlimited
	Now      func() time.Time
	mu       sync.Mutex
}

func (q *Quota) key(scope string) string {
	n := time.Now
	if q.Now != nil {
		n = q.Now
	}
	return "ai:quota:" + scope + ":" + n().UTC().Format("20060102")
}

func (q *Quota) used(ctx context.Context, scope string) float64 {
	s, err := q.KV.Get(ctx, q.key(scope))
	if err != nil || s == "" {
		return 0
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return float64(v) / 1e6
}

// Usage returns the spend of today and the limit.
func (q *Quota) Usage(ctx context.Context, scope string) (used, limit float64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.used(ctx, scope), q.DailyUSD
}

// Check fails with *QuotaError when the estimate does not fit in today's remaining budget.
func (q *Quota) Check(ctx context.Context, scope string, estimate float64) error {
	if q == nil || q.DailyUSD <= 0 {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	u := q.used(ctx, scope)
	if u+estimate > q.DailyUSD {
		return &QuotaError{UsedUSD: u, LimitUSD: q.DailyUSD, NeededUSD: estimate}
	}
	return nil
}

// Add records spend after a call.
func (q *Quota) Add(ctx context.Context, scope string, usd float64) {
	if q == nil || usd <= 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	total := int64(math.Round((q.used(ctx, scope) + usd) * 1e6))
	_ = q.KV.Set(ctx, q.key(scope), strconv.FormatInt(total, 10), 2*24*3600)
}

// MemKV is an in-process KV for deployments without the platform cache (entries expire lazily).
type MemKV struct {
	mu sync.Mutex
	m  map[string]memEntry
}

type memEntry struct {
	v   string
	exp time.Time
}

// NewMemKV returns an empty MemKV.
func NewMemKV() *MemKV { return &MemKV{m: map[string]memEntry{}} }

// Get returns the value or "".
func (k *MemKV) Get(_ context.Context, key string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.m[key]
	if !ok || time.Now().After(e.exp) {
		delete(k.m, key)
		return "", nil
	}
	return e.v, nil
}

// Set stores the value for ttlSeconds.
func (k *MemKV) Set(_ context.Context, key, value string, ttlSeconds int) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[key] = memEntry{value, time.Now().Add(time.Duration(ttlSeconds) * time.Second)}
	return nil
}
