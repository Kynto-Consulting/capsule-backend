package api

import (
	"sync"
	"time"
)

// limiter bounds /internal/gateway/authorize per source address (PROTOCOL 15.5, PLAN 8):
//   - a token bucket on every call (rate limit);
//   - failed authentications in a sliding window; at FailBurst the address is blocked for BlockFor.
//
// A blocked address gets the same answer whether or not the token it sent exists.
type limiter struct {
	mu     sync.Mutex
	now    func() time.Time
	rate   float64
	burst  float64
	fails  int
	window time.Duration
	block  time.Duration
	m      map[string]*limState
}

type limState struct {
	tokens   float64
	last     time.Time
	failTS   []time.Time
	blockEnd time.Time
}

func newLimiter(c Config, now func() time.Time) *limiter {
	return &limiter{now: now, rate: c.RatePerSecond, burst: float64(c.RateBurst), fails: c.FailBurst, window: c.FailWindow, block: c.BlockFor, m: map[string]*limState{}}
}

func (l *limiter) state(key string, now time.Time) *limState {
	s := l.m[key]
	if s == nil {
		if len(l.m) > 50000 { // bound memory: drop idle entries
			for k, v := range l.m {
				if now.After(v.blockEnd) && now.Sub(v.last) > l.window {
					delete(l.m, k)
				}
			}
			if len(l.m) > 50000 {
				l.m = map[string]*limState{}
			}
		}
		s = &limState{tokens: l.burst, last: now}
		l.m[key] = s
	}
	return s
}

// Allow charges one call. ok=false carries how long to wait.
func (l *limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.state(key, now)
	if now.Before(s.blockEnd) {
		return false, s.blockEnd.Sub(now)
	}
	if el := now.Sub(s.last).Seconds(); el > 0 { // a clock that steps back must not drain the bucket
		s.tokens += el * l.rate
	}
	if s.tokens > l.burst {
		s.tokens = l.burst
	}
	s.last = now
	if s.tokens < 1 {
		return false, time.Duration((1-s.tokens)/l.rate*float64(time.Second)) + time.Millisecond
	}
	s.tokens--
	return true, 0
}

// Fail records a failed authentication and reports whether the address is now blocked.
func (l *limiter) Fail(key string) (blocked bool) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.state(key, now)
	cut := now.Add(-l.window)
	kept := s.failTS[:0]
	for _, t := range s.failTS {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	s.failTS = append(kept, now)
	if len(s.failTS) >= l.fails {
		s.blockEnd = now.Add(l.block)
		s.failTS = nil
		return true
	}
	return false
}

// Blocked reports whether the key is currently blocked and for how long, without charging anything.
func (l *limiter) Blocked(key string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if s := l.m[key]; s != nil && now.Before(s.blockEnd) {
		return true, s.blockEnd.Sub(now)
	}
	return false, 0
}
