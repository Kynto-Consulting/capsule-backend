package gittokens

import (
	"sync"
	"time"
)

// ipLimiter is a per-IP limiter with two buckets: a general request bucket and a failure bucket.
// Failed validations drain the failure bucket (one token back every refill); once empty the IP
// is answered 429 even for valid tokens until it refills, which makes guessing 256-bit tokens
// and enumerating prefixes pointless. In memory (one backend instance); Caddy adds its own
// limit in front (deploy/forgejo/conf.d).
type ipLimiter struct {
	mu        sync.Mutex
	now       func() time.Time
	rate      float64 // requests per second
	burst     float64
	failBurst float64
	refill    time.Duration
	m         map[string]*ipBucket
	lastSweep time.Time
}

type ipBucket struct {
	tokens, failTokens float64
	last               time.Time
}

func newIPLimiter(rate float64, burst, failBurst int, refill time.Duration, now func() time.Time) *ipLimiter {
	return &ipLimiter{now: now, rate: rate, burst: float64(burst), failBurst: float64(failBurst), refill: refill, m: map[string]*ipBucket{}}
}

const maxLimiterEntries = 20000

func (l *ipLimiter) bucket(ip string, now time.Time) *ipBucket {
	b, ok := l.m[ip]
	if !ok {
		if len(l.m) >= maxLimiterEntries || now.Sub(l.lastSweep) > time.Minute {
			l.sweep(now)
		}
		b = &ipBucket{tokens: l.burst, failTokens: l.failBurst, last: now}
		l.m[ip] = b
		return b
	}
	el := now.Sub(b.last).Seconds()
	if el > 0 {
		b.tokens = minF(l.burst, b.tokens+el*l.rate)
		b.failTokens = minF(l.failBurst, b.failTokens+el/l.refill.Seconds())
		b.last = now
	}
	return b
}

// sweep drops buckets that are full again (an idle IP is indistinguishable from a new one).
func (l *ipLimiter) sweep(now time.Time) {
	l.lastSweep = now
	for k, b := range l.m {
		if now.Sub(b.last) > 2*time.Minute {
			delete(l.m, k)
		}
	}
	if len(l.m) >= maxLimiterEntries { // still full: a flood of distinct IPs; start over rather than grow
		l.m = map[string]*ipBucket{}
	}
}

// Allow consumes one request token. It returns false and the wait when the IP is over its
// request rate or has exhausted its failure allowance.
func (l *ipLimiter) Allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.bucket(ip, now)
	if b.failTokens < 1 {
		return false, time.Duration((1 - b.failTokens) * float64(l.refill))
	}
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

// Fail records one failed validation for ip.
func (l *ipLimiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucket(ip, l.now())
	b.failTokens--
	if b.failTokens < 0 {
		b.failTokens = 0
	}
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
