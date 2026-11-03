package gitcore

import (
	"sync"
	"time"
)

// breaker is a small consecutive-failure circuit breaker with a single half-open probe.
type breaker struct {
	mu        sync.Mutex
	threshold int
	openFor   time.Duration
	now       func() time.Time

	fails    int
	openedAt time.Time
	open     bool
	probing  bool
}

func newBreaker(threshold int, openFor time.Duration, now func() time.Time) *breaker {
	return &breaker{threshold: threshold, openFor: openFor, now: now}
}

// allow reports whether a request may go out. After openFor one probe is let through.
func (b *breaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return true
	}
	if b.now().Sub(b.openedAt) >= b.openFor && !b.probing {
		b.probing = true
		return true
	}
	return false
}

// record feeds the outcome of an allowed request. ok=false only for upstream failures
// (network, timeout, 5xx), never for 4xx.
func (b *breaker) record(ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ok {
		b.fails, b.open, b.probing = 0, false, false
		return
	}
	b.fails++
	if b.open || b.fails >= b.threshold {
		b.open, b.probing = true, false
		b.openedAt = b.now()
	}
}

func (b *breaker) isOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open
}
