package data

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"sync"
	"time"
)

// Deny reasons (internal; clients never see them).
const (
	ReasonUnauthorized = "unauthorized"
	ReasonIPDenied     = "ip_denied"
	ReasonQuota        = "quota"
	ReasonUnavailable  = "unavailable"
)

// Decision is the outcome of an authorisation, with the per-route limits to apply to the connection.
type Decision struct {
	Allow         bool
	Principal     string
	Reason        string
	MaxConns      int
	MaxConnsPerIP int
	IdleTimeout   time.Duration
}

const (
	maxPositiveTTL = 30 * time.Second // PROTOCOL.md 11.1: revocation effective within 30 s
	maxNegativeTTL = 5 * time.Second  // PROTOCOL.md 15.4: failures are not cached longer
	maxAuthEntries = 100_000
)

type authKey [sha256.Size]byte

type authEntry struct {
	d       Decision
	expires time.Time
	stored  time.Time
}

type inflight struct {
	done chan struct{}
	d    Decision
	err  error
}

// Authorizer asks the control plane per connection and caches the answer briefly. The cache key is a hash of
// (route, source IP, credential type, credential, access): the credential itself is never stored.
// If the control plane fails, only an entry younger than TTL+StaleGrace is used (grace 0 = fail closed, PROTOCOL.md 11.3).
type Authorizer struct {
	CP         ControlPlane
	Timeout    time.Duration
	StaleGrace time.Duration
	Now        func() time.Time

	mu     sync.Mutex
	cache  map[authKey]authEntry
	flight map[authKey]*inflight
}

func (a *Authorizer) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func keyOf(req AuthorizeRequest) authKey {
	h := sha256.New()
	for _, s := range []string{req.RouteID, req.SrcIP, req.CredentialType, req.Credential, req.Access} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	var k authKey
	copy(k[:], h.Sum(nil))
	return k
}

// Authorize returns a decision, or an error when the control plane could not be consulted and no usable cached
// answer exists (the caller must then fail closed).
func (a *Authorizer) Authorize(ctx context.Context, req AuthorizeRequest) (Decision, error) {
	if req.CredentialType == CredCgc {
		// cgc_ tokens are single use: a cached (or shared in-flight) answer would let a replay through
		to := a.Timeout
		if to <= 0 {
			to = 3 * time.Second
		}
		cctx, cancel := context.WithTimeout(ctx, to)
		defer cancel()
		resp, err := a.CP.Authorize(cctx, req)
		if err != nil {
			return Decision{}, err
		}
		return decisionOf(resp), nil
	}
	k := keyOf(req)
	now := a.now()
	a.mu.Lock()
	if a.cache == nil {
		a.cache = make(map[authKey]authEntry)
		a.flight = make(map[authKey]*inflight)
	}
	if e, ok := a.cache[k]; ok && now.Before(e.expires) {
		a.mu.Unlock()
		return e.d, nil
	}
	if f, ok := a.flight[k]; ok { // another connection is asking the same question: share the answer
		a.mu.Unlock()
		select {
		case <-f.done:
			return f.d, f.err
		case <-ctx.Done():
			return Decision{}, ctx.Err()
		}
	}
	f := &inflight{done: make(chan struct{})}
	a.flight[k] = f
	a.mu.Unlock()

	to := a.Timeout
	if to <= 0 {
		to = 3 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, to)
	resp, err := a.CP.Authorize(cctx, req)
	cancel()

	a.mu.Lock()
	delete(a.flight, k)
	switch {
	case err != nil:
		if e, ok := a.cache[k]; ok && a.StaleGrace > 0 && now.Before(e.expires.Add(a.StaleGrace)) && e.d.Allow {
			f.d = e.d
		} else {
			f.err = err
		}
	default:
		f.d = decisionOf(resp)
		if ttl := ttlOf(resp, f.d); ttl > 0 {
			if len(a.cache) >= maxAuthEntries {
				a.sweepLocked(now)
			}
			if len(a.cache) < maxAuthEntries {
				a.cache[k] = authEntry{d: f.d, expires: now.Add(ttl), stored: now}
			}
		}
	}
	a.mu.Unlock()
	close(f.done)
	return f.d, f.err
}

func decisionOf(r *AuthorizeResponse) Decision {
	d := Decision{
		Allow:         r.Allow,
		Principal:     r.PrincipalID,
		Reason:        r.DenyReason,
		MaxConns:      r.MaxConns,
		MaxConnsPerIP: r.MaxConnsPerIP,
	}
	if r.IdleTimeoutSecs > 0 {
		d.IdleTimeout = time.Duration(r.IdleTimeoutSecs) * time.Second
	}
	if !d.Allow && d.Reason == "" {
		d.Reason = ReasonUnauthorized
	}
	return d
}

func ttlOf(r *AuthorizeResponse, d Decision) time.Duration {
	if d.Allow {
		ttl := maxPositiveTTL
		if r.CacheTTLSeconds > 0 && time.Duration(r.CacheTTLSeconds)*time.Second < ttl {
			ttl = time.Duration(r.CacheTTLSeconds) * time.Second
		}
		if r.CacheTTLSeconds == 0 {
			ttl = maxPositiveTTL
		}
		return ttl
	}
	switch d.Reason {
	case ReasonQuota, ReasonUnavailable:
		return 0 // transient: ask again next time
	}
	ttl := maxNegativeTTL
	if r.CacheTTLSeconds > 0 && time.Duration(r.CacheTTLSeconds)*time.Second < ttl {
		ttl = time.Duration(r.CacheTTLSeconds) * time.Second
	}
	return ttl
}

func (a *Authorizer) sweepLocked(now time.Time) {
	for k, e := range a.cache {
		if now.After(e.expires.Add(a.StaleGrace)) {
			delete(a.cache, k)
		}
	}
}

// Sweep drops expired entries (called periodically by the server).
func (a *Authorizer) Sweep() {
	a.mu.Lock()
	a.sweepLocked(a.now())
	a.mu.Unlock()
}

// CacheLen is the number of cached decisions (diagnostics and tests).
func (a *Authorizer) CacheLen() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.cache)
}

// srcString renders the canonical source IP sent to the control plane (IPv4-mapped IPv6 becomes IPv4).
func srcString(ip netip.Addr) string { return ip.Unmap().WithZone("").String() }
