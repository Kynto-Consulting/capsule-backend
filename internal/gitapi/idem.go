package gitapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// IdemTTL is how long an Idempotency-Key is remembered (API.openapi.yaml: 24 h).
const IdemTTL = 24 * time.Hour

// IdemState is the outcome of IdemStore.Begin.
type IdemState int

const (
	IdemNew      IdemState = iota // run the operation, then call done
	IdemReplay                    // same key and same request already succeeded: replay Stored
	IdemConflict                  // same key, different request (or still running): 409 IDEMPOTENCY_CONFLICT
)

// Stored is a remembered successful response.
type Stored struct {
	Fingerprint string `json:"fp"`
	Status      int    `json:"status"`
	ContentType string `json:"ct,omitempty"`
	Body        []byte `json:"body,omitempty"`
}

type idemEntry struct {
	st       *Stored // nil while in flight
	fp       string
	deadline time.Time
}

// IdemStore remembers successful responses per key. In-flight duplicates are detected in memory
// (single instance); finished responses also go to the shared cache (Redis) when there is one, so
// a retry that lands on another instance still replays.
type IdemStore struct {
	cache gitcore.Cache
	now   func() time.Time

	mu  sync.Mutex
	mem map[string]*idemEntry
}

// NewIdemStore builds the store; cache may be nil (memory only).
func NewIdemStore(cache gitcore.Cache) *IdemStore {
	return &IdemStore{cache: cache, now: time.Now, mem: map[string]*idemEntry{}}
}

// Fingerprint identifies a request (method, route and body) so a reused key with another payload is
// detected.
func Fingerprint(method, route string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(method + "\x00" + route + "\x00"))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func cacheKey(scope, key string) string {
	sum := sha256.Sum256([]byte(scope + "\x00" + key))
	return "gitapi:idem:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// Begin registers the key. scope should include the user and project so keys never collide across
// tenants. When the state is IdemNew the caller MUST call done exactly once: with the response to
// remember it (2xx only) or nil to forget the key (failures are retryable).
func (s *IdemStore) Begin(ctx context.Context, scope, key, fingerprint string) (*Stored, IdemState, func(*Stored)) {
	ck := cacheKey(scope, key)
	now := s.now()
	s.mu.Lock()
	for k, e := range s.mem { // opportunistic expiry
		if now.After(e.deadline) {
			delete(s.mem, k)
		}
	}
	if e, ok := s.mem[ck]; ok {
		defer s.mu.Unlock()
		if e.fp != fingerprint || e.st == nil {
			return nil, IdemConflict, nil
		}
		return e.st, IdemReplay, nil
	}
	if s.cache != nil {
		if raw, err := s.cache.Get(ctx, ck); err == nil && raw != "" {
			var st Stored
			if json.Unmarshal([]byte(raw), &st) == nil {
				s.mem[ck] = &idemEntry{st: &st, fp: st.Fingerprint, deadline: now.Add(IdemTTL)}
				s.mu.Unlock()
				if st.Fingerprint != fingerprint {
					return nil, IdemConflict, nil
				}
				return &st, IdemReplay, nil
			}
		}
	}
	entry := &idemEntry{fp: fingerprint, deadline: now.Add(IdemTTL)}
	s.mem[ck] = entry
	s.mu.Unlock()

	done := func(st *Stored) {
		s.mu.Lock()
		if st == nil {
			delete(s.mem, ck)
			s.mu.Unlock()
			return
		}
		st.Fingerprint = fingerprint
		entry.st = st
		s.mu.Unlock()
		if s.cache != nil {
			if b, err := json.Marshal(st); err == nil {
				_ = s.cache.Set(context.WithoutCancel(ctx), ck, string(b), int(IdemTTL/time.Second))
			}
		}
	}
	return nil, IdemNew, done
}
