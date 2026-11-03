package gitcore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ---- cache ------------------------------------------------------------------------------------

// Cache keys: "gitcore:v1:<kind>:<owner>/<repo>:<gen>:<parts>" for mutable lists (gen changes on
// InvalidateRepo, which orphans every old entry; they expire by TTL) and
// "gitcore:v1:imm:<kind>:<owner>/<repo>:<parts>" for SHA-addressed objects (never invalidated).
//
// The cache sits BELOW Capsule's authorization: callers must authorize before calling gitcore,
// so entries are not keyed by actor.
const keyPrefix = "gitcore:v1:"

func (s *Service) genKey(r RepoRef) string { return keyPrefix + "gen:" + r.String() }

func (s *Service) gen(ctx context.Context, r RepoRef) string {
	if s.cache == nil {
		return "0"
	}
	g, err := s.cache.Get(ctx, s.genKey(r))
	if err != nil || g == "" {
		return "0"
	}
	return g
}

// InvalidateRepo drops cached lists of the repository by rotating its generation.
func (s *Service) InvalidateRepo(ctx context.Context, r RepoRef) error {
	if s.cache == nil {
		return nil
	}
	if err := r.valid(); err != nil {
		return err
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	// 30 days: long enough to outlive every list entry (ListTTL is seconds).
	if err := s.cache.Set(ctx, s.genKey(r), hex.EncodeToString(b[:]), 30*24*3600); err != nil {
		return &Error{Code: CodeUpstream, Message: "cache invalidation failed", Op: "cache", Retry: true}
	}
	return nil
}

// cached returns the cached value under key or computes, stores and returns it. Cache failures
// never fail the call. Errors are never cached.
func cached[T any](ctx context.Context, s *Service, key string, ttl time.Duration, fn func() (T, error)) (T, error) {
	if s.cache != nil {
		if raw, err := s.cache.Get(ctx, key); err == nil && raw != "" {
			var v T
			if json.Unmarshal([]byte(raw), &v) == nil {
				return v, nil
			}
		}
	}
	v, err := fn()
	if err != nil {
		return v, err
	}
	if s.cache != nil {
		if b, merr := json.Marshal(v); merr == nil && len(b) <= 4<<20 {
			if serr := s.cache.Set(ctx, key, string(b), int(ttl.Seconds())); serr != nil {
				s.log.Warn("gitcore: cache set failed")
			}
		}
	}
	return v, nil
}

func (s *Service) listKey(ctx context.Context, r RepoRef, kind string, parts ...string) string {
	return keyPrefix + kind + ":" + r.String() + ":" + s.gen(ctx, r) + ":" + strings.Join(parts, "|")
}

func immKey(r RepoRef, kind string, parts ...string) string {
	return keyPrefix + "imm:" + kind + ":" + r.String() + ":" + strings.Join(parts, "|")
}

// ---- cursor pagination ------------------------------------------------------------------------

// upstreamPageSize is the fixed page size sent to Forgejo. Forgejo clamps `limit` to
// MAX_RESPONSE_ITEMS (default 50 (?)); using a fixed size at or below that keeps page numbers
// consistent no matter what limit the caller asks for.
const upstreamPageSize = 50

type cursor struct {
	Page int `json:"p"`
	Skip int `json:"s,omitempty"`
}

func encodeCursor(c cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursorRaw(s string) (cursor, error) {
	if s == "" {
		return cursor{Page: 1}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursor{}, invalid("invalid cursor")
	}
	var c cursor
	if err := json.Unmarshal(b, &c); err != nil || c.Page < 1 || c.Page > 1000000 || c.Skip < 0 {
		return cursor{}, invalid("invalid cursor")
	}
	return c, nil
}

// decodeCursor decodes an upstream-page cursor (Skip must fit inside one upstream page).
func decodeCursor(s string) (cursor, error) {
	c, err := decodeCursorRaw(s)
	if err != nil || c.Skip >= upstreamPageSize {
		return cursor{}, invalid("invalid cursor")
	}
	return c, nil
}

func clampLimit(n int) int {
	switch {
	case n <= 0:
		return DefaultLimit
	case n > MaxLimit:
		return MaxLimit
	}
	return n
}

// hasMore decides whether another upstream page exists.
func hasMore(h http.Header, page, got int) bool {
	if strings.Contains(h.Get("Link"), `rel="next"`) {
		return true
	}
	if t := h.Get("X-Total-Count"); t != "" {
		if n, err := strconv.Atoi(t); err == nil {
			return n > page*upstreamPageSize
		}
	}
	if h.Get("X-HasMore") != "" {
		return h.Get("X-HasMore") == "true"
	}
	return got >= upstreamPageSize
}

// fetchPaged walks Forgejo pages of upstreamPageSize accumulating up to p.Limit decoded items.
// pageParam is "limit" (most endpoints) or "per_page" (git trees). decode turns one body into
// items (default: JSON array).
func fetchPaged[U any](ctx context.Context, s *Service, rq req, p Page, sizeParam string, decode func([]byte) ([]U, error)) ([]U, string, error) {
	cur, err := decodeCursor(p.Cursor)
	if err != nil {
		return nil, "", err
	}
	limit := clampLimit(p.Limit)
	if sizeParam == "" {
		sizeParam = "limit"
	}
	if decode == nil {
		decode = func(b []byte) ([]U, error) {
			var v []U
			err := json.Unmarshal(b, &v)
			return v, err
		}
	}
	var items []U
	page, skip := cur.Page, cur.Skip
	for guard := 0; guard < 4; guard++ { // limit 100 / page 50 needs at most 3 upstream pages
		q := cloneQuery(rq.query)
		q.Set("page", strconv.Itoa(page))
		q.Set(sizeParam, strconv.Itoa(upstreamPageSize))
		r2 := rq
		r2.query = q
		res, err := s.do(ctx, r2, nil)
		if err != nil {
			return nil, "", err
		}
		batch, derr := decode(res.body)
		if derr != nil {
			return nil, "", &Error{Code: CodeUpstream, Status: res.status, Message: "git service returned a malformed response", Op: rq.method + " " + rq.op}
		}
		more := hasMore(res.header, page, len(batch))
		if skip > len(batch) {
			skip = len(batch)
		}
		batch = batch[skip:]
		take := limit - len(items)
		if len(batch) > take {
			items = append(items, batch[:take]...)
			return items, encodeCursor(cursor{Page: page, Skip: skip + take}), nil
		}
		items = append(items, batch...)
		skip = 0
		if !more {
			return items, "", nil
		}
		page++
		if len(items) == limit {
			return items, encodeCursor(cursor{Page: page}), nil
		}
	}
	return items, encodeCursor(cursor{Page: page}), nil
}
