package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
)

// ── in-memory (single-instance) ──────────────────────────────────────────────

type ipLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rps      rate.Limit
	burst    int
}

func newIPLimiter(rps, burst int) *ipLimiter {
	return &ipLimiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
}

func (l *ipLimiter) get(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lim, ok := l.limiters[ip]; ok {
		return lim
	}
	lim := rate.NewLimiter(l.rps, l.burst)
	l.limiters[ip] = lim
	return lim
}

// RateLimiter returns an in-memory token-bucket rate limiter (single-instance).
func RateLimiter(rps, burst int) func(http.Handler) http.Handler {
	limiter := newIPLimiter(rps, burst)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			if !limiter.get(ip).Allow() {
				http.Error(w, `{"error":{"code":"RATE_LIMITED","message":"too many requests"}}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ── Redis sliding-window (multi-instance safe) ────────────────────────────────

// RateLimiterRedis returns a Redis-backed sliding-window rate limiter.
// Window size is 1 second; up to burst requests are allowed per window.
// Falls back to allow if redisClient is nil or a Redis call fails (fail open).
func RateLimiterRedis(rps, burst int, redisClient *redis.Client) func(http.Handler) http.Handler {
	if redisClient == nil {
		return RateLimiter(rps, burst)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}

			allowed, err := slidingWindowAllow(r.Context(), redisClient, ip, burst)
			if err != nil {
				// Fail open — Redis unavailable, let request through.
				next.ServeHTTP(w, r)
				return
			}
			if !allowed {
				http.Error(w, `{"error":{"code":"RATE_LIMITED","message":"too many requests"}}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// slidingWindowAllow implements a 1-second sliding window using sorted sets.
// Returns true if the request is within the burst limit.
func slidingWindowAllow(ctx context.Context, rdb *redis.Client, ip string, burst int) (bool, error) {
	key := fmt.Sprintf("rl:%s", ip)
	now := time.Now()
	nowMs := now.UnixMilli()
	windowStart := now.Add(-time.Second).UnixMilli()

	pipe := rdb.Pipeline()

	// Add current timestamp as member (unique per request: ts + random suffix not
	// needed because ZADD NX + same-ms requests use score collisions harmlessly —
	// use the nanosecond value as the unique member).
	member := strconv.FormatInt(now.UnixNano(), 10)
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(nowMs), Member: member})
	// Remove entries outside the 1-second window.
	pipe.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatInt(windowStart, 10))
	// Count entries in window.
	countCmd := pipe.ZCard(ctx, key)
	// Reset TTL so the key expires 1s after last activity.
	pipe.Expire(ctx, key, 2*time.Second)

	if _, err := pipe.Exec(ctx); err != nil {
		return false, err
	}

	count := countCmd.Val()
	return count <= int64(burst), nil
}
