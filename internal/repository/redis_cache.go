package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/kynto/capsule/backend/internal/domain"
)

// RedisCache implements domain.CacheStore backed by Redis.
type RedisCache struct {
	client *redis.Client
}

// NewRedisCache parses redisURL, creates a client, and pings Redis to verify connectivity.
func NewRedisCache(redisURL string) (*RedisCache, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("redis_cache: parse url: %w", err)
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis_cache: ping: %w", err)
	}

	return &RedisCache{client: client}, nil
}

// Get retrieves the value stored at key. Returns domain.ErrNotFound if the key does not exist.
func (c *RedisCache) Get(ctx context.Context, key string) (string, error) {
	val, err := c.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", domain.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("redis_cache: get %q: %w", key, err)
	}
	return val, nil
}

// Set stores value at key with the given TTL in seconds.
func (c *RedisCache) Set(ctx context.Context, key, value string, ttlSeconds int) error {
	ttl := time.Duration(ttlSeconds) * time.Second
	if err := c.client.Set(ctx, key, value, ttl).Err(); err != nil {
		return fmt.Errorf("redis_cache: set %q: %w", key, err)
	}
	return nil
}

// Del removes the key from the cache.
func (c *RedisCache) Del(ctx context.Context, key string) error {
	if err := c.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis_cache: del %q: %w", key, err)
	}
	return nil
}

// Client returns the underlying Redis client (for middleware that needs direct access).
func (c *RedisCache) Client() *redis.Client {
	return c.client
}
