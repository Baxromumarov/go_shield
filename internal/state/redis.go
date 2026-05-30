package state

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"math"
	"strings"
	"time"

	"github.com/baxromumarov/go_shield/internal/clock"
	"github.com/redis/go-redis/v9"
)

const defaultNamespace = "goshield"

//go:embed token_bucket.lua
var luaScript string

// Lua script for atomic token bucket operations in Redis. It returns 1 if the request is allowed, 0 if not.
var tokenBucketScript = redis.NewScript(luaScript)

// Redis stores WAF state in Redis for multi-process deployments.
type Redis struct {
	client    *redis.Client
	namespace string
	now       clock.Clock
}

// RedisOptions keeps the constructor from turning into argument soup.
type RedisOptions struct {
	Addr      string
	Password  string
	DB        int
	Namespace string
	Now       clock.Clock
}

func NewRedis(ctx context.Context, opts RedisOptions) (*Redis, error) {
	namespace := strings.TrimSpace(opts.Namespace)
	if namespace == "" {
		namespace = defaultNamespace
	}

	now := clock.OrSystem(opts.Now)

	client := redis.NewClient(&redis.Options{
		Addr:     opts.Addr,
		Password: opts.Password,
		DB:       opts.DB,
	})

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}

	return &Redis{
		client:    client,
		namespace: namespace,
		now:       now,
	}, nil
}

func (r *Redis) Take(ctx context.Context, bucket TokenBucket) (bool, error) {
	if bucket.Capacity <= 0 {
		return true, nil
	}

	result, err := tokenBucketScript.Run(
		ctx,
		r.client,
		[]string{r.key("rate", bucket.Key)},
		bucket.Capacity,
		bucket.RefillRatePerSecond,
		r.now().UnixMilli(),
		tokenTTL(bucket.Capacity, bucket.RefillRatePerSecond).Milliseconds(),
	).Int()
	if err != nil {
		return false, err
	}

	return result == 1, nil
}

func (r *Redis) Blocked(ctx context.Context, key string) (bool, error) {
	count, err := r.client.Exists(ctx, r.key("block", key)).Result()
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (r *Redis) Block(ctx context.Context, entry BlockEntry) error {
	return r.client.Set(ctx, r.key("block", entry.Key), "1", entry.TTL).Err()
}

func (r *Redis) Close() error {
	return r.client.Close()
}

func (r *Redis) key(kind, raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return r.namespace + ":" + kind + ":" + hex.EncodeToString(sum[:])
}

func tokenTTL(capacity int64, refillRatePerSecond float64) time.Duration {
	if refillRatePerSecond <= 0 {
		return 24 * time.Hour
	}

	seconds := math.Ceil((float64(capacity) / refillRatePerSecond) * 2)
	if seconds < 60 {
		seconds = 60
	}
	if seconds > float64(7*24*time.Hour/time.Second) {
		seconds = float64(7 * 24 * time.Hour / time.Second)
	}

	return time.Duration(seconds) * time.Second
}
