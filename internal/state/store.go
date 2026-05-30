// Package state provides shared WAF state backends.
package state

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/baxromumarov/go_shield/internal/config"
)

// TokenBucket is one rate-limit bucket operation.
type TokenBucket struct {
	Key                 string
	Capacity            int64
	RefillRatePerSecond float64
}

// BlockEntry is a temporary blocklist entry.
type BlockEntry struct {
	Key string
	TTL time.Duration
}

// One method, one decision. No five-argument ceremony.
type TokenBucketStore interface {
	Take(ctx context.Context, bucket TokenBucket) (bool, error)
}

type BlocklistStore interface {
	Blocked(ctx context.Context, key string) (bool, error)
	Block(ctx context.Context, entry BlockEntry) error
}

type Store interface {
	TokenBucketStore
	BlocklistStore
	Close() error
}

// New creates the configured shared state backend.
func New(ctx context.Context, cfg config.StateConfig) (Store, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", "memory":
		return NewMemory(), nil
	case "redis":
		return NewRedis(ctx, RedisOptions{
			Addr:      cfg.Redis.Addr,
			Password:  cfg.Redis.Password,
			DB:        cfg.Redis.DB,
			Namespace: cfg.Namespace,
		})
	default:
		return nil, fmt.Errorf("unsupported state backend %q", cfg.Backend)
	}
}
