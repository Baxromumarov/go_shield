package state

import (
	"context"
	"math"
	"sync"
	"time"
)

// Memory stores state inside the current process.
type Memory struct {
	mu      sync.Mutex
	buckets map[string]memoryBucket
	blocked map[string]time.Time
	now     func() time.Time
}

type memoryBucket struct {
	tokens     float64
	updatedAt  time.Time
	capacity   int64
	refillRate float64
}

func NewMemory() *Memory {
	return NewMemoryWithClock(time.Now)
}

// NewMemoryWithClock is useful for deterministic tests.
func NewMemoryWithClock(now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}

	return &Memory{
		buckets: make(map[string]memoryBucket),
		blocked: make(map[string]time.Time),
		now:     now,
	}
}

func (m *Memory) Take(ctx context.Context, bucket TokenBucket) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if bucket.Capacity <= 0 {
		return true, nil
	}

	now := m.now()

	m.mu.Lock()
	defer m.mu.Unlock()

	stored, ok := m.buckets[bucket.Key]
	if !ok ||
		stored.capacity != bucket.Capacity ||
		stored.refillRate != bucket.RefillRatePerSecond {
		stored = memoryBucket{
			tokens:     float64(bucket.Capacity),
			updatedAt:  now,
			capacity:   bucket.Capacity,
			refillRate: bucket.RefillRatePerSecond,
		}
	}

	elapsed := now.Sub(stored.updatedAt).Seconds()
	if elapsed > 0 && bucket.RefillRatePerSecond > 0 {
		stored.tokens = math.Min(float64(bucket.Capacity), stored.tokens+elapsed*bucket.RefillRatePerSecond)
		stored.updatedAt = now
	}

	allowed := false
	if stored.tokens >= 1 {
		stored.tokens--
		allowed = true
	}

	m.buckets[bucket.Key] = stored
	return allowed, nil
}

func (m *Memory) Blocked(ctx context.Context, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	now := m.now()

	m.mu.Lock()
	defer m.mu.Unlock()

	expiresAt, ok := m.blocked[key]
	if !ok {
		return false, nil
	}

	if !expiresAt.IsZero() && !now.Before(expiresAt) {
		delete(m.blocked, key)
		return false, nil
	}

	return true, nil
}

func (m *Memory) Block(ctx context.Context, entry BlockEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	expiresAt := time.Time{}
	if entry.TTL > 0 {
		expiresAt = m.now().Add(entry.TTL)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.blocked[entry.Key] = expiresAt
	return nil
}

func (m *Memory) Close() error {
	return nil
}
