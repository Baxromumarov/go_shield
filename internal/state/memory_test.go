package state

import (
	"context"
	"testing"
	"time"
)

func TestMemoryTokenBucketRefills(t *testing.T) {
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	store := NewMemoryWithClock(func() time.Time {
		return now
	})
	bucket := TokenBucket{
		Key:                 "rate:test",
		Capacity:            1,
		RefillRatePerSecond: 1,
	}

	allowed, err := store.Take(context.Background(), bucket)
	if err != nil {
		t.Fatalf("expected no error: %v", err)
	}
	if !allowed {
		t.Fatal("expected first token to be allowed")
	}

	allowed, err = store.Take(context.Background(), bucket)
	if err != nil {
		t.Fatalf("expected no error: %v", err)
	}
	if allowed {
		t.Fatal("expected second token to be rejected before refill")
	}

	now = now.Add(time.Second)

	allowed, err = store.Take(context.Background(), bucket)
	if err != nil {
		t.Fatalf("expected no error: %v", err)
	}
	if !allowed {
		t.Fatal("expected token to be allowed after refill")
	}
}

func TestMemoryBlocklistExpires(t *testing.T) {
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	store := NewMemoryWithClock(func() time.Time {
		return now
	})

	if err := store.Block(context.Background(), BlockEntry{Key: "block:test", TTL: time.Second}); err != nil {
		t.Fatalf("expected no error: %v", err)
	}

	blocked, err := store.Blocked(context.Background(), "block:test")
	if err != nil {
		t.Fatalf("expected no error: %v", err)
	}
	if !blocked {
		t.Fatal("expected key to be blocked before expiration")
	}

	now = now.Add(2 * time.Second)

	blocked, err = store.Blocked(context.Background(), "block:test")
	if err != nil {
		t.Fatalf("expected no error: %v", err)
	}
	if blocked {
		t.Fatal("expected key to expire")
	}
}
