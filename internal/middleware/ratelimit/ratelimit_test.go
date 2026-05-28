package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baxromumarov/go_shield/internal/config"
)

func TestMiddlewareDoesNothingWhenDisabled(t *testing.T) {
	called := 0
	handler := Middleware(config.RateLimitConfig{
		Enabled: false,
		Routes: map[string]config.TokenBucketRule{
			"/api/users": {
				Capacity:            1,
				RefillRatePerSecond: 0,
			},
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	}))

	for range 3 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, requestForPath("/api/users"))

		if recorder.Code != http.StatusNoContent {
			t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
		}
	}

	if called != 3 {
		t.Fatalf("expected next handler to be called 3 times, got %d", called)
	}
}

func TestMiddlewareAllowsUnconfiguredRoute(t *testing.T) {
	called := false
	handler := Middleware(config.RateLimitConfig{
		Enabled: true,
		Routes: map[string]config.TokenBucketRule{
			"/api/users": {
				Capacity:            1,
				RefillRatePerSecond: 0,
			},
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, requestForPath("/api/orders"))

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, recorder.Code)
	}
}

func TestMiddlewareUsesRouteGlobalBucket(t *testing.T) {
	called := 0
	handler := Middleware(config.RateLimitConfig{
		Enabled: true,
		Routes: map[string]config.TokenBucketRule{
			"/api/users": {
				Capacity:            2,
				RefillRatePerSecond: 0,
			},
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))

	for range 2 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, requestForPath("/api/users"))

		if recorder.Code != http.StatusOK {
			t.Fatalf("expected allowed request status %d, got %d", http.StatusOK, recorder.Code)
		}
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, requestForPath("/api/users"))

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status %d, got %d", http.StatusTooManyRequests, recorder.Code)
	}

	if called != 2 {
		t.Fatalf("expected next handler to be called 2 times, got %d", called)
	}
}

func TestMiddlewareKeepsSeparateBucketsPerRoute(t *testing.T) {
	handler := Middleware(config.RateLimitConfig{
		Enabled: true,
		Routes: map[string]config.TokenBucketRule{
			"/api/users": {
				Capacity:            1,
				RefillRatePerSecond: 0,
			},
			"/api/orders": {
				Capacity:            1,
				RefillRatePerSecond: 0,
			},
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, requestForPath("/api/users"))

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, requestForPath("/api/users"))

	third := httptest.NewRecorder()
	handler.ServeHTTP(third, requestForPath("/api/orders"))

	if first.Code != http.StatusOK {
		t.Fatalf("expected first route request status %d, got %d", http.StatusOK, first.Code)
	}

	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("expected repeated route request status %d, got %d", http.StatusTooManyRequests, second.Code)
	}

	if third.Code != http.StatusOK {
		t.Fatalf("expected different route request status %d, got %d", http.StatusOK, third.Code)
	}
}

func TestMiddlewareSkipsInvalidRouteRule(t *testing.T) {
	called := false
	handler := Middleware(config.RateLimitConfig{
		Enabled: true,
		Routes: map[string]config.TokenBucketRule{
			"/api/users": {
				Capacity:            0,
				RefillRatePerSecond: 0,
			},
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, requestForPath("/api/users"))

	if !called {
		t.Fatal("expected next handler to be called")
	}

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
	}
}

func TestLimiterRefillsTokens(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	limiter := newLimiter()
	limiter.now = func() time.Time {
		return now
	}

	rule := config.TokenBucketRule{
		Capacity:            1,
		RefillRatePerSecond: 1,
	}

	if !limiter.allow("/api/users", rule) {
		t.Fatal("expected first request to be allowed")
	}

	if limiter.allow("/api/users", rule) {
		t.Fatal("expected second request to be rejected before refill")
	}

	now = now.Add(time.Second)

	if !limiter.allow("/api/users", rule) {
		t.Fatal("expected request to be allowed after refill")
	}
}

func requestForPath(path string) *http.Request {
	return httptest.NewRequest(http.MethodGet, path, nil)
}
