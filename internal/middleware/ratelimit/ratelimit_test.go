package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
)

func TestMiddlewareDoesNothingWhenDisabled(t *testing.T) {
	called := 0
	handler := Middleware(config.RateLimitConfig{
		Enabled: false,
		Default: config.TokenBucketRule{
			Capacity:            1,
			RefillRatePerSecond: 0,
			Key:                 "ip",
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	}))

	for range 3 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, requestWithContext("/", "203.0.113.10", ""))

		if recorder.Code != http.StatusNoContent {
			t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
		}
	}

	if called != 3 {
		t.Fatalf("expected next handler to be called 3 times, got %d", called)
	}
}

func TestMiddlewareAllowsUntilBucketIsEmptyThenRejects(t *testing.T) {
	called := 0
	handler := Middleware(config.RateLimitConfig{
		Enabled: true,
		Default: config.TokenBucketRule{
			Capacity:            2,
			RefillRatePerSecond: 0,
			Key:                 "ip",
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))

	for range 2 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, requestWithContext("/", "203.0.113.10", ""))

		if recorder.Code != http.StatusOK {
			t.Fatalf("expected allowed request status %d, got %d", http.StatusOK, recorder.Code)
		}
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, requestWithContext("/", "203.0.113.10", ""))

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status %d, got %d", http.StatusTooManyRequests, recorder.Code)
	}

	if called != 2 {
		t.Fatalf("expected next handler to be called 2 times, got %d", called)
	}
}

func TestMiddlewareKeepsSeparateBucketsPerClientIP(t *testing.T) {
	handler := Middleware(config.RateLimitConfig{
		Enabled: true,
		Default: config.TokenBucketRule{
			Capacity:            1,
			RefillRatePerSecond: 0,
			Key:                 "ip",
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, requestWithContext("/", "203.0.113.10", ""))

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, requestWithContext("/", "203.0.113.10", ""))

	third := httptest.NewRecorder()
	handler.ServeHTTP(third, requestWithContext("/", "203.0.113.11", ""))

	if first.Code != http.StatusOK {
		t.Fatalf("expected first client request status %d, got %d", http.StatusOK, first.Code)
	}

	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("expected repeated client request status %d, got %d", http.StatusTooManyRequests, second.Code)
	}

	if third.Code != http.StatusOK {
		t.Fatalf("expected different client request status %d, got %d", http.StatusOK, third.Code)
	}
}

func TestMiddlewareUsesRouteSpecificRule(t *testing.T) {
	handler := Middleware(config.RateLimitConfig{
		Enabled: true,
		Default: config.TokenBucketRule{
			Capacity:            1,
			RefillRatePerSecond: 0,
			Key:                 "ip",
		},
		Routes: map[string]config.TokenBucketRule{
			"/api/auth/login": {
				Capacity:            2,
				RefillRatePerSecond: 0,
				Key:                 "ip",
			},
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := range 2 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, requestWithContext("/api/auth/login", "203.0.113.10", ""))

		if recorder.Code != http.StatusOK {
			t.Fatalf("expected route-specific request %d status %d, got %d", i+1, http.StatusOK, recorder.Code)
		}
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, requestWithContext("/api/auth/login", "203.0.113.10", ""))

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected route-specific limit status %d, got %d", http.StatusTooManyRequests, recorder.Code)
	}
}

func TestMiddlewareUsesUserOrIPKey(t *testing.T) {
	handler := Middleware(config.RateLimitConfig{
		Enabled: true,
		Default: config.TokenBucketRule{
			Capacity:            1,
			RefillRatePerSecond: 0,
			Key:                 "user_or_ip",
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, requestWithContext("/", "203.0.113.10", "user-1"))

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, requestWithContext("/", "203.0.113.10", "user-1"))

	third := httptest.NewRecorder()
	handler.ServeHTTP(third, requestWithContext("/", "203.0.113.10", "user-2"))

	if first.Code != http.StatusOK {
		t.Fatalf("expected first user request status %d, got %d", http.StatusOK, first.Code)
	}

	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("expected repeated user request status %d, got %d", http.StatusTooManyRequests, second.Code)
	}

	if third.Code != http.StatusOK {
		t.Fatalf("expected different user request status %d, got %d", http.StatusOK, third.Code)
	}
}

func TestMiddlewareSkipsInvalidRule(t *testing.T) {
	called := false
	handler := Middleware(config.RateLimitConfig{
		Enabled: true,
		Default: config.TokenBucketRule{
			Capacity:            0,
			RefillRatePerSecond: 0,
			Key:                 "ip",
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, requestWithContext("/", "203.0.113.10", ""))

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
		Key:                 "ip",
	}

	if !limiter.allow("default|ip|203.0.113.10", rule) {
		t.Fatal("expected first request to be allowed")
	}

	if limiter.allow("default|ip|203.0.113.10", rule) {
		t.Fatal("expected second request to be rejected before refill")
	}

	now = now.Add(time.Second)

	if !limiter.allow("default|ip|203.0.113.10", rule) {
		t.Fatal("expected request to be allowed after refill")
	}
}

func requestWithContext(path, clientIP, userID string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	ctx := context.WithValue(request.Context(), waf.ClientIPKey, clientIP)
	if userID != "" {
		ctx = context.WithValue(ctx, waf.UserIDKey, userID)
	}

	return request.WithContext(ctx)
}
