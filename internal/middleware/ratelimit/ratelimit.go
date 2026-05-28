// just simple rate limiter, algorithm: token bucket
// in memory => for large scales we can use distributed cache like memcache
// or something like that
package ratelimit

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
)

func Middleware(cfg config.RateLimitConfig) waf.Middleware {
	limiter := newLimiter()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			rule, scope := ruleForRequest(cfg, r)
			if !ruleEnabled(rule) {
				next.ServeHTTP(w, r)
				return
			}

			key := bucketKey(scope, rule.Key, keyValue(r, rule.Key))
			if !limiter.allow(key, rule) {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// this is textbook token bucket implementation
// Ask from any software engineer
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

func newLimiter() *limiter {
	return &limiter{
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

func (l *limiter) allow(key string, rule config.TokenBucketRule) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{
			tokens:     float64(rule.Capacity),
			lastRefill: now,
		}
		l.buckets[key] = b
	}

	refill(b, rule, now)

	if b.tokens < 1 {
		return false
	}

	b.tokens--
	return true
}

func refill(b *bucket, rule config.TokenBucketRule, now time.Time) {
	if now.Before(b.lastRefill) {
		b.lastRefill = now
		return
	}

	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed <= 0 || rule.RefillRatePerSecond <= 0 {
		return
	}

	b.tokens += elapsed * rule.RefillRatePerSecond
	if b.tokens > float64(rule.Capacity) {
		b.tokens = float64(rule.Capacity)
	}
	b.lastRefill = now
}

func ruleForRequest(cfg config.RateLimitConfig, r *http.Request) (config.TokenBucketRule, string) {
	if cfg.Routes != nil {
		if rule, ok := cfg.Routes[r.URL.Path]; ok {
			return rule, r.URL.Path
		}
	}

	return cfg.Default, "default"
}

func ruleEnabled(rule config.TokenBucketRule) bool {
	return rule.Capacity > 0 && rule.RefillRatePerSecond >= 0
}

func bucketKey(scope, keyMode, value string) string {
	return scope + "|" + strings.ToLower(strings.TrimSpace(keyMode)) + "|" + value
}

func keyValue(r *http.Request, keyMode string) string {
	switch strings.ToLower(strings.TrimSpace(keyMode)) {
	case "user", "jwt_subject":
		if userID, _ := r.Context().Value(waf.UserIDKey).(string); userID != "" {
			return userID
		}
	case "user_or_ip":
		if userID, _ := r.Context().Value(waf.UserIDKey).(string); userID != "" {
			return userID
		}

		return clientIP(r)
	case "api_key":
		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			return apiKey
		}
	}

	return clientIP(r)
}

func clientIP(r *http.Request) string {
	if clientIP, _ := r.Context().Value(waf.ClientIPKey).(string); clientIP != "" {
		return clientIP
	}

	return r.RemoteAddr
}
