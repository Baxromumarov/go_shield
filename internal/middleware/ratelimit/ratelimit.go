// just simple rate limiter, algorithm: token bucket
// in memory => for large scales we can use distributed cache like memcache
// or something like that
package ratelimit

import (
	"net/http"
	"sync"
	"time"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/waf"
	"golang.org/x/time/rate"
)

func Middleware(cfg config.RateLimitConfig) waf.Middleware {
	limiter := newLimiter()

	return waf.Wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if !cfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		rule, ok := ruleForRequest(cfg, r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		if !limiter.allow(r.URL.Path, rule) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// it's a text book token bucket rate limiter
// ask any software engineer
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*rate.Limiter
	now     func() time.Time
}

func newLimiter() *limiter {
	return &limiter{
		buckets: make(map[string]*rate.Limiter),
		now:     time.Now,
	}
}

func (l *limiter) allow(key string, rule config.TokenBucketRule) bool {
	if !ruleEnabled(rule) {
		return true
	}

	bucket := l.bucket(key, rule)

	return bucket.AllowN(l.now(), 1)
}

func (l *limiter) bucket(key string, rule config.TokenBucketRule) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, ok := l.buckets[key]
	if ok {
		return bucket
	}

	bucket = rate.NewLimiter(rate.Limit(rule.RefillRatePerSecond), int(rule.Capacity))
	l.buckets[key] = bucket
	return bucket
}

func ruleForRequest(cfg config.RateLimitConfig, r *http.Request) (config.TokenBucketRule, bool) {
	if cfg.Routes != nil {
		if rule, ok := cfg.Routes[r.URL.Path]; ok {
			return rule, ruleEnabled(rule)
		}
	}

	return config.TokenBucketRule{}, false
}

func ruleEnabled(rule config.TokenBucketRule) bool {
	return rule.Capacity > 0 && rule.RefillRatePerSecond >= 0
}
