// Package ratelimit applies per-route token bucket limits using the configured
// shared state backend.
//
// Still a textbook token bucket. Ask any software engineer.
package ratelimit

import (
	"fmt"
	"net"
	"net/http"

	"github.com/baxromumarov/go_shield/internal/config"
	"github.com/baxromumarov/go_shield/internal/state"
	"github.com/baxromumarov/go_shield/internal/textutil"
	"github.com/baxromumarov/go_shield/internal/waf"
)

func Middleware(cfg config.RateLimitConfig, stores ...state.TokenBucketStore) waf.Middleware {
	limiter := newLimiter(stores...)

	return waf.Wrap(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if !cfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		route, rule, ok := ruleForRequest(cfg, r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		allowed, err := limiter.allow(r, rateLimitKey(cfg, route, r), rule)
		if err != nil {
			if cfg.FailOpen {
				next.ServeHTTP(w, r)
				return
			}

			http.Error(w, "rate limiter unavailable", http.StatusServiceUnavailable)
			return
		}

		if !allowed {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type limiter struct {
	store state.TokenBucketStore
}

func newLimiter(stores ...state.TokenBucketStore) *limiter {
	store := state.TokenBucketStore(state.NewMemory())
	if len(stores) > 0 && stores[0] != nil {
		store = stores[0]
	}

	return &limiter{
		store: store,
	}
}

func (l *limiter) allow(r *http.Request, key string, rule config.TokenBucketRule) (bool, error) {
	if !ruleEnabled(rule) {
		return true, nil
	}

	return l.store.Take(r.Context(), state.TokenBucket{
		Key:                 key,
		Capacity:            rule.Capacity,
		RefillRatePerSecond: rule.RefillRatePerSecond,
	})
}

func ruleForRequest(cfg config.RateLimitConfig, r *http.Request) (string, config.TokenBucketRule, bool) {
	if cfg.Routes != nil {
		if rule, ok := cfg.Routes[r.URL.Path]; ok {
			return r.URL.Path, rule, ruleEnabled(rule)
		}
	}

	return "", config.TokenBucketRule{}, false
}

func ruleEnabled(rule config.TokenBucketRule) bool {
	return rule.Capacity > 0 && rule.RefillRatePerSecond >= 0
}

func rateLimitKey(cfg config.RateLimitConfig, route string, r *http.Request) string {
	return fmt.Sprintf("route=%s identity=%s", route, requestIdentity(cfg.KeyBy, r))
}

func requestIdentity(keyBy string, r *http.Request) string {
	switch textutil.LowerTrim(keyBy) {
	case "global":
		return "global"
	case "user_id":
		if userID, ok := waf.LookupCtxKey(r, waf.UserIDKey); ok && userID != "" {
			return "user:" + userID
		}
		return "anonymous:" + clientIdentifier(r)
	case "user_or_ip":
		if userID, ok := waf.LookupCtxKey(r, waf.UserIDKey); ok && userID != "" {
			return "user:" + userID
		}
		return "ip:" + clientIdentifier(r)
	default:
		return "ip:" + clientIdentifier(r)
	}
}

func clientIdentifier(r *http.Request) string {
	if clientIP, ok := waf.LookupCtxKey(r, waf.ClientIPKey); ok && clientIP != "" {
		return clientIP
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	if host == "" {
		return "unknown"
	}

	return host
}
