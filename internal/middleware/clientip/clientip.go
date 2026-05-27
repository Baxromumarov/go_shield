// Package clientip resolves the real client IP address for a request.
//
// This file centralizes IP extraction so IP blocking, rate limiting, and logs
// all use the same value.
//
// Plan: add trusted proxy configuration before fully trusting X-Forwarded-For.
// Without trusted proxy checks, attackers can spoof these headers when they
// connect directly to GoShield.
package clientip

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/baxromumarov/go_shield/internal/waf"
)

// Middleware stores the resolved client IP in request context.
func Middleware() waf.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), waf.ClientIPKey, Resolve(r))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Resolve returns the best available client IP for the request.
func Resolve(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}

	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}
