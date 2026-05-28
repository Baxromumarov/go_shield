// Package waf contains shared building blocks for the GoShield security pipeline.
//
// This file defines how middleware components are connected together.
// Each WAF feature should be a small middleware that either blocks the request
// or passes it to the next handler.
//
// Plan: keep this package generic. It should not know about SQLi, JWT, CORS,
// or rate limiting directly; it only provides the common pipeline mechanism.
package waf

import "net/http"

// Middleware wraps an http.Handler with additional behavior.
type Middleware func(http.Handler) http.Handler

// MiddlewareFunc is the inner function most middleware packages implement.
type MiddlewareFunc func(http.ResponseWriter, *http.Request, http.Handler)

// Wrap converts a MiddlewareFunc into a Middleware.
func Wrap(fn MiddlewareFunc) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fn(w, r, next)
		})
	}
}

// Chain applies middleware in the order they are provided.
//
// Example:
//
//	handler := waf.Chain(proxy, logging, sizeLimit, rateLimit)
//
// Request flow will be: logging -> sizeLimit -> rateLimit -> proxy.
func Chain(final http.Handler, middleware ...Middleware) http.Handler {
	for i := len(middleware) - 1; i >= 0; i-- {
		final = middleware[i](final)
	}

	return final
}
