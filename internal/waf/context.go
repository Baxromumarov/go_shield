// Package waf contains shared building blocks for the GoShield security pipeline.
//
// This file defines request context keys used by multiple middleware packages.
// Shared values such as request ID, client IP, user ID, and block reasons should
// be stored in the request context so later middleware and loggers can use them.
//
// Plan: add helper functions here when several packages need the same metadata.
// Avoid storing large data such as full request bodies in context.
package waf

type contextKey string

const (
	RequestIDKey contextKey = "request_id"
	ClientIPKey  contextKey = "client_ip"
	UserIDKey    contextKey = "user_id"
	UserRoleKey  contextKey = "user_role"
)
