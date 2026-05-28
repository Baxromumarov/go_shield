// Package waf contains shared building blocks for the GoShield security pipeline.
//
// This file defines request context keys used by multiple middleware packages.
// Shared values such as request ID, client IP, user ID, and block reasons should
// be stored in the request context so later middleware and loggers can use them.
//
// Plan: add helper functions here when several packages need the same metadata.
// Avoid storing large data such as full request bodies in context.
package waf

import (
	"log"
	"net/http"
)

type contextKey string

const (
	RequestIDKey contextKey = "request_id"
	ClientIPKey  contextKey = "client_ip"
	UserIDKey    contextKey = "user_id"
	UserRoleKey  contextKey = "user_role"
)

func GetCtxKey(r *http.Request, key contextKey) string {
	contextValue, ok := r.Context().Value(key).(string)
	if !ok {
		// TODO: handle the error
		log.Println("request id doesn't exists or not a string")
	}

	return contextValue
}
