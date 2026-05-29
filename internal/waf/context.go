package waf

import (
	"log/slog"
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
		slog.Warn("request context value missing or not a string", "key", string(key))
	}

	return contextValue
}
