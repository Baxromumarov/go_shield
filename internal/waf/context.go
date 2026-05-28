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
